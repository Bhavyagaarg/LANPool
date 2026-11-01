import argparse
import asyncio
import hashlib
import ipaddress
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Optional

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Header, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from config import (
    ALLOW_LOOPBACK_DOWNLOADS,
    API_TOKEN,
    BASE_DIR,
    BEACON_INTERVAL_SECONDS,
    CACHE_DIR,
    CHUNK_SIZE,
    DEFAULT_PORT,
    DOWNLOAD_DIR,
    MANUAL_PEER_PROBE_TIMEOUT_SECONDS,
    MAX_CONCURRENT_DOWNLOADS,
    MAX_DOWNLOAD_TASKS,
    PEER_TTL_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    UDP_DISCOVERY_PORT,
)
from core.cache_manager import HEX_64_PATTERN, CacheManager
from core.downloader import SoloDownloadTask
from core.net_utils import get_lan_ip
from core.peer_discovery import PeerDiscovery
from core.peer_registry import PeerRegistry
from core.worker import RemoteContentChangedError, fetch_chunk_from_origin
from core.test_data import get_deterministic_data
from core.url_safety import validate_download_url
from core.watchdog import NodeQoSManager

logger = logging.getLogger("LANPool.Main")

# Unique Node ID per daemon startup (Rule A)
NODE_ID = uuid.uuid4().hex


def require_api_token(request: Request):
    """
    Safeguard / Finding 6: API Token Authentication.
    Reads X-LANPool-Token header when API_TOKEN is configured.
    """
    if API_TOKEN:
        token = request.headers.get("X-LANPool-Token", "").strip()
        if token != API_TOKEN:
            raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing API token")


def get_node_cache_manager(request: Request) -> CacheManager:
    """Retrieves the per-node CacheManager from request.app.state, raising HTTP 500 if uninitialized."""
    if not request or not hasattr(request.app.state, "cache_manager"):
        raise HTTPException(status_code=500, detail="Node CacheManager is not initialized.")
    return request.app.state.cache_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI Lifespan Context Manager.
    Initializes per-instance CacheManager, PeerRegistry, and PeerDiscovery on startup,
    and cleanly stops background tasks and UDP transport on shutdown.
    """
    port = getattr(app.state, "http_port", DEFAULT_PORT)
    lan_ip = getattr(app.state, "lan_ip", None) or get_lan_ip()
    cache_dir = getattr(app.state, "cache_dir", CACHE_DIR)
    download_dir = getattr(app.state, "download_dir", DOWNLOAD_DIR)

    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    Path(download_dir).mkdir(parents=True, exist_ok=True)

    app.state.node_id = NODE_ID
    app.state.http_port = port
    app.state.lan_ip = lan_ip
    app.state.cache_dir = Path(cache_dir)
    app.state.download_dir = Path(download_dir)

    # Initialize per-node CacheManager (Finding 7)
    app.state.cache_manager = CacheManager(cache_dir=cache_dir)

    # Initialize per-node QoS Manager (Safeguard #11 & Stage 5)
    qos_manager = getattr(app.state, "qos_manager", None)
    if qos_manager is None:
        qos_manager = NodeQoSManager()
    qos_manager.start()
    app.state.qos_manager = qos_manager

    registry = PeerRegistry(own_node_id=NODE_ID, own_http_port=port, own_lan_ip=lan_ip)
    discovery = PeerDiscovery(
        node_id=NODE_ID,
        http_port=port,
        lan_ip=lan_ip,
        registry=registry,
        udp_port=UDP_DISCOVERY_PORT,
        beacon_interval=BEACON_INTERVAL_SECONDS,
        peer_ttl=PEER_TTL_SECONDS,
        qos_manager=qos_manager,
    )
    app.state.peer_registry = registry
    app.state.peer_discovery = discovery

    await discovery.start()
    try:
        yield
    finally:
        await discovery.stop()
        if hasattr(app.state, "qos_manager") and app.state.qos_manager:
            app.state.qos_manager.stop()


app = FastAPI(title="LANPool Node", version="1.0.0", lifespan=lifespan)

# Active download tasks registry
download_tasks: Dict[str, SoloDownloadTask] = {}
latest_job_id: Optional[str] = None


class DownloadRequest(BaseModel):
    url: str
    filename: Optional[str] = None


class PeerAddRequest(BaseModel):
    ip: str
    port: int = 8000


class WorkerChunkRequest(BaseModel):
    url: str
    start_byte: int
    end_byte: int
    chunk_id: int
    etag: str = ""


class QoSUpdateRequest(BaseModel):
    share_pct: Optional[int] = None
    boosted: Optional[bool] = None
    simulate_game_mode: Optional[bool] = None
    throttling_enabled: Optional[bool] = None


class BoostRequestModel(BaseModel):
    filename: str
    total_size: int


class BoostNotifyModel(BaseModel):
    requester_id: str
    requester_ip: str
    filename: str
    total_size: int


class BoostResponseModel(BaseModel):
    action: str


@app.get("/api/health")
async def health(request: Request):
    """Safeguard #3: Reports node health, physical LAN IP, node_id, port, and UDP listener status."""
    discovery: Optional[PeerDiscovery] = getattr(request.app.state, "peer_discovery", None)
    udp_running = discovery.listener_running if discovery else False
    udp_port = discovery.udp_port if discovery else UDP_DISCOVERY_PORT

    lan_ip = getattr(request.app.state, "lan_ip", None) or get_lan_ip()
    http_port = getattr(request.app.state, "http_port", DEFAULT_PORT)
    node_id = getattr(request.app.state, "node_id", NODE_ID)

    return {
        "status": "online",
        "lan_ip": lan_ip,
        "stage": 5,
        "version": "1.0.0",
        "active_downloads": len([t for t in download_tasks.values() if t.status in ("probing", "downloading", "queued")]),
        "node_id": node_id,
        "http_port": http_port,
        "udp_listener": {
            "running": udp_running,
            "port": udp_port,
        },
    }


# -----------------------------------------------------------------------------
# STAGE 3 & 3.5: Peer Discovery, Registry & Diagnostics Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/peers/list", dependencies=[Depends(require_api_token)])
async def list_peers(request: Request):
    """Returns currently discovered and manual peers with live age calculation."""
    registry: Optional[PeerRegistry] = getattr(request.app.state, "peer_registry", None)
    peers = registry.list_peers() if registry else []
    return {
        "peers": peers,
        "count": len(peers),
        "node_id": getattr(request.app.state, "node_id", NODE_ID),
        "http_port": getattr(request.app.state, "http_port", DEFAULT_PORT),
    }


@app.post("/api/peers/add", dependencies=[Depends(require_api_token)])
async def add_peer(req: PeerAddRequest, request: Request):
    """
    Manual fallback when UDP broadcast is blocked by firewalls (Rule C).
    Enforces IP safety validation (Finding 10) and health verification.
    """
    raw_ip = (req.ip or "").strip()
    try:
        ip_obj = ipaddress.IPv4Address(raw_ip)
        if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_link_local or str(ip_obj) == "255.255.255.255":
            raise HTTPException(
                status_code=400,
                detail=f"Prohibited peer IP: '{raw_ip}'. Unspecified, multicast, and broadcast addresses are forbidden."
            )
        clean_ip = str(ip_obj)
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IPv4 address: '{req.ip}'. Must be a valid IPv4 string."
        )

    if not (1 <= req.port <= 65535):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid port: {req.port}. Port must be between 1 and 65535."
        )

    current_port = getattr(request.app.state, "http_port", DEFAULT_PORT)
    current_lan_ip = getattr(request.app.state, "lan_ip", None) or get_lan_ip()
    if req.port == current_port and clean_ip in ("127.0.0.1", "localhost", current_lan_ip, "0.0.0.0"):
        raise HTTPException(status_code=400, detail="Cannot add self as a peer.")

    health_url = f"http://{clean_ip}:{req.port}/api/health"
    try:
        async with httpx.AsyncClient(timeout=MANUAL_PEER_PROBE_TIMEOUT_SECONDS) as client:
            resp = await client.get(health_url)
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Peer health check returned status {resp.status_code} at {health_url}"
                )
            data = resp.json()
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to peer at {health_url}: {exc}"
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Unexpected error probing peer at {health_url}: {exc}"
        )

    if data.get("status") != "online":
        raise HTTPException(
            status_code=502,
            detail=f"Peer at {health_url} is not online (status='{data.get('status')}')."
        )

    peer_node_id = data.get("node_id")
    if not peer_node_id or not isinstance(peer_node_id, str):
        raise HTTPException(
            status_code=502,
            detail=f"Peer at {health_url} returned invalid or missing node_id."
        )

    if peer_node_id == getattr(request.app.state, "node_id", NODE_ID):
        raise HTTPException(status_code=400, detail="Cannot add self as a peer (node_id matches).")

    registry: Optional[PeerRegistry] = getattr(request.app.state, "peer_registry", None)
    if not registry:
        raise HTTPException(status_code=500, detail="Peer registry not initialized.")

    peer = registry.add_manual(
        ip=clean_ip,
        port=req.port,
        node_id=peer_node_id,
        lan_ip=data.get("lan_ip", clean_ip),
    )
    return peer


@app.get("/api/diagnostics/network", dependencies=[Depends(require_api_token)])
async def network_diagnostics(request: Request):
    """Returns network diagnostics and firewall troubleshooting information."""
    discovery: Optional[PeerDiscovery] = getattr(request.app.state, "peer_discovery", None)
    if discovery:
        return discovery.get_diagnostics()

    lan_ip = getattr(request.app.state, "lan_ip", None) or get_lan_ip()
    port = getattr(request.app.state, "http_port", DEFAULT_PORT)
    return {
        "node_id": getattr(request.app.state, "node_id", NODE_ID),
        "http_port": port,
        "lan_ip": lan_ip,
        "udp": {
            "listener_running": False,
            "bind_host": "0.0.0.0",
            "port": UDP_DISCOVERY_PORT,
            "reuse_address": True,
            "reuse_port": True,
            "broadcast_targets": ["255.255.255.255", "127.255.255.255"],
            "beacon_interval_seconds": BEACON_INTERVAL_SECONDS,
            "last_beacon_sent": None,
            "last_beacon_received": None,
            "last_error": "Discovery not initialized",
        },
        "peers": {
            "total": 0,
            "udp": 0,
            "manual": 0,
            "stale_after_seconds": PEER_TTL_SECONDS,
        },
        "firewall_hint": (
            f"If UDP discovery fails across LAN, ensure UDP port {UDP_DISCOVERY_PORT} "
            "is allowed in firewall settings, or use POST /api/peers/add to connect directly."
        ),
    }


# -----------------------------------------------------------------------------
# STAGE 4: Cooperative Worker Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/worker/fetch-chunk", dependencies=[Depends(require_api_token)])
async def worker_fetch_chunk(req: WorkerChunkRequest, request: Request):
    """
    Stage 4 Helper Endpoint:
    Fetches a single validated chunk from the origin on behalf of a peer.
    Enforces Range assertions, ETag pinning, exact byte length, SHA-256 verification,
    and Stage 5 QoS bandwidth sharing throttling.
    """
    if req.start_byte < 0 or req.end_byte < req.start_byte:
        raise HTTPException(
            status_code=400,
            detail="Invalid byte range: start_byte must be >= 0 and <= end_byte",
        )
    if (req.end_byte - req.start_byte + 1) > CHUNK_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Requested range exceeds CHUNK_SIZE ({CHUNK_SIZE} bytes)",
        )
    if req.chunk_id < 0:
        raise HTTPException(
            status_code=400,
            detail="Invalid chunk_id: must be >= 0",
        )

    try:
        await validate_download_url(req.url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"SSRF validation failed: {exc}")

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            chunk_data, chunk_sha = await fetch_chunk_from_origin(
                url=req.url,
                start_byte=req.start_byte,
                end_byte=req.end_byte,
                etag=req.etag,
                client=client,
            )
    except RemoteContentChangedError as exc:
        raise HTTPException(status_code=409, detail=f"Remote content changed: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {exc}")

    qos: Optional[NodeQoSManager] = getattr(request.app.state, "qos_manager", None)
    if qos:
        await qos.throttle_bytes(len(chunk_data))

    return Response(
        content=chunk_data,
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(len(chunk_data)),
            "X-Chunk-SHA256": chunk_sha,
        },
    )


# -----------------------------------------------------------------------------
# STAGE 1 & 2: Download & LAN-Cache Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/download/start", dependencies=[Depends(require_api_token)])
async def start_download(req: DownloadRequest, request: Request):
    """
    Starts Stage 1 Solo Download Task:
    Validates URL safety (Finding 6), checks concurrency limit (Finding 11),
    prunes task history (Finding 11), prevents duplicate filename conflicts (Finding 4),
    and dispatches workers with isolated per-job .part path.
    """
    sanitized_filename = (req.filename or "").strip() if req.filename is not None else None
    if sanitized_filename is not None:
        if (
            not sanitized_filename
            or sanitized_filename in (".", "..")
            or "/" in sanitized_filename
            or "\\" in sanitized_filename
            or "\x00" in sanitized_filename
            or os.path.basename(sanitized_filename) != sanitized_filename
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid filename: must be a non-empty base filename and must not contain '/', '\\', null bytes, or traversal elements."
            )

    # Finding 6: SSRF URL validation
    try:
        await validate_download_url(req.url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=f"Invalid download URL: {val_err}")

    # Finding 11: Concurrency limit (MAX_CONCURRENT_DOWNLOADS = 4)
    active_downloads = [t for t in download_tasks.values() if t.status in ("probing", "downloading", "queued")]
    if len(active_downloads) >= MAX_CONCURRENT_DOWNLOADS:
        raise HTTPException(
            status_code=429,
            detail=f"Concurrent download limit reached ({MAX_CONCURRENT_DOWNLOADS} active jobs)."
        )

    # Finding 11: Prune finished tasks if task history exceeds limit
    if len(download_tasks) >= MAX_DOWNLOAD_TASKS:
        finished = [
            (jid, t) for jid, t in download_tasks.items()
            if t.status in ("completed", "failed")
        ]
        if finished:
            finished.sort(key=lambda item: item[1].end_time or item[1].start_time or 0)
            to_remove = len(download_tasks) - MAX_DOWNLOAD_TASKS + 1
            for jid, _ in finished[:to_remove]:
                download_tasks.pop(jid, None)

    # Finding 4: Prevent duplicate active download for same destination file
    download_dir = getattr(request.app.state, "download_dir", DOWNLOAD_DIR)
    target_name = sanitized_filename or SoloDownloadTask._derive_filename(req.url)
    target_final_path = (download_dir / target_name).resolve()

    for active_t in active_downloads:
        if active_t.final_path == target_final_path:
            raise HTTPException(
                status_code=409,
                detail=f"A download task for file '{target_name}' is already active (job {active_t.job_id})."
            )

    global latest_job_id
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    cache_mgr = get_node_cache_manager(request)

    task = SoloDownloadTask(
        job_id=job_id,
        url=req.url,
        filename=target_name,
        download_dir=download_dir,
        cache_manager=cache_mgr,
        peer_registry=getattr(request.app.state, "peer_registry", None),
        api_token=API_TOKEN,
        own_node_id=getattr(request.app.state, "node_id", ""),
    )
    download_tasks[job_id] = task
    latest_job_id = job_id

    await task.start()

    return {
        "job_id": job_id,
        "status": "started",
        "url": req.url,
        "filename": task.filename,
    }


@app.get("/api/download/status", dependencies=[Depends(require_api_token)])
async def download_status(job_id: Optional[str] = None):
    """Returns live status, progress, speed, and chunk states for a download job."""
    target_id = job_id or latest_job_id
    if not target_id or target_id not in download_tasks:
        raise HTTPException(status_code=404, detail="No active or matching download job found.")

    task = download_tasks[target_id]
    return task.get_progress()


@app.get("/api/test-file/{size_mb}")
@app.head("/api/test-file/{size_mb}")
async def serve_test_file(
    size_mb: int,
    request: Request,
    range: Optional[str] = Header(None)
):
    """
    Deterministic binary stream endpoint supporting HTTP HEAD and Range: bytes=X-Y (HTTP 206).
    Capped at 100 MB (Finding 8).
    """
    if size_mb <= 0 or size_mb > 100:
        raise HTTPException(status_code=400, detail="size_mb must be between 1 and 100 MB")

    data = get_deterministic_data(size_mb)
    total_size = len(data)
    etag = f'"test-file-{size_mb}mb-{hashlib.sha256(data[:1024]).hexdigest()[:12]}"'

    common_headers = {
        "Accept-Ranges": "bytes",
        "ETag": etag,
    }

    if request.method == "HEAD":
        headers = dict(common_headers)
        headers["Content-Length"] = str(total_size)
        return Response(status_code=200, headers=headers)

    if range and range.startswith("bytes="):
        range_spec = range[len("bytes="):].strip()
        parts = range_spec.split("-")

        try:
            if not parts[0] and len(parts) > 1 and parts[1]:
                # Suffix range: bytes=-500 -> last 500 bytes
                suffix_len = int(parts[1])
                start = max(total_size - suffix_len, 0)
                end = total_size - 1
            else:
                start = int(parts[0]) if parts[0] else 0
                end = int(parts[1]) if len(parts) > 1 and parts[1] else total_size - 1
        except ValueError:
            raise HTTPException(status_code=416, detail="Invalid Range header format")

        if start < 0 or end >= total_size or start > end:
            raise HTTPException(
                status_code=416,
                detail="Requested range not satisfiable",
                headers={"Content-Range": f"bytes */{total_size}"}
            )

        content = data[start:end + 1]
        range_headers = dict(common_headers)
        range_headers["Content-Range"] = f"bytes {start}-{end}/{total_size}"
        range_headers["Content-Length"] = str(len(content))
        return Response(content=content, status_code=206, headers=range_headers)

    full_headers = dict(common_headers)
    full_headers["Content-Length"] = str(total_size)
    return Response(content=data, status_code=200, headers=full_headers)


@app.get("/api/cache/list", dependencies=[Depends(require_api_token)])
async def cache_list(request: Request):
    """Lists all files registered in the LAN-Cache ring buffer."""
    cache_mgr = get_node_cache_manager(request)
    return cache_mgr.list_items()


@app.get("/api/cache/lookup", dependencies=[Depends(require_api_token)])
async def cache_lookup(url: str, request: Request, etag: str = ""):
    """
    Safeguard #6: Stale Cache Prevention via ETag Verification.
    Returns {"hit": true, "sha256": ..., "size": ...} on exact composite match, else {"hit": false}.
    """
    cache_mgr = get_node_cache_manager(request)
    return cache_mgr.lookup(url=url, etag=etag)


@app.get("/api/cache/stream/{sha256:path}", dependencies=[Depends(require_api_token)])
async def cache_stream(sha256: str, request: Request):
    """
    Safeguard #7: Zero Path Traversal (SHA-256 Hash-Only Serving).
    Validates strictly 64 hex characters. Serves exclusively from approved in-memory index.
    """
    clean_sha = sha256.lower().strip()
    if not HEX_64_PATTERN.match(clean_sha):
        raise HTTPException(
            status_code=400,
            detail="Invalid hash format: sha256 must be strictly 64 lowercase hexadecimal characters."
        )

    cache_mgr = get_node_cache_manager(request)
    file_path = cache_mgr.stream_path(clean_sha)
    if not file_path or not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Hash '{clean_sha}' not found in approved LAN-Cache."
        )

    entry = cache_mgr.approved_hash_map.get(clean_sha, {})
    download_filename = entry.get("filename", f"{clean_sha}.bin")

    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=download_filename,
    )


# -----------------------------------------------------------------------------
# STAGE 5: QoS Watchdog, Good Samaritan Boost & Web Dashboard Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/qos/status", dependencies=[Depends(require_api_token)])
async def get_qos_status(request: Request):
    """Safeguard #11: Returns current QoS status, bandwidth share, and active boost request."""
    qos: Optional[NodeQoSManager] = getattr(request.app.state, "qos_manager", None)
    if not qos:
        raise HTTPException(status_code=500, detail="QoS Manager not initialized.")
    return qos.get_status()


@app.post("/api/qos/update", dependencies=[Depends(require_api_token)])
async def update_qos(req: QoSUpdateRequest, request: Request):
    """Updates bandwidth share, boost state, or simulates game focus mode."""
    qos: Optional[NodeQoSManager] = getattr(request.app.state, "qos_manager", None)
    if not qos:
        raise HTTPException(status_code=500, detail="QoS Manager not initialized.")
    try:
        return qos.update(
            share_pct=req.share_pct,
            boosted=req.boosted,
            simulate_game_mode=req.simulate_game_mode,
            throttling_enabled=req.throttling_enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/qos/boost-request", dependencies=[Depends(require_api_token)])
async def broadcast_boost_request(req: BoostRequestModel, request: Request):
    """
    Broadcasts a Good Samaritan boost request to all active peers on the LAN.
    Active peers with Game Mode inactive will display an interactive boost toast.
    """
    registry: Optional[PeerRegistry] = getattr(request.app.state, "peer_registry", None)
    node_id = getattr(request.app.state, "node_id", NODE_ID)
    lan_ip = getattr(request.app.state, "lan_ip", None) or get_lan_ip()
    peers = registry.list_peers() if registry else []
    active_peers = [p for p in peers if p.get("node_id") != node_id]

    headers = {}
    if API_TOKEN:
        headers["X-LANPool-Token"] = API_TOKEN

    payload = {
        "requester_id": node_id,
        "requester_ip": lan_ip,
        "filename": req.filename,
        "total_size": req.total_size,
    }

    async def _notify(p: dict):
        pip = p.get("ip") or p.get("lan_ip")
        pport = p.get("port") or p.get("http_port")
        url = f"http://{pip}:{pport}/api/qos/boost-notify"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.post(url, json=payload, headers=headers)
                return {
                    "peer": p.get("node_id"),
                    "status": r.status_code,
                    "data": r.json() if r.status_code == 200 else None,
                }
        except Exception as exc:
            return {"peer": p.get("node_id"), "error": str(exc)}

    raw_results = await asyncio.gather(*[_notify(p) for p in active_peers], return_exceptions=True)
    clean_results = []
    for r in raw_results:
        if isinstance(r, Exception):
            clean_results.append({"error": str(r)})
        else:
            clean_results.append(r)
    return {"status": "broadcast_complete", "notified_count": len(active_peers), "results": clean_results}


@app.post("/api/qos/boost-notify", dependencies=[Depends(require_api_token)])
async def receive_boost_notification(req: BoostNotifyModel, request: Request):
    """
    Receives an incoming boost notification from a downloading peer.
    If Game Focus Mode is active, automatically suppresses/silences the request.
    """
    qos: Optional[NodeQoSManager] = getattr(request.app.state, "qos_manager", None)
    if not qos:
        raise HTTPException(status_code=500, detail="QoS Manager not initialized.")

    accepted, reason = qos.handle_incoming_boost(
        requester_id=req.requester_id,
        requester_ip=req.requester_ip,
        filename=req.filename,
        total_size=req.total_size,
    )
    return {"accepted": accepted, "reason": reason}


@app.post("/api/qos/boost-respond", dependencies=[Depends(require_api_token)])
async def respond_to_boost(req: BoostResponseModel, request: Request):
    """User accepts ('boost') or dismisses ('dismiss') an active boost request."""
    qos: Optional[NodeQoSManager] = getattr(request.app.state, "qos_manager", None)
    if not qos:
        raise HTTPException(status_code=500, detail="QoS Manager not initialized.")
    try:
        return qos.respond_to_boost(req.action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# Static Files & Dashboard UI
STATIC_DIR = (BASE_DIR / "static").resolve()
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def serve_dashboard():
    """Serves the Stage 5 precision engineering web dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file, media_type="text/html")
    return {"status": "online", "message": "LANPool Web Dashboard UI loading...", "stage": 5}


def main():
    parser = argparse.ArgumentParser(description="LANPool Node Daemon")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind (default 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface to bind")
    parser.add_argument("--cache-dir", type=str, default=str(CACHE_DIR), help="Directory for LANPool cache storage")
    parser.add_argument("--download-dir", type=str, default=str(DOWNLOAD_DIR), help="Directory for temporary/completed downloads")
    args = parser.parse_args()

    app.state.http_port = args.port
    app.state.lan_ip = get_lan_ip()
    app.state.cache_dir = Path(args.cache_dir).resolve()
    app.state.download_dir = Path(args.download_dir).resolve()

    if not API_TOKEN:
        logger.warning("WARNING: LANPOOL_API_TOKEN is not set; any LAN host can use this daemon.")
    if ALLOW_LOOPBACK_DOWNLOADS:
        logger.warning("WARNING: Loopback downloads allowed (default); set LANPOOL_ALLOW_LOOPBACK=0 in production.")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
