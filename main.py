import argparse
import asyncio
import hashlib
import hmac
import json
import re
import secrets
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
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from config import PEER_SECRET, MAX_HELPER_REQUESTS
from core.peer_auth import verify_request, signed_request, verify_content, sign_content, send_bounded, peer_url, peer_client
from core.url_safety import origin_client
from core.io_utils import disk_call, acquire_resource, ManagedStreamingResponse
from core.http_limits import BodyLimitMiddleware

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
from core.test_data import iter_test_data
from config import APP_VERSION, PROJECT_STAGE, TEST_FILES_ENABLED, TRUST_GROUP_CONTENT
from core.url_safety import validate_download_url
from core.watchdog import NodeQoSManager

logger = logging.getLogger("LANPool.Main")

# Unique Node ID per daemon startup (Rule A)
NODE_ID = uuid.uuid4().hex


_peer_replays = {}
_download_tickets = {}
PEER_ROUTES = {"/api/worker/fetch-chunk", "/api/cache/lookup", "/api/qos/boost-notify", "/api/qos/boost-release", "/api/qos/status"}


async def require_api_token(request: Request):
    ticket = request.query_params.get("ticket", "")
    grant = _download_tickets.pop(ticket, None) if ticket else None
    if grant and request.method == "GET" and grant[1] >= time.monotonic() and request.url.path == "/api/cache/stream/" + grant[0]:
        return
    token = request.headers.get("X-LANPool-Token", "")
    if API_TOKEN and hmac.compare_digest(token.encode(), API_TOKEN.encode()):
        return
    path = request.scope.get("raw_path", request.url.path.encode()).decode("ascii")
    if request.scope.get("query_string"):
        path += "?" + request.scope["query_string"].decode("ascii")
    if (request.url.path in PEER_ROUTES or request.url.path.startswith("/api/cache/stream/")) and verify_request(request.method, path, await request.body(), request.headers, _peer_replays):
        return
    # With no admin credential only same-machine callers may control the daemon.
    host = request.client.host if request.client else ""
    if not API_TOKEN and host in ("127.0.0.1", "::1", "testclient") and request.url.hostname in ("127.0.0.1", "localhost", "::1", "test", "testserver") and not request.headers.get("X-LANPool-Peer-Signature"):
        origin = request.headers.get("Origin")
        if not origin or origin == str(request.base_url).rstrip("/"):
            return
    raise HTTPException(status_code=401, detail="Authentication required")


def signed_json(data):
    response = JSONResponse(data)
    response.headers["X-LANPool-Content-Signature"] = sign_content(hashlib.sha256(response.body).hexdigest())
    response.headers["Cache-Control"] = "no-store"
    return response


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
    if Path(cache_dir).resolve() == Path(download_dir).resolve():
        raise ValueError("Cache and downloads directories must be distinct")

    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    Path(download_dir).mkdir(parents=True, exist_ok=True)

    app.state.node_id = NODE_ID
    app.state.http_port = port
    app.state.lan_ip = lan_ip
    app.state.cache_dir = Path(cache_dir)
    app.state.download_dir = Path(download_dir)

    # Initialize per-node CacheManager (Finding 7)
    app.state.cache_manager = await asyncio.to_thread(CacheManager, cache_dir=cache_dir)
    app.state.helper_slots = asyncio.Semaphore(MAX_HELPER_REQUESTS)
    app.state.fixture_slots = asyncio.Semaphore(4)
    await load_history(app)

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
        scheme=getattr(app.state, "http_scheme", "http"),
    )
    app.state.peer_registry = registry
    app.state.peer_discovery = discovery

    async def flush_cache_periodically():
        while True:
            await asyncio.sleep(2)
            await disk_call(app.state.cache_manager.flush)
    cache_flush_task = asyncio.create_task(flush_cache_periodically(), name="lanpool-cache-flush")
    await discovery.start()
    try:
        yield
    finally:
        await asyncio.gather(*(task.cancel() for task in download_tasks.values()))
        await save_history()
        await discovery.stop()
        await app.state.qos_manager.aclose()
        cache_flush_task.cancel()
        await asyncio.gather(cache_flush_task, return_exceptions=True)
        await disk_call(app.state.cache_manager.flush)


app = FastAPI(title="LANPool Node", version=APP_VERSION, lifespan=lifespan)
app.add_middleware(BodyLimitMiddleware)

# Active download tasks registry
download_tasks: Dict[str, SoloDownloadTask] = {}
latest_job_id: Optional[str] = None
archived_jobs = {}
_history_lock = asyncio.Lock()


async def save_history():
    async with _history_lock:
        entries = {**archived_jobs, **{key: task.get_progress() for key, task in download_tasks.items()}}
        entries = dict(list(entries.items())[-MAX_DOWNLOAD_TASKS:])
        folder = getattr(app.state, "download_dir", DOWNLOAD_DIR)
        def persist():
            path = Path(folder) / "jobs.json"
            temp = path.with_suffix(".json.tmp")
            temp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
            os.replace(temp, path)
        await asyncio.to_thread(persist)


async def load_history(application):
    global latest_job_id
    path = application.state.download_dir / "jobs.json"
    def read():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}
    for job_id, record in list((await asyncio.to_thread(read)).items())[-MAX_DOWNLOAD_TASKS:]:
        if not isinstance(record, dict) or not re.fullmatch(r"job-[0-9a-f]+", job_id):
            continue
        if record.get("status") in ("probing", "queued", "downloading"):
            record["status"], record["error"] = "cancelled", "Interrupted by restart; Retry starts a fresh verified download"
        archived_jobs[job_id] = record
        latest_job_id = job_id
    # Only this instance's own incomplete parts; cached completed files are retained.
    for part in application.state.download_dir.glob("*.part"):
        part.unlink(missing_ok=True)


class DownloadRequest(BaseModel):
    url: str = Field(max_length=8192)
    filename: Optional[str] = Field(default=None, max_length=180)
    expected_sha256: str = Field(default="", pattern=r"^(?:[0-9a-fA-F]{64})?$")
    offline: bool = False
    use_cache: bool = True
    use_peers: bool = True


class PeerAddRequest(BaseModel):
    ip: str
    port: int = 8000
    scheme: str = Field(default="http", pattern="^(http|https)$")


class WorkerChunkRequest(BaseModel):
    url: str
    start_byte: int
    end_byte: int
    chunk_id: int
    etag: str = ""
    total_size: Optional[int] = None


class QoSUpdateRequest(BaseModel):
    share_pct: Optional[int] = Field(default=None, strict=True)
    boosted: Optional[bool] = None
    simulate_game_mode: Optional[bool] = None
    throttling_enabled: Optional[bool] = None


class BoostRequestModel(BaseModel):
    filename: str
    total_size: int
    job_id: str = "manual"


class BoostNotifyModel(BaseModel):
    requester_id: str
    requester_ip: str
    filename: str
    total_size: int
    job_id: str = "manual"


class BoostReleaseModel(BaseModel):
    job_id: str


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

    return signed_json({
        "nonce": request.query_params.get("nonce", ""),
        "qos": {key: request.app.state.qos_manager.get_status()[key] for key in ("effective_share_pct", "effective_game_mode", "boosted")},
        "status": "online",
        "lan_ip": lan_ip,
        "stage": PROJECT_STAGE,
        "peer_hash_required": not TRUST_GROUP_CONTENT,
        "version": APP_VERSION,
        "active_downloads": len([t for t in download_tasks.values() if t.status in ("probing", "downloading", "queued")]),
        "node_id": node_id,
        "http_port": http_port,
        "udp_listener": {
            "running": udp_running,
            "port": udp_port,
        },
    })


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

    nonce = uuid.uuid4().hex
    health_url = f"{req.scheme}://{clean_ip}:{req.port}/api/health?nonce={nonce}"
    try:
        async with peer_client(MANUAL_PEER_PROBE_TIMEOUT_SECONDS) as client:
            resp = await send_bounded(client, client.build_request("GET", health_url))
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"Peer health check returned status {resp.status_code} at {health_url}"
                )
            data = resp.json()
            peer_trusted = bool(PEER_SECRET and data.get("nonce") == nonce and verify_content(hashlib.sha256(resp.content).hexdigest(), resp.headers.get("X-LANPool-Content-Signature", "")))
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
        trusted=peer_trusted,
        scheme=req.scheme,
    )
    registry.refresh_health(peer_node_id, data, peer_trusted)
    return registry.get(peer_node_id)


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
    if req.start_byte < 0 or req.end_byte < req.start_byte or req.chunk_id < 0 or req.end_byte - req.start_byte + 1 > CHUNK_SIZE:
        raise HTTPException(400, "Invalid chunk range/id")
    slots = request.app.state.helper_slots
    qos = request.app.state.qos_manager
    if qos.effective_share_pct == 0:
        raise HTTPException(503, "Sharing is disabled")
    if slots.locked():
        raise HTTPException(429, "Helper concurrency limit reached")
    await slots.acquire()
    try:
        await validate_download_url(req.url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)
        data, sha = await fetch_chunk_from_origin(req.url, req.start_byte, req.end_byte, req.etag, total_size=req.total_size, throttle=qos.throttle_bytes)
    except Exception as exc:
        slots.release()
        code = 409 if isinstance(exc, RemoteContentChangedError) else 400 if isinstance(exc, ValueError) else 503 if isinstance(exc, PermissionError) else 502
        raise HTTPException(code, str(exc))
    except BaseException:
        slots.release()
        raise
    released = False
    async def release_slot():
        nonlocal released
        if not released:
            released = True
            slots.release()
    async def stream():
        try:
            for offset in range(0, len(data), 65536):
                block = data[offset:offset+65536]
                await qos.throttle_bytes(len(block))
                yield block
        finally:
            await release_slot()
    return ManagedStreamingResponse(stream(), on_close=release_slot, media_type="application/octet-stream", headers={"Content-Length": str(len(data)), "X-Chunk-SHA256": sha, "X-LANPool-Content-Signature": sign_content(sha)})


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
            or any(char in sanitized_filename for char in '<>:"|?*')
            or sanitized_filename.endswith((".", " "))
            or sanitized_filename.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
            or os.path.basename(sanitized_filename) != sanitized_filename
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid filename: must be a non-empty base filename and must not contain '/', '\\', null bytes, or traversal elements."
            )

    # Finding 6: SSRF URL validation
    try:
        if not req.offline:
            await validate_download_url(req.url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)
        elif not req.expected_sha256:
            raise ValueError("Offline mode requires an expected SHA-256")
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
            if t.status in ("completed", "failed", "cancelled")
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
        expected_sha256=req.expected_sha256,
        offline=req.offline,
        on_state_change=save_history,
        use_cache=req.use_cache,
        use_peers=req.use_peers,
    )
    download_tasks[job_id] = task
    latest_job_id = job_id

    await task.start()
    await save_history()

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
    if target_id in archived_jobs and target_id not in download_tasks:
        return archived_jobs[target_id]
    if not target_id or target_id not in download_tasks:
        raise HTTPException(status_code=404, detail="No active or matching download job found.")

    task = download_tasks[target_id]
    return task.get_progress()


@app.get("/api/download/jobs", dependencies=[Depends(require_api_token)])
async def list_jobs():
    entries = {**archived_jobs, **{key: task.get_progress() for key, task in download_tasks.items()}}
    return {"jobs": list(entries.values())[-MAX_DOWNLOAD_TASKS:]}


@app.post("/api/download/{job_id}/cancel", dependencies=[Depends(require_api_token)])
async def cancel_job(job_id: str):
    if job_id not in download_tasks:
        raise HTTPException(404, "Live job not found")
    await download_tasks[job_id].cancel()
    return download_tasks[job_id].get_progress()


@app.post("/api/download/{job_id}/retry", dependencies=[Depends(require_api_token)])
async def retry_job(job_id: str, request: Request):
    record = download_tasks[job_id].get_progress() if job_id in download_tasks else archived_jobs.get(job_id)
    if not record:
        raise HTTPException(404, "Job not found")
    if record["status"] in ("probing", "queued", "downloading"):
        raise HTTPException(409, "Cancel the running job before retrying")
    return await start_download(DownloadRequest(**{key: record[key] for key in ("url", "filename", "expected_sha256", "offline", "use_cache", "use_peers") if key in record}), request)


@app.get("/api/test-file/{size_mb}")
@app.head("/api/test-file/{size_mb}")
async def serve_test_file(size_mb: int, request: Request, range: Optional[str] = Header(None)):
    if not TEST_FILES_ENABLED:
        raise HTTPException(404, "Test fixtures are disabled")
    if not 1 <= size_mb <= 100:
        raise HTTPException(400, "size_mb must be between 1 and 100 MiB")
    total = size_mb * 1048576
    headers = {"Accept-Ranges": "bytes", "ETag": f'"test-file-v3-{size_mb}mb"'}
    if request.method == "HEAD":
        return Response(headers={**headers, "Content-Length": str(total)})
    start, end, status = 0, total - 1, 200
    if range:
        match = re.fullmatch(r"bytes=(\d*)-(\d*)", range)
        if not match or not any(match.groups()):
            raise HTTPException(416, "Invalid Range", headers={"Content-Range": f"bytes */{total}"})
        first, last = match.groups()
        if first:
            start, end = int(first), min(int(last), total - 1) if last else total - 1
        else:
            suffix = int(last)
            if suffix <= 0:
                raise HTTPException(416, "Invalid suffix range")
            start = max(0, total - suffix)
        if start > end or start >= total:
            raise HTTPException(416, "Range not satisfiable", headers={"Content-Range": f"bytes */{total}"})
        headers["Content-Range"] = f"bytes {start}-{end}/{total}"
        status = 206
    slots = request.app.state.fixture_slots
    if slots.locked():
        raise HTTPException(429, "Test fixture stream limit reached")
    await slots.acquire()
    released = False
    async def release():
        nonlocal released
        if not released:
            released = True
            slots.release()
    async def stream():
        for block in iter_test_data(size_mb, start, end):
            yield block
    headers["Content-Length"] = str(end - start + 1)
    return ManagedStreamingResponse(stream(), status_code=status, on_close=release, headers=headers, media_type="application/octet-stream")


@app.get("/api/cache/list", dependencies=[Depends(require_api_token)])
async def cache_list(request: Request):
    """Lists all files registered in the LAN-Cache ring buffer."""
    cache_mgr = get_node_cache_manager(request)
    return await asyncio.to_thread(cache_mgr.list_items)


@app.get("/api/cache/lookup", dependencies=[Depends(require_api_token)])
async def cache_lookup(url: str, request: Request, etag: str = ""):
    """
    Safeguard #6: Stale Cache Prevention via ETag Verification.
    Returns {"hit": true, "sha256": ..., "size": ...} on exact composite match, else {"hit": false}.
    """
    cache_mgr = get_node_cache_manager(request)
    return signed_json(await asyncio.to_thread(cache_mgr.lookup, url=url, etag=etag))


@app.get("/api/cache/stream/{sha256:path}", dependencies=[Depends(require_api_token)])
async def cache_stream(sha256: str, request: Request):
    clean_sha = sha256.lower().strip()
    if not HEX_64_PATTERN.fullmatch(clean_sha):
        raise HTTPException(400, "Invalid SHA-256")
    manager = get_node_cache_manager(request)
    qos = request.app.state.qos_manager
    if qos.effective_share_pct == 0:
        raise HTTPException(503, "Sharing is disabled")
    lease = manager.lease(clean_sha)
    acquired = False
    try:
        path = await acquire_resource(lease.__enter__, lambda _: lease.__exit__(None, None, None))
        acquired = True
        size = path.stat().st_size
    except (OSError, ValueError):
        if acquired:
            await disk_call(lease.__exit__, None, None, None)
        raise HTTPException(404, "Cached file missing or corrupt")
    handle = None
    closed = False
    async def close_stream():
        nonlocal closed
        if closed:
            return
        closed = True
        def close():
            if handle:
                handle.close()
            lease.__exit__(None, None, None)
        await disk_call(close)
    async def stream():
        nonlocal handle
        try:
            handle = await acquire_resource(lambda: open(path, "rb"), lambda file: file.close())
            remaining = size
            while remaining:
                await qos.throttle_bytes(min(65536, remaining))
                block = await disk_call(handle.read, min(65536, remaining))
                if not block:
                    break
                remaining -= len(block)
                yield block
        finally:
            await close_stream()
    return ManagedStreamingResponse(stream(), on_close=close_stream, media_type="application/octet-stream", headers={"Content-Length": str(size), "X-LANPool-Content-Signature": sign_content(clean_sha)})


@app.post("/api/cache/ticket/{sha256}", dependencies=[Depends(require_api_token)])
async def create_download_ticket(sha256: str, request: Request):
    if not HEX_64_PATTERN.fullmatch(sha256):
        raise HTTPException(400, "Invalid SHA-256")
    manager = get_node_cache_manager(request)
    if not (await asyncio.to_thread(manager.find_by_sha, sha256)).get("hit"):
        raise HTTPException(404, "Cached file not found")
    for key, grant in list(_download_tickets.items()):
        if grant[1] < time.monotonic():
            _download_tickets.pop(key, None)
    if len(_download_tickets) >= 1024:
        raise HTTPException(429, "Too many pending download grants")
    ticket = secrets.token_urlsafe(32)
    _download_tickets[ticket] = (sha256, time.monotonic() + 30)
    return JSONResponse({"url": f"/api/cache/stream/{sha256}?ticket={ticket}"}, headers={"Cache-Control": "no-store"})


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
    active_peers = [p for p in peers if p.get("node_id") != node_id and p.get("trusted") and p.get("available", True)]

    headers = {}  # Separate peer signatures, never the administrative token.

    payload = {
        "requester_id": node_id,
        "requester_ip": lan_ip,
        "filename": req.filename,
        "total_size": req.total_size,
        "job_id": req.job_id,
    }

    async def _notify(p: dict):
        pip = p.get("ip") or p.get("lan_ip")
        pport = p.get("port") or p.get("http_port")
        url = peer_url(p, "/api/qos/boost-notify")
        try:
            async with peer_client(3.0) as client:
                r = await send_bounded(client, signed_request(client, "POST", url, json=payload))
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
        job_id=req.job_id,
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


@app.post("/api/qos/boost-release", dependencies=[Depends(require_api_token)])
async def release_boost(req: BoostReleaseModel, request: Request):
    request.app.state.qos_manager.release_boost(req.job_id)
    return {"status": "released"}


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
    return {"status": "online", "message": "LANPool Web Dashboard UI loading...", "stage": PROJECT_STAGE}


def main():
    parser = argparse.ArgumentParser(description="LANPool Node Daemon")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind (default 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (LAN binding requires API and peer credentials)")
    parser.add_argument("--cache-dir", type=str, default=str(CACHE_DIR), help="Directory for LANPool cache storage")
    parser.add_argument("--download-dir", type=str, default=str(DOWNLOAD_DIR), help="Directory for temporary/completed downloads")
    parser.add_argument("--tls-certfile", help="TLS certificate chain PEM")
    parser.add_argument("--tls-keyfile", help="TLS private key PEM")
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "::1", "localhost") and (not API_TOKEN or not PEER_SECRET):
        parser.error("LAN binding requires LANPOOL_API_TOKEN and LANPOOL_PEER_SECRET")
    if bool(args.tls_certfile) != bool(args.tls_keyfile):
        parser.error("Provide both TLS certificate and key")
    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.tls_certfile and os.environ.get("LANPOOL_ALLOW_INSECURE_LAN") != "1":
        parser.error("LAN binding requires TLS, or explicit LANPOOL_ALLOW_INSECURE_LAN=1 on a trusted VPN/LAN")

    app.state.http_port = args.port
    app.state.http_scheme = "https" if args.tls_certfile else "http"
    app.state.lan_ip = "127.0.0.1" if args.host in ("127.0.0.1", "localhost") else get_lan_ip()
    app.state.cache_dir = Path(args.cache_dir).resolve()
    app.state.download_dir = Path(args.download_dir).resolve()

    if not API_TOKEN:
        logger.info("No admin token configured; control is restricted to local clients.")
    if ALLOW_LOOPBACK_DOWNLOADS:
        logger.info("Loopback origins explicitly enabled for this instance.")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info", ssl_certfile=args.tls_certfile, ssl_keyfile=args.tls_keyfile, limit_concurrency=128)


if __name__ == "__main__":
    main()
