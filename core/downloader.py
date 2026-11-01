import asyncio
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
from contextlib import asynccontextmanager


@asynccontextmanager
async def _closing_response(response):
    try:
        yield response
    finally:
        await response.aclose()
from pathlib import Path
from typing import List, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse

import httpx

import shutil

from config import (
    ALLOW_LOOPBACK_DOWNLOADS,
    CHUNK_SIZE,
    DEFAULT_CONCURRENT_WORKERS,
    DOWNLOAD_DIR,
    HELPER_TIMEOUT_SECONDS,
    MAX_CHUNK_RETRIES,
    PEER_LOOKUP_TIMEOUT_SECONDS,
    PEER_STREAM_TIMEOUT_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
)
from core.cache_manager import CacheManager, default_cache_manager, normalize_etag
from core.net_utils import verify_disk_space_or_raise
from core.peer_registry import PeerRegistry
from core.url_safety import validate_download_url, origin_client
from core.peer_auth import signed_request, verify_content, send_bounded, read_bounded, peer_client, peer_url
from config import PEER_SECRET, BOOST_THRESHOLD_MB
from core.cache_manager import strong_etag
from core.io_utils import disk_call, acquire_resource
from core.worker import PoisonedChunkError, RemoteContentChangedError, format_if_range

logger = logging.getLogger("LANPool.Downloader")


@dataclass
class ChunkDescriptor:
    chunk_id: int
    start_byte: int
    end_byte: int
    status: str = "queued"
    downloaded_bytes: int = 0
    worker_id: Optional[str] = None
    retries: int = 0

    @property
    def expected_length(self) -> int:
        return self.end_byte - self.start_byte + 1

    def to_dict(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "expected_length": self.expected_length,
            "status": self.status,
            "downloaded_bytes": self.downloaded_bytes,
            "worker_id": self.worker_id,
            "retries": self.retries,
        }


async def probe_url(
    url: str,
    client: Optional[httpx.AsyncClient] = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> dict:
    """
    Safeguard #5 & Findings 2, 6:
    Probes origin using client.stream('GET', Range: bytes=0-0) without buffering payload into RAM.
    Manually tracks redirects (up to 5 hops), validating each URL for SSRF safety.
    Extracts final_url, total_size, etag, and accept_ranges.
    Fails fast if Content-Range is wildcard or total size cannot be determined.
    """
    created_client = client is None
    c = client or origin_client(timeout)

    current_url = url.strip()
    max_redirects = 5
    headers = {"User-Agent": "LANPool/1.1", "Range": "bytes=0-0", "Accept-Encoding": "identity"}

    try:
        for _ in range(max_redirects + 1):
            await validate_download_url(current_url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)

            async with c.stream("GET", current_url, headers=headers, follow_redirects=False) as response:
                status = response.status_code

                # Handle manual redirects
                if status in (301, 302, 303, 307, 308):
                    loc = response.headers.get("Location")
                    if not loc:
                        raise ValueError(f"HTTP {status} redirect missing Location header.")
                    current_url = urljoin(current_url, loc)
                    continue

                total_size: Optional[int] = None
                accept_ranges = False
                etag = response.headers.get("ETag", "").strip()

                if status == 206:
                    cr = response.headers.get("Content-Range", "").strip()
                    # Expect: bytes 0-0/<number>
                    match = re.fullmatch(r"bytes 0-0/(\d+)", cr)
                    if match:
                        total_size = int(match.group(1))
                        accept_ranges = True
                    elif "/*" in cr or not cr:
                        raise ValueError(f"Content-Range is unspecified or wildcard: '{cr}'")
                    else:
                        raise ValueError(f"Invalid Content-Range format: '{cr}'")

                elif status == 200:
                    # Origin returned full file: Range is not supported
                    accept_ranges = False
                    cl = response.headers.get("Content-Length")
                    if cl and cl.isdigit():
                        total_size = int(cl)

                else:
                    raise ValueError(f"Origin responded with unexpected status code: HTTP {status}")

                if total_size is None or total_size <= 0:
                    raise ValueError(f"Could not determine valid positive total size for URL: {current_url}")

                return {
                    "final_url": current_url,
                    "total_size": total_size,
                    "etag": etag,
                    "accept_ranges": accept_ranges,
                    "probe_bytes": 0,  # response body is deliberately not consumed
                }

        raise ValueError("Exceeded maximum redirect limit (5 hops).")

    finally:
        if created_client:
            await c.aclose()


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """Computes SHA-256 hash of a file on disk in streaming 64KB blocks."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class SoloDownloadTask:
    """
    Stage 1 & 3.5 Solo Download Task:
    - Enforces Safeguard #1: Dynamic 10 MB micro-chunk queue.
    - Enforces Safeguard #2: Single dedicated disk-writer task consuming from a bounded writer queue.
    - Enforces Safeguard #4: Range assertions (status_code == 206 and exact byte length).
    - Enforces Safeguard #10: Pre-flight free-space check before disk creation.
    - Finding 1: Bounded retries (MAX_CHUNK_RETRIES = 5) and fail-fast Range check.
    - Finding 3: Bounded writer queue (maxsize=4) and fatal event handling.
    - Finding 4: Per-job part path (<filename>.<job_id>.part).
    - Finding 5: Automated cleanup of .part file on failure/cancellation.
    - Finding 7: Support for per-node CacheManager and download directory isolation.
    - Finding 15: ETag pinning with If-Range header and RemoteContentChangedError detection.
    """

    def __init__(
        self,
        job_id: str,
        url: str,
        filename: Optional[str] = None,
        download_dir: Optional[Union[str, Path]] = None,
        chunk_size: int = CHUNK_SIZE,
        num_workers: int = DEFAULT_CONCURRENT_WORKERS,
        http_client: Optional[httpx.AsyncClient] = None,
        cache_manager: Optional[CacheManager] = None,
        peer_registry: Optional[PeerRegistry] = None,
        api_token: str = "",
        own_node_id: str = "",
        expected_sha256: str = "",
        offline: bool = False,
        on_state_change=None,
        use_cache=True,
        use_peers=True,
    ):
        self.job_id = job_id
        self.url = url
        name = (filename or "").strip() if filename is not None else ""
        if (
            not name
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            or chr(0) in name
            or os.path.basename(name) != name
        ):
            self.filename = self._derive_filename(url)
        else:
            self.filename = name
        self.download_dir = Path(download_dir).resolve() if download_dir else DOWNLOAD_DIR
        self.chunk_size = chunk_size
        self.num_workers = num_workers
        self.custom_client = http_client
        self.cache_manager = cache_manager
        self.peer_registry = peer_registry
        self.api_token = api_token
        self.own_node_id = own_node_id
        self.expected_sha256 = expected_sha256.lower().strip()
        if self.expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", self.expected_sha256):
            raise ValueError("Expected SHA-256 must contain 64 hex characters")
        self.offline = offline
        self.on_state_change = on_state_change
        self.use_cache = use_cache
        self.use_peers = use_peers
        self.helper_origin_bytes = 0
        self.probe_requests = 0
        self.origin_received_bytes = 0
        self._speed_sample = (time.monotonic(), 0, 0, 0)
        self._speeds = (0.0, 0.0, 0.0)
        self._wait_handles = []

        # Per-job isolated part path (Finding 4)
        self.final_path = self.download_dir / self.filename
        self.part_path = self.download_dir / f"{self.filename}.{self.job_id}.part"

        # State tracking
        self.final_url: str = url
        self.total_size: int = 0
        self.downloaded_bytes: int = 0
        self.etag: str = ""
        self.status: str = "initialized"  # initialized, probing, queued, downloading, completed, failed
        self.error: Optional[str] = None
        self.sha256: Optional[str] = None
        self.start_time: float = 0.0
        self.end_time: Optional[float] = None
        self.source: str = "probing"  # probing, local_cache, peer_cache, pooled, solo
        self.wan_bytes: int = 0
        self.lan_bytes: int = 0

        # Chunk & Writer Queues (Finding 3: bounded queue)
        self.chunks: List[ChunkDescriptor] = []
        self.chunk_queue: asyncio.Queue[ChunkDescriptor] = asyncio.Queue()
        self.writer_queue: asyncio.Queue[Optional[Tuple[int, int, bytes]]] = asyncio.Queue(maxsize=4)

        # Fatal event for immediate cooperative cancellation (Findings 1, 3, 15)
        self.fatal_event = asyncio.Event()
        self._writer_error: Optional[Exception] = None

        self._task_handle: Optional[asyncio.Task] = None
        self._writer_handle: Optional[asyncio.Task] = None
        self._worker_handles: List[asyncio.Task] = []

    @staticmethod
    def _derive_filename(url: str) -> str:
        parsed = urlparse(url)
        name = re.sub(r'[<>:"|?*\\\x00-\x1f]', "_", Path(parsed.path).name).strip().rstrip(". ")[:180]
        if name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
            name = "download_" + name
        if not name or name in ("", "/", ".", ".."):
            name = f"download_{int(time.time())}.bin"
        return name

    def get_progress(self) -> dict:
        now = time.time()
        elapsed = (self.end_time or now) - (self.start_time or now)
        speed_bps = (self.downloaded_bytes / elapsed) if elapsed > 0 else 0.0
        wan_speed_bps = (self.wan_bytes / elapsed) if elapsed > 0 else 0.0
        lan_speed_bps = (self.lan_bytes / elapsed) if elapsed > 0 else 0.0

        sample_now = time.monotonic()
        previous_time, previous_total, previous_wan, previous_lan = self._speed_sample
        interval = sample_now - previous_time
        if interval >= 0.25:
            self._speeds = tuple(max(0, value - old) / interval / 1048576 for value, old in ((self.downloaded_bytes, previous_total), (self.origin_received_bytes, previous_wan), (self.lan_bytes, previous_lan)))
            self._speed_sample = (sample_now, self.downloaded_bytes, self.origin_received_bytes, self.lan_bytes)
        if self.status in ("completed", "failed", "cancelled"):
            self._speeds = (0.0, 0.0, 0.0)
        return {
            "speed_mibps": round(self._speeds[0], 3),
            "wan_speed_mibps": round(self._speeds[1], 3),
            "lan_speed_mibps": round(self._speeds[2], 3),
            "average_speed_mibps": round(speed_bps / 1048576, 3),
            "origin_received_bytes": self.origin_received_bytes,
            "helper_origin_bytes": self.helper_origin_bytes,
            "probe_requests": self.probe_requests,
            "expected_sha256": self.expected_sha256,
            "offline": self.offline,
            "use_cache": self.use_cache,
            "use_peers": self.use_peers,
            "job_id": self.job_id,
            "url": self.url,
            "final_url": self.final_url,
            "filename": self.filename,
            "total_size": self.total_size,
            "downloaded_bytes": self.downloaded_bytes,
            "progress_pct": round((self.downloaded_bytes / self.total_size * 100), 2) if self.total_size else 0.0,
            "speed_mbps": round((speed_bps * 8 / (1024 * 1024)), 2),
            "source": self.source,
            "wan_bytes": self.wan_bytes,
            "lan_bytes": self.lan_bytes,
            "wan_speed_mbps": round((wan_speed_bps * 8 / (1024 * 1024)), 2),
            "lan_speed_mbps": round((lan_speed_bps * 8 / (1024 * 1024)), 2),
            "status": self.status,
            "etag": self.etag,
            "sha256": self.sha256,
            "error": self.error,
            "chunks_total": len(self.chunks),
            "chunks_done": sum(1 for c in self.chunks if c.status == "done"),
            "chunks": [c.to_dict() for c in self.chunks],
        }

    async def start(self) -> None:
        self.start_time = time.time()
        self.status = "probing"
        self._task_handle = asyncio.create_task(self._run())

    async def cancel(self):
        if self._task_handle and not self._task_handle.done():
            self._task_handle.cancel()
            await asyncio.gather(self._task_handle, return_exceptions=True)

    async def _disk_call(self, function, *args, **kwargs):
        return await disk_call(function, *args, **kwargs)

    async def _open_file(self, path, mode):
        return await acquire_resource(lambda: open(path, mode), lambda handle: handle.close())

    def _eligible_peers(self):
        if not self.use_peers or not PEER_SECRET or not self.peer_registry:
            return []
        peers = [p for p in self.peer_registry.list_peers() if p.get("trusted") and p.get("available", True) and p.get("node_id") != self.own_node_id]
        return sorted(peers, key=lambda peer: (bool(peer.get("game_mode")), -peer.get("share_pct", 0)))

    async def _notify_boost(self, release=False):
        peers = self._eligible_peers()
        path = "/api/qos/boost-release" if release else "/api/qos/boost-notify"
        payload = {"job_id": self.job_id} if release else {"requester_id": self.own_node_id, "requester_ip": "LAN peer", "filename": self.filename, "total_size": self.total_size, "job_id": self.job_id}
        async def send(peer):
            try:
                async with peer_client(3) as c:
                    request = signed_request(c, "POST", peer_url(peer, path), json=payload)
                    await c.send(request)
            except httpx.HTTPError:
                pass
        await asyncio.gather(*(send(p) for p in peers))

    async def _use_local(self, cache_mgr, hit):
        if not hit.get("hit"):
            return False
        sha = hit["sha256"]
        if self.expected_sha256 and sha != self.expected_sha256:
            return False
        try:
            size = await self._disk_call(cache_mgr.copy_verified, sha, self.part_path)
            if self.total_size and size != self.total_size:
                raise ValueError("Cached size does not match origin")
            await self._disk_call(os.replace, self.part_path, self.final_path)
            await self._disk_call(cache_mgr.update_alias, sha, self.filename)
            self.total_size = self.downloaded_bytes = size
            self.sha256, self.source, self.status = sha, "local_cache", "completed"
            self.end_time = time.time()
            return True
        except (OSError, ValueError) as exc:
            logger.warning("Ignoring missing/corrupt cache: %s", exc)
            await self._disk_call(self.part_path.unlink, missing_ok=True)
            return False

    async def _run(self):
        client = self.custom_client or origin_client()
        boosted = False
        cache_mgr = self.cache_manager or default_cache_manager
        try:
            self.download_dir.mkdir(parents=True, exist_ok=True)
            if self.offline:
                if not self.expected_sha256:
                    raise ValueError("Offline mode requires a trusted expected SHA-256")
                hit = await self._disk_call(cache_mgr.find_by_sha, self.expected_sha256)
                if not await self._use_local(cache_mgr, hit):
                    raise ValueError("Verified offline content is not available in this node's cache")
                return
            self.probe_requests += 1
            probe = await probe_url(self.url, client=client)
            if not probe["accept_ranges"]:
                raise ValueError("Origin must support HTTP byte ranges")
            self.final_url, self.total_size, self.etag = probe["final_url"], probe["total_size"], probe["etag"]
            await self._disk_call(verify_disk_space_or_raise, self.download_dir, self.total_size)
            if not strong_etag(self.etag) and self.total_size > self.chunk_size and not self.expected_sha256:
                raise ValueError("Multi-chunk downloads require a strong ETag or a trusted expected SHA-256")
            hit = await self._disk_call(cache_mgr.lookup, self.final_url, self.etag) if self.use_cache else {"hit": False}
            if await self._use_local(cache_mgr, hit):
                return
            if self.use_cache and strong_etag(self.etag):
                for peer, hit in await self._query_peer_caches(self._eligible_peers()):
                    sha = hit.get("sha256", "")
                    if self.expected_sha256 and sha != self.expected_sha256:
                        continue
                    if await self._stream_from_peer_cache(peer, sha):
                        self.sha256, self.source = sha, "peer_cache"
                        self.downloaded_bytes = self.lan_bytes = self.total_size
                        await self._publish(cache_mgr)
                        return
                    self.downloaded_bytes = self.lan_bytes = 0
                    await self._disk_call(self.part_path.unlink, missing_ok=True)
            self._generate_chunks()
            self.status = "downloading"
            self._writer_handle = asyncio.create_task(self._disk_writer_task(), name="lanpool-disk-writer")
            peers = [p for p in self._eligible_peers() if p.get("share_pct", 0) > 0]
            count = min(self.num_workers, len(self.chunks))
            helpers = min(len(peers), max(0, count - 1))
            self.source = "pooled" if helpers else "solo"
            if helpers and self.total_size >= BOOST_THRESHOLD_MB * 1048576:
                boosted = True
                await self._notify_boost()
            for i in range(count - helpers):
                self._worker_handles.append(asyncio.create_task(self._network_worker(f"self-{i+1}", client), name="lanpool-self-worker"))
            for peer in peers[:helpers]:
                self._worker_handles.append(asyncio.create_task(self._helper_worker(peer), name="lanpool-helper-worker"))
            join = asyncio.create_task(self.chunk_queue.join(), name="lanpool-chunk-join")
            fatal = asyncio.create_task(self.fatal_event.wait(), name="lanpool-fatal-wait")
            self._wait_handles = [join, fatal]
            done, _ = await asyncio.wait([join, fatal, self._writer_handle], return_when=asyncio.FIRST_COMPLETED)
            if fatal in done or self._writer_handle in done:
                raise RuntimeError(self.error or str(self._writer_error or "Writer stopped prematurely"))
            for worker in self._worker_handles:
                worker.cancel()
            await asyncio.gather(*self._worker_handles, return_exceptions=True)
            await self.writer_queue.put(None)
            await self._writer_handle
            if not all(chunk.status == "done" for chunk in self.chunks):
                raise RuntimeError("Some chunks were not written")
            await self._publish(cache_mgr)
        except asyncio.CancelledError:
            self.status, self.error = "cancelled", "Cancelled; retry starts a new verified download"
            self.end_time = time.time()
            raise
        except Exception as exc:
            self.status, self.error = "failed", self.error or str(exc)
            self.end_time = time.time()
        finally:
            if self._writer_handle and not self._writer_handle.done() and not asyncio.current_task().cancelling():
                try:
                    await asyncio.wait_for(self.writer_queue.put(None), timeout=1)
                    await asyncio.wait_for(asyncio.shield(self._writer_handle), timeout=3)
                except (Exception, asyncio.CancelledError):
                    pass
            children = [*self._worker_handles, *self._wait_handles]
            if self._writer_handle:
                children.append(self._writer_handle)
            for child in children:
                if not child.done():
                    child.cancel()
            await asyncio.gather(*children, return_exceptions=True)
            if self.custom_client is None:
                await client.aclose()
            if self.status != "completed":
                await self._disk_call(self.part_path.unlink, missing_ok=True)
            if boosted:
                await self._notify_boost(release=True)
            if self.on_state_change:
                await self.on_state_change()

    async def _publish(self, cache_mgr):
        if self.expected_sha256 and self.sha256 != self.expected_sha256:
            raise ValueError("Final SHA-256 does not match the trusted expected hash")
        await self._disk_call(os.replace, self.part_path, self.final_path)
        await self._disk_call(cache_mgr.register_completed, self.final_path, self.final_url, self.etag, self.sha256, self.filename, self.total_size, original_url=self.url)
        self.status, self.end_time = "completed", time.time()

    def _generate_chunks(self) -> None:
        """Slices total_size into 10 MB micro-chunks."""
        self.chunks.clear()
        start = 0
        chunk_id = 0
        while start < self.total_size:
            end = min(start + self.chunk_size - 1, self.total_size - 1)
            chunk = ChunkDescriptor(chunk_id=chunk_id, start_byte=start, end_byte=end, status="queued")
            self.chunks.append(chunk)
            self.chunk_queue.put_nowait(chunk)
            start = end + 1
            chunk_id += 1

    async def _disk_writer_task(self):
        handle = await self._open_file(self.part_path, "wb+")
        def write(offset, data):
            handle.seek(offset)
            handle.write(data)
            handle.flush()
        try:
            while True:
                item = await self.writer_queue.get()
                try:
                    if item is None:
                        break
                    chunk_id, offset, data = item
                    await self._disk_call(write, offset, data)
                    chunk = self.chunks[chunk_id]
                    chunk.status, chunk.downloaded_bytes = "done", len(data)
                    self.downloaded_bytes += len(data)
                    if (chunk.worker_id or "").startswith("helper-"):
                        self.lan_bytes += len(data)
                    else:
                        self.wan_bytes += len(data)
                finally:
                    self.writer_queue.task_done()
            self.sha256 = await self._disk_call(compute_file_sha256, self.part_path)
        except Exception as exc:
            self._writer_error = exc
            self.fatal_event.set()
            raise
        finally:
            await self._disk_call(handle.close)

    async def _network_worker(self, worker_id, client):
        from core.worker import fetch_chunk_from_origin
        def received(size):
            self.origin_received_bytes += size
        while not self.fatal_event.is_set():
            chunk = await self.chunk_queue.get()
            chunk.worker_id, chunk.status = worker_id, "downloading"
            try:
                data, _ = await fetch_chunk_from_origin(self.final_url, chunk.start_byte, chunk.end_byte, self.etag, client=client, total_size=self.total_size, on_bytes=received)
                await self.writer_queue.put((chunk.chunk_id, chunk.start_byte, data))
            except asyncio.CancelledError:
                chunk.status = "cancelled"
                raise
            except RemoteContentChangedError as exc:
                self.error = str(exc)
                chunk.status = "poisoned"
                self.fatal_event.set()
            except Exception as exc:
                chunk.retries += 1
                if chunk.retries >= MAX_CHUNK_RETRIES:
                    self.error = f"Chunk {chunk.chunk_id} exceeded max retries: {exc}"
                    chunk.status = "poisoned"
                    self.fatal_event.set()
                else:
                    chunk.status = "requeued"
                    self.chunk_queue.put_nowait(chunk)
                    await asyncio.sleep(0.05)
            finally:
                self.chunk_queue.task_done()

    async def _query_peer_caches(self, peers):
        async def query(peer):
            if not PEER_SECRET or not peer.get("trusted") or not peer.get("available", True):
                return None
            try:
                async with peer_client(PEER_LOOKUP_TIMEOUT_SECONDS) as client:
                    request = signed_request(client, "GET", peer_url(peer, "/api/cache/lookup"), params={"url": self.final_url, "etag": self.etag})
                    response = await send_bounded(client, request)
                    if response.status_code == 200 and verify_content(hashlib.sha256(response.content).hexdigest(), response.headers.get("X-LANPool-Content-Signature", "")):
                        data = response.json()
                        if data.get("hit"):
                            return peer, data
            except (httpx.HTTPError, ValueError):
                pass
            return None
        results = await asyncio.gather(*(query(p) for p in peers))
        return [result for result in results if result]

    @asynccontextmanager
    async def _async_file(self, path, mode):
        handle = await self._open_file(path, mode)
        try:
            yield handle
        finally:
            await self._disk_call(handle.close)

    async def _stream_from_peer_cache(self, peer: dict, sha256: str) -> bool:
        """Streams a completed cached file from a peer, verifying exact length and SHA-256."""
        pip = peer.get("ip") or peer.get("lan_ip")
        pport = peer.get("port") or peer.get("http_port")
        url = peer_url(peer, f"/api/cache/stream/{sha256}")
        headers = {}  # Admin credentials must never be forwarded to peers.

        try:
            hasher = hashlib.sha256()
            bytes_written = 0
            self.part_path.parent.mkdir(parents=True, exist_ok=True)
            async with peer_client(PEER_STREAM_TIMEOUT_SECONDS) as c:
                request = signed_request(c, "GET", url)
                resp = await c.send(request, stream=True)
                async with _closing_response(resp):
                    if resp.status_code != 200 or not verify_content(sha256, resp.headers.get("X-LANPool-Content-Signature", "")):
                        return False
                    async with self._async_file(self.part_path, "wb") as f:
                        async for chunk in resp.aiter_bytes(chunk_size=1024 * 1024):
                            bytes_written += len(chunk)
                            if bytes_written > self.total_size:
                                logger.warning(f"Peer cache stream exceeded expected total size ({self.total_size})")
                                return False
                            await self._disk_call(f.write, chunk)
                            hasher.update(chunk)
                            self.downloaded_bytes = bytes_written

            if bytes_written != self.total_size:
                logger.warning(f"Peer cache stream length mismatch: expected {self.total_size}, got {bytes_written}")
                return False

            if hasher.hexdigest() != sha256:
                logger.warning(f"Peer cache stream SHA mismatch: expected {sha256}, got {hasher.hexdigest()}")
                return False

            return True
        except Exception as exc:
            logger.warning(f"Error streaming from peer cache {peer.get('node_id')}: {exc}")
            return False

    async def _helper_worker(self, peer: dict) -> None:
        """
        Cooperative helper worker (Stage 4).
        Dispatches micro-chunks to a peer helper via POST /api/worker/fetch-chunk.
        Enforces exact payload length and X-Chunk-SHA256 verification.
        On timeout/disconnect/5xx/poison: increments chunk.retries, 1s delay, requeues.
        On 409 (ETag/content change): sets fatal_event and aborts immediately.
        """
        peer_ip = peer.get("ip") or peer.get("lan_ip")
        peer_port = peer.get("port") or peer.get("http_port")
        peer_id = peer.get("node_id", "unknown")
        worker_id = f"helper-{peer_id[:8]}"
        url = peer_url(peer, "/api/worker/fetch-chunk")

        headers = {}  # Admin credentials must never be forwarded to peers.

        consecutive_errors = 0
        async with peer_client(HELPER_TIMEOUT_SECONDS) as helper_client:
            while not self.fatal_event.is_set():
                try:
                    chunk = await self.chunk_queue.get()
                except asyncio.CancelledError:
                    break

                chunk.worker_id = worker_id
                chunk.status = "downloading"

                payload = {
                    "url": self.final_url,
                    "start_byte": chunk.start_byte,
                    "end_byte": chunk.end_byte,
                    "chunk_id": chunk.chunk_id,
                    "etag": self.etag,
                    "total_size": self.total_size,
                }

                try:
                    request = signed_request(helper_client, "POST", url, json=payload)
                    response = await helper_client.send(request, stream=True)
                    async with _closing_response(response) as resp:
                        if resp.status_code == 409:
                            resp_text = (await read_bounded(resp)).decode(errors="replace")
                            self.error = f"Remote content changed on helper {peer_id}: {resp_text}"
                            self.fatal_event.set()
                            chunk.status = "poisoned"
                            self.chunk_queue.task_done()
                            break

                        if resp.status_code != 200:
                            resp_text = (await read_bounded(resp)).decode(errors="replace")
                            raise PoisonedChunkError(f"Helper {peer_id} returned HTTP {resp.status_code}: {resp_text[:120]}")

                        expected_sha = resp.headers.get("X-Chunk-SHA256", "").strip().lower()
                        if not expected_sha or not re.match(r"^[0-9a-f]{64}$", expected_sha):
                            raise PoisonedChunkError(
                                f"Helper {peer_id} returned invalid or missing X-Chunk-SHA256: '{expected_sha}'"
                            )

                        if not verify_content(expected_sha, resp.headers.get("X-LANPool-Content-Signature", "")):
                            raise PoisonedChunkError("Unauthenticated helper content digest")
                        body = bytearray()
                        async for b in resp.aiter_bytes(chunk_size=65536):
                            body.extend(b)
                            if len(body) > chunk.expected_length:
                                raise PoisonedChunkError(
                                    f"Helper {peer_id} returned payload exceeding expected length ({chunk.expected_length})"
                                )

                        if len(body) != chunk.expected_length:
                            raise PoisonedChunkError(
                                f"Helper {peer_id} returned payload length mismatch: expected {chunk.expected_length}, got {len(body)}"
                            )

                        body_bytes = bytes(body)
                        computed_sha = hashlib.sha256(body_bytes).hexdigest().lower()
                        if computed_sha != expected_sha:
                            raise PoisonedChunkError(
                                f"Helper {peer_id} returned corrupted chunk: expected SHA {expected_sha}, computed {computed_sha}"
                            )

                        self.helper_origin_bytes += len(body_bytes)
                        consecutive_errors = 0
                        chunk.status = "downloaded"
                        await self.writer_queue.put((chunk.chunk_id, chunk.start_byte, body_bytes))
                        self.chunk_queue.task_done()

                except asyncio.CancelledError:
                    chunk.status = "requeued"
                    self.chunk_queue.task_done()
                    if not self.fatal_event.is_set():
                        self.chunk_queue.put_nowait(chunk)
                    break

                except Exception as exc:
                    consecutive_errors += 1
                    chunk.status = "requeued"
                    chunk.retries += 1
                    logger.warning(
                        f"Helper {peer_id} failed chunk {chunk.chunk_id} (retry {chunk.retries}/{MAX_CHUNK_RETRIES}, consecutive errors {consecutive_errors}): {exc}."
                    )

                    if chunk.retries >= MAX_CHUNK_RETRIES:
                        self.error = f"Chunk {chunk.chunk_id} exceeded max retries ({MAX_CHUNK_RETRIES}) on helper {peer_id}: {exc}"
                        self.fatal_event.set()
                        self.chunk_queue.task_done()
                        break
                    else:
                        await self.chunk_queue.put(chunk)
                        self.chunk_queue.task_done()
                        if consecutive_errors >= 2 or self.fatal_event.is_set():
                            logger.info(f"Helper worker {worker_id} retired after {consecutive_errors} consecutive errors.")
                            break
                        await asyncio.sleep(0.3)
