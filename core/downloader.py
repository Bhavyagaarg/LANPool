import asyncio
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
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
from core.url_safety import validate_download_url
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
    c = client or httpx.AsyncClient(timeout=timeout)

    current_url = url.strip()
    max_redirects = 5
    headers = {"User-Agent": "LANPool-SoloDownloader/1.0", "Range": "bytes=0-0"}

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
                    match = re.search(r"bytes\s+0-0/(\d+)", cr)
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
        name = Path(parsed.path).name.strip()
        if not name or name in ("", "/", ".", ".."):
            name = f"download_{int(time.time())}.bin"
        return name

    def get_progress(self) -> dict:
        now = time.time()
        elapsed = (self.end_time or now) - (self.start_time or now)
        speed_bps = (self.downloaded_bytes / elapsed) if elapsed > 0 else 0.0
        wan_speed_bps = (self.wan_bytes / elapsed) if elapsed > 0 else 0.0
        lan_speed_bps = (self.lan_bytes / elapsed) if elapsed > 0 else 0.0

        return {
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

    async def _run(self) -> None:
        client_provided = self.custom_client is not None
        client = self.custom_client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS)

        try:
            # 1. Probe URL
            probe_info = await probe_url(self.url, client=client)
            if not probe_info.get("accept_ranges"):
                raise ValueError("Origin does not support HTTP Range requests; LANPool requires byte ranges.")

            self.final_url = probe_info["final_url"]
            self.total_size = probe_info["total_size"]
            self.etag = probe_info["etag"]

            # 2. Pre-flight Disk Space Check (Safeguard #10)
            verify_disk_space_or_raise(self.download_dir, self.total_size)

            cache_mgr = self.cache_manager or default_cache_manager

            # Phase 1a: Instant local cache lookup
            if cache_mgr is not None:
                local_hit = cache_mgr.lookup(self.final_url, self.etag)
                if local_hit.get("hit"):
                    cached_sha = local_hit["sha256"]
                    cached_path = cache_mgr.stream_path(cached_sha)
                    if cached_path and cached_path.exists():
                        try:
                            # Copy through .part, verify size, then atomic replace (Phase 1a Safe Copy)
                            if self.part_path.exists():
                                self.part_path.unlink(missing_ok=True)
                            await asyncio.to_thread(shutil.copyfile, cached_path, self.part_path)
                            part_size = self.part_path.stat().st_size
                            if part_size != self.total_size:
                                raise ValueError(f"Local cache copy size mismatch: expected {self.total_size}, got {part_size}")
                            os.replace(self.part_path, self.final_path)

                            # Ensure canonical alias in cache dir if requested with distinct filename (keeps Stage 2 T4 & T5 green with 0 orphans)
                            if self.filename and hasattr(cache_mgr, "update_alias"):
                                cache_mgr.update_alias(cached_sha, self.filename)

                            self.source = "local_cache"
                            self.lan_bytes = 0
                            self.wan_bytes = 0
                            self.sha256 = cached_sha
                            self.downloaded_bytes = self.total_size
                            self.status = "completed"
                            self.end_time = time.time()
                            logger.info(f"[{self.job_id}] Phase 1a: Instant local cache hit for {self.filename} (sha={cached_sha[:8]}).")
                            return
                        except Exception as copy_err:
                            logger.warning(f"Local cache copy failed: {copy_err}")
                            if self.part_path.exists():
                                self.part_path.unlink(missing_ok=True)

            # Phase 1b: Peer cache lookup & streaming
            if self.peer_registry is not None:
                peers = [p for p in self.peer_registry.list_peers() if p.get("node_id") != self.own_node_id]
                if peers:
                    peer_hits = await self._query_peer_caches(peers)
                    for peer, hit_data in peer_hits:
                        peer_sha = hit_data.get("sha256")
                        if not peer_sha:
                            continue
                        stream_ok = await self._stream_from_peer_cache(peer, peer_sha)
                        if stream_ok:
                            os.replace(self.part_path, self.final_path)
                            try:
                                if cache_mgr:
                                    cache_mgr.register_completed(
                                        file_path=self.final_path,
                                        final_url=self.final_url,
                                        etag=self.etag,
                                        sha256=peer_sha,
                                        filename=self.filename,
                                        size=self.total_size,
                                        original_url=self.url,
                                    )
                            except Exception as reg_exc:
                                logger.warning(f"Cache registration failed: {reg_exc}")
                            self.source = "peer_cache"
                            self.lan_bytes = self.total_size
                            self.wan_bytes = 0
                            self.sha256 = peer_sha
                            self.downloaded_bytes = self.total_size
                            self.status = "completed"
                            self.end_time = time.time()
                            logger.info(f"[{self.job_id}] Phase 1b: Completed via peer cache on {peer.get('node_id')} (sha={peer_sha[:8]}).")
                            return
                        else:
                            if self.part_path.exists():
                                self.part_path.unlink(missing_ok=True)

            # Phase 2: Pooled Chunks (Self workers + Helper workers)
            # 3. Dynamic Micro-Chunk Generator (Safeguard #1)
            self._generate_chunks()

            # 4. Start Single Dedicated Disk-Writer Task (Safeguard #2)
            self.status = "downloading"
            self._writer_handle = asyncio.create_task(
                self._disk_writer_task(),
                name="lanpool-disk-writer",
            )

            # 5. Start Concurrent Network & Helper Workers
            total_workers = min(self.num_workers, len(self.chunks)) if self.chunks else 1
            active_peers = [
                p for p in (self.peer_registry.list_peers() if self.peer_registry else [])
                if p.get("node_id") != self.own_node_id and p.get("share_pct", 30) > 0
            ]
            num_helpers = min(len(active_peers), total_workers - 1) if active_peers and total_workers > 1 else 0
            num_self = total_workers - num_helpers
            self.source = "pooled" if num_helpers > 0 else "solo"

            for i in range(num_self):
                w = asyncio.create_task(
                    self._network_worker(worker_id=f"self-{i+1}", client=client),
                    name=f"lanpool-self-worker-{i+1}",
                )
                self._worker_handles.append(w)

            for i, peer in enumerate(active_peers[:num_helpers]):
                w = asyncio.create_task(
                    self._helper_worker(peer),
                    name=f"lanpool-helper-{peer.get('node_id', '')[:8]}",
                )
                self._worker_handles.append(w)

            # Wait on chunk_queue.join(), writer_handle, or fatal_event (Finding 1, 3)
            join_task = asyncio.create_task(self.chunk_queue.join())
            fatal_task = asyncio.create_task(self.fatal_event.wait())

            done, pending = await asyncio.wait(
                [join_task, self._writer_handle, fatal_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # If fatal event occurred or writer failed prematurely:
            if fatal_task in done or (self._writer_handle in done and self._writer_error is not None):
                # Cancel helper tasks, but NOT writer handle
                if join_task in pending:
                    join_task.cancel()
                if fatal_task in pending:
                    fatal_task.cancel()

                # Stop network workers immediately so they stop pushing to writer_queue
                for w in self._worker_handles:
                    w.cancel()
                await asyncio.gather(*self._worker_handles, return_exceptions=True)

                # Cleanly signal disk writer and await termination (Finding 1, 3)
                if self._writer_handle and not self._writer_handle.done():
                    try:
                        while self.writer_queue.full():
                            try:
                                self.writer_queue.get_nowait()
                                self.writer_queue.task_done()
                            except (asyncio.QueueEmpty, ValueError):
                                break
                        await self.writer_queue.put(None)
                        await asyncio.wait_for(self._writer_handle, timeout=3.0)
                    except Exception:
                        if not self._writer_handle.done():
                            self._writer_handle.cancel()
                elif self._writer_handle and self._writer_handle.done():
                    try:
                        _ = self._writer_handle.exception()
                    except Exception:
                        pass

                # Drain queues so no worker remains blocked
                while not self.chunk_queue.empty():
                    try:
                        self.chunk_queue.get_nowait()
                        self.chunk_queue.task_done()
                    except (asyncio.QueueEmpty, ValueError):
                        break

                while not self.writer_queue.empty():
                    try:
                        self.writer_queue.get_nowait()
                        self.writer_queue.task_done()
                    except (asyncio.QueueEmpty, ValueError):
                        break

                err_msg = self.error or (str(self._writer_error) if self._writer_error else "Download failed.")
                raise RuntimeError(err_msg)

            # Normal completion flow:
            for w in self._worker_handles:
                w.cancel()
            await asyncio.gather(*self._worker_handles, return_exceptions=True)

            # Cleanly signal disk writer and await termination
            await self.writer_queue.put(None)
            if self._writer_handle:
                await self._writer_handle

            # Clean up pending helper tasks
            for p in pending:
                p.cancel()

            # Ensure all chunks actually succeeded
            if not all(c.status == "done" for c in self.chunks):
                raise RuntimeError("Download queue unblocked but not all chunks were completed.")

            # 6. Verify completion and atomic rename
            if self.part_path.exists():
                os.replace(self.part_path, self.final_path)

                # Register in cache
                try:
                    cache_mgr = self.cache_manager or default_cache_manager
                    cache_mgr.register_completed(
                        file_path=self.final_path,
                        final_url=self.final_url,
                        etag=self.etag,
                        sha256=self.sha256 or "",
                        filename=self.filename,
                        size=self.total_size,
                        original_url=self.url,
                    )
                except Exception as reg_exc:
                    logger.warning(f"Cache registration failed (download completed): {reg_exc}")

                self.status = "completed"
                self.end_time = time.time()
            else:
                raise FileNotFoundError(f"Expected part file {self.part_path} was not created.")

        except Exception as exc:
            self.status = "failed"
            self.error = self.error or str(exc)
            self.end_time = time.time()

            # Ensure workers and writer are halted
            for w in self._worker_handles:
                w.cancel()
            if self._writer_handle and not self._writer_handle.done():
                try:
                    while self.writer_queue.full():
                        try:
                            self.writer_queue.get_nowait()
                            self.writer_queue.task_done()
                        except (asyncio.QueueEmpty, ValueError):
                            break
                    await self.writer_queue.put(None)
                    await asyncio.wait_for(self._writer_handle, timeout=3.0)
                except Exception:
                    if not self._writer_handle.done():
                        self._writer_handle.cancel()

        finally:
            if not client_provided:
                await client.aclose()

            # Finding 5: Unlink .part on failure or abnormal exit
            if self.status != "completed" and self.part_path.exists():
                try:
                    self.part_path.unlink()
                    logger.info(f"Cleaned up part file on failure: {self.part_path.name}")
                except Exception as unl_exc:
                    logger.warning(f"Failed to unlink part file {self.part_path}: {unl_exc}")

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

    async def _disk_writer_task(self) -> None:
        """
        Safeguard #2: WinError 32 Guard & Finding 3: Dead writer detection.
        Single dedicated task that writes chunk data to disk.
        """
        self.part_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(self.part_path, "wb+") as f:
                while True:
                    item = await self.writer_queue.get()
                    if item is None:
                        self.writer_queue.task_done()
                        break

                    chunk_id, start_byte, raw_bytes = item
                    try:
                        f.seek(start_byte)
                        f.write(raw_bytes)
                        f.flush()

                        chunk = self.chunks[chunk_id]
                        chunk.status = "done"
                        chunk.downloaded_bytes = len(raw_bytes)
                        self.downloaded_bytes += len(raw_bytes)
                        if (chunk.worker_id or "").startswith("helper-"):
                            self.lan_bytes += len(raw_bytes)
                        else:
                            self.wan_bytes += len(raw_bytes)
                    finally:
                        self.writer_queue.task_done()

                f.flush()
                f.seek(0)
                hasher = hashlib.sha256()
                while block := f.read(65536):
                    hasher.update(block)
                self.sha256 = hasher.hexdigest()

        except Exception as exc:
            self._writer_error = exc
            self.fatal_event.set()
            logger.error(f"Disk writer encountered error on {self.part_path.name}: {exc}")
            raise

    async def _network_worker(self, worker_id: str, client: httpx.AsyncClient) -> None:
        """
        Fetches micro-chunks using HTTP 206 Range requests.
        Enforces ETag pinning (Finding 15) and bounded retries (Finding 1).
        """
        while not self.fatal_event.is_set():
            try:
                chunk = await self.chunk_queue.get()
            except asyncio.CancelledError:
                break

            chunk.worker_id = worker_id
            chunk.status = "downloading"

            headers = {
                "User-Agent": "LANPool-SoloDownloader/1.0",
                "Range": f"bytes={chunk.start_byte}-{chunk.end_byte}",
            }

            # Finding 15: ETag Pinning with If-Range
            if self.etag:
                wire_etag = self.etag.strip()
                if not wire_etag.startswith('"') and not wire_etag.startswith("W/"):
                    wire_etag = f'"{wire_etag}"'
                if not wire_etag.startswith("W/"):
                    headers["If-Range"] = wire_etag

            try:
                resp = await client.get(
                    self.final_url,
                    headers=headers,
                    follow_redirects=False,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

                # Check for unexpected redirect (poison)
                if resp.status_code in (301, 302, 303, 307, 308):
                    raise PoisonedChunkError(f"Unexpected redirect HTTP {resp.status_code} during chunk download.")

                # Finding 15: Remote content changed check
                if "If-Range" in headers and resp.status_code == 200:
                    raise RemoteContentChangedError("Remote content changed during download (HTTP 200 returned for range request).")

                resp_etag = resp.headers.get("ETag", "").strip()
                if self.etag and resp_etag:
                    if normalize_etag(resp_etag) != normalize_etag(self.etag):
                        raise RemoteContentChangedError(f"Remote ETag changed from {self.etag} to {resp_etag}")

                if resp.status_code != 206:
                    raise PoisonedChunkError(
                        f"Expected HTTP 206 for byte range {chunk.start_byte}-{chunk.end_byte}, got {resp.status_code}"
                    )

                if len(resp.content) != chunk.expected_length:
                    raise PoisonedChunkError(
                        f"Expected {chunk.expected_length} bytes, received {len(resp.content)} bytes"
                    )

                # Feed to disk writer queue (bounded)
                await self.writer_queue.put((chunk.chunk_id, chunk.start_byte, resp.content))
                self.chunk_queue.task_done()

            except asyncio.CancelledError:
                chunk.status = "requeued"
                self.chunk_queue.task_done()
                break

            except RemoteContentChangedError as rce:
                chunk.status = "poisoned"
                self.chunk_queue.task_done()
                self.error = str(rce)
                self.fatal_event.set()
                logger.error(f"Fatal download abort: {rce}")
                break

            except Exception as exc:
                chunk.status = "poisoned"
                chunk.retries += 1

                # Finding 1: Check bounded retry limit
                if chunk.retries >= MAX_CHUNK_RETRIES:
                    self.chunk_queue.task_done()
                    self.error = f"Chunk {chunk.chunk_id} exceeded max retries ({MAX_CHUNK_RETRIES}): {exc}"
                    self.fatal_event.set()
                    logger.error(self.error)
                    break
                else:
                    await asyncio.sleep(0.05)
                    chunk.status = "requeued"
                    await self.chunk_queue.put(chunk)
                    self.chunk_queue.task_done()

    async def _query_peer_caches(self, peers: List[dict]) -> List[Tuple[dict, dict]]:
        """Queries active peers in parallel for cache lookup (Phase 1b)."""
        headers = {}
        if self.api_token:
            headers["X-LANPool-Token"] = self.api_token

        async def _check_peer(peer: dict):
            pip = peer.get("ip") or peer.get("lan_ip")
            pport = peer.get("port") or peer.get("http_port")
            url = f"http://{pip}:{pport}/api/cache/lookup"
            try:
                async with httpx.AsyncClient(timeout=PEER_LOOKUP_TIMEOUT_SECONDS) as c:
                    r = await c.get(url, params={"url": self.final_url, "etag": self.etag}, headers=headers)
                    if r.status_code == 200:
                        data = r.json()
                        if data.get("hit"):
                            return (peer, data)
            except Exception:
                pass
            return None

        results = await asyncio.gather(*[_check_peer(p) for p in peers], return_exceptions=True)
        return [res for res in results if isinstance(res, tuple) and res[0] is not None]

    async def _stream_from_peer_cache(self, peer: dict, sha256: str) -> bool:
        """Streams a completed cached file from a peer, verifying exact length and SHA-256."""
        pip = peer.get("ip") or peer.get("lan_ip")
        pport = peer.get("port") or peer.get("http_port")
        url = f"http://{pip}:{pport}/api/cache/stream/{sha256}"
        headers = {}
        if self.api_token:
            headers["X-LANPool-Token"] = self.api_token

        try:
            hasher = hashlib.sha256()
            bytes_written = 0
            self.part_path.parent.mkdir(parents=True, exist_ok=True)
            async with httpx.AsyncClient(timeout=PEER_STREAM_TIMEOUT_SECONDS) as c:
                async with c.stream("GET", url, headers=headers) as resp:
                    if resp.status_code != 200:
                        return False
                    with open(self.part_path, "wb") as f:
                        async for chunk in resp.aiter_bytes(chunk_size=1024 * 1024):
                            bytes_written += len(chunk)
                            if bytes_written > self.total_size:
                                logger.warning(f"Peer cache stream exceeded expected total size ({self.total_size})")
                                return False
                            f.write(chunk)
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
        url = f"http://{peer_ip}:{peer_port}/api/worker/fetch-chunk"

        headers = {}
        if self.api_token:
            headers["X-LANPool-Token"] = self.api_token

        consecutive_errors = 0
        async with httpx.AsyncClient(timeout=HELPER_TIMEOUT_SECONDS) as helper_client:
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
                }

                try:
                    async with helper_client.stream("POST", url, json=payload, headers=headers) as resp:
                        if resp.status_code == 409:
                            resp_text = (await resp.aread()).decode(errors="replace")
                            self.error = f"Remote content changed on helper {peer_id}: {resp_text}"
                            self.fatal_event.set()
                            chunk.status = "poisoned"
                            self.chunk_queue.task_done()
                            break

                        if resp.status_code != 200:
                            resp_text = (await resp.aread()).decode(errors="replace")
                            raise PoisonedChunkError(f"Helper {peer_id} returned HTTP {resp.status_code}: {resp_text[:120]}")

                        expected_sha = resp.headers.get("X-Chunk-SHA256", "").strip().lower()
                        if not expected_sha or not re.match(r"^[0-9a-f]{64}$", expected_sha):
                            raise PoisonedChunkError(
                                f"Helper {peer_id} returned invalid or missing X-Chunk-SHA256: '{expected_sha}'"
                            )

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
