"""
LANPool Worker Module (core/worker.py)
Implements helper fetch primitives for Stage 4 Cooperative Multi-Peer Pooling:
- format_if_range(etag): formats If-Range wire header (quotes, skips weak W/).
- fetch_chunk_from_origin(...): streams a validated chunk from the origin server,
  enforcing Range assertions, ETag pinning, exact byte length, and SHA-256 verification.
"""

import hashlib
import logging
import re
from typing import Optional, Tuple

import httpx

from config import ALLOW_LOOPBACK_DOWNLOADS, REQUEST_TIMEOUT_SECONDS
from core.url_safety import validate_download_url, origin_client

logger = logging.getLogger("lanpool.worker")


class RemoteContentChangedError(Exception):
    """Raised when origin content or ETag changes during download (Finding 15)."""
    pass


class PoisonedChunkError(Exception):
    """Raised when server returns non-206, redirect, or mismatched payload size (Safeguard #4)."""
    pass


def format_if_range(etag: str) -> Optional[str]:
    """
    Formats the wire value for HTTP If-Range header:
    - Strips whitespace.
    - Rejects weak validators (prefixed with 'W/').
    - Ensures standard double quotes around the entity tag.
    - Returns None if etag is empty, invalid, or weak.
    """
    if not etag:
        return None
    val = etag.strip()
    if not val or val.startswith("W/"):
        return None
    if not (val.startswith('"') and val.endswith('"')):
        val = f'"{val}"'
    return val


def validate_range_response(resp, start, end, total_size=None, etag=""):
    if resp.status_code == 200 and format_if_range(etag):
        raise RemoteContentChangedError("Origin no longer honors the pinned ETag")
    if resp.status_code != 206:
        raise PoisonedChunkError(f"Expected HTTP 206, got {resp.status_code}")
    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", resp.headers.get("Content-Range", ""))
    if not match:
        raise PoisonedChunkError("Missing or invalid Content-Range")
    actual_start, actual_end, total = map(int, match.groups())
    if (actual_start, actual_end) != (start, end) or total <= end or (total_size is not None and total != total_size):
        raise PoisonedChunkError("Content-Range does not match requested offset/total")
    if resp.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise PoisonedChunkError("Encoded byte ranges are not supported")
    if etag and format_if_range(etag) and resp.headers.get("ETag", "").strip() != format_if_range(etag):
        raise RemoteContentChangedError("Origin ETag changed or disappeared")
    return total


async def fetch_chunk_from_origin(
    url: str,
    start_byte: int,
    end_byte: int,
    etag: str = "",
    client: Optional[httpx.AsyncClient] = None,
    total_size: Optional[int] = None,
    throttle=None,
    on_bytes=None,
) -> Tuple[bytes, str]:
    """
    Fetches a single chunk from the origin server via HTTP Range:
    1. Validates the URL against SSRF policy (Finding 6).
    2. Sends a streamed GET request with Range: bytes=start-end and follow_redirects=False.
    3. Sends If-Range if a strong ETag is available.
    4. Enforces:
       - No 3xx redirects (treated as error).
       - Status code must be 206 Partial Content (status 200 with If-Range raises RemoteContentChangedError).
       - ETag must match origin ETag if present.
       - Body length must match exact expected byte count.
    5. Returns tuple of (body_bytes, sha256_hex).
    """
    # 1. SSRF URL validation
    await validate_download_url(url, allow_loopback=ALLOW_LOOPBACK_DOWNLOADS)

    headers = {
        "User-Agent": "LANPool/1.1",
        "Range": f"bytes={start_byte}-{end_byte}",
        "Accept-Encoding": "identity",
    }
    if_range = format_if_range(etag)
    if if_range:
        headers["If-Range"] = if_range

    expected_len = end_byte - start_byte + 1

    async def _execute_fetch(http_client: httpx.AsyncClient) -> Tuple[bytes, str]:
        async with http_client.stream("GET", url, headers=headers, follow_redirects=False) as resp:
            validate_range_response(resp, start_byte, end_byte, total_size, etag)
            # Check redirects (Poison / SSRF circumvention attempt)
            if 300 <= resp.status_code < 400:
                raise PoisonedChunkError(
                    f"Unexpected redirect status {resp.status_code} for chunk {start_byte}-{end_byte}. "
                    "Redirects are disabled for worker chunk fetches."
                )

            # Check RemoteContentChangedError (HTTP 200 returned when If-Range sent)
            if "If-Range" in headers and resp.status_code == 200:
                raise RemoteContentChangedError(
                    "Remote content changed during chunk fetch: HTTP 200 returned for range request with If-Range."
                )

            # Enforce 206 Partial Content
            if resp.status_code != 206:
                raise PoisonedChunkError(
                    f"Expected HTTP 206 for byte range {start_byte}-{end_byte}, got {resp.status_code}"
                )

            # Verify ETag consistency if provided
            if etag:
                resp_etag = resp.headers.get("ETag")
                if resp_etag:
                    clean_resp_etag = resp_etag.strip('"')
                    clean_expected_etag = etag.strip('"')
                    if clean_resp_etag != clean_expected_etag:
                        raise RemoteContentChangedError(
                            f"Remote ETag changed: expected '{etag}', received '{resp_etag}'"
                        )

            # Read chunk body with strict bounds check (Finding E)
            body = bytearray()
            async for chunk_bytes in resp.aiter_bytes(chunk_size=65536):
                if throttle:
                    await throttle(len(chunk_bytes))
                if on_bytes:
                    on_bytes(len(chunk_bytes))
                body.extend(chunk_bytes)
                if len(body) > expected_len:
                    raise PoisonedChunkError(
                        f"Chunk payload exceeded expected length ({expected_len} bytes)."
                    )

            if len(body) != expected_len:
                raise PoisonedChunkError(
                    f"Chunk payload length mismatch: expected {expected_len} bytes, received {len(body)} bytes."
                )

            body_bytes = bytes(body)
            sha256_hex = hashlib.sha256(body_bytes).hexdigest()
            return body_bytes, sha256_hex

    if client is not None:
        return await _execute_fetch(client)
    else:
        async with origin_client() as default_client:
            return await _execute_fetch(default_client)
