"""
LANPool Test Data Generator (core/test_data.py)
Generates deterministic pseudo-random binary data for verification gates and test streams.
The HTTP endpoint uses random-access 64 KiB blocks, never whole-file allocation.
Has zero imports from main, app, or cache_manager.
"""

import functools
import hashlib


@functools.lru_cache(maxsize=2)
def get_deterministic_data(size_mb: int) -> bytes:
    """Test-only convenience for calculating expected bytes, not used by the server."""
    return b"".join(iter_test_data(size_mb))


BLOCK_SIZE = 65536


@functools.lru_cache(maxsize=16)
def _block(size_mb, index):
    return hashlib.shake_256(f"LANPool-test-v3-{size_mb}-{index}".encode()).digest(BLOCK_SIZE)


def iter_test_data(size_mb, start=0, end=None):
    total = size_mb * 1048576
    end = total - 1 if end is None else end
    if not 0 <= start <= end < total:
        raise ValueError("Invalid test-data byte range")
    while start <= end:
        block = _block(size_mb, start // BLOCK_SIZE)
        offset = start % BLOCK_SIZE
        length = min(BLOCK_SIZE - offset, end - start + 1)
        yield block[offset:offset+length]
        start += length
