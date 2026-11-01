"""
LANPool Test Data Generator (core/test_data.py)
Generates deterministic pseudo-random binary data for verification gates and test streams.
Uses functools.lru_cache with maxsize=2 to prevent memory bloat.
Has zero imports from main, app, or cache_manager.
"""

import functools


@functools.lru_cache(maxsize=2)
def get_deterministic_data(size_mb: int) -> bytes:
    """Generates deterministic pseudo-random binary data of size size_mb MB."""
    total_bytes = size_mb * 1024 * 1024
    # Seeded 64KB block repeated
    seed_block = bytes([(i * 37 + 19) % 256 for i in range(65536)])
    repeats = (total_bytes // 65536) + 1
    return (seed_block * repeats)[:total_bytes]
