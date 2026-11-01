"""
LANPool Test Data Generator (core/test_data.py)
Generates deterministic pseudo-random binary data for verification gates and test streams.
Uses functools.lru_cache with maxsize=2 to prevent memory bloat.
Has zero imports from main, app, or cache_manager.
"""

import functools
import hashlib


@functools.lru_cache(maxsize=2)
def get_deterministic_data(size_mb: int) -> bytes:
    """Generates deterministic pseudo-random binary data of size size_mb MB."""
    total_bytes = size_mb * 1024 * 1024
    # Position-dependent data: equal-sized ranges at different offsets differ.
    return hashlib.shake_256(f"LANPool-test-v2-{size_mb}".encode()).digest(total_bytes)
