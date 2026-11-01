import os
from pathlib import Path

# Base Paths & Per-Instance Storage (Finding 7)
BASE_DIR = Path(__file__).resolve().parent
DOWNLOAD_DIR = Path(os.environ.get("LANPOOL_DOWNLOAD_DIR", BASE_DIR / "downloads")).resolve()
CACHE_DIR = Path(os.environ.get("LANPOOL_CACHE_DIR", BASE_DIR / "LANPool_Cache")).resolve()

# Ensure default directories exist
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Networking & Download Settings
DEFAULT_PORT = int(os.environ.get("LANPOOL_PORT", 8000))
CHUNK_SIZE = 10_485_760  # 10 MB in bytes (Safeguard #1)
DISK_FREE_BUFFER = 100 * 1024 * 1024  # 100 MB free buffer (Safeguard #10)
DEFAULT_CONCURRENT_WORKERS = 4
REQUEST_TIMEOUT_SECONDS = 15.0

# Stage 3.5 Hardening (Findings 1, 6, 11)
MAX_CHUNK_RETRIES = 5
MAX_CONCURRENT_DOWNLOADS = 4
MAX_DOWNLOAD_TASKS = 50
ALLOW_LOOPBACK_DOWNLOADS = os.environ.get("LANPOOL_ALLOW_LOOPBACK", "1") == "1"
API_TOKEN = os.environ.get("LANPOOL_API_TOKEN", "").strip()

# Stage 2 Settings
MAX_CACHE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB (Safeguard #8)

# Stage 3 Settings: Discovery & Peer Registry
UDP_DISCOVERY_PORT = int(os.environ.get("LANPOOL_UDP_PORT", 9999))
BEACON_INTERVAL_SECONDS = 3.0
PEER_TTL_SECONDS = 15.0
MANUAL_PEER_PROBE_TIMEOUT_SECONDS = 2.0

# Stage 4 Settings: Cooperative Multi-Peer Pooling
HELPER_TIMEOUT_SECONDS = 8.0
PEER_LOOKUP_TIMEOUT_SECONDS = 3.0
PEER_STREAM_TIMEOUT_SECONDS = 60.0

# Stage 5 Placeholder: Fullscreen game process list (Safeguard #11)
GAME_PROCESS_NAMES = [
    "valorant.exe",
    "cs2.exe",
    "dota2.exe",
    "leagueclient.exe",
    "overwatch.exe",
    "apex.exe"
]
