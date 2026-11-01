import shutil
import socket
from pathlib import Path
from typing import Tuple, Union
from config import DISK_FREE_BUFFER

class DiskSpaceError(Exception):
    """Raised when free disk space is insufficient for download + safety buffer."""
    def __init__(self, required: int, available: int, path: Path):
        super().__init__(
            f"Insufficient disk space on {path}: need {required} bytes "
            f"(file_size + 100MB buffer), but only {available} bytes available."
        )
        self.required = required
        self.available = available
        self.path = path


def get_lan_ip() -> str:
    """
    Safeguard #3: Physical LAN IP Resolution (Virtual Adapter Bypass).
    Never uses socket.gethostbyname() to avoid resolving virtual adapters / loopback.
    Uses dummy UDP socket connected to an external target (8.8.8.8:80) to inspect local routing socket name.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting a UDP socket does not transmit any packets over the wire,
        # but queries the OS routing table for the outbound physical interface.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def check_disk_space(
    target_dir: Union[str, Path],
    file_size: int,
    buffer_bytes: int = DISK_FREE_BUFFER
) -> Tuple[bool, int, int]:
    """
    Safeguard #10: Pre-Flight Disk Space Check.
    Requires: free > file_size + 100*1024*1024.
    Returns: (is_sufficient, free_bytes, required_bytes)
    """
    path = Path(target_dir).resolve()
    # Find existing parent directory if target_dir doesn't exist yet
    check_path = path
    while not check_path.exists() and check_path.parent != check_path:
        check_path = check_path.parent

    usage = shutil.disk_usage(check_path)
    required = file_size + buffer_bytes
    is_sufficient = usage.free > required
    return is_sufficient, usage.free, required


def verify_disk_space_or_raise(
    target_dir: Union[str, Path],
    file_size: int,
    buffer_bytes: int = DISK_FREE_BUFFER
) -> None:
    """Convenience helper that raises DiskSpaceError if pre-flight check fails."""
    path = Path(target_dir).resolve()
    sufficient, free_bytes, required = check_disk_space(path, file_size, buffer_bytes)
    if not sufficient:
        raise DiskSpaceError(required=required, available=free_bytes, path=path)
