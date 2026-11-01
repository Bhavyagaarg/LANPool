"""
LANPool QoS Watchdog & Good Samaritan Boost Module (core/watchdog.py)
Implements NodeQoSManager (Safeguard #11 & Stage 5):
- share_pct (default 30, range 0..100)
- boosted (default False; when enabled, sets effective_share_pct = 80)
- game_mode (auto-detected every 5s via psutil scanning GAME_PROCESS_NAMES)
- simulate_game_mode (manual override toggle for live testing/demos)
- max_helper_kbps (default 20480 = 20 MB/s baseline capacity)
- active_boost_request (stores incoming boost request for 30s)
- throttle_bytes(num_bytes): rate limiting outbound helper chunk responses
- handle_incoming_boost(...): handles peer boost requests, suppressed if game_mode is active
- respond_to_boost("boost" | "dismiss"): accepts or dismisses active boost request
"""

import asyncio
import logging
import time
import os
from typing import Any, Dict, List, Optional, Tuple

import psutil

from config import GAME_PROCESS_NAMES, BOOST_LEASE_SECONDS

logger = logging.getLogger("lanpool.watchdog")

DEFAULT_SHARE_PCT = 30
BOOSTED_SHARE_PCT = 80
GAME_MODE_MAX_SHARE_PCT = 15
DEFAULT_MAX_HELPER_KBPS = max(1, int(os.environ.get("LANPOOL_MAX_HELPER_KBPS", "20480")))
BOOST_REQUEST_TTL_SECONDS = 30.0
WATCHDOG_INTERVAL_SECONDS = 5.0


class NodeQoSManager:
    """
    Manages station bandwidth sharing fairness, game process detection,
    and Good Samaritan boost requests (Safeguard #11).
    """

    def __init__(
        self,
        share_pct: int = DEFAULT_SHARE_PCT,
        max_helper_kbps: int = DEFAULT_MAX_HELPER_KBPS,
        game_process_names: Optional[List[str]] = None,
        throttling_enabled: bool = True,
    ):
        self.share_pct: int = max(0, min(100, int(share_pct)))
        self.boosted: bool = False
        self.game_mode: bool = False
        self.simulate_game_mode: bool = False
        self.max_helper_kbps: int = max(1, int(max_helper_kbps))
        self.throttling_enabled: bool = throttling_enabled

        self.game_process_names: set = {
            name.lower().strip() for name in (game_process_names or GAME_PROCESS_NAMES)
        }
        self.active_boost_request: Optional[Dict[str, Any]] = None

        self._loop_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._rate_lock = asyncio.Lock()
        self.boost_job_id = None
        self.boost_expires_at = 0.0

    @property
    def effective_game_mode(self) -> bool:
        """True if either real game processes are running or simulation toggle is active."""
        return bool(self.game_mode or self.simulate_game_mode)

    @property
    def effective_share_pct(self) -> int:
        """
        Computes effective bandwidth share percentage (Safeguard #11):
        - In Game Mode: capped strictly at min(share_pct, 15) and boosted flag is disabled.
        - When Boosted: 80%.
        - Normal: configured share_pct (0..100).
        """
        if self.boosted and time.monotonic() >= self.boost_expires_at:
            self.boosted = False
            self.boost_job_id = None
        if self.effective_game_mode:
            return min(self.share_pct, GAME_MODE_MAX_SHARE_PCT)
        if self.boosted:
            return BOOSTED_SHARE_PCT
        return self.share_pct

    @property
    def effective_rate_limit_bps(self) -> int:
        """Effective outbound helper rate limit in bytes per second."""
        pct = self.effective_share_pct
        return int(self.max_helper_kbps * 1024 * (pct / 100.0))

    def check_game_processes(self) -> bool:
        """
        Scans running OS processes using psutil for configured game executables.
        Safely handles access denied, zombie, or missing processes.
        """
        found = False
        try:
            for proc in psutil.process_iter(["name"]):
                try:
                    pname = (proc.info.get("name") or "").lower().strip()
                    if pname in self.game_process_names:
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as exc:
            logger.debug(f"psutil process scan encountered exception: {exc}")

        self.game_mode = found
        if self.effective_game_mode:
            self.boosted = False
            self.active_boost_request = None

        return found

    def clean_expired_boost_requests(self) -> None:
        """Prunes boost requests older than BOOST_REQUEST_TTL_SECONDS."""
        if self.active_boost_request:
            ts = self.active_boost_request.get("timestamp", 0)
            if (time.time() - ts) > BOOST_REQUEST_TTL_SECONDS:
                logger.info("Active boost request expired after TTL.")
                self.active_boost_request = None

    async def throttle_bytes(self, num_bytes: int) -> None:
        """One aggregate byte budget for all network streams on this node.

        Small intervals recheck game/share changes and support immediate cancellation.
        Budget is reserved before each stream read/send; concurrency cannot multiply it.
        """
        if self.effective_share_pct == 0:
            raise PermissionError("Bandwidth sharing is disabled (0%)")
        if not self.throttling_enabled:
            return
        async with self._rate_lock:
            remaining = float(num_bytes)
            while remaining > 0:
                rate = self.effective_rate_limit_bps
                if rate <= 0:
                    raise PermissionError("Bandwidth sharing was disabled")
                duration = min(remaining / rate, 0.1)
                started = time.monotonic()
                await asyncio.sleep(duration)
                remaining -= rate * (time.monotonic() - started)

    def handle_incoming_boost(
        self,
        requester_id: str,
        requester_ip: str,
        filename: str,
        total_size: int,
        job_id: str = "manual",
    ) -> Tuple[bool, str]:
        """
        Handles an incoming boost notification from a peer.
        If effective_game_mode is True, automatically suppresses/rejects the popup.
        """
        if self.effective_game_mode:
            logger.info(
                f"Suppressed boost notification from {requester_id} ({requester_ip}) "
                f"due to active Game Focus Mode."
            )
            return False, "game_mode_silent"

        self.active_boost_request = {
            "requester_id": str(requester_id),
            "requester_ip": str(requester_ip),
            "filename": str(filename),
            "total_size": int(total_size),
            "timestamp": time.time(),
            "job_id": job_id,
        }
        logger.info(f"Received active boost request from {requester_id} for file '{filename}'.")
        return True, "accepted"

    def respond_to_boost(self, action: str) -> Dict[str, Any]:
        """
        User responds to a pending boost request via dashboard UI:
        - 'boost': sets boosted=True, share_pct=80, clears pending request.
        - 'dismiss': dismisses pending request without altering share settings.
        """
        action = (action or "").strip().lower()
        if action == "boost":
            if self.effective_game_mode:
                self.active_boost_request = None
                return {
                    "status": "rejected",
                    "reason": "game_mode_silent",
                    "effective_share_pct": self.effective_share_pct,
                }
            self.boosted = True
            self.boost_job_id = (self.active_boost_request or {}).get("job_id", "manual")
            self.boost_expires_at = time.monotonic() + BOOST_LEASE_SECONDS
            self.active_boost_request = None
            logger.info("Good Samaritan Boost accepted! Helper bandwidth raised to 80%.")
            return {
                "status": "boosted",
                "boosted": True,
                "effective_share_pct": self.effective_share_pct,
            }
        elif action == "dismiss":
            self.active_boost_request = None
            logger.info("Boost request dismissed by user.")
            return {
                "status": "dismissed",
                "boosted": self.boosted,
                "effective_share_pct": self.effective_share_pct,
            }
        else:
            raise ValueError(f"Invalid boost response action: '{action}'. Must be 'boost' or 'dismiss'.")

    def update(
        self,
        share_pct: Optional[int] = None,
        boosted: Optional[bool] = None,
        simulate_game_mode: Optional[bool] = None,
        throttling_enabled: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Updates QoS settings with strict boundary validation."""
        if share_pct is not None:
            if type(share_pct) is not int or share_pct < 0 or share_pct > 100:
                raise ValueError(f"Invalid share_pct: {share_pct}. Must be an integer between 0 and 100.")
            self.share_pct = share_pct

        if simulate_game_mode is not None:
            self.simulate_game_mode = bool(simulate_game_mode)

        if boosted is not None:
            self.boosted = bool(boosted)
            self.boost_job_id = "manual" if boosted else None
            self.boost_expires_at = time.monotonic() + BOOST_LEASE_SECONDS if boosted else 0.0

        if throttling_enabled is not None:
            self.throttling_enabled = bool(throttling_enabled)

        if self.effective_game_mode:
            self.boosted = False
            self.active_boost_request = None

        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status dictionary for API and Web Dashboard."""
        self.clean_expired_boost_requests()
        return {
            "share_pct": self.share_pct,
            "effective_share_pct": self.effective_share_pct,
            "boosted": self.boosted,
            "game_mode": self.game_mode,
            "simulate_game_mode": self.simulate_game_mode,
            "effective_game_mode": self.effective_game_mode,
            "max_helper_kbps": self.max_helper_kbps,
            "effective_rate_limit_bps": self.effective_rate_limit_bps,
            "active_boost_request": self.active_boost_request if not self.effective_game_mode else None,
            "throttling_enabled": self.throttling_enabled,
            "boost_job_id": self.boost_job_id,
            "boost_remaining_seconds": max(0, round(self.boost_expires_at - time.monotonic(), 1)) if self.boosted else 0,
            "detection_mode": "process_name",
        }

    async def _watchdog_loop(self) -> None:
        """Background loop polling game processes every 5 seconds and pruning stale requests."""
        while self._running:
            try:
                await asyncio.to_thread(self.check_game_processes)
                self.clean_expired_boost_requests()
            except Exception as exc:
                logger.warning(f"Error in QoS watchdog loop: {exc}")

            try:
                await asyncio.sleep(WATCHDOG_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                break

    def start(self) -> None:
        """Starts the background watchdog loop."""
        if not self._running:
            self._running = True
            self._loop_task = asyncio.create_task(self._watchdog_loop(), name="lanpool-qos-watchdog")

    def stop(self) -> None:
        """Stops the background watchdog loop."""
        self._running = False
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()

    async def aclose(self):
        self.stop()
        if self._loop_task:
            await asyncio.gather(self._loop_task, return_exceptions=True)
            self._loop_task = None

    def release_boost(self, job_id):
        if self.boost_job_id == job_id:
            self.boosted = False
            self.boost_job_id = None
            self.boost_expires_at = 0.0
        if self.active_boost_request and self.active_boost_request.get("job_id") == job_id:
            self.active_boost_request = None
