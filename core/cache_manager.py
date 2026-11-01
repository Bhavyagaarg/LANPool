import hashlib
import json
import logging
import os
import re
import shutil
import time
import uuid
import threading
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from config import CACHE_DIR, MAX_CACHE_BYTES, DISK_FREE_BUFFER

logger = logging.getLogger("LANPool.CacheManager")
HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call


def strong_etag(etag):
    return bool(etag and etag.strip() and not etag.strip().startswith("W/"))


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """Computes SHA-256 hash of a file on disk in streaming 64KB blocks."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def normalize_etag(etag: str) -> str:
    """Normalizes ETag string by stripping weak 'W/' prefixes and surrounding quotes."""
    clean = (etag or "").strip()
    if clean.startswith("W/"):
        clean = clean[2:]
    return clean.strip('"').strip()


class CacheManager:
    """
    Stage 2 & 3.5: Security-Hardened LRU LAN-Cache Engine.
    Enforces:
    - Safeguard #6: Stale Cache Prevention via ETag Verification (url + remote_etag composite match).
    - Safeguard #7: Zero Path Traversal (SHA-256 Hash-Only Serving).
    - Safeguard #8: 10 GB Ring-Buffer LRU Cache Eviction (true LRU via last_access).
    - Safeguard #9: Deep-Freeze / Reboot Resilience (Startup directory self-indexing).
    - Finding 13: O(1) lookup index & running total_bytes tracking.
    - Finding 14: Redirect support indexing both original_url and final_url.
    """

    def __init__(self, cache_dir: Union[str, Path] = CACHE_DIR, max_cache_bytes: int = MAX_CACHE_BYTES):
        self._lock = threading.RLock()
        self._leases = {}
        self._dirty = False
        self._last_flush = 0.0
        self.cache_dir = Path(cache_dir).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_cache_bytes = max_cache_bytes
        self.index_file = self.cache_dir / "cache_index.json"

        # In-memory approved hash mapping: sha256 -> metadata dict
        self.approved_hash_map: Dict[str, dict] = {}
        # O(1) composite lookup index: (url, normalized_etag) -> sha256
        self._lookup_index: Dict[Tuple[str, str], str] = {}
        # Running total bytes count (Finding 13)
        self._total_bytes: int = 0

        self.scan_and_rebuild()

    @synchronized
    def get_total_bytes(self) -> int:
        """Returns sum of sizes of currently indexed files."""
        return self._total_bytes

    def _rebuild_indices(self) -> None:
        """Rebuilds running _total_bytes and _lookup_index from approved_hash_map."""
        self._lookup_index.clear()
        total = 0
        for sha, item in self.approved_hash_map.items():
            total += item.get("size", 0)
            norm_etag = normalize_etag(item.get("etag", ""))

            url = item.get("url", "").strip()
            if url:
                self._lookup_index[(url, norm_etag)] = sha

            orig_url = item.get("original_url", "").strip()
            if orig_url and orig_url != url:
                self._lookup_index[(orig_url, norm_etag)] = sha
            for alias in item.get("aliases", []):
                if strong_etag(alias.get("etag", "")):
                    self._lookup_index[(alias["url"], normalize_etag(alias["etag"]))] = sha

        self._total_bytes = total

    def _dedupe_paths(self) -> None:
        """
        Assert-by-construction (F5): ensures no two entries in approved_hash_map share a resolved path.
        If duplicates exist, retains the newest mtime entry and removes older colliding entries.
        """
        path_to_shas: Dict[Path, List[str]] = {}
        for sha, item in list(self.approved_hash_map.items()):
            p_res = Path(item["path"]).resolve()
            path_to_shas.setdefault(p_res, []).append(sha)

        for p_res, shas in path_to_shas.items():
            if len(shas) > 1:
                # Keep the entry with newest mtime
                shas_sorted = sorted(shas, key=lambda s: self.approved_hash_map[s].get("mtime", 0), reverse=True)
                kept_sha = shas_sorted[0]
                for dup_sha in shas_sorted[1:]:
                    logger.warning(
                        f"Path collision invariant violation detected: {p_res.name} shared by {kept_sha} and {dup_sha}. Evicting {dup_sha} from index."
                    )
                    self.approved_hash_map.pop(dup_sha, None)

        self._rebuild_indices()
        # Assert-by-construction
        resolved_paths = [Path(item["path"]).resolve() for item in self.approved_hash_map.values()]
        assert len(resolved_paths) == len(set(resolved_paths)), "Path collision invariant violated!"

    @synchronized
    def scan_and_rebuild(self) -> None:
        """
        Safeguard #9: Deep-Freeze / Reboot Resilience.
        Scans cache_dir, validates/hashes existing files, and rebuilds approved_hash_map and cache_index.json.
        Incorporates fast boot-scan path when (filename, size, mtime_ns) match the persisted index.
        """
        new_map: Dict[str, dict] = {}
        existing_index: Dict[str, dict] = {}

        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        existing_index = data
            except Exception as e:
                logger.warning(f"Could not parse existing index file, rebuilding from scratch: {e}")

        fast_lookup: Dict[Path, Tuple[str, dict]] = {}
        for k_sha, entry in existing_index.items():
            if not isinstance(entry, dict):
                continue
            entry_sha = (entry.get("sha256") or k_sha).lower().strip()
            if not HEX_64_PATTERN.match(entry_sha):
                continue
            fname = entry.get("filename")
            if fname:
                expected_path = (self.cache_dir / f"{entry_sha}_{fname}").resolve()
                fast_lookup[expected_path] = (entry_sha, entry)

        sha_to_candidates: Dict[str, list] = {}

        if self.cache_dir.exists():
            for p in self.cache_dir.iterdir():
                if not p.is_file() or p.name == "cache_index.json" or p.name.endswith(".tmp") or p.name.startswith("."):
                    continue

                try:
                    p_resolved = p.resolve()
                    file_stat = p.stat()
                    file_size = file_stat.st_size
                    file_mtime = file_stat.st_mtime
                    file_mtime_ns = file_stat.st_mtime_ns

                    parts = p.name.split("_", 1)
                    claimed_sha = parts[0].lower() if len(parts) > 1 and HEX_64_PATTERN.match(parts[0].lower()) else None

                    fast_hit = False
                    actual_sha = ""
                    matched_entry: Optional[dict] = None

                    if p_resolved in fast_lookup:
                        cand_sha, cand_entry = fast_lookup[p_resolved]
                        if cand_entry.get("size") == file_size and cand_entry.get("mtime_ns") == file_mtime_ns:
                            actual_sha = cand_sha
                            matched_entry = cand_entry
                            fast_hit = True

                    if not fast_hit:
                        actual_sha = compute_file_sha256(p).lower()
                        matched_entry = existing_index.get(actual_sha)

                    prev_entry = matched_entry or existing_index.get(actual_sha, {})
                    filename = prev_entry.get("filename") or (parts[1] if claimed_sha and len(parts) > 1 else p.name)
                    url = prev_entry.get("url", "")
                    original_url = prev_entry.get("original_url", url)
                    # Old indexes stripped weak prefixes, losing validator provenance.
                    etag = prev_entry.get("etag", "") if prev_entry.get("validator_version") == 2 else ""
                    last_access = prev_entry.get("last_access", file_mtime)

                    canonical_name = f"{actual_sha}_{filename}"
                    canonical_path = (self.cache_dir / canonical_name).resolve()

                    if p_resolved != canonical_path:
                        if canonical_path.exists() and canonical_path != p_resolved:
                            try:
                                canonical_path.unlink()
                                logger.info(f"Unlinked orphan duplicate at canonical path during scan: {canonical_name}")
                            except Exception as e:
                                logger.warning(f"Could not unlink pre-existing canonical file {canonical_path}: {e}")
                        try:
                            os.replace(str(p_resolved), str(canonical_path))
                            logger.info(f"Restored naming invariant on scan: renamed {p.name} -> {canonical_name}")
                            p_resolved = canonical_path
                            file_stat = p_resolved.stat()
                            file_size = file_stat.st_size
                            file_mtime = file_stat.st_mtime
                            file_mtime_ns = file_stat.st_mtime_ns
                        except Exception as e:
                            logger.error(f"Failed to rename {p.name} to canonical {canonical_name}: {e}")

                    candidate = {
                        "sha256": actual_sha,
                        "path": str(p_resolved),
                        "url": url,
                        "original_url": original_url,
                        "etag": etag,
                        "filename": filename,
                        "size": file_size,
                        "mtime": file_mtime,
                        "mtime_ns": file_mtime_ns,
                        "last_access": last_access,
                        "aliases": prev_entry.get("aliases", []) if prev_entry.get("validator_version") == 2 else [],
                        "validator_version": 2,
                    }

                    if actual_sha not in sha_to_candidates:
                        sha_to_candidates[actual_sha] = []
                    sha_to_candidates[actual_sha].append(candidate)

                except Exception as e:
                    logger.warning(f"Error scanning cache file {p}: {e}")

        for sha, candidates in sha_to_candidates.items():
            if len(candidates) == 1:
                kept = candidates[0]
            else:
                indexed_path = existing_index.get(sha, {}).get("path")
                kept = None
                if indexed_path:
                    for c in candidates:
                        if c["path"] == indexed_path:
                            kept = c
                            break
                if not kept:
                    kept = max(candidates, key=lambda c: c["mtime"])

                for c in candidates:
                    if c["path"] != kept["path"]:
                        try:
                            dup_path = Path(c["path"])
                            if dup_path.exists():
                                dup_path.unlink()
                                logger.info(f"Unlinked duplicate physical file during scan for {sha}: {dup_path.name}")
                        except Exception as e:
                            logger.warning(f"Could not unlink duplicate cache file {c['path']}: {e}")

            new_map[sha] = {
                "sha256": sha,
                "path": kept["path"],
                "url": kept["url"],
                "original_url": kept.get("original_url", kept["url"]),
                "etag": kept["etag"],
                "filename": kept["filename"],
                "size": kept["size"],
                "mtime": kept["mtime"],
                "mtime_ns": kept["mtime_ns"],
                "last_access": kept.get("last_access", kept["mtime"]),
                "aliases": kept.get("aliases", []),
                "validator_version": 2,
            }

        self.approved_hash_map = new_map
        self._dedupe_paths()
        self._evict_to_fit(0)
        self._persist_index()

    @synchronized
    def _persist_index(self) -> None:
        """Atomically persists approved_hash_map to cache_index.json using unique temp file."""
        unique_suffix = f"{os.getpid()}.{uuid.uuid4().hex[:6]}"
        temp_file = self.cache_dir / f"cache_index.json.{unique_suffix}.tmp"
        self._dirty = True
        self._last_flush = time.monotonic()
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(self.approved_hash_map, f, indent=2)
            os.replace(temp_file, self.index_file)
            self._dirty = False
        except Exception as e:
            logger.error(f"Failed to persist cache index: {e}")
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    @synchronized
    def register_completed(
        self,
        file_path: Union[str, Path],
        final_url: str,
        etag: str,
        sha256: str,
        filename: str,
        size: int,
        original_url: str = "",
    ) -> bool:
        """
        Safeguard #8: 10 GB Ring-Buffer LRU Cache Eviction.
        Evicts oldest files and atomically copies into cache, retaining the user's output.
        Indexes both original_url and final_url (Finding 14).
        """
        try:
            src_path = Path(file_path).resolve()
            if not src_path.exists():
                logger.error(f"Cannot register cache file: source path does not exist: {src_path}")
                return False

            sha256_lower = sha256.lower().strip()
            if not HEX_64_PATTERN.match(sha256_lower):
                logger.error(f"Cannot register cache file: invalid sha256 '{sha256}'")
                return False

            actual_size = src_path.stat().st_size
            if (size > 0 and size != actual_size) or compute_file_sha256(src_path) != sha256_lower:
                raise ValueError("Cache registration size/hash mismatch")

            # Safeguard #8: If a single file exceeds entire quota, skip caching
            if actual_size > self.max_cache_bytes:
                logger.warning(
                    f"File size {actual_size} exceeds max cache quota {self.max_cache_bytes}. "
                    "Skipping cache registration to preserve existing cache."
                )
                return False
            if shutil.disk_usage(self.cache_dir).free < actual_size + DISK_FREE_BUFFER:
                logger.warning("Skipping cache copy: insufficient free space; download retained")
                return False

            # Subtract replaced sha's size if already present (to avoid double counting during eviction check)
            old_entry = self.approved_hash_map.get(sha256_lower)
            if not self._evict_to_fit(0 if old_entry else actual_size, exclude=sha256_lower):
                return False  # Active streams/failed deletions still count toward quota.
            aliases = list(old_entry.get("aliases", [])) if old_entry else []
            for metadata in ([old_entry] if old_entry else []) + [{"url": final_url, "original_url": original_url, "etag": etag}]:
                for key in ("url", "original_url"):
                    if metadata.get(key) and strong_etag(metadata.get("etag", "")):
                        alias = {"url": metadata[key].strip(), "etag": metadata["etag"]}
                        if alias not in aliases:
                            aliases.append(alias)
            if old_entry and self._leases.get(sha256_lower, 0):
                old_entry["aliases"] = aliases
                if src_path.parent == self.cache_dir and src_path != Path(old_entry["path"]):
                    src_path.unlink()  # Internal cache import, not a user download.
                self._rebuild_indices()
                self._persist_index()
                return True

            # Destination filename in cache: <sha256>_<sanitized_basename>
            sanitized_name = Path(filename).name
            dest_filename = f"{sha256_lower}_{sanitized_name}"
            dest_path = (self.cache_dir / dest_filename).resolve()

            # F5: Collision guard: remove any OTHER index entry whose resolved path equals dest_path
            colliding_shas = [
                s for s, item in list(self.approved_hash_map.items())
                if s != sha256_lower and Path(item.get("path", "")).resolve() == dest_path
            ]
            for col_sha in colliding_shas:
                self.approved_hash_map.pop(col_sha, None)
                logger.warning(
                    f"Removed colliding index entry for sha {col_sha}: dest_path {dest_path.name} is being replaced"
                )

            old_path = Path(old_entry["path"]).resolve() if (old_entry and "path" in old_entry) else None

            # F5: If dest_path exists on disk and is not the current sha's own indexed file, unlink it before the move
            if dest_path != src_path and dest_path.exists() and (old_path is None or old_path != dest_path):
                try:
                    dest_path.unlink()
                    logger.info(f"Unlinked orphan occupying canonical destination path: {dest_path.name}")
                except Exception as e:
                    logger.warning(f"Could not unlink orphan at destination path {dest_path}: {e}")

            # Independent copy: editing the user's download cannot mutate the cache.
            if src_path.parent == self.cache_dir and src_path != dest_path:
                os.replace(src_path, dest_path)  # Canonicalize an already cache-owned import.
            elif src_path != dest_path:
                temporary = self.cache_dir / f".{sha256_lower}.{uuid.uuid4().hex}.tmp"
                try:
                    shutil.copyfile(src_path, temporary)
                    if compute_file_sha256(temporary) != sha256_lower:
                        raise ValueError("Cache copy failed SHA-256 verification")
                    os.replace(temporary, dest_path)
                finally:
                    temporary.unlink(missing_ok=True)
            dest_stat = dest_path.stat()
            now = time.time()

            if old_path and old_path != dest_path and old_path.exists():
                try:
                    old_path.unlink()
                    logger.info(f"Unlinked superseded duplicate cache file for {sha256_lower}: {old_path.name}")
                except Exception as e:
                    logger.warning(f"Could not unlink old cache file {old_path}: {e}")

            resolved_original_url = original_url.strip() if original_url else final_url.strip()

            self.approved_hash_map[sha256_lower] = {
                "sha256": sha256_lower,
                "path": str(dest_path),
                "url": final_url.strip(),
                "original_url": resolved_original_url,
                "etag": etag.strip() if strong_etag(etag) else "",
                "validator_version": 2,
                "filename": sanitized_name,
                "size": dest_stat.st_size,
                "mtime": dest_stat.st_mtime,
                "mtime_ns": dest_stat.st_mtime_ns,
                "last_access": now,
                "aliases": aliases,
            }

            self._dedupe_paths()
            self._persist_index()
            logger.info(f"Successfully registered completed file in LAN-Cache: {dest_filename}")
            return True

        except Exception as exc:
            logger.error(f"Error in register_completed (download remains successful): {exc}")
            return False

    @synchronized
    def update_alias(self, sha256: str, new_filename: str) -> bool:
        """
        Updates the cached filename alias for an existing entry:
        Renames canonical cached file to <sha256>_<sanitized_new_filename>,
        updates approved_hash_map[sha256]["path"] and ["filename"],
        calls _rebuild_indices(), and persists cache_index.json atomically.
        Guarantees exactly ONE physical file on disk per SHA-256 with zero orphan duplicates.
        """
        if not isinstance(sha256, str):
            return False
        sha_lower = sha256.lower().strip()
        if sha_lower not in self.approved_hash_map:
            return False

        entry = self.approved_hash_map[sha_lower]
        if self._leases.get(sha_lower, 0):
            return True  # Never rename an active stream's file.
        sanitized_name = Path(new_filename).name.strip()
        if not sanitized_name:
            return False

        canonical_name = f"{sha_lower}_{sanitized_name}"
        dest_path = (self.cache_dir / canonical_name).resolve()
        curr_path = Path(entry["path"]).resolve()

        if curr_path == dest_path and dest_path.exists():
            entry["filename"] = sanitized_name
            entry["last_access"] = time.time()
            self._persist_index()
            return True

        try:
            if dest_path.exists() and dest_path != curr_path:
                try:
                    dest_path.unlink()
                except Exception as e:
                    logger.warning(f"Could not unlink colliding target file {dest_path}: {e}")

            if curr_path.exists():
                os.replace(str(curr_path), str(dest_path))
            elif not dest_path.exists():
                logger.error(f"Cannot update alias: source path {curr_path} does not exist")
                return False

            dest_stat = dest_path.stat()
            entry["path"] = str(dest_path)
            entry["filename"] = sanitized_name
            entry["mtime"] = dest_stat.st_mtime
            entry["mtime_ns"] = dest_stat.st_mtime_ns
            entry["last_access"] = time.time()

            self._dedupe_paths()
            self._persist_index()
            logger.info(f"Updated cache alias for {sha_lower[:8]}: {canonical_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to update cache alias: {e}")
            return False

    @synchronized
    def lookup(self, url: str, etag: str = "") -> dict:
        """
        Safeguard #6: Stale Cache Prevention via ETag Verification.
        O(1) dictionary lookup via _lookup_index (Finding 13).
        Matches against both final_url and original_url (Finding 14).
        Updates last_access on hit (Finding 12).
        """
        target_url = url.strip()
        if not strong_etag(etag):
            return {"hit": False}
        norm_etag = normalize_etag(etag)

        # 1. O(1) Index Lookup
        target_sha = self._lookup_index.get((target_url, norm_etag))
        entry = self.approved_hash_map.get(target_sha) if target_sha else None

        # 2. Resilient fallback scan for unindexed or legacy matches
        if not entry:
            for sha, item in self.approved_hash_map.items():
                stored_url = item.get("url", "").strip()
                stored_orig_url = item.get("original_url", "").strip()
                stored_etag = normalize_etag(item.get("etag", ""))

                if (stored_url == target_url or stored_orig_url == target_url) and stored_etag == norm_etag:
                    target_sha = sha
                    entry = item
                    break

        if entry and target_sha:
            path = Path(entry["path"])
            if path.exists():
                self._touch(entry)
                return {
                    "hit": True,
                    "sha256": target_sha,
                    "size": entry["size"],
                }
            else:
                # File missing on disk: prune stale entry
                self.approved_hash_map.pop(target_sha, None)
                self._dedupe_paths()
                return {"hit": False}

        return {"hit": False}

    @synchronized
    def stream_path(self, sha256: str) -> Optional[Path]:
        """
        Safeguard #7: Zero Path Traversal (SHA-256 Hash-Only Serving).
        Validates ^[0-9a-f]{64}$ BEFORE lookup.
        Updates last_access on access (Finding 12).
        """
        if not isinstance(sha256, str):
            return None

        sha256_clean = sha256.lower().strip()
        if not HEX_64_PATTERN.match(sha256_clean):
            return None

        entry = self.approved_hash_map.get(sha256_clean)
        if not entry:
            return None

        path = Path(entry["path"]).resolve()

        try:
            path.relative_to(self.cache_dir.resolve())
        except ValueError:
            logger.error(f"Security Alert: Path traversal attempt prevented for hash {sha256_clean}: {path}")
            return None

        if not path.is_file():
            return None

        # Update last_access timestamp (Finding 12)
        self._touch(entry)
        return path

    @synchronized
    def list_items(self) -> dict:
        """Lists all items in the cache index without exposing absolute server paths (F4)."""
        sanitized_items = [
            {
                "sha256": it["sha256"],
                "filename": it["filename"],
                "url": it["url"],
                "original_url": it.get("original_url", it["url"]),
                "etag": it["etag"],
                "size": it["size"],
                "mtime": it["mtime"],
                "last_access": it.get("last_access", it["mtime"]),
            }
            for it in self.approved_hash_map.values()
        ]
        return {
            "count": len(sanitized_items),
            "total_bytes": self.get_total_bytes(),
            "max_cache_bytes": self.max_cache_bytes,
            "items": sanitized_items,
        }

    def _evict_to_fit(self, incoming, exclude=None):
        self._rebuild_indices()
        candidates = sorted(self.approved_hash_map, key=lambda sha: self.approved_hash_map[sha].get("last_access", 0))
        for sha in candidates:
            if self._total_bytes + incoming <= self.max_cache_bytes:
                return True
            if sha == exclude or self._leases.get(sha, 0):
                continue
            try:
                Path(self.approved_hash_map[sha]["path"]).unlink(missing_ok=True)
            except OSError:
                continue
            self.approved_hash_map.pop(sha)
            self._rebuild_indices()
        return self._total_bytes + incoming <= self.max_cache_bytes

    @contextmanager
    def lease(self, sha256, verify=True):
        with self._lock:
            path = self.stream_path(sha256)
            if path is None or (verify and compute_file_sha256(path) != sha256):
                raise FileNotFoundError("Cached file missing or corrupt")
            self._leases[sha256] = self._leases.get(sha256, 0) + 1
        try:
            yield path
        finally:
            with self._lock:
                self._leases[sha256] -= 1

    def copy_verified(self, sha256, destination):
        with self.lease(sha256) as source:
            shutil.copyfile(source, destination)
            if compute_file_sha256(destination) != sha256:
                Path(destination).unlink(missing_ok=True)
                raise ValueError("Cached copy failed SHA-256 verification")
        return Path(destination).stat().st_size

    @synchronized
    def find_by_sha(self, sha256):
        entry = self.approved_hash_map.get(sha256)
        return {"hit": True, "sha256": sha256, "size": entry["size"]} if entry else {"hit": False}

    def _touch(self, entry):
        entry["last_access"] = time.time()
        self._dirty = True
        if time.monotonic() - self._last_flush >= 2.0:
            self._persist_index()

    @synchronized
    def flush(self):
        if self._dirty:
            self._persist_index()


# Lazy singleton fallback instance (Finding 16: zero scan on module import)
_default_cache_manager: Optional[CacheManager] = None


def get_default_cache_manager() -> CacheManager:
    global _default_cache_manager
    if _default_cache_manager is None:
        _default_cache_manager = CacheManager()
    return _default_cache_manager


class _LazyDefaultCacheManager:
    def __getattr__(self, name: str):
        return getattr(get_default_cache_manager(), name)

    def __bool__(self):
        return True


default_cache_manager = _LazyDefaultCacheManager()
