"""Executable checks for the gaps identified by PONYTAIL_REVIEW.md."""
import asyncio
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import test_regressions as regression
from core.cache_manager import CacheManager
from core.downloader import SoloDownloadTask
from core.peer_auth import sign_content
from core.peer_registry import PeerRegistry
from core.test_data import iter_test_data
from core.watchdog import NodeQoSManager
from core.worker import fetch_chunk_from_origin


class PonytailCoreTests(unittest.TestCase):
    def test_linux_and_windows_game_names_match_without_prefix_false_positives(self):
        qos = NodeQoSManager(game_process_names=["CS2.EXE", "dota2"])
        for name in ("cs2", "CS2.exe", "dota2", "DOTA2.EXE"):
            with self.subTest(name=name), patch("core.watchdog.psutil.process_iter", return_value=[SimpleNamespace(info={"name": name})]):
                self.assertTrue(qos.check_game_processes())
        with patch("core.watchdog.psutil.process_iter", return_value=[SimpleNamespace(info={"name": "cs2-launcher"})]):
            self.assertFalse(qos.check_game_processes())

    def test_manual_identity_cannot_be_replaced_by_beacon(self):
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        registry.add_manual("127.0.0.1", 8001, node_id="enrolled", trusted=True, scheme="https")
        result = registry.upsert_udp("attacker", "127.0.0.1", 8001, "127.0.0.1", trusted=True)
        self.assertIsNone(result)
        self.assertIsNone(registry.get("attacker"))
        self.assertEqual(registry.get("enrolled")["scheme"], "https")

    def test_html_node_ids_are_rejected_even_with_group_trust(self):
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        self.assertIsNone(registry.upsert_udp('<img onerror="x">', "127.0.0.1", 8001, "127.0.0.1", trusted=True))
        with self.assertRaises(ValueError):
            registry.add_manual("127.0.0.1", 8001, node_id='<svg/onload="x">')

    def test_cache_keeps_independent_user_output_and_debounces_lru(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = CacheManager(root / "cache")
            output = root / "download.bin"
            output.write_bytes(b"original")
            sha = hashlib.sha256(output.read_bytes()).hexdigest()
            self.assertTrue(cache.register_completed(output, "http://test/file", '"v1"', sha, output.name, 8))
            self.assertEqual(output.read_bytes(), b"original")
            output.write_bytes(b"modified")
            with cache.lease(sha) as path:
                self.assertEqual(path.read_bytes(), b"original")
            with patch.object(cache, "_persist_index", wraps=cache._persist_index) as persist:
                for _ in range(200):
                    self.assertTrue(cache.lookup("http://test/file", '"v1"')["hit"])
                self.assertLessEqual(persist.call_count, 1)
                accessed = cache.approved_hash_map[sha]["last_access"]
                cache.flush()
                self.assertTrue(persist.called)
            restarted = CacheManager(root / "cache")
            self.assertEqual(restarted.approved_hash_map[sha]["last_access"], accessed)

    def test_config_import_does_not_create_storage(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            cache, downloads = Path(folder) / "not-created-cache", Path(folder) / "not-created-downloads"
            result = subprocess.run([sys.executable, "-c", "import config"], cwd=root, env={**os.environ, "LANPOOL_CACHE_DIR": str(cache), "LANPOOL_DOWNLOAD_DIR": str(downloads)}, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(cache.exists())
            self.assertFalse(downloads.exists())

    def test_exporter_owns_and_removes_only_its_fixture_storage(self):
        before = dict(os.environ)
        exporter = importlib.import_module("scripts.export_state")
        self.assertEqual(dict(os.environ), before, "Importing the exporter must not change the calling environment")
        observed = []
        def inspect_fixture():
            cache = Path(os.environ["LANPOOL_CACHE_DIR"])
            downloads = Path(os.environ["LANPOOL_DOWNLOAD_DIR"])
            self.assertEqual(cache.parent, downloads.parent)
            self.assertTrue(cache.is_dir() and downloads.is_dir())
            self.assertNotEqual(cache, exporter.PROJECT_ROOT / "LANPool_Cache")
            (downloads / "owned-fixture.bin").write_bytes(b"fixture")
            observed.append(cache.parent)
            return 0
        with patch.object(exporter, "_export_project_state", side_effect=inspect_fixture):
            self.assertEqual(exporter.export_project_state(), 0)
        self.assertFalse(observed[0].exists())
        self.assertEqual(dict(os.environ), before)

    def test_large_fixture_generator_has_bounded_blocks_and_memory(self):
        tracemalloc.start()
        try:
            total = 0
            for block in iter_test_data(100):
                self.assertLessEqual(len(block), 65536)
                total += len(block)
            _, peak = tracemalloc.get_traced_memory()
            self.assertEqual(total, 100 * 1048576)
            self.assertLess(peak, 3 * 1048576)
        finally:
            tracemalloc.stop()


class PonytailDownloadTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = regression.DownloadTests.asyncSetUp
    asyncTearDown = regression.DownloadTests.asyncTearDown

    async def test_even_authenticated_peer_requests_never_include_admin_token(self):
        seen = []
        def peer(request):
            seen.append(request.headers)
            response = httpx.Response(200, json={"hit": False})
            response.headers["X-LANPool-Content-Signature"] = sign_content(hashlib.sha256(response.content).hexdigest())
            return response
        task = SoloDownloadTask("headers", "http://127.0.0.1/file", api_token="private-administration-secret", expected_sha256="a" * 64)
        with patch("core.downloader.peer_client", side_effect=lambda *args: httpx.AsyncClient(transport=httpx.MockTransport(peer))):
            await task._query_peer_caches([{"ip": "127.0.0.1", "port": 8001, "trusted": True}])
        self.assertEqual(len(seen), 1)
        self.assertNotIn("X-LANPool-Token", seen[0])
        self.assertIn("X-LANPool-Peer-Signature", seen[0])

    async def test_peer_content_needs_expected_hash_by_default(self):
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        registry.add_manual("127.0.0.1", 8001, node_id="paired", trusted=True)
        task = SoloDownloadTask("job", "http://127.0.0.1/file", peer_registry=registry, own_node_id="own")
        with patch("core.downloader.TRUST_GROUP_CONTENT", False):
            self.assertEqual(task._eligible_peers(), [])
            task.expected_sha256 = "a" * 64
            self.assertEqual(len(task._eligible_peers()), 1)

    async def test_a_helper_signed_forgery_fails_independent_final_hash(self):
        payload = b"A" * 2048
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        registry.add_manual("127.0.0.1", 8001, node_id="paired", trusted=True)
        def malicious(request):
            data = json.loads(request.content)
            body = b"B" * (data["end_byte"] - data["start_byte"] + 1)
            sha = hashlib.sha256(body).hexdigest()
            return httpx.Response(200, content=body, headers={"X-Chunk-SHA256": sha, "X-LANPool-Content-Signature": sign_content(sha)})
        async with httpx.AsyncClient(transport=regression.origin(payload)) as client:
            task = SoloDownloadTask("forgery", "http://127.0.0.1/file", "forgery.bin", self.down, chunk_size=1024, cache_manager=self.cache, http_client=client, peer_registry=registry, own_node_id="own", expected_sha256=hashlib.sha256(payload).hexdigest())
            task._query_peer_caches = AsyncMock(return_value=[])
            normal_worker = task._network_worker
            async def delayed_worker(*args):
                await asyncio.sleep(0.05)
                await normal_worker(*args)
            task._network_worker = delayed_worker
            with patch("core.downloader.peer_client", side_effect=lambda *args: httpx.AsyncClient(transport=httpx.MockTransport(malicious))):
                await task.start()
                await asyncio.wait_for(task._task_handle, 5)
        self.assertEqual(task.status, "failed")
        self.assertIn("trusted expected hash", task.error)
        self.assertFalse(task.final_path.exists())
        self.assertEqual(self.cache.list_items()["count"], 0)

    async def test_weak_etag_comparison_is_shared_and_consistent(self):
        payload = b"data"
        for expected, response in [('W/"same"', '"same"'), ('W/"same"', 'W/"same"')]:
            async with httpx.AsyncClient(transport=regression.origin(payload, etag=response)) as client:
                body, sha = await fetch_chunk_from_origin("http://127.0.0.1/file", 0, 3, expected, client=client, total_size=4)
                self.assertEqual(body, payload)
                self.assertEqual(sha, hashlib.sha256(payload).hexdigest())


class PonytailApiTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = regression.ApiTests.asyncSetUp
    asyncTearDown = regression.ApiTests.asyncTearDown

    async def test_stage_reports_the_single_current_constant(self):
        from config import PROJECT_STAGE
        response = await self.client.get("/api/health")
        self.assertEqual(response.json()["stage"], PROJECT_STAGE)
        self.assertEqual(PROJECT_STAGE, 6)

    async def test_test_endpoint_disabled_by_default_and_head_allocates_no_payload(self):
        with patch.object(self.main, "TEST_FILES_ENABLED", False):
            self.assertEqual((await self.client.get("/api/test-file/100")).status_code, 404)
        with patch.object(self.main, "TEST_FILES_ENABLED", True), patch.object(self.main, "iter_test_data", side_effect=AssertionError("HEAD generated payload")):
            response = await self.client.head("/api/test-file/100")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(int(response.headers["Content-Length"]), 100 * 1048576)
        self.assertEqual(response.content, b"")

    async def test_small_range_of_large_fixture_does_not_allocate_large_body(self):
        self.main.app.state.fixture_slots = asyncio.Semaphore(4)
        with patch.object(self.main, "TEST_FILES_ENABLED", True):
            response = await self.client.get("/api/test-file/100", headers={"Range": "bytes=65530-65550"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, b"".join(iter_test_data(100, 65530, 65550)))
        self.assertEqual(self.main.app.state.fixture_slots._value, 4)

    async def test_xss_filename_rejected_before_any_download_starts(self):
        for filename in ['x<img src=x onerror=alert(1)>.bin', 'x" autofocus onfocus="alert(1).bin']:
            response = await self.client.post("/api/download/start", headers=self.headers, json={"url": "http://127.0.0.1/file", "filename": filename})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.main.download_tasks, {})
