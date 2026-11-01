"""Adversarial regression coverage for the 2026-11-01 audit."""
import os
os.environ.setdefault("LANPOOL_ALLOW_LOOPBACK", "1")
os.environ.setdefault("LANPOOL_PEER_SECRET", "lanpool-regression-test-key")

import asyncio
import hashlib
import json
import subprocess
import shutil
import socket
import sys
import tempfile
import time
import unittest
from html.parser import HTMLParser
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock, patch
import httpx
import psutil
import anyio
from core.io_utils import disk_call

from core.cache_manager import CacheManager
from core.downloader import SoloDownloadTask
from core.peer_auth import beacon_signature, request_headers, verify_request, peer_client
from core.peer_discovery import PeerDiscovery
from core.peer_registry import PeerRegistry
from core.url_safety import validate_download_url, PinnedOriginTransport
from core.watchdog import NodeQoSManager
from core.worker import fetch_chunk_from_origin, PoisonedChunkError


def origin(payload, etag='"v1"', wrong=False):
    def respond(request):
        start, end = map(int, request.headers["Range"].split("=")[1].split("-"))
        offset = 0 if wrong else start
        headers = {"Content-Range": f"bytes {offset}-{offset+end-start}/{len(payload)}"}
        if etag:
            headers["ETag"] = etag
        return httpx.Response(206, headers=headers, content=payload[offset:offset+end-start+1])
    return httpx.MockTransport(respond)


class DownloadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.down = self.root / "downloads"
        self.down.mkdir()
        self.cache = CacheManager(self.root / "cache")

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def download(self, payload, *, etag='"v1"', wrong=False, expected="", offline=False, chunk_size=1024, name="file.bin"):
        async with httpx.AsyncClient(transport=origin(payload, etag, wrong)) as client:
            task = SoloDownloadTask("test", "http://127.0.0.1/file", name, self.down, cache_manager=self.cache, http_client=client, chunk_size=chunk_size, expected_sha256=expected, offline=offline)
            await task.start()
            await asyncio.wait_for(task._task_handle, 10)
            return task

    async def test_wrong_range_fails_in_solo_and_helper(self):
        payload = b"A" * 1024 + b"B" * 1024
        task = await self.download(payload, wrong=True)
        self.assertEqual(task.status, "failed")
        self.assertIn("Content-Range", task.error)
        self.assertFalse(task.final_path.exists())
        async with httpx.AsyncClient(transport=origin(payload, wrong=True)) as client:
            with self.assertRaises(PoisonedChunkError):
                await fetch_chunk_from_origin(task.url, 1024, 2047, '"v1"', client=client, total_size=2048)

    async def test_missing_etag_never_reuses_stale_cache(self):
        first = await self.download(b"A" * 512, etag="")
        second = await self.download(b"B" * 512, etag="", name="second.bin")
        self.assertEqual(second.status, "completed")
        self.assertEqual(second.source, "solo")
        self.assertNotEqual(first.sha256, second.sha256)

    async def test_weak_or_missing_validator_requires_hash_for_multichunk(self):
        for etag in ("", 'W/"weak"'):
            task = await self.download(b"C" * 2048, etag=etag)
            self.assertEqual(task.status, "failed")
            self.assertIn("strong ETag", task.error)
        payload = b"D" * 2048
        task = await self.download(payload, etag="", expected=hashlib.sha256(payload).hexdigest())
        self.assertEqual(task.status, "completed", task.error)

    async def test_cache_corruption_does_not_claim_success_with_old_hash(self):
        payload = b"A" * 512
        first = await self.download(payload)
        path = self.cache.stream_path(first.sha256)
        stamp = path.stat().st_mtime_ns
        path.write_bytes(b"X" * 512)
        os.utime(path, ns=(stamp, stamp))
        second = await self.download(payload, name="second.bin")
        self.assertEqual(second.status, "completed", second.error)
        self.assertEqual(second.source, "solo")
        self.assertEqual(hashlib.sha256(self.cache.stream_path(first.sha256).read_bytes()).hexdigest(), first.sha256)

    async def test_expected_hash_rejected_before_publishing(self):
        task = await self.download(b"A" * 512, expected="0" * 64)
        self.assertEqual(task.status, "failed")
        self.assertIn("trusted expected", task.error)
        self.assertFalse(task.final_path.exists())
        self.assertFalse(task.part_path.exists())

    async def test_offline_hash_copy_never_contacts_origin(self):
        first = await self.download(b"A" * 512)
        with patch("core.downloader.probe_url", side_effect=AssertionError("Offline must not probe")):
            second = await self.download(b"unused", expected=first.sha256, offline=True, name="offline.bin")
        self.assertEqual(second.status, "completed", second.error)
        self.assertEqual(second.source, "local_cache")
        self.assertEqual(second.probe_requests, 0)

    async def test_admin_secret_never_sent_to_unpaired_peer(self):
        task = SoloDownloadTask("test", "http://127.0.0.1/file", api_token="private-admin-token")
        with patch("core.downloader.httpx.AsyncClient", side_effect=AssertionError("Unpaired peer contacted")):
            self.assertEqual(await task._query_peer_caches([{"ip": "127.0.0.1", "port": 9999, "trusted": False}]), [])

    async def test_automatic_boost_is_requested_and_released_on_completion(self):
        payload = b"A" * 2048
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        registry.add_manual("127.0.0.1", 8001, node_id="paired", trusted=True)
        async with httpx.AsyncClient(transport=origin(payload)) as client:
            task = SoloDownloadTask("boost-job", "http://127.0.0.1/file", "boost.bin", self.down, cache_manager=self.cache, http_client=client, chunk_size=1024, peer_registry=registry, own_node_id="own")
            task._notify_boost = AsyncMock()
            task._query_peer_caches = AsyncMock(return_value=[])
            task._helper_worker = AsyncMock()
            with patch("core.downloader.BOOST_THRESHOLD_MB", 0):
                await task.start()
                await task._task_handle
            self.assertEqual(task.status, "completed", task.error)
            self.assertEqual(task._notify_boost.await_count, 2)
            self.assertEqual(task._notify_boost.await_args.kwargs, {"release": True})

    async def test_oversized_stream_stops_before_buffering_entire_body(self):
        blocks = []
        class Oversized(httpx.AsyncByteStream):
            async def __aiter__(self):
                for i in range(1000):
                    blocks.append(i)
                    yield b"X" * 65536
        def respond(request):
            return httpx.Response(206, headers={"Content-Range": "bytes 0-65535/65536"}, stream=Oversized())
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            with self.assertRaises(PoisonedChunkError):
                await fetch_chunk_from_origin("http://127.0.0.1/file", 0, 65535, client=client)
        self.assertEqual(len(blocks), 2)

    async def test_cancel_awaits_all_children_and_removes_part(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(16):
                    await asyncio.sleep(0.05)
                    yield b"a" * 65536
        def respond(request):
            start, end = map(int, request.headers["Range"].split("=")[1].split("-"))
            return httpx.Response(206, headers={"Content-Range": f"bytes {start}-{end}/1048576", "ETag": '"slow"'}, stream=Slow())
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            task = SoloDownloadTask("cancel", "http://127.0.0.1/slow", "cancel.bin", self.down, cache_manager=self.cache, http_client=client)
            await task.start()
            for _ in range(100):
                if task.status == "downloading":
                    break
                await asyncio.sleep(0.01)
            await task.cancel()
            self.assertEqual(task.status, "cancelled")
            self.assertTrue(all(child.done() for child in task._worker_handles + task._wait_handles))
            self.assertTrue(task._writer_handle.done())
            self.assertFalse(task.part_path.exists())


class CacheTests(unittest.TestCase):
    def test_dashboard_fields_have_unique_ids_and_expected_contract(self):
        class Fields(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids = []
            def handle_starttag(self, tag, attrs):
                self.ids.extend(value for key, value in attrs if key == "id")
        parser = Fields()
        html = (Path(__file__).resolve().parents[1] / "static/index.html").read_text(encoding="utf-8")
        parser.feed(html)
        self.assertEqual([key for key, count in Counter(parser.ids).items() if count > 1], [])
        self.assertIn("dl-sha", parser.ids)
        self.assertIn("job-selector", parser.ids)
        self.assertIn("const files = data.items", html)

    def test_aliases_quota_persistence_and_read_leases(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = CacheManager(root / "cache", max_cache_bytes=8)
            sha = hashlib.sha256(b"aaaa").hexdigest()
            for i in (1, 2):
                src = root / f"{i}.bin"
                src.write_bytes(b"aaaa")
                self.assertTrue(cache.register_completed(src, f"http://test/{i}", '"e1"', sha, src.name, 4))
            self.assertTrue(cache.lookup("http://test/1", '"e1"')["hit"])
            accessed = cache.approved_hash_map[sha]["last_access"]
            restarted = CacheManager(root / "cache", max_cache_bytes=8)
            self.assertEqual(restarted.approved_hash_map[sha]["last_access"], accessed)
            self.assertTrue(restarted.lookup("http://test/1", '"e1"')["hit"])
            with restarted.lease(sha) as leased:
                old_path = leased
                self.assertTrue(restarted.update_alias(sha, "renamed.bin"))
                self.assertTrue(old_path.exists())
                src = root / "big.bin"
                src.write_bytes(b"bbbbbb")
                self.assertFalse(restarted.register_completed(src, "http://test/b", '"b"', hashlib.sha256(src.read_bytes()).hexdigest(), src.name, 6))
                self.assertTrue(old_path.exists())
            tiny = CacheManager(root / "cache", max_cache_bytes=1)
            self.assertLessEqual(tiny.get_total_bytes(), 1)


class SecurityAndQoSTests(unittest.IsolatedAsyncioTestCase):
    async def test_thread_io_finishes_under_server_cancel_scope(self):
        finished = []
        def slow_operation():
            time.sleep(0.1)
            finished.append(True)
        async def work():
            await disk_call(slow_operation)
        async with anyio.create_task_group() as group:
            group.start_soon(work)
            await asyncio.sleep(0.02)
            group.cancel_scope.cancel()
        self.assertEqual(finished, [True])

    async def test_private_policy_and_dns_pinning(self):
        for url in ("http://127.0.0.1/", "http://192.168.1.1/", "http://169.254.169.254/"):
            with self.assertRaises(ValueError):
                await validate_download_url(url, allow_loopback=False, allow_private=False)
        seen = []
        transport = PinnedOriginTransport()
        transport.transports[("https", "example.com", None)] = httpx.MockTransport(lambda request: (seen.append(request) or httpx.Response(200, content=b"ok")))
        with patch("core.url_safety.resolve_download_url", AsyncMock(return_value="93.184.216.34")) as resolver:
            async with httpx.AsyncClient(transport=transport) as client:
                await client.get("https://example.com/file")
            self.assertEqual(resolver.await_count, 1)
        self.assertEqual(seen[0].url.host, "93.184.216.34")
        self.assertEqual(seen[0].headers["Host"], "example.com")
        self.assertEqual(seen[0].extensions["sni_hostname"], "example.com")

    async def test_signed_request_replay_and_tampering(self):
        headers = request_headers("POST", "/api/test", b"body")
        replay = {}
        self.assertTrue(verify_request("POST", "/api/test", b"body", headers, replay))
        self.assertFalse(verify_request("POST", "/api/test", b"body", headers, replay))
        self.assertFalse(verify_request("POST", "/api/test", b"changed", request_headers("POST", "/api/test", b"body"), {}))

    async def test_discovery_rejects_bad_share_nan_and_unsigned_beacons(self):
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        discovery = PeerDiscovery("own", 8000, "127.0.0.1", registry)
        packet = {"node_id": "peer", "http_port": 8001, "lan_ip": "127.0.0.1", "timestamp": time.time(), "share_pct": 30}
        for override in ({"share_pct": "bad"}, {"share_pct": -1}, {"timestamp": float("nan")}, {"signature": "\u2603" * 64}, {}):
            discovery.handle_datagram(json.dumps({**packet, **override}).encode(), ("127.0.0.1", 9999))
            self.assertEqual(registry.counts()["total"], 0)
        packet["signature"] = beacon_signature(packet)
        discovery.handle_datagram(json.dumps(packet).encode(), ("127.0.0.1", 9999))
        self.assertTrue(registry.list_peers()[0]["trusted"])

    async def test_manual_endpoint_is_preserved_and_authenticated_restart_refreshes_identity(self):
        registry = PeerRegistry("own", 8000, "127.0.0.1")
        registry.add_manual("127.0.0.1", 8001, node_id="before", trusted=True, scheme="https")
        registry.upsert_udp("before", "192.168.1.20", 9000, "192.168.1.20", trusted=True, scheme="http")
        peer = registry.get("before")
        self.assertEqual((peer["ip"], peer["port"], peer["scheme"]), ("127.0.0.1", 8001, "https"))
        registry.refresh_health("before", {"node_id": "after", "qos": {"effective_share_pct": 0}}, trusted=True)
        self.assertIsNone(registry.get("before"))
        self.assertEqual(registry.get("after")["share_pct"], 0)

    async def test_rate_limit_is_aggregate_and_zero_share_denies(self):
        qos = NodeQoSManager(share_pct=50, max_helper_kbps=32)
        started = time.monotonic()
        await asyncio.gather(qos.throttle_bytes(8192), qos.throttle_bytes(8192))
        self.assertGreaterEqual(time.monotonic() - started, 0.95)
        qos.update(share_pct=0)
        with self.assertRaises(PermissionError):
            await qos.throttle_bytes(1)

    async def test_boost_releases_and_expires_without_changing_baseline(self):
        qos = NodeQoSManager(share_pct=23)
        qos.handle_incoming_boost("peer", "127.0.0.1", "file", 1024, job_id="job-a")
        qos.respond_to_boost("boost")
        self.assertEqual(qos.share_pct, 23)
        self.assertEqual(qos.effective_share_pct, 80)
        qos.release_boost("other")
        self.assertEqual(qos.effective_share_pct, 80)
        qos.release_boost("job-a")
        self.assertEqual(qos.effective_share_pct, 23)
        qos.update(boosted=True)
        qos.boost_expires_at = time.monotonic() - 1
        self.assertEqual(qos.effective_share_pct, 23)

    async def test_real_process_scanner_and_awaited_shutdown(self):
        command = ["ping", "-n", "20", "127.0.0.1"] if os.name == "nt" else ["sleep", "20"]
        child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            name = psutil.Process(child.pid).name()
            qos = NodeQoSManager(game_process_names=[name])
            self.assertTrue(qos.check_game_processes())
            self.assertLessEqual(qos.effective_share_pct, 15)
            qos.start()
            await qos.aclose()
            self.assertIsNone(qos._loop_task)
        finally:
            child.terminate()
            child.wait(timeout=3)


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import main
        self.main = main
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = CacheManager(self.root / "cache")
        main.download_tasks.clear()
        main.archived_jobs.clear()
        main.app.state.download_dir = self.root
        main.app.state.cache_manager = self.manager
        main.app.state.qos_manager = NodeQoSManager(throttling_enabled=False)
        main.app.state.helper_slots = asyncio.Semaphore(4)
        self.token = patch.object(main, "API_TOKEN", "admin-only")
        self.token.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://test")
        self.headers = {"X-LANPool-Token": "admin-only"}

    async def asyncTearDown(self):
        await asyncio.gather(*(task.cancel() for task in self.main.download_tasks.values()))
        await self.client.aclose()
        self.token.stop()
        self.temp.cleanup()

    async def test_helper_concurrency_and_zero_share(self):
        gate = asyncio.Event()
        async def fetch(*args, **kwargs):
            await gate.wait()
            return b"x", hashlib.sha256(b"x").hexdigest()
        payload = {"url": "http://127.0.0.1/file", "start_byte": 0, "end_byte": 0, "chunk_id": 0}
        with patch.object(self.main, "fetch_chunk_from_origin", fetch):
            jobs = [asyncio.create_task(self.client.post("/api/worker/fetch-chunk", json=payload, headers=self.headers)) for _ in range(8)]
            await asyncio.sleep(0.1)
            gate.set()
            responses = await asyncio.gather(*jobs)
        self.assertEqual(sorted(r.status_code for r in responses), [200]*4 + [429]*4)
        self.main.app.state.qos_manager.update(share_pct=0)
        self.assertEqual((await self.client.post("/api/worker/fetch-chunk", json=payload, headers=self.headers)).status_code, 503)

    async def test_body_limit_applies_before_json_validation(self):
        response = await self.client.post("/api/download/start", content=b"x" * 65537, headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)

    async def fail_at_response_headers(self, method, path, payload=None):
        starts = []
        body = json.dumps(payload).encode() if payload is not None else b""
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "method": method, "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "headers": [(b"host", b"test"), (b"content-type", b"application/json"), (b"x-lanpool-token", b"admin-only")], "client": ("127.0.0.1", 12345), "server": ("test", 80)}
        sent_body = False
        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}
        async def send(message):
            if message["type"] == "http.response.start":
                starts.append(message["status"])
            raise OSError("Test client disconnected before response body started")
        with self.assertRaises(Exception):
            await self.main.app(scope, receive, send)
        self.assertEqual(starts, [200])

    async def test_helper_slot_released_if_disconnect_precedes_first_body(self):
        payload = {"url": "http://127.0.0.1/file", "start_byte": 0, "end_byte": 0, "chunk_id": 0}
        with patch.object(self.main, "fetch_chunk_from_origin", AsyncMock(return_value=(b"x", hashlib.sha256(b"x").hexdigest()))):
            await self.fail_at_response_headers("POST", "/api/worker/fetch-chunk", payload)
        self.assertEqual(self.main.app.state.helper_slots._value, 4)

    async def test_cache_lease_released_if_disconnect_precedes_first_body(self):
        src = self.root / "cached.bin"
        src.write_bytes(b"file")
        sha = hashlib.sha256(b"file").hexdigest()
        self.manager.register_completed(src, "http://test/file", '"e"', sha, src.name, 4)
        await self.fail_at_response_headers("GET", "/api/cache/stream/" + sha)
        self.assertEqual(self.manager._leases[sha], 0)

    async def test_loopback_admin_rejects_rebound_host(self):
        with patch.object(self.main, "API_TOKEN", ""):
            response = await self.client.get("/api/qos/status", headers={"Host": "evil.example", "Origin": "http://evil.example"})
        self.assertEqual(response.status_code, 401)

    async def test_cache_schema_and_scoped_single_use_download_ticket(self):
        src = self.root / "test.bin"
        src.write_bytes(b"content")
        sha = hashlib.sha256(b"content").hexdigest()
        self.manager.register_completed(src, "http://test/file", '"e"', sha, "test.bin", 7)
        listing = await self.client.get("/api/cache/list", headers=self.headers)
        self.assertEqual(len(listing.json()["items"]), 1)
        self.assertEqual((await self.client.get("/api/cache/stream/" + sha)).status_code, 401)
        ticket = await self.client.post("/api/cache/ticket/" + sha, headers=self.headers)
        url = ticket.json()["url"]
        downloaded = await self.client.get(url)
        self.assertEqual(downloaded.content, b"content")
        self.assertEqual((await self.client.get(url)).status_code, 401)
        self.assertEqual(self.manager._leases[sha], 0)

    async def test_job_history_survives_restart_and_exposes_retry(self):
        payload = b"content"
        with patch("core.downloader.origin_client", lambda: httpx.AsyncClient(transport=origin(payload))):
            response = await self.client.post("/api/download/start", json={"url": "http://127.0.0.1/file", "expected_sha256": hashlib.sha256(payload).hexdigest()}, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text)
            job_id = response.json()["job_id"]
            await self.main.download_tasks[job_id]._task_handle
            self.main.download_tasks.clear()
            await self.main.load_history(self.main.app)
            status = await self.client.get("/api/download/status", params={"job_id": job_id}, headers=self.headers)
            self.assertEqual(status.json()["status"], "completed")
            retry = await self.client.post(f"/api/download/{job_id}/retry", headers=self.headers)
            self.assertEqual(retry.status_code, 200, retry.text)
            await self.main.download_tasks[retry.json()["job_id"]]._task_handle

    async def test_tls_enrollment_checks_certificate_and_group_identity(self):
        openssl = shutil.which("openssl")
        bundled = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
        if not openssl and bundled.exists():
            openssl = str(bundled)
        if not openssl:
            self.skipTest("openssl is required to generate an ephemeral TLS test certificate")
        certificate, key = self.root / "cert.pem", self.root / "key.pem"
        generation = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(certificate), "-days", "1", "-subj", "/CN=LANPool-Test", "-addext", "subjectAltName=IP:127.0.0.1"], capture_output=True)
        self.assertEqual(generation.returncode, 0, generation.stderr.decode(errors="replace"))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        root = Path(__file__).resolve().parents[1]
        log_path = self.root / "tls-node.log"
        with log_path.open("w") as log:
            child = subprocess.Popen([sys.executable, "main.py", "--port", str(port), "--cache-dir", str(self.root / "tls-cache"), "--download-dir", str(self.root / "tls-downloads"), "--tls-certfile", str(certificate), "--tls-keyfile", str(key)], cwd=root, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, "LANPOOL_API_TOKEN": "tls-node-admin"})
        try:
            with patch.dict(os.environ, {"LANPOOL_CA_FILE": str(certificate)}):
                async with peer_client(2) as client:
                    for _ in range(60):
                        if child.poll() is not None:
                            self.fail(log_path.read_text(errors="replace"))
                        try:
                            response = await client.get(f"https://127.0.0.1:{port}/api/health")
                            if response.status_code == 200:
                                break
                        except httpx.HTTPError:
                            pass
                        await asyncio.sleep(0.1)
                    else:
                        self.fail("TLS test server did not become healthy")
                self.main.app.state.peer_registry = PeerRegistry("controller", 8000, "127.0.0.1")
                paired = await self.client.post("/api/peers/add", json={"ip": "127.0.0.1", "port": port, "scheme": "https"}, headers=self.headers)
                self.assertEqual(paired.status_code, 200, paired.text)
                self.assertTrue(paired.json()["trusted"])
                self.assertEqual(paired.json()["scheme"], "https")
            with patch.dict(os.environ, {"LANPOOL_CA_FILE": ""}):
                async with peer_client(2) as client:
                    with self.assertRaises(httpx.ConnectError):
                        await client.get(f"https://127.0.0.1:{port}/api/health")
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
