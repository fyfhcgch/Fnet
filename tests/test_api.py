"""HTTP API smoke tests (no browser, real tshark job)."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.jobs import JobManager
from fnet.webui.server import make_server

DATA = Path(__file__).resolve().parent / "data"


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cache = Path(cls.tmp.name) / "cache"
        cls.cache.mkdir(parents=True, exist_ok=True)
        cls.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cls.cache),
            mock.patch("fnet.paths.CACHE_DIR", cls.cache),
        ]
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))
        cls.server = make_server(cls.runtime.app, "127.0.0.1", 0)
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.token = cls.runtime.app.token

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    # -- helpers -------------------------------------------------------
    def request(self, path: str, data: bytes | None = None,
                token: bool = True, headers: dict | None = None,
                method: str | None = None):
        request_headers = dict(headers or {})
        if token:
            request_headers["X-Fnet-Token"] = self.token
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=request_headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.read()
            finally:
                error.close()

    def json_request(self, path: str, payload=None, token: bool = True):
        data = None if payload is None else json.dumps(payload).encode()
        status, body = self.request(
            path, data=data, token=token,
            headers={"Content-Type": "application/json"} if data else None)
        return status, json.loads(body.decode("utf-8"))

    # -- tests ---------------------------------------------------------
    def test_health_is_public(self):
        status, body = self.request("/api/health", token=False)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_meta_requires_token(self):
        status, _ = self.request("/api/meta", token=False)
        self.assertEqual(status, 403)

    def test_meta_payload(self):
        status, meta = self.json_request("/api/meta")
        self.assertEqual(status, 200)
        self.assertEqual(len(meta["features"]), 37)
        self.assertEqual(len(meta["categories"]), 13)
        self.assertEqual(meta["initial"], {"pcap": "", "features": []})
        self.assertIn("tshark", meta["tools"])
        self.assertIn("report", meta)
        self.assertEqual([item["key"] for item in meta["report"]["sections"]],
                         ["summary", "features", "findings", "log",
                          "artifacts", "params"])
        self.assertNotIn("params", meta["report"]["default_sections"])
        kinds = {item["key"] for item in meta["findings"]["kinds"]}
        self.assertIn("hash", kinds)
        self.assertIn("flag", kinds)

    def test_upload_rejects_unknown_suffix(self):
        status, body = self.request(
            "/api/upload", data=b"not a capture", token=True,
            headers={"X-Filename": "evil.exe"})
        self.assertEqual(status, 400)
        self.assertIn("仅支持", json.loads(body)["error"])

    def test_upload_analyze_download(self):
        raw = (DATA / "http_ntlm.pcap").read_bytes()
        status, body = self.request(
            "/api/upload", data=raw, token=True,
            headers={"X-Filename": "http_ntlm.pcap"})
        self.assertEqual(status, 200)
        uploaded = json.loads(body)
        self.assertTrue(Path(uploaded["path"]).is_file())
        self.assertEqual(uploaded["name"], "http_ntlm.pcap")

        status, result = self.json_request("/api/analyze", {
            "pcap": uploaded["path"],
            "features": ["checkBox_39"],
            "params": {},
        })
        self.assertEqual(status, 200)
        job = result["job"]
        self.assertEqual(job["status"], "running")

        deadline = time.time() + 120
        state = None
        while time.time() < deadline:
            status, payload = self.json_request(f"/api/jobs/{job['id']}?cursor=0")
            state = payload["job"]
            if state["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(0.1)
        self.assertEqual(state["status"], "done", state["error"])
        logs = "\n".join(entry["text"] for entry in payload["logs"])
        self.assertIn("NetNTLMv1", logs)
        names = {item["name"] for item in payload["artifacts"]}
        self.assertIn("ntlm_hashes.txt", names)
        self.assertIn("report.txt", names)
        self.assertIn("report.md", names)
        self.assertIn("report.html", names)
        self.assertIn("findings.json", names)
        self.assertIn("findings.csv", names)

        status, payload = self.json_request(f"/api/findings?job={job['id']}")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(payload["total"], 1)
        self.assertEqual(payload["kinds"].get("hash"), payload["total"])
        records = payload["findings"]
        self.assertTrue(any("Administrator" in item["summary"] for item in records))
        self.assertTrue(all(item["feature"] == "NTLM HASH提取" for item in records))

        status, payload = self.json_request(
            f"/api/findings?job={job['id']}&kind=hash&q=administrator")
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], payload["total"])

        status, payload = self.json_request(
            f"/api/findings?job={job['id']}&kind=flag")
        self.assertEqual(status, 200)
        self.assertEqual(payload["count"], 0)

        status, payload = self.json_request(
            f"/api/findings?job={job['id']}&limit=abc")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["count"], 1)

        status, content = self.request(
            f"/api/findings?job={job['id']}&format=csv")
        self.assertEqual(status, 200)
        self.assertIn("类别,级别,帧,功能,摘要,详情".encode(), content)
        self.assertIn(b"Administrator", content)

        status, _ = self.request("/api/findings?job=0123456789abcdef")
        self.assertEqual(status, 404)

        status, packet = self.json_request(
            f"/api/packet?job={job['id']}&frame=4&context=1")
        self.assertEqual(status, 200)
        self.assertTrue(packet["ok"])
        self.assertEqual(packet["packet"]["frame"], "4")
        self.assertEqual(packet["packet"]["protocol"], "HTTP")
        self.assertIn("GET /admin/", packet["packet"]["info"])
        self.assertEqual(packet["range"], [3, 5])
        self.assertEqual(len(packet["neighbors"]), 3)
        self.assertIn("GET /admin/", packet["detail"])
        self.assertIn("wireshark", packet["tools"])

        status, clip = self.request(
            f"/api/packet?job={job['id']}&frame=4&context=1&format=pcap")
        self.assertEqual(status, 200)
        self.assertTrue(clip.startswith(b"\x0a\x0d\x0d\x0a")
                        or clip.startswith(b"\xd4\xc3\xb2\xa1"))
        self.assertTrue(
            (self.cache / "jobs" / job["id"] / "frames" /
             "frame-4-ctx1.pcapng").is_file())

        status, _ = self.request(
            f"/api/packet?job={job['id']}&frame=0")
        self.assertEqual(status, 400)
        status, _ = self.request(
            f"/api/packet?job={job['id']}&frame=abc")
        self.assertEqual(status, 400)
        status, _ = self.request(
            "/api/packet?job=0123456789abcdef&frame=4")
        self.assertEqual(status, 404)

        status, content = self.request(
            f"/api/download?job={job['id']}&path=ntlm_hashes.txt")
        self.assertEqual(status, 200)
        self.assertIn(b"Administrator::WORKGROUP:", content)

        status, content = self.request(
            f"/api/report?job={job['id']}&format=html&sections=summary,findings")
        self.assertEqual(status, 200)
        self.assertIn(b"<!doctype html>", content)
        self.assertIn("Fnet 分析报告".encode(), content)
        self.assertIn(b"NetNTLMv1", content)
        self.assertNotIn(b'id="section-log"', content)

        status, content = self.request(
            f"/api/report?job={job['id']}&format=markdown&sections=summary")
        self.assertEqual(status, 200)
        self.assertIn(b"## \xe6\xa6\x82\xe8\xa6\x81", content)
        self.assertNotIn(b"## \xe5\xae\x8c\xe6\x95\xb4\xe6\x97\xa5\xe5\xbf\x97",
                         content)

        status, _ = self.request(
            "/api/report?job=0123456789abcdef&format=html")
        self.assertEqual(status, 404)

        status, bundle = self.request(
            f"/api/download?job={job['id']}&bundle=1")
        self.assertEqual(status, 200)
        self.assertTrue(bundle.startswith(b"PK"))

    def test_timeline_stats_action(self):
        status, payload = self.json_request("/api/action", {
            "action": "stats", "sub": "timeline",
            "pcap": str(DATA / "http_ntlm.pcap"), "buckets": 10,
        })
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["points"]), 10)
        self.assertEqual(sum(point["frames"] for point in payload["points"]), 36)
        self.assertEqual(payload["total_frames"], 36)
        self.assertGreater(payload["total_bytes"], 0)

    def test_decode(self):
        status, payload = self.json_request(
            "/api/decode", {"text": "ZmxhZ3tkZWNvZGVfdGVzdH0="})
        self.assertEqual(status, 200)
        self.assertIn("flag{decode_test}", payload["flags"])
        labels = {item["label"] for item in payload["candidates"]}
        self.assertIn("Base64", labels)

    def test_config_save_and_read(self):
        status, payload = self.json_request("/api/config", {
            "section": "config", "values": {"winrm_port": "5986"}})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        status, payload = self.json_request("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(payload["config"]["winrm_port"], "5986")

    def test_job_history_view_and_delete(self):
        raw = (DATA / "http_ntlm.pcap").read_bytes()
        status, body = self.request(
            "/api/upload", data=raw, token=True,
            headers={"X-Filename": "history_ntlm.pcap"})
        self.assertEqual(status, 200)
        uploaded = json.loads(body)

        status, result = self.json_request("/api/analyze", {
            "pcap": uploaded["path"], "features": ["checkBox_39"], "params": {},
        })
        self.assertEqual(status, 200)
        job_id = result["job"]["id"]

        deadline = time.time() + 120
        state = None
        while time.time() < deadline:
            status, payload = self.json_request(f"/api/jobs/{job_id}?cursor=0")
            state = payload["job"]
            if state["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(0.1)
        self.assertEqual(state["status"], "done", state["error"])

        status, payload = self.json_request("/api/history")
        self.assertEqual(status, 200)
        entries = {item["id"]: item for item in payload["jobs"]}
        self.assertIn(job_id, entries)
        self.assertEqual(entries[job_id]["features"], ["checkBox_39"])
        self.assertEqual(entries[job_id]["status"], "done")

        status, payload = self.json_request(f"/api/history/{job_id}")
        self.assertEqual(status, 200)
        self.assertIn("NetNTLMv1", payload["report"])
        self.assertFalse(payload["report_truncated"])
        names = {item["name"] for item in payload["artifacts"]}
        self.assertIn("ntlm_hashes.txt", names)
        self.assertNotIn("job.json", names)

        # A fresh manager (as after a process restart) still sees the job.
        fresh = JobManager(self.runtime.config, self.runtime.toolbox)
        self.assertIn(job_id, {item["id"] for item in fresh.history()})
        self.assertIn("NetNTLMv1", fresh.history_detail(job_id)["report"])
        self.assertEqual(fresh.pcap_for(job_id), uploaded["path"])
        recovered = fresh.findings_for(job_id)
        self.assertIsNotNone(recovered)
        self.assertGreaterEqual(recovered["total"], 1)
        self.assertFalse(recovered["derived"])

        # Recovered jobs parse report.txt, so reports still export after a
        # process restart when the in-memory log buffer is gone.
        exported = fresh.export_report(job_id, "html", "summary,log")
        self.assertIn("Fnet 分析报告", exported["content"])
        self.assertIn("NetNTLMv1", exported["content"])
        self.assertEqual(exported["sections"], ["summary", "log"])

        status, payload = self.json_request(
            f"/api/history/{job_id}/delete", {})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertFalse((self.cache / "jobs" / job_id).exists())

        status, payload = self.json_request(f"/api/history/{job_id}")
        self.assertEqual(status, 404)

    def test_batch_queue_and_jobs_listing(self):
        raw = (DATA / "http_ntlm.pcap").read_bytes()
        paths = []
        for name in ("batch_a.pcap", "batch_b.pcap"):
            status, body = self.request(
                "/api/upload", data=raw, token=True,
                headers={"X-Filename": name})
            self.assertEqual(status, 200)
            paths.append(json.loads(body)["path"])

        status, result = self.json_request("/api/batch", {
            "pcaps": paths, "features": ["checkBox_39"], "params": {},
            "concurrency": 1,
        })
        self.assertEqual(status, 200)
        self.assertEqual(result["count"], 2)
        ids = [job["id"] for job in result["jobs"]]
        self.assertEqual(len(set(ids)), 2)
        self.assertEqual({job["pcap"] for job in result["jobs"]},
                         set(paths))

        deadline = time.time() + 120
        states = {}
        while time.time() < deadline:
            status, payload = self.json_request("/api/jobs")
            self.assertEqual(status, 200)
            states = {item["id"]: item["status"] for item in payload["jobs"]}
            if all(states.get(job_id) in ("done", "error", "cancelled")
                   for job_id in ids):
                break
            time.sleep(0.1)
        self.assertEqual([states.get(job_id) for job_id in ids],
                         ["done", "done"])

        listed = {item["id"] for item in payload["jobs"]}
        self.assertTrue(set(ids) <= listed)

    def test_batch_controls_and_merged_report(self):
        path = str(DATA / "http_ntlm.pcap")
        status, result = self.json_request("/api/batch", {
            "pcaps": [path], "features": ["checkBox_10"], "params": {},
            "concurrency": 1,
        })
        self.assertEqual(status, 200)
        job_id = result["jobs"][0]["id"]
        status, payload = self.json_request("/api/batch")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(payload["summary"]["total"], 1)
        status, payload = self.json_request("/api/batch/pause", {})
        self.assertTrue(payload["summary"]["paused"])
        status, payload = self.json_request("/api/batch/reorder",
                                            {"ids": [job_id]})
        self.assertEqual(status, 200)
        status, payload = self.json_request("/api/batch/concurrency",
                                            {"concurrency": 2})
        self.assertEqual(payload["summary"]["concurrency"], 2)
        status, payload = self.json_request("/api/batch/resume", {})
        self.assertFalse(payload["summary"]["paused"])

        deadline = time.time() + 120
        while time.time() < deadline:
            _, listing = self.json_request("/api/jobs")
            state = {item["id"]: item["status"]
                     for item in listing["jobs"]}
            if state.get(job_id) in ("done", "error", "cancelled"):
                break
            time.sleep(0.05)
        url = (f"/api/batch/report?jobs={job_id}&format=html")
        status, body = self.request(url)
        self.assertEqual(status, 200)
        self.assertIn("<!doctype html>", body.decode("utf-8"))

    def test_topology_and_protocol_drilldown(self):
        path = str(DATA / "http_ntlm.pcap")
        status, payload = self.json_request("/api/action", {
            "action": "stats", "sub": "topology", "pcap": path,
        })
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(len(payload["nodes"]), 2)
        self.assertGreaterEqual(len(payload["edges"]), 1)
        self.assertIn("10.0.0.5:40001", {node["id"] for node in payload["nodes"]})
        status, payload = self.json_request("/api/action", {
            "action": "stats", "sub": "protocol", "pcap": path,
            "protocol": "HTTP",
        })
        self.assertEqual(status, 200)
        self.assertTrue(payload["packets"])
        self.assertIn("GET /admin/", payload["packets"][0]["info"])

    def test_batch_rejects_invalid_payloads(self):
        status, payload = self.json_request("/api/batch", {"pcaps": []})
        self.assertEqual(status, 400)
        self.assertIn("pcaps", payload["error"])
        status, payload = self.json_request("/api/batch", {
            "pcaps": [str(i) for i in range(51)],
            "features": ["checkBox_39"],
        })
        self.assertEqual(status, 400)
        self.assertIn("50", payload["error"])
        status, payload = self.json_request("/api/batch", {
            "pcaps": [""], "features": ["checkBox_39"],
        })
        self.assertEqual(status, 400)
        status, payload = self.json_request("/api/batch", {
            "pcaps": [str(DATA / "http_ntlm.pcap"), "/nonexistent/x.pcap"],
            "features": ["checkBox_39"],
        })
        self.assertEqual(status, 400)
        self.assertIn("不存在", payload["error"])
        status, payload = self.json_request("/api/batch", {
            "pcaps": [str(DATA / "http_ntlm.pcap")],
            "features": ["checkBox_39"], "handlers": "bad",
        })
        self.assertEqual(status, 400)
        self.assertIn("handlers", payload["error"])

    def test_upload_tls_keylog_and_private_key(self):
        status, body = self.request(
            "/api/upload", data=b"CLIENT_RANDOM aa bb\n", token=True,
            headers={"X-Filename": "browser.log", "X-Kind": "keylog"})
        self.assertEqual(status, 200)
        keylog = json.loads(body)
        self.assertTrue(keylog["ok"])
        self.assertEqual(keylog["kind"], "keylog")
        self.assertEqual(keylog["config"], "tls_keylog")
        self.assertTrue(Path(keylog["path"]).is_file())
        self.assertEqual(Path(keylog["path"]).parent,
                         self.cache / "keys")

        status, payload = self.json_request("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(payload["paths"]["tls_keylog"], keylog["path"])

        pem = (b"-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"
               b"-----END RSA PRIVATE KEY-----\n")
        status, body = self.request(
            "/api/upload", data=pem, token=True,
            headers={"X-Filename": "server.pem", "X-Kind": "key"})
        self.assertEqual(status, 200)
        private = json.loads(body)
        self.assertEqual(private["kind"], "key")
        self.assertEqual(private["config"], "tls_private_key")
        self.assertTrue(Path(private["path"]).is_file())

        status, payload = self.json_request("/api/config")
        self.assertEqual(payload["paths"]["tls_private_key"],
                         private["path"])

        status, body = self.request(
            "/api/upload", data=b"not a key", token=True,
            headers={"X-Filename": "fake.log", "X-Kind": "keylog"})
        self.assertEqual(status, 400)
        self.assertIn("keylog", json.loads(body)["error"])

    def test_unknown_action_is_rejected(self):
        status, payload = self.json_request(
            "/api/action", {"action": "rm_rf", "pcap": ""})
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
