"""Tests for the WebUI "wave" APIs: annotations, topology and replay.

Runs against a real HTTP server like ``test_api.py``, but builds the job
directory on disk instead of running tshark jobs, so annotation tests work
without any external tool.  Topology/replay tests need tshark and are
skipped otherwise.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.findings import make, normalise
from fnet.webui.server import make_server

DATA = Path(__file__).resolve().parent / "data"
JOB_ID = "0a1b2c3d4e5f6a7b"


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


class WaveApiTest(unittest.TestCase):
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
        cls._make_fake_job()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    @classmethod
    def _make_fake_job(cls):
        """A finished job on disk: job.json + findings.json, no tshark run."""
        output = cls.cache / "jobs" / JOB_ID
        output.mkdir(parents=True, exist_ok=True)
        pcap = str(DATA / "http_ntlm.pcap")
        (output / "job.json").write_text(json.dumps({
            "id": JOB_ID, "pcap": pcap, "pcap_name": "http_ntlm.pcap",
            "status": "done", "progress": 100, "created": "2026-01-01T00:00:00",
            "features": ["checkBox_39"], "params": {},
        }, ensure_ascii=False), encoding="utf-8")
        (output / "findings.json").write_text(json.dumps({
            "job": JOB_ID,
            "count": 2,
            "findings": [
                make("credential", "Administrator::WORKGROUP", frame="4",
                     detail="NTLMv1 hash", feature="NTLM HASH提取"),
                make("flag", "flag{fake_wave_test}", frame="9", detail=""),
            ],
        }, ensure_ascii=False), encoding="utf-8")

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
        self.last_csp = ""
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                self.last_csp = response.headers.get(
                    "Content-Security-Policy", "")
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            try:
                self.last_csp = error.headers.get(
                    "Content-Security-Policy", "") if error.headers else ""
                return error.code, error.read()
            finally:
                error.close()

    def json_request(self, path: str, payload=None, token: bool = True):
        data = None if payload is None else json.dumps(payload).encode()
        status, body = self.request(
            path, data=data, token=token,
            headers={"Content-Type": "application/json"} if data else None)
        return status, json.loads(body.decode("utf-8"))

    # -- annotations ---------------------------------------------------
    def test_annotations_roundtrip(self):
        status, payload = self.json_request(f"/api/findings?job={JOB_ID}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["total"], 2)
        self.assertTrue(all("annotation" not in item for item in payload["findings"]))

        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 1, "status": "confirmed", "note": "已人工核对",
        })
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        saved = (self.cache / "jobs" / JOB_ID / "annotations.json")
        self.assertTrue(saved.is_file())

        status, payload = self.json_request(f"/api/findings?job={JOB_ID}")
        first = payload["findings"][0]
        self.assertEqual(first["annotation"]["status"], "confirmed")
        self.assertEqual(first["annotation"]["note"], "已人工核对")
        self.assertNotIn("annotation", payload["findings"][1])

        status, payload = self.json_request(f"/api/annotations?job={JOB_ID}")
        self.assertEqual(status, 200)
        self.assertIn("1", payload["annotations"])

        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 1, "status": "false_positive",
        })
        self.assertEqual(status, 200)
        status, payload = self.json_request(f"/api/findings?job={JOB_ID}")
        self.assertEqual(payload["findings"][0]["annotation"]["status"],
                         "false_positive")

        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 1, "status": "", "note": "",
        })
        self.assertEqual(status, 200)
        status, payload = self.json_request(f"/api/findings?job={JOB_ID}")
        self.assertTrue(all("annotation" not in item
                            for item in payload["findings"]))
        status, payload = self.json_request(f"/api/annotations?job={JOB_ID}")
        self.assertEqual(payload["annotations"], {})

    def test_annotation_note_only_kept(self):
        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 2, "note": "关注这条", "status": "",
        })
        self.assertEqual(status, 200)
        status, payload = self.json_request(f"/api/findings?job={JOB_ID}")
        self.assertEqual(payload["findings"][1]["annotation"]["note"], "关注这条")
        self.json_request("/api/annotations",
                          {"job": JOB_ID, "seq": 2, "status": "", "note": ""})

    def test_annotation_rejects_bad_input(self):
        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 1, "status": "bogus"})
        self.assertEqual(status, 400)
        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": "abc", "note": "x"})
        self.assertEqual(status, 400)
        status, payload = self.json_request("/api/annotations", {
            "job": JOB_ID, "seq": 0, "note": "x"})
        self.assertEqual(status, 400)
        status, _ = self.json_request("/api/annotations", {
            "job": "1234567890abcdef", "seq": 1, "note": "x"})
        self.assertEqual(status, 404)
        status, _ = self.request("/api/annotations", token=False,
                                 data=json.dumps({"job": JOB_ID, "seq": 1,
                                                  "note": ""}).encode(),
                                 headers={"Content-Type": "application/json"})
        self.assertEqual(status, 403)

    def test_findings_unknown_job_404(self):
        status, _ = self.json_request("/api/findings?job=1234567890abcdef")
        self.assertEqual(status, 404)

    # -- topology ------------------------------------------------------
    @unittest.skipUnless(tshark_available(), "需要 tshark")
    def test_topology_api(self):
        status, payload = self.json_request(f"/api/topology?job={JOB_ID}")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertGreaterEqual(len(payload["nodes"]), 2)
        self.assertGreaterEqual(len(payload["links"]), 1)
        node = payload["nodes"][0]
        for key in ("id", "label", "protocols", "count"):
            self.assertIn(key, node)
        link = payload["links"][0]
        for key in ("source", "target", "protocol", "frames"):
            self.assertIn(key, link)
        self.assertTrue(any(node["id"].startswith("10.0.0.5")
                            for node in payload["nodes"]))

        status, _ = self.json_request("/api/topology?job=1234567890abcdef")
        self.assertEqual(status, 404)
        status, _ = self.request(f"/api/topology?job={JOB_ID}", token=False)
        self.assertEqual(status, 403)

    # -- replay --------------------------------------------------------
    @unittest.skipUnless(tshark_available(), "需要 tshark")
    def test_replay_from_frame_generates_requests_script(self):
        status, payload = self.json_request("/api/replay",
                                            {"job": JOB_ID, "frame": 4})
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["kind"], "http")
        script = payload["script"]
        self.assertIn("import requests", script)
        self.assertIn("requests.Session()", script)
        self.assertIn("session.request(", script)
        self.assertIn("/admin/", script)
        # Sensitive data is kept verbatim, with a reminder comment.
        self.assertIn("敏感", script)
        self.assertIn("10.0.0.5", script)
        self.assertTrue(payload["stream"] != "")
        # The script is valid Python syntax.
        compile(script, "replay.py", "exec")

        # The stream reported back can be replayed directly.
        status, by_stream = self.json_request("/api/replay", {
            "job": JOB_ID, "stream": payload["stream"]})
        self.assertEqual(status, 200)
        self.assertEqual(by_stream["kind"], "http")
        self.assertEqual(by_stream["stream"], payload["stream"])

    @unittest.skipUnless(tshark_available(), "需要 tshark")
    def test_replay_rejects_bad_input(self):
        status, payload = self.json_request("/api/replay", {"job": JOB_ID})
        self.assertEqual(status, 400)
        status, payload = self.json_request("/api/replay",
                                            {"job": JOB_ID, "frame": "abc"})
        self.assertEqual(status, 400)
        status, _ = self.json_request("/api/replay",
                                      {"job": "1234567890abcdef", "frame": 4})
        self.assertEqual(status, 404)
        status, _ = self.request("/api/replay", token=False,
                                 data=json.dumps({"job": JOB_ID,
                                                  "frame": 4}).encode(),
                                 headers={"Content-Type": "application/json"})
        self.assertEqual(status, 403)

    # -- findings capture time -----------------------------------------
    def test_findings_capture_field_roundtrip(self):
        record = make("flag", "flag{capture}", frame="7", capture="12.5")
        self.assertEqual(record["capture"], "12.5")
        restored = normalise(record)
        self.assertEqual(restored["capture"], "12.5")
        self.assertEqual(normalise({"summary": "x"})["capture"], "")

    # -- pre-auth hardening --------------------------------------------
    def test_non_ascii_token_is_rejected_not_500(self):
        """非 ASCII token 必须走 403，不能把 TypeError 兜底成预认证 500。

        ``secrets.compare_digest("测试", "test")`` 直接抛 TypeError，旧实现
        会把它渲染成 500 并把异常文本回显给客户端。
        """
        # 头部（"é" 是 latin-1 可编码的非 ASCII 字符，能过 urllib）。
        status, body = self.request(
            "/api/meta", token=False, headers={"X-Fnet-Token": "é"})
        self.assertEqual(status, 403)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(set(payload), {"ok", "error"})
        self.assertFalse(payload["ok"])
        self.assertIsInstance(payload["error"], str)
        self.assertNotIn("TypeError", payload["error"])

        # 查询参数（%E6%B5%8B%E8%AF%95 解码为 "测试"，纯非 ASCII）。
        status, body = self.request("/api/meta?token=%E6%B5%8B%E8%AF%95",
                                    token=False)
        self.assertEqual(status, 403)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(set(payload), {"ok", "error"})
        self.assertFalse(payload["ok"])

        # 真正的 token 仍然有效。
        status, body = self.request("/api/meta", token=True)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body.decode("utf-8"))["token"])

    def test_static_does_not_serve_prefix_sibling_directory(self):
        """同前缀兄弟目录（``staticX/``）不能被当成 ``static/`` 的子路径。"""
        import http.client

        from fnet.webui import server as server_mod

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            static = root / "static"
            static.mkdir()
            (static / "app.js").write_text("// ok", encoding="utf-8")
            sibling = root / "staticX"
            sibling.mkdir()
            (sibling / "evil.js").write_text("// evil", encoding="utf-8")

            def raw(path: str):
                # http.client 不会规范化 ``..``，这样才真正走到前缀校验。
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.server.server_address[1], timeout=30)
                try:
                    connection.request("GET", path)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            with mock.patch.object(server_mod, "STATIC_DIR", static):
                status, body = raw("/static/app.js")
                self.assertEqual(status, 200)
                self.assertEqual(body, b"// ok")
                status, body = raw("/static/../staticX/evil.js")
                self.assertEqual(status, 404)
                self.assertFalse(json.loads(body.decode("utf-8"))["ok"])
                status, _ = raw("/static/%2e%2e/staticX/evil.js")
                self.assertEqual(status, 404)

    def test_index_csp_has_no_unsafe_inline_scripts(self):
        """首页 CSP 只放行带 nonce 的那一段内联脚本。"""
        status, body = self.request("/", token=False)
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn('window.FNET_TOKEN = "', html)
        match = re.search(r'<script nonce="([^"]+)">', html)
        self.assertIsNotNone(match, html[-400:])
        nonce = match.group(1)
        self.assertIn(f"'nonce-{nonce}'", self.last_csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", self.last_csp)
        self.assertNotIn("__NONCE__", html)
        # app.js 仍然以普通 src 加载（'self' 覆盖它）。
        self.assertIn('<script src="/static/app.js"></script>', html)

    def test_internal_error_does_not_leak_details(self):
        """500 只回通用中文文案，异常细节进日志。"""
        secret = "/very/secret/path/capture.pcap argv=['tshark', '-r']"
        with mock.patch.object(self.runtime.app.jobs, "list",
                               side_effect=RuntimeError(secret)):
            status, body = self.request("/api/jobs")
        self.assertEqual(status, 500)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload["ok"])
        self.assertNotIn("secret", payload["error"])
        self.assertNotIn("tshark", payload["error"])
        self.assertTrue(payload["error"])

    def test_batch_report_html_carries_csp(self):
        """合并报告与 /api/report 一样带 ``default-src 'none'``。"""
        status, body = self.request(
            f"/api/batch/report?jobs={JOB_ID}&format=html")
        self.assertEqual(status, 200)
        self.assertTrue(body.decode("utf-8").startswith("<!doctype html>"))
        self.assertEqual(self.last_csp,
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "img-src data:")


if __name__ == "__main__":
    unittest.main()
