"""Tests for the WebUI "wave" APIs: annotations, topology and replay.

Runs against a real HTTP server like ``test_api.py``, but builds the job
directory on disk instead of running tshark jobs, so annotation tests work
without any external tool.  Topology/replay tests need tshark and are
skipped otherwise.
"""
from __future__ import annotations

import json
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


if __name__ == "__main__":
    unittest.main()
