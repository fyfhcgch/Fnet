"""Regression tests for the route-map features added in 2.19.0.

Covered here:

* ``fnet.live.parse_interfaces`` (``tshark -D`` parsing);
* streaming ``multipart/form-data`` uploads (no whole-body read);
* ``/api/rules`` import + rule execution during a job;
* ``/api/jobs/<id>/pause|resume`` error paths and ``Job.can_resume``;
* ``/api/compare`` and the ``--compare`` CLI;
* ``--json`` CLI output;
* the new protocol integrations (DNS/ICMP tunnel, SMTP, MySQL, Kerberos, WPA);
* the English metadata used by the WebUI language switch.

They are stdlib-only and skip themselves when ``tshark`` is missing.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
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
from fnet.live import parse_interfaces
from fnet.tools.runner import find_tool
from fnet.webui.server import make_server

DATA = Path(__file__).resolve().parent / "data"
ROOT = Path(__file__).resolve().parents[1]
TSHARK = find_tool("tshark", "")


class ParseInterfacesTest(unittest.TestCase):
    def test_plain_and_described_lines(self):
        output = (
            "1. eth0\n"
            "2. wlan0 (Wireless interface)\n"
            "3. any (Pseudo-device that captures on all interfaces)\n"
            "noise that should be ignored\n"
        )
        items = parse_interfaces(output)
        self.assertEqual([item["index"] for item in items], [1, 2, 3])
        self.assertEqual(items[0]["name"], "eth0")
        self.assertEqual(items[0]["description"], "")
        self.assertEqual(items[1]["name"], "wlan0")
        self.assertEqual(items[1]["description"], "Wireless interface")

    def test_empty_output(self):
        self.assertEqual(parse_interfaces(""), [])
        self.assertEqual(parse_interfaces(None), [])


@unittest.skipUnless(TSHARK, "需要 tshark")
class RoadmapApiTest(unittest.TestCase):
    """HTTP level tests sharing one server / cache directory."""

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
        cls.runtime.config.set("tshark_cache", "0")
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
    def request(self, path, data=None, token=True, headers=None, method=None):
        request_headers = dict(headers or {})
        if token:
            request_headers["X-Fnet-Token"] = self.token
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, error.read()
            finally:
                error.close()

    def json_request(self, path, payload=None, token=True, method=None):
        data = None if payload is None else json.dumps(payload).encode()
        status, body = self.request(
            path, data=data, token=token, method=method,
            headers={"Content-Type": "application/json"} if data else None)
        return status, json.loads(body.decode("utf-8"))

    def multipart(self, filename: str, payload: bytes, kind: str = ""):
        boundary = "----fnetboundary1337"
        head = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; '
            f'filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(head) + len(payload) + len(tail)),
        }
        if kind:
            headers["X-Kind"] = kind
        return head + payload + tail, headers

    def wait_job(self, job_id, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            status, payload = self.json_request(f"/api/jobs/{job_id}?cursor=0")
            if status != 200:
                self.fail(f"任务查询失败: {status} {payload}")
            job = payload["job"]
            if job["status"] in ("done", "error", "cancelled", "paused"):
                return job
            time.sleep(0.05)
        self.fail(f"任务超时: {job_id}")

    def analyze(self, pcap: str, features: list[str], params=None):
        status, result = self.json_request("/api/analyze", {
            "pcap": pcap, "features": features, "params": params or {},
        })
        self.assertEqual(status, 200, result)
        return self.wait_job(result["job"]["id"])

    # -- streaming upload ---------------------------------------------
    def test_streaming_multipart_upload(self):
        raw = (DATA / "http_ntlm.pcap").read_bytes()
        body, headers = self.multipart("http_ntlm.pcap", raw)
        status, payload = self.request("/api/upload", data=body, headers=headers)
        self.assertEqual(status, 200, payload)
        data = json.loads(payload)
        self.assertTrue(Path(data["path"]).is_file())
        self.assertEqual(Path(data["path"]).read_bytes(), raw)
        self.assertEqual(data["name"], "http_ntlm.pcap")

    def test_streaming_upload_rejects_bad_suffix(self):
        body, headers = self.multipart("payload.exe", b"MZ")
        status, payload = self.request("/api/upload", data=body, headers=headers)
        self.assertEqual(status, 400)
        self.assertIn("仅支持", json.loads(payload)["error"])
        leftovers = list((self.cache / "uploads").glob("upload-*.part"))
        self.assertEqual(leftovers, [])

    # -- custom rules ---------------------------------------------------
    def test_rules_import_and_execution(self):
        rule_text = (
            "rule ntlm_token : credential\n"
            "{\n"
            "  meta:\n"
            '    severity = "warn"\n'
            "  strings:\n"
            '    $a = "NTLM" nocase\n'
            "  condition:\n"
            "    any of them\n"
            "}\n"
        )
        body, headers = self.multipart("ntlm.yar", rule_text.encode(),
                                       kind="rules")
        status, payload = self.request("/api/upload", data=body, headers=headers)
        self.assertEqual(status, 200, payload)
        imported = json.loads(payload)
        self.assertEqual(imported["count"], 1)
        self.assertTrue(Path(imported["path"]).is_file())

        status, info = self.json_request("/api/rules")
        self.assertEqual(status, 200)
        self.assertEqual(info["file"], imported["path"])
        self.assertEqual(info["count"], 1)

        job = self.analyze(str(DATA / "http_ntlm.pcap"), ["checkBox_30"],
                           {"rules": imported["path"]})
        self.assertEqual(job["status"], "done")
        status, findings = self.json_request(
            f"/api/findings?job={job['id']}")
        self.assertEqual(status, 200)
        rules = [item for item in findings["findings"]
                 if item.get("kind") == "rule"]
        self.assertTrue(rules, findings)
        self.assertTrue(any("ntlm_token" in item["summary"] for item in rules))

    def test_rules_api_rejects_missing_file(self):
        status, info = self.json_request("/api/rules",
                                         {"file": "/nope/rules.yar"})
        self.assertEqual(status, 400)
        self.assertIn("不存在", info["error"])

    # -- pause / resume --------------------------------------------------
    def test_pause_and_resume_error_paths(self):
        status, payload = self.json_request(
            "/api/jobs/0000000000000000/pause", {}, method="POST")
        self.assertEqual(status, 200)
        self.assertFalse(payload["ok"])

        status, payload = self.json_request(
            "/api/jobs/0000000000000000/resume", {}, method="POST")
        self.assertEqual(status, 400)
        self.assertIn("不可恢复", payload["error"])

        job = self.runtime.jobs.create(
            str(DATA / "http_ntlm.pcap"), ["checkBox_10"], {})
        job.status = "paused"
        self.assertTrue(job.can_resume)
        job.status = "done"
        self.assertFalse(job.can_resume)

    def test_resume_after_pause(self):
        job = self.runtime.jobs.create(
            str(DATA / "http_ntlm.pcap"), ["checkBox_10", "checkBox_30"], {})
        job.pause_event.set()
        resumed_job = self.runtime.jobs.start(job)
        state = self.wait_job(resumed_job.id)
        if state["status"] == "paused":
            status, payload = self.json_request(
                f"/api/jobs/{job.id}/resume", {}, method="POST")
            self.assertEqual(status, 200, payload)
            state = self.wait_job(job.id)
        self.assertIn(state["status"], ("done", "paused", "cancelled"))

    # -- compare ---------------------------------------------------------
    def test_compare_two_jobs(self):
        base = self.analyze(str(DATA / "http_ntlm.pcap"), ["checkBox_39"])
        target = self.analyze(str(DATA / "http_ntlm.pcap"), ["checkBox_30"])
        status, payload = self.json_request(
            f"/api/compare?base={base['id']}&target={target['id']}")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["base"], base["id"])
        self.assertEqual(payload["target"], target["id"])
        self.assertGreater(payload["counts"]["common"]
                           + payload["counts"]["added"], 0)
        self.assertTrue(payload["added"] or payload["removed"])

    def test_compare_unknown_job(self):
        status, payload = self.json_request(
            "/api/compare?base=0000000000000000&target=1111111111111111")
        self.assertEqual(status, 404)

    # -- protocol handlers ----------------------------------------------
    def test_dns_and_icmp_tunnel_reassembly(self):
        job = self.analyze(str(DATA / "dns_arp_icmp.pcap"),
                           ["flows.dns", "flows.icmp"])
        status, payload = self.json_request(f"/api/jobs/{job['id']}?cursor=0")
        log = "\n".join(item["text"] for item in payload["logs"])
        self.assertIn("DNS 隧道分块重组", log)
        self.assertIn("ICMP 隧道分块重组", log)
        self.assertIn("flag{dns_tunnel}", log)
        self.assertIn("flag{icmp_payload}", log)
        artifacts = payload.get("artifacts") or []
        names = [item["name"] for item in artifacts]
        self.assertTrue(any(name.startswith("dns_tunnel") for name in names),
                        names)
        self.assertTrue(any(name.startswith("icmp_tunnel") for name in names),
                        names)

    def test_smtp_attachment_recovery(self):
        job = self.analyze(str(DATA / "ftp_smtp_telnet.pcap"),
                           ["flows.smtp"])
        status, payload = self.json_request(f"/api/jobs/{job['id']}?cursor=0")
        log = "\n".join(item["text"] for item in payload["logs"])
        self.assertTrue("SMTP" in log or "邮件" in log, log[-2000:])

    def test_mysql_session_summary(self):
        job = self.analyze(str(DATA / "protocol_deep.pcap"),
                           ["flows.mysql"])
        self.assertEqual(job["status"], "done")

    def test_kerberos_and_wifi_handlers_complete(self):
        job = self.analyze(str(DATA / "wifi_eapol.pcap"),
                           ["checkBox_18", "checkBox_45"])
        self.assertEqual(job["status"], "done")
        status, payload = self.json_request(f"/api/jobs/{job['id']}?cursor=0")
        log = "\n".join(item["text"] for item in payload["logs"])
        self.assertIn("完成", log)

    # -- English metadata -------------------------------------------------
    def test_feature_metadata_is_bilingual(self):
        status, meta = self.json_request("/api/meta")
        self.assertEqual(status, 200)
        self.assertTrue(all(item["title_en"] for item in meta["features"]))
        self.assertTrue(all(item["description_en"] for item in meta["features"]))
        self.assertTrue(all(item["name_en"] for item in meta["categories"]))
        self.assertIn(meta["language"], ("zh", "en"))


@unittest.skipUnless(TSHARK, "需要 tshark")
class CliRoadmapTest(unittest.TestCase):
    """Run the real CLI in a subprocess so ``--json``/``--compare`` are covered."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.env = dict(os.environ)
        self.env["FNET_HOME"] = str(self.home)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args, timeout=180):
        process = subprocess.run(
            [sys.executable, "-m", "fnet", *args],
            cwd=str(ROOT), env=self.env, capture_output=True, text=True,
            timeout=timeout)
        return process

    def test_json_output(self):
        process = self.run_cli(
            "-C", str(DATA / "http_ntlm.pcap"),
            "--features", "checkBox_10", "--json")
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])
        payload = json.loads(process.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["job"]["status"], "done")
        self.assertGreater(payload["count"], 0)
        self.assertTrue(payload["findings"])
        self.assertIn("artifacts", payload)

    def test_compare_json(self):
        first = self.run_cli("-C", str(DATA / "http_ntlm.pcap"),
                             "--features", "checkBox_39", "--json")
        second = self.run_cli("-C", str(DATA / "http_ntlm.pcap"),
                              "--features", "checkBox_30", "--json")
        self.assertEqual(first.returncode, 0, first.stderr[-2000:])
        self.assertEqual(second.returncode, 0, second.stderr[-2000:])
        base = json.loads(first.stdout)["job"]["id"]
        target = json.loads(second.stdout)["job"]["id"]
        process = self.run_cli("--compare", base, target, "--json")
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])
        payload = json.loads(process.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["base"], base)
        self.assertEqual(payload["target"], target)
        self.assertIn("counts", payload)

    def test_rule_file_param(self):
        rule_path = self.home / "rules.txt"
        rule_path.write_text("NTLM\n", encoding="utf-8")
        process = self.run_cli(
            "-C", str(DATA / "http_ntlm.pcap"),
            "--features", "checkBox_10", "--rules", str(rule_path), "--json")
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])
        payload = json.loads(process.stdout)
        rules = [item for item in payload["findings"]
                 if item.get("kind") == "rule"]
        self.assertTrue(rules, payload["findings"][:5])

    def test_shards_preserve_frame_numbers(self):
        one = self.run_cli("-C", str(DATA / "http_ntlm.pcap"),
                           "--features", "checkBox_10", "--json")
        four = self.run_cli("-C", str(DATA / "http_ntlm.pcap"),
                            "--features", "checkBox_10",
                            "--shards", "4", "--json")
        self.assertEqual(one.returncode, 0, one.stderr[-2000:])
        self.assertEqual(four.returncode, 0, four.stderr[-2000:])
        single = json.loads(one.stdout)
        shared = json.loads(four.stdout)
        self.assertEqual(shared["job"]["shards"], 4)
        self.assertEqual(shared["job"]["status"], "done")
        self.assertEqual(shared["count"], single["count"])
        frames_one = {item.get("frame") for item in single["findings"]
                      if item.get("frame")}
        frames_four = {item.get("frame") for item in shared["findings"]
                       if item.get("frame")}
        self.assertTrue(frames_one)
        # Frame numbers must be translated back to the original capture.
        self.assertEqual(frames_four, frames_one)

    def test_resume_cli_after_pause(self):
        script = (
            "import os, time\n"
            "from pathlib import Path\n"
            "from fnet.app import build\n"
            "from fnet.config import Config\n"
            "rt = build(Config(Path(os.environ['FNET_HOME']) / 'config.ini'))\n"
            "job = rt.jobs.create(\n"
            "    str(Path('tests/data/http_ntlm.pcap').resolve()),\n"
            "    ['checkBox_10'], {})\n"
            "job.pause_event.set()\n"
            "rt.jobs.start(job)\n"
            "deadline = time.time() + 60\n"
            "while time.time() < deadline and job.status not in (\n"
            "        'paused', 'done', 'error', 'cancelled'):\n"
            "    time.sleep(0.05)\n"
            "assert job.status == 'paused', job.status\n"
            "print(job.id)\n"
        )
        created = subprocess.run(
            [sys.executable, "-c", script], cwd=str(ROOT), env=self.env,
            capture_output=True, text=True, timeout=180)
        self.assertEqual(created.returncode, 0, created.stderr[-2000:])
        job_id = created.stdout.strip().splitlines()[-1]
        process = self.run_cli("--resume", job_id, "--json")
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])
        payload = json.loads(process.stdout)
        self.assertEqual(payload["job"]["status"], "done")
        self.assertEqual(payload["job"]["completed"], ["checkBox_10"])
        self.assertEqual(payload["job"]["progress"], 100)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
