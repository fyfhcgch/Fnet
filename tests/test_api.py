"""HTTP API smoke tests (no browser, real tshark job)."""
from __future__ import annotations

import http.client
import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.crack import CrackTask
from fnet.jobs import JobManager
from fnet.ntlmcrack_service import NtlmCrackTask
from fnet.webui.server import SMB_HINT_FIELDS, empty_smb_hints, make_server

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

    def run_job(self, pcap: str, features: list[str]) -> str:
        """Submit a job through the shared app and wait until it is done."""
        job = self.runtime.jobs.submit(pcap, features, {})
        deadline = time.time() + 120
        state = None
        while time.time() < deadline:
            status, payload = self.json_request(f"/api/jobs/{job.id}?cursor=0")
            state = payload["job"]
            if state["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(0.1)
        self.assertEqual(state["status"], "done", state and state["error"])
        return job.id

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
        self.assertEqual(len(meta["features"]), 54)
        self.assertEqual(len(meta["categories"]), 14)
        self.assertEqual(meta["initial"], {"pcap": "", "features": []})
        self.assertIn("tshark", meta["tools"])
        self.assertIn("report", meta)
        self.assertEqual([item["key"] for item in meta["report"]["sections"]],
                         ["summary", "features", "findings", "timeline",
                          "iocs", "attack", "log", "artifacts", "params"])
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

    def test_smb_decrypt_route(self):
        status, meta = self.json_request("/api/meta")
        self.assertEqual(status, 200)
        self.assertIn("smb", meta)
        self.assertIn("available", meta["smb"])

        status, payload = self.json_request("/api/smb/decrypt",
                                            {"job": "0123456789abcdef"})
        self.assertEqual(status, 404)
        self.assertFalse(payload["ok"])

        job = self.runtime.jobs.submit(str(DATA / "smb2_deep.pcap"),
                                       ["checkBox_49"], {})
        deadline = time.time() + 120
        state = None
        while time.time() < deadline:
            status, body = self.json_request(f"/api/jobs/{job.id}?cursor=0")
            state = body["job"]
            if state["status"] in ("done", "error", "cancelled"):
                break
            time.sleep(0.1)
        self.assertEqual(state["status"], "done", state["error"])

        status, payload = self.json_request("/api/smb/decrypt", {
            "job": job.id, "password": "wrong", "nt_hash": "", "stream": "0"})
        self.assertEqual(status, 200)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["error"])
        self.assertEqual(payload["decrypted"], 0)

    def test_smb_hints_route(self):
        """GET /api/smb/hints answers with hints/sources/accounts/notes."""
        job_id = self.run_job(str(DATA / "smb2_deep.pcap"), ["checkBox_49"])

        status, meta = self.json_request("/api/meta")
        self.assertEqual(status, 200)
        self.assertIn("available", meta["smb"])
        self.assertTrue(meta["smb"]["hints"])

        status, payload = self.json_request(
            f"/api/smb/hints?job={job_id}&stream=2")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["job"], job_id)
        self.assertEqual(payload["stream"], "2")
        for key in ("hints", "sources", "accounts", "notes", "cracked"):
            self.assertIn(key, payload)
        self.assertEqual(sorted(payload["hints"]), sorted(SMB_HINT_FIELDS))
        self.assertEqual(sorted(payload["sources"]), sorted(SMB_HINT_FIELDS))
        self.assertTrue(all(isinstance(value, str)
                            for value in payload["hints"].values()))
        self.assertTrue(all(isinstance(value, str)
                            for value in payload["sources"].values()))
        self.assertIsInstance(payload["accounts"], list)
        self.assertIsInstance(payload["notes"], list)
        self.assertIsInstance(payload["cracked"], list)

        # The route sits behind the shared /api/ token check.
        status, _ = self.request(f"/api/smb/hints?job={job_id}", token=False)
        self.assertEqual(status, 403)

        status, payload = self.json_request("/api/smb/hints")
        self.assertEqual(status, 400)
        self.assertIn("任务", payload["error"])

        status, payload = self.json_request(
            "/api/smb/hints?job=0123456789abcdef")
        self.assertEqual(status, 404)
        self.assertIn("任务不存在", payload["error"])

    def test_smb_hints_lists_cracked_passwords(self):
        """Cracked hashcat/NTLM tasks of the job are reported as plaintexts."""
        job_id = self.run_job(str(DATA / "smb2_deep.pcap"), ["checkBox_49"])
        hashcat = CrackTask(id="apicrack", job=job_id, seq=1, mode=5600,
                            hash_line="winuser::LAB:4078a5505a450ffd:"
                                      "fcb9156af9c94cf4c46d9110d09275b1:"
                                      "0101000000000000",
                            status="cracked", password="Passw0rd!")
        running = CrackTask(id="apirun", job=job_id, seq=9, mode=5600,
                            hash_line="guest::LAB:4078a5505a450ffd:"
                                      "fcb9156af9c94cf4c46d9110d09275b1:"
                                      "0101000000000000",
                            status="running", password="still guessing")
        local = NtlmCrackTask(id="apintlm", job=job_id, seq=2, user="svc",
                              domain="CORP", challenge="4078a5505a450ffd",
                              nt_response="ab" * 33, status="cracked",
                              password="P@ssw0rd")
        managers = ((hashcat, self.runtime.app.crack),
                    (running, self.runtime.app.crack),
                    (local, self.runtime.app.ntlmcrack))
        for task, manager in managers:
            with manager._lock:
                manager._tasks[task.id] = task
        try:
            status, payload = self.json_request(f"/api/smb/hints?job={job_id}")
            self.assertEqual(status, 200)
            entries = {item["source"]: item for item in payload["cracked"]}
            self.assertNotIn("still guessing",
                             [item["password"] for item in payload["cracked"]])
            self.assertEqual(sorted(item["seq"] for item in payload["cracked"]),
                             [1, 2])
            self.assertEqual(entries["hashcat -m 5600"]["password"],
                             "Passw0rd!")
            self.assertEqual(entries["hashcat -m 5600"]["user"], "winuser")
            self.assertEqual(entries["hashcat -m 5600"]["domain"], "LAB")
            self.assertEqual(entries["本地 NTLM 破解"]["password"], "P@ssw0rd")
            self.assertEqual(entries["本地 NTLM 破解"]["user"], "svc")
            self.assertEqual(entries["本地 NTLM 破解"]["domain"], "CORP")
            self.assertEqual(entries["本地 NTLM 破解"]["mode"], 5600)
            # ``stream`` mirrors the originating finding's ``extra.stream``.
            _, findings = self.json_request(
                f"/api/findings?job={job_id}&limit=1000000")
            streams = {}
            for item in findings["findings"]:
                extra = item.get("extra") or {}
                if isinstance(extra, dict) and extra.get("stream"):
                    streams[item["seq"]] = str(extra["stream"])
            for item in payload["cracked"]:
                self.assertEqual(item["stream"],
                                 streams.get(item["seq"], ""))
        finally:
            for _, manager in managers:
                with manager._lock:
                    for task_id in ("apicrack", "apirun", "apintlm"):
                        manager._tasks.pop(task_id, None)

    def test_smb_decrypt_without_any_secret_is_a_clean_error(self):
        """An empty decrypt request never crashes: it is a 4xx JSON error."""
        job_id = self.run_job(str(DATA / "smb2_deep.pcap"), ["checkBox_49"])
        status, payload = self.json_request("/api/smb/decrypt", {"job": job_id})
        self.assertIn(status, (200, 400))
        self.assertIsInstance(payload["ok"], bool)
        if not payload["ok"]:
            self.assertTrue(payload["error"])

        # With no clue to fall back on the message names the missing secret.
        with mock.patch("fnet.webui.server.smb_hints_payload",
                        return_value=empty_smb_hints()):
            status, payload = self.json_request("/api/smb/decrypt",
                                                {"job": job_id})
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertIn("缺少 NT 哈希、密码或会话密钥", payload["error"])

    def test_smb_decrypt_autofills_hints_when_blank(self):
        """A known plaintext is used (and logged) instead of asking the user."""
        job_id = self.run_job(str(DATA / "smb2_deep.pcap"), ["checkBox_49"])
        payload = empty_smb_hints()
        payload["hints"]["password"] = "Passw0rd!"
        payload["sources"]["password"] = "hashcat -m 5600"
        payload["hints"]["user"] = "winuser"
        payload["sources"]["user"] = "SMB NTLM 认证"
        with mock.patch("fnet.webui.server.smb_hints_payload",
                        return_value=payload):
            status, body = self.json_request("/api/smb/decrypt", {"job": job_id})
        self.assertEqual(status, 200)
        self.assertIsInstance(body["ok"], bool)
        self.assertIn("keys", body)
        self.assertIsInstance(body["keys"], list)
        self.assertIn("已自动填入：明文密码 来自 hashcat -m 5600", body["log"])
        self.assertIn("已自动填入：账号 来自 SMB NTLM 认证", body["log"])

        # A supplied secret keeps the old behaviour: hints are not consulted.
        with mock.patch("fnet.webui.server.smb_hints_payload") as probe:
            status, body = self.json_request("/api/smb/decrypt", {
                "job": job_id, "password": "wrong", "stream": "0"})
        probe.assert_not_called()
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])
        self.assertEqual(body["decrypted"], 0)
        self.assertIn("keys", body)

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
        # 分析结果文件不进产出列表：findings 在"分析结果"页查看。
        self.assertNotIn("findings.json", names)
        self.assertNotIn("findings.csv", names)
        self.assertNotIn("annotations.json", names)
        # Reports are exported from the result view, not listed as artifacts.
        self.assertNotIn("report.txt", names)
        self.assertNotIn("report.md", names)
        self.assertNotIn("report.html", names)

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
        self.assertIn("类别,级别,帧,时间,功能,摘要,详情".encode(), content)
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
        # 打包 ZIP 同样跳过分析结果文件，交付物保留。
        packed = set(zipfile.ZipFile(io.BytesIO(bundle)).namelist())
        self.assertIn("ntlm_hashes.txt", packed)
        self.assertNotIn("findings.json", packed)
        self.assertNotIn("findings.csv", packed)

    def test_history_artifacts_hide_analysis_files(self):
        """构造含分析结果文件与假交付物的任务目录，产出列表只留交付物。"""
        job_id = "abc12345"
        output = self.cache / "jobs" / job_id
        output.mkdir(parents=True, exist_ok=True)
        (output / "job.json").write_text(
            json.dumps({"id": job_id, "status": "done"}), encoding="utf-8")
        for name in ("findings.json", "findings.csv", "annotations.json",
                     "log_fields.csv", "log_entities.csv"):
            (output / name).write_text("analysis", encoding="utf-8")
        (output / "restored_admin.aspx").write_text("payload", encoding="utf-8")

        status, payload = self.json_request(f"/api/history/{job_id}")
        self.assertEqual(status, 200)
        names = {item["name"] for item in payload["artifacts"]}
        self.assertEqual(names, {"restored_admin.aspx"})

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

    def test_stats_action_routes_log_inputs(self):
        """A text-log input answers the same stats subs with kind="log"."""
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.log"
            log.write_text("\n".join(
                json.dumps({"time": f"2026-01-02T00:00:{index:02d}",
                            "level": "info",
                            "client_ip": f"10.0.0.{index % 2}",
                            "server": "web01", "message": f"hit {index}"})
                for index in range(6)) + "\n")
            common = {"action": "stats", "pcap": str(log)}
            status, timeline = self.json_request("/api/action", {
                **common, "sub": "timeline", "buckets": 10})
            self.assertEqual(status, 200)
            self.assertTrue(timeline["ok"])
            self.assertEqual(timeline["kind"], "log")
            self.assertEqual(timeline["total_frames"], 6)

            status, hierarchy = self.json_request("/api/action", {
                **common, "sub": "hierarchy"})
            self.assertTrue(hierarchy["ok"])
            self.assertEqual(hierarchy["kind"], "log")
            self.assertEqual(
                {item["label"] for item in hierarchy["items"]}, {"info"})

            status, entities = self.json_request("/api/action", {
                **common, "sub": "ip"})
            self.assertTrue(entities["ok"])
            self.assertEqual(entities["kind"], "log")
            self.assertEqual({item["label"] for item in entities["items"]},
                             {"10.0.0.0", "10.0.0.1"})

            status, topology = self.json_request("/api/action", {
                **common, "sub": "topology"})
            self.assertTrue(topology["ok"])
            self.assertEqual(topology["kind"], "log")
            self.assertTrue(topology["nodes"])

            status, unsupported = self.json_request("/api/action", {
                **common, "sub": "ports"})
            self.assertEqual(status, 200)
            self.assertFalse(unsupported["ok"])
            self.assertIn("日志任务", unsupported["text"])

    def test_stats_entities_action_for_log_inputs(self):
        """sub:"entities" routes to the log stats API with graceful errors."""
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.log"
            log.write_text("\n".join(
                json.dumps({"time": f"2026-01-02T00:00:{index:02d}",
                            "level": "info",
                            "client_id": f"user{index % 2}",
                            "client_ip": f"10.0.0.{index % 2}",
                            "message": "ok" if index % 3 else "failed"})
                for index in range(6)) + "\n")
            common = {"action": "stats", "pcap": str(log)}

            status, entities = self.json_request("/api/action", {
                **common, "sub": "entities", "dimension": "client_id"})
            self.assertEqual(status, 200)
            self.assertTrue(entities["ok"])
            self.assertEqual(entities["kind"], "log")
            self.assertEqual(entities["dimension"], "client_id")
            self.assertIn("client_id", entities["dimensions"])
            self.assertIn("网段", entities["dimensions"])
            self.assertEqual(len(entities["items"]), 2)
            item = entities["items"][0]
            for key in ("value", "count", "share", "fail", "fail_rate",
                        "success", "success_rate", "first", "last",
                        "line", "sample"):
                self.assertIn(key, item)
            # "ok"×4 / "failed"×2 的默认失败口径。
            self.assertEqual(
                sum(entry["fail"] for entry in entities["items"]), 2)

            status, bad = self.json_request("/api/action", {
                **common, "sub": "entities", "dimension": "nope"})
            self.assertEqual(status, 200)
            self.assertFalse(bad["ok"])
            self.assertEqual(bad["kind"], "log")
            self.assertIn("可用维度", bad["text"])
            self.assertIn("client_id", bad["dimensions"])

            status, fallback = self.json_request("/api/action", {
                **common, "sub": "entities", "dimension": "client_id",
                "subnet_prefix": 40, "success_regex": "("})
            self.assertEqual(status, 200)
            self.assertTrue(fallback["ok"])
            self.assertIn("success_regex 无效", fallback["text"])
            self.assertIn("subnet_prefix 超出范围", fallback["text"])
            self.assertEqual(fallback["subnet_prefix"], 24)

            status, missing = self.json_request("/api/action", {
                **common, "sub": "entities", "dimension": "client_id",
                "pcap": str(Path(tmp) / "nope.log")})
            self.assertEqual(status, 200)
            self.assertFalse(missing["ok"])
            self.assertTrue(missing["text"])

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

    def test_bodyless_post_keeps_keepalive_clean(self):
        """A POST answered without reading its body must not poison the next request.

        ``protocol_version`` is HTTP/1.1, so the WebUI reuses one connection for
        ``POST /api/history/<id>/delete`` (body ``{}``) followed by
        ``GET /api/history``.  The unread ``{}`` used to be parsed as the next
        request line (``{}GET /api/history``), which the server answered 501.
        """
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=30)
        try:
            connection.request(
                "POST", "/api/history/0123456789abcdef/delete", body=b"{}",
                headers={"X-Fnet-Token": self.token,
                         "Content-Type": "application/json"})
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 200)

            connection.request("GET", "/api/history",
                               headers={"X-Fnet-Token": self.token})
            response = connection.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200, body)
            self.assertTrue(json.loads(body)["ok"])
        finally:
            connection.close()

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
