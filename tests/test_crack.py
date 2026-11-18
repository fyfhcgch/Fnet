"""Tests for the one-click hashcat cracking backend (``fnet.crack``)."""
from __future__ import annotations

import json
import stat
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
from fnet.crack import (CrackManager, CrackTask, crack_target,
                       identity_from_hash_line, mode_label)
from fnet.webui.server import make_server

NTLMV2 = ("winuser::LAB:4078a5505a450ffd:"
          "fcb9156af9c94cf4c46d9110d09275b1:"
          "01010000000000007d6fffd5bd5add01b11f2ed8cc4eaeaa00000000020006"
          "004c004100420001001000500043002d00570049004e0031003100000000")

NTLMV1 = ("svc::CORP:1122334455667788:"
          "aabbccddeeff00112233445566778899aabbccddeeff00:"
          "4078a5505a450ffd")

FAKE_HASHCAT = """#!/usr/bin/env python3
import os, sys, time
args = sys.argv[1:]
here = os.path.dirname(os.path.abspath(__file__))
values = ["cracked", "0.2"]
try:
    values = open(os.path.join(here, "mode.txt"), encoding="utf-8").read().split()
except OSError:
    pass
result = values[0] if values else "cracked"
sleep = float(values[1]) if len(values) > 1 else 0.2
if "--show" in args:
    if result == "cracked":
        hashes = [a for a in args if a.endswith(".txt")]
        line = open(hashes[0], encoding="utf-8").read().strip()
        user, rest = line.split("::", 1)
        print(f"{user.upper()}::{rest}:secret123")
    sys.exit(0)
print("Session..........: fake")
print("Status...........: Running")
sys.stdout.flush()
time.sleep(sleep)
if result in ("exhausted", "slow"):
    print("Status...........: Exhausted")
    sys.exit(1)
if result == "error":
    print("No hashes loaded.")
    sys.exit(244)
print("Status...........: Cracked")
sys.exit(0)
"""


class FakeJobs:
    """Minimal JobManager stand-in used by the CrackManager tests."""

    def __init__(self, output: Path, findings: list[dict]) -> None:
        self.output = output
        self.findings = findings

    def findings_for(self, job_id, query="", kind="", level="", limit=5000):
        if job_id != "abc123":
            return None
        return {"findings": self.findings, "total": len(self.findings)}

    def output_dir_for(self, job_id):
        return self.output if job_id == "abc123" else None


class FakeToolbox:
    def __init__(self, path: str) -> None:
        self.hashcat = path

    def path(self, key):
        return self.hashcat if key == "hashcat" else None


def wait_for(task, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while not task.finished and time.time() < deadline:
        time.sleep(0.05)


class CrackTargetTest(unittest.TestCase):
    def test_uses_explicit_mode(self):
        finding = {"summary": "x", "extra": {"hash": NTLMV2, "mode": "5600"}}
        self.assertEqual(crack_target(finding), (5600, NTLMV2))

    def test_legacy_ntlmv2_inferred_from_summary(self):
        finding = {"summary": "LAB\\winuser NetNTLMv2",
                   "extra": {"protocol": "ntlm", "hash": NTLMV2}}
        self.assertEqual(crack_target(finding)[0], 5600)

    def test_legacy_ntlmv1_inferred_from_summary(self):
        finding = {"summary": "LAB\\winuser NetNTLMv1",
                   "extra": {"protocol": "ntlm", "hash": NTLMV2}}
        self.assertEqual(crack_target(finding)[0], 5500)

    def test_wifi_and_kerberos_fallbacks(self):
        wifi = {"summary": "WPA", "extra": {"protocol": "wifi",
                                            "hash": "WPA*01*aa"}}
        self.assertEqual(crack_target(wifi), (22000, "WPA*01*aa"))
        kerb = {"summary": "user AS-REP (hashcat -m 18200)",
                "extra": {"protocol": "kerberos", "hash": "$krb5asrep$..."}}
        self.assertEqual(crack_target(kerb), (18200, "$krb5asrep$..."))

    def test_non_hash_findings_are_rejected(self):
        self.assertIsNone(crack_target({"summary": "flag{test}"}))
        self.assertIsNone(crack_target({"summary": "x", "extra": {"hash": ""}}))

    def test_mode_label(self):
        self.assertEqual(mode_label(5600), "NetNTLMv2")
        self.assertIn("5601", mode_label(5601))


class IdentityFromHashLineTest(unittest.TestCase):
    """``identity_from_hash_line`` feeds the SMB3 auto-fill hints."""

    def test_netntlmv2_line(self):
        self.assertEqual(identity_from_hash_line(NTLMV2), ("winuser", "LAB"))

    def test_netntlmv1_line(self):
        self.assertEqual(identity_from_hash_line(NTLMV1), ("svc", "CORP"))

    def test_empty_user_and_domain(self):
        self.assertEqual(identity_from_hash_line("::LAB:aa:bb:cc"), ("", "LAB"))
        self.assertEqual(identity_from_hash_line("admin::::aa:bb"),
                         ("admin", ""))

    def test_blob_colons_are_ignored(self):
        # Only the first three colon-separated fields are read, so the
        # NetNTLMv2 client blob (full of colons) cannot leak into the domain.
        line = "user::DOM:challenge:" + "aa" * 16 + ":" + "bb" * 8 + ":cc"
        self.assertEqual(identity_from_hash_line(line), ("user", "DOM"))

    def test_surrounding_whitespace_is_trimmed(self):
        self.assertEqual(identity_from_hash_line(f"  {NTLMV2} \n"),
                         ("winuser", "LAB"))

    def test_other_formats_and_junk_have_no_identity(self):
        for line in ("", None, "   ", "not a hash",
                     "Administrator:31d6cfe0d16ae931b73c59d7e0c089c0",
                     "$krb5asrep$23-user@LAB:aa", "WPA*01*aa*bb",
                     "$NETNTLM$4078a5505a450ffd$fcb9156a"):
            self.assertEqual(identity_from_hash_line(line), ("", ""), line)

    def test_unexpected_input_never_raises(self):
        for line in (12345, ["unexpected"], {"hash": NTLMV2}, object()):
            identity = identity_from_hash_line(line)
            self.assertIsInstance(identity, tuple)
            self.assertEqual(len(identity), 2)
            self.assertTrue(all(isinstance(part, str) for part in identity))


class CrackManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.output = self.root / "job"
        self.output.mkdir()
        self.wordlist = self.root / "words.txt"
        self.wordlist.write_text("secret123\n", encoding="utf-8")
        self.hashcat = self.root / "hashcat"
        self.hashcat.write_text(FAKE_HASHCAT, encoding="utf-8")
        self.hashcat.chmod(self.hashcat.stat().st_mode | stat.S_IEXEC)
        self.config = Config(self.root / "config.ini")
        self.findings = [{
            "seq": 1, "kind": "hash", "level": "good",
            "summary": "LAB\\winuser NetNTLMv2", "detail": NTLMV2,
            "extra": {"protocol": "ntlm", "hash": NTLMV2},
        }, {
            "seq": 2, "kind": "flag", "level": "good",
            "summary": "flag{test}", "detail": "",
        }]
        self.mode_file = self.root / "mode.txt"
        self.mode_file.write_text("cracked\n", encoding="utf-8")
        self.jobs = FakeJobs(self.output, self.findings)
        self.manager = CrackManager(self.jobs, FakeToolbox(str(self.hashcat)),
                                    self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_start_cracked_streams_log_and_persists_settings(self):
        task = self.manager.start("abc123", 1,
                                  wordlist=str(self.wordlist),
                                  workload=2, optimized=True, force=False,
                                  timeout=60, extra="--username")
        wait_for(task)
        self.assertEqual(task.status, "cracked")
        self.assertEqual(task.password, "secret123")
        self.assertIn("Session", task.log)
        self.assertIn("已破解", task.log)
        self.assertTrue(Path(task.hash_file).is_file())
        self.assertEqual(Path(task.hash_file).read_text(encoding="utf-8").strip(),
                         NTLMV2)
        self.assertIn("--username", task.command)
        self.assertIn("-O", task.command)
        self.assertIn("-w", task.command)
        self.assertEqual(self.config.get("passwddir"), str(self.wordlist))
        self.assertEqual(self.config.get("hashcat_workload"), "2")
        self.assertEqual(self.config.get("hashcat_optimized"), "1")
        self.assertEqual(self.config.get("hashcat_timeout"), "60")
        self.assertEqual(self.config.get("hashcat_extra"), "--username")

    def test_exhausted_wordlist(self):
        self.mode_file.write_text("exhausted\n", encoding="utf-8")
        task = self.manager.start("abc123", 1, wordlist=str(self.wordlist))
        wait_for(task)
        self.assertEqual(task.status, "exhausted")
        self.assertEqual(task.password, "")

    def test_unparsable_hash_is_reported_as_error(self):
        self.mode_file.write_text("error\n", encoding="utf-8")
        task = self.manager.start("abc123", 1, wordlist=str(self.wordlist))
        wait_for(task)
        self.assertEqual(task.status, "error")
        self.assertIn("未加载任何哈希", task.error)

    def test_log_streams_while_the_child_is_running(self):
        self.mode_file.write_text("slow 2\n", encoding="utf-8")
        task = self.manager.start("abc123", 1, wordlist=str(self.wordlist))
        time.sleep(0.8)
        self.assertIn("Session", task.log)
        self.assertFalse(task.finished)
        wait_for(task)
        self.assertEqual(task.status, "exhausted")

    def test_cancel_stops_the_child(self):
        self.mode_file.write_text("cracked 30\n", encoding="utf-8")
        task = self.manager.start("abc123", 1, wordlist=str(self.wordlist))
        time.sleep(0.4)
        self.assertTrue(self.manager.cancel(task.id))
        wait_for(task, timeout=10)
        self.assertEqual(task.status, "cancelled")

    def test_rejects_unknown_job_and_non_hash_finding(self):
        with self.assertRaises(ValueError):
            self.manager.start("deadbeef", 1, wordlist=str(self.wordlist))
        with self.assertRaises(ValueError):
            self.manager.start("abc123", 2, wordlist=str(self.wordlist))
        with self.assertRaises(ValueError):
            self.manager.start("abc123", 99, wordlist=str(self.wordlist))

    def test_rejects_missing_wordlist(self):
        with self.assertRaises(ValueError):
            self.manager.start("abc123", 1, wordlist=str(self.root / "nope.txt"))

    def test_show_ignores_case_of_the_netntlm_username(self):
        task = CrackTask(id="t1", job="abc123", seq=1, mode=5600,
                         hash_line=NTLMV2, hash_file="h.txt",
                         potfile="p.pot", command=[str(self.hashcat)])
        shown = "WINUSER::" + NTLMV2.split("::", 1)[1] + ":Password123!\n"
        with mock.patch("fnet.crack.run", return_value=(0, shown)):
            self.assertEqual(self.manager._show(task), "Password123!")


class BrokenJobs:
    """A jobs stand-in whose findings lookup always fails."""

    def findings_for(self, job_id, query="", kind="", level="", limit=5000):
        raise RuntimeError("没有 findings.json")


class CrackPasswordsForTest(unittest.TestCase):
    """``CrackManager.passwords_for`` exposes cracked plaintexts per job."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.output = self.root / "job"
        self.output.mkdir()
        self.wordlist = self.root / "words.txt"
        self.wordlist.write_text("secret123\n", encoding="utf-8")
        self.hashcat = self.root / "hashcat"
        self.hashcat.write_text(FAKE_HASHCAT, encoding="utf-8")
        self.hashcat.chmod(self.hashcat.stat().st_mode | stat.S_IEXEC)
        self.mode_file = self.root / "mode.txt"
        self.mode_file.write_text("cracked\n", encoding="utf-8")
        self.findings = [{
            "seq": 1, "kind": "hash", "level": "good",
            "summary": "LAB\\winuser NetNTLMv2",
            "extra": {"protocol": "ntlm", "hash": NTLMV2, "stream": "7"},
        }, {
            "seq": 2, "kind": "hash", "level": "good",
            "summary": "CORP\\svc NetNTLMv1",
            "extra": {"protocol": "ntlm", "hash": NTLMV1, "mode": "5500"},
        }]
        self.jobs = FakeJobs(self.output, self.findings)
        self.manager = CrackManager(self.jobs, FakeToolbox(str(self.hashcat)),
                                    Config(self.root / "config.ini"))

    def tearDown(self):
        self.tmp.cleanup()

    def _add(self, task_id, **kwargs):
        """Register a finished task without spawning hashcat."""
        task = CrackTask(
            id=task_id, job=kwargs.pop("job", "abc123"),
            seq=kwargs.pop("seq"), mode=kwargs.pop("mode", 5600),
            hash_line=kwargs.pop("hash_line", NTLMV2), **kwargs)
        with self.manager._lock:
            self.manager._tasks[task_id] = task
        return task

    def test_filters_by_job_and_status(self):
        self._add("t1", seq=2, mode=5500, hash_line=NTLMV1,
                  status="cracked", password="Spring2024")
        self._add("t2", seq=3, status="cracked", password="")
        self._add("t3", seq=4, status="running", password="secret123")
        self._add("t5", seq=5, status="exhausted", password="secret123")
        self._add("t6", seq=6, job="deadbeef", status="cracked",
                  password="otherjob")
        entries = self.manager.passwords_for("abc123")
        self.assertEqual([item["seq"] for item in entries], [2])
        self.assertEqual(entries[0], {
            "user": "svc", "domain": "CORP", "password": "Spring2024",
            "stream": "", "source": "hashcat -m 5500", "mode": 5500, "seq": 2})
        self.assertEqual(self.manager.passwords_for(""), [])
        # Tasks of another job stay out of this job's list (and vice versa).
        self.assertEqual([item["seq"]
                          for item in self.manager.passwords_for("deadbeef")],
                         [6])
        self.assertEqual(self.manager.passwords_for("nope"), [])

    def test_sorted_by_seq_with_stream_from_the_finding(self):
        self._add("a", seq=3, status="cracked", password="c")
        self._add("b", seq=1, status="cracked", password="a")
        self._add("c", seq=2, mode=5500, hash_line=NTLMV1,
                  status="cracked", password="b")
        entries = self.manager.passwords_for("abc123")
        self.assertEqual([item["seq"] for item in entries], [1, 2, 3])
        self.assertEqual([item["stream"] for item in entries], ["7", "", ""])
        self.assertEqual([item["source"] for item in entries],
                         ["hashcat -m 5600", "hashcat -m 5500",
                          "hashcat -m 5600"])
        self.assertTrue(all(isinstance(item["password"], str)
                            for item in entries))

    def test_real_cracked_task_is_reported(self):
        task = self.manager.start("abc123", 1, wordlist=str(self.wordlist))
        wait_for(task)
        self.assertEqual(task.status, "cracked")
        entries = self.manager.passwords_for("abc123")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["password"], "secret123")
        self.assertEqual(entries[0]["user"], "winuser")
        self.assertEqual(entries[0]["domain"], "LAB")
        self.assertEqual(entries[0]["stream"], "7")
        self.assertEqual(entries[0]["source"], "hashcat -m 5600")

    def test_broken_findings_only_cost_the_stream(self):
        self._add("t1", seq=1, status="cracked", password="secret123")
        self.manager.jobs = BrokenJobs()
        entries = self.manager.passwords_for("abc123")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["password"], "secret123")
        self.assertEqual(entries[0]["stream"], "")


class CrackApiTest(unittest.TestCase):
    """The WebUI exposes the persisted knobs and validates bad requests."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cache = Path(cls.tmp.name) / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        cls.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cache),
            mock.patch("fnet.paths.CACHE_DIR", cache),
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

    def request(self, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"X-Fnet-Token": self.token}
        if data:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read().decode())
            finally:
                error.close()

    def test_meta_exposes_crack_settings(self):
        status, meta = self.request("/api/meta")
        self.assertEqual(status, 200)
        crack = meta["crack"]
        self.assertIn("available", crack)
        settings = crack["settings"]
        for key in ("wordlist", "workload", "optimized", "force",
                    "timeout", "extra"):
            self.assertIn(key, settings)
        self.assertEqual(settings["workload"], "3")
        self.assertTrue(settings["optimized"])

    def test_start_requires_job_and_valid_finding(self):
        status, body = self.request("/api/crack", {})
        self.assertEqual(status, 400)
        self.assertIn("任务", body["error"])
        status, body = self.request("/api/crack", {"job": "deadbeef", "seq": 1})
        self.assertEqual(status, 400)
        self.assertIn("任务不存在", body["error"])

    def test_status_and_cancel_unknown_task(self):
        status, body = self.request("/api/crack?id=nope")
        self.assertEqual(status, 404)
        self.assertIn("不存在", body["error"])
        status, body = self.request("/api/crack/cancel", {"id": "nope"})
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])


if __name__ == "__main__":
    unittest.main()
