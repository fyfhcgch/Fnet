"""Tests for the local NetNTLMv2 cracking backend (``fnet.ntlmcrack_service``)."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.ntlmcrack_service import (
    NtlmCrackManager,
    _is_ntlmv1,
    _parse_target,
)
from fnet.utils.crypto import hmac_md5, md4

USER, DOMAIN, PASSWORD = "bob", "CORP", "ab12"
CHALLENGE = bytes.fromhex("0011223344556677")
BLOB = bytes(16) + bytes.fromhex("aabbccddeeff0011")


def _hash_line(password: str = PASSWORD) -> str:
    """按协议构造一条真实的 NetNTLMv2 hashcat -m 5600 哈希行。"""
    nt_hash = md4(password.encode("utf-16le"))
    response_key = hmac_md5(
        nt_hash, USER.upper().encode("utf-16le")
        + DOMAIN.upper().encode("utf-16le"))
    proof = hmac_md5(response_key, CHALLENGE + BLOB)
    return (f"{USER}::{DOMAIN}:{CHALLENGE.hex()}:{proof.hex()}:"
            f"{BLOB.hex()}")


class FakeJobs:
    """Minimal JobManager stand-in for the NtlmCrackManager tests."""

    def __init__(self, findings: list[dict]) -> None:
        self.findings = findings

    def findings_for(self, job_id, query="", kind="", level="", limit=5000):
        if job_id != "abc123":
            return None
        items = [dict(item, seq=index, id=f"f{index:05d}")
                 for index, item in enumerate(self.findings, 1)]
        return {"findings": items, "total": len(items)}


def wait_for(task, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while not task.finished and time.time() < deadline:
        time.sleep(0.02)


class ParseTargetTest(unittest.TestCase):
    def test_parses_hashcat_line(self):
        line = _hash_line()
        finding = {"summary": f"{DOMAIN}\\{USER} NetNTLMv2",
                   "extra": {"protocol": "ntlm", "hash": line,
                             "mode": "5600"}}
        target = _parse_target(finding)
        self.assertEqual(target["user"], USER)
        self.assertEqual(target["domain"], DOMAIN)
        self.assertEqual(target["challenge"], CHALLENGE.hex())
        self.assertTrue(target["nt_response"].startswith(
            line.split(":")[4]))
        self.assertFalse(_is_ntlmv1(finding))

    def test_parses_structured_extra(self):
        finding = {"summary": "x",
                   "extra": {"protocol": "ntlm", "user": "alice",
                             "domain": "LAB",
                             "challenge": "0123456789abcdef",
                             "ntproofstr": "aa" * 16, "blob": "bb" * 12}}
        target = _parse_target(finding)
        self.assertEqual(target["user"], "alice")
        self.assertEqual(target["nt_response"], "aa" * 16 + "bb" * 12)

    def test_user_falls_back_to_account(self):
        finding = {"summary": "x",
                   "extra": {"protocol": "smb2", "account": "LAB\\carol",
                             "challenge": "0123456789abcdef",
                             "nt_response": "cd" * 26}}
        self.assertEqual(_parse_target(finding)["user"], "carol")

    def test_non_ntlm_findings_are_rejected(self):
        self.assertIsNone(_parse_target({"summary": "flag{test}"}))
        self.assertIsNone(_parse_target(
            {"summary": "x", "extra": {"hash": ""}}))
        self.assertIsNone(_parse_target(
            {"summary": "x", "extra": {"protocol": "ntlm",
                                       "user": "u"}}))

    def test_ntlmv1_is_detected_and_rejected(self):
        finding = {"summary": "u NetNTLMv1",
                   "extra": {"protocol": "ntlm",
                             "hash": "u::DOM:aabbccddeeff0011:"
                                     "1122334455667788445566778899aabb:"
                                     "4078a5505a450ffd"}}
        self.assertTrue(_is_ntlmv1(finding))
        self.assertIsNone(_parse_target(finding))

    def test_normalize_candidates(self):
        normalize = NtlmCrackManager._normalize_candidates
        self.assertEqual(normalize(None), [])
        self.assertEqual(normalize("a, b;;c\n d"), ["a", "b", "c", "d"])
        self.assertEqual(normalize(["x", "x", " y "]), ["x", "y"])
        with self.assertRaises(ValueError):
            normalize(123)


class NtlmCrackManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Config(Path(self.tmp.name) / "config.ini")
        self.findings = [
            {"kind": "hash", "level": "good",
             "summary": f"{DOMAIN}\\{USER} NetNTLMv2",
             "detail": _hash_line(),
             "extra": {"protocol": "ntlm", "hash": _hash_line(),
                       "mode": "5600"}},
            {"kind": "flag", "level": "good", "summary": "flag{test}",
             "extra": {}},
        ]
        self.jobs = FakeJobs(self.findings)
        self.manager = NtlmCrackManager(self.jobs, object(), self.config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bruteforce_cracks_short_password(self):
        task = self.manager.start("abc123", 1, min_len=1, max_len=4,
                                  alphabet="ab12", timeout=60)
        self.assertEqual(task.engine, "bruteforce")
        wait_for(task)
        self.assertEqual(task.status, "cracked")
        self.assertEqual(task.password, PASSWORD)
        self.assertGreaterEqual(task.attempts, 1)
        self.assertIn("已破解", task.log)

    def test_candidates_engine_hits_by_finding_id(self):
        task = self.manager.start("abc123", "f00001",
                                  candidates="aaa, ab12, zzz", timeout=60)
        self.assertEqual(task.engine, "candidates")
        wait_for(task)
        self.assertEqual(task.status, "cracked")
        self.assertEqual(task.password, PASSWORD)
        self.assertEqual(task.attempts, 2)

    def test_exhausted_candidates(self):
        task = self.manager.start("abc123", 1,
                                  candidates="aaa,bbb,zzz", timeout=60)
        wait_for(task)
        self.assertEqual(task.status, "exhausted")
        self.assertEqual(task.password, "")
        self.assertEqual(task.attempts, 3)
        self.assertIn("未命中", task.log)

    def test_max_attempts_cap_is_respected(self):
        task = self.manager.start("abc123", 1, min_len=1, max_len=2,
                                  alphabet="abcdefghijklmnopqrstuvwxyz",
                                  max_attempts=5, timeout=60)
        wait_for(task)
        self.assertEqual(task.status, "exhausted")
        self.assertEqual(task.attempts, 5)

    def test_cancel_stops_without_crashing(self):
        task = self.manager.start("abc123", 1, min_len=1, max_len=8,
                                  alphabet="abcdefghijklmnopqrstuvwxyz"
                                           "0123456789", timeout=300)
        time.sleep(0.1)
        self.assertTrue(self.manager.cancel(task.id))
        wait_for(task)
        self.assertEqual(task.status, "cancelled")
        self.assertEqual(task.password, "")
        # 取消已结束的任务再次返回 False，不抛异常
        self.assertFalse(self.manager.cancel(task.id))
        self.assertIsNone(self.manager.get("nope"))

    def test_timeout_reports_error(self):
        task = self.manager.start("abc123", 1, min_len=1, max_len=10,
                                  alphabet="abcdefghijklmnopqrstuvwxyz"
                                           "0123456789"
                                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                                  timeout=1)
        wait_for(task)
        self.assertEqual(task.status, "error")
        self.assertIn("超过", task.error)

    def test_start_rejects_bad_targets_with_clear_errors(self):
        # 未知任务
        with self.assertRaises(ValueError) as ctx:
            self.manager.start("deadbeef", 1)
        self.assertIn("任务不存在", str(ctx.exception))
        # 结果里没有 NTLM 目标
        with self.assertRaises(ValueError) as ctx:
            self.manager.start("abc123", 2)
        self.assertIn("NetNTLMv2", str(ctx.exception))
        # 序号不存在
        with self.assertRaises(ValueError) as ctx:
            self.manager.start("abc123", 99)
        self.assertIn("找不到该分析结果", str(ctx.exception))
        # 缺少任务 ID
        with self.assertRaises(ValueError) as ctx:
            self.manager.start("", 1)
        self.assertIn("任务 ID", str(ctx.exception))

    def test_start_rejects_ntlmv1_with_hashcat_hint(self):
        self.jobs.findings.append(
            {"kind": "hash", "summary": "u NetNTLMv1",
             "extra": {"protocol": "ntlm", "hash": "u::DOM:aabbccddeeff0011:"
                                               "1122334455667788445566778"
                                               "899aabb:4078a5505a450ffd",
                       "mode": "5500"}})
        with self.assertRaises(ValueError) as ctx:
            self.manager.start("abc123", 3)
        self.assertIn("NetNTLMv1", str(ctx.exception))
        self.assertIn("hashcat", str(ctx.exception))

    def test_start_rejects_bad_candidates(self):
        with self.assertRaises(ValueError):
            self.manager.start("abc123", 1, candidates=123)

    def test_as_dict_exposes_polling_fields(self):
        task = self.manager.start("abc123", 1, candidates="aaa",
                                  max_attempts=10, timeout=30,
                                  alphabet="abc", min_len=1, max_len=2)
        data = task.as_dict()
        for key in ("id", "job", "seq", "status", "finished", "elapsed",
                    "timeout", "password", "error", "log", "user", "domain",
                    "challenge", "nt_response", "engine", "attempts",
                    "max_attempts", "alphabet", "min_len", "max_len"):
            self.assertIn(key, data)
        self.assertEqual(data["user"], USER)
        self.assertEqual(data["challenge"], CHALLENGE.hex())
        wait_for(task)
        self.assertTrue(task.as_dict()["finished"])


if __name__ == "__main__":
    unittest.main()
