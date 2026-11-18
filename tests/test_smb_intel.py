"""Unit tests for the SMB3 intelligence pipeline (smb_intel) and password
candidate generation (smb_password).

Offline: no real tshark nor capture is needed. ``smb3.decrypt_capture`` is
monkeypatched so the pipeline's automatic fallback and reporting logic is
exercised with fake results.
"""
from __future__ import annotations

import unittest
from unittest import mock
from pathlib import Path

from fnet.features import smb_intel, smb_password
from fnet.features.common import protocol_streams

# 复用 tests/test_smb_feature.py 里的纯报文构建器（不依赖 tshark）。
from tests.test_smb_feature import (  # noqa: E402
    nbss, negotiate_request, session_setup_challenge,
    session_setup_request, transform_payload,
)


class FakeContext:
    """Minimal ``FeatureContext`` stand-in (report / add_finding / params ...)."""

    def __init__(self, params=None, pcap="fake.pcapng", tshark=None):
        self.params = params or {}
        self.pcap = pcap
        self.tshark = tshark
        self.output_dir = None
        self.cancel = None
        self.progress = None
        self.findings = []
        self.reports = []

    def report(self, text, level="info"):
        self.reports.append((text, level))

    def add_finding(self, kind, summary, *, frame="", detail="", level="info",
                    extra=None):
        item = {"kind": kind, "summary": summary, "frame": frame,
                "detail": detail, "level": level, "extra": extra or {}}
        self.findings.append(item)
        return item

    def set_progress(self, value):
        self.progress = value

    def check_cancel(self):
        return None

    def cancelled(self):
        return False

    def write_output(self, name, data):
        return Path("/tmp") / name


class _WriteRecordingContext(FakeContext):
    """FakeContext 的变体：记录每次 write_output 的调用，用于断言工件。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.writes: list[tuple[str, object]] = []

    def write_output(self, name, data):
        self.writes.append((name, data))
        return Path("/tmp") / name


# A couple of reassembled stream objects so protocol_streams' output shape
# matches (stream.stream / direction / data / frame_at).
class FakeStream:
    def __init__(self, stream, data, direction="a", src="10.0.0.1",
                 sport="50000"):
        self.stream = stream
        self.data = data
        self.direction = direction
        self.src = src
        self.sport = sport
        self.gaps = 0

    def frame_at(self, offset):
        return str(offset + 1)


class SmbPasswordTest(unittest.TestCase):
    def test_candidates_include_lower_upper_digit_suffix(self):
        cands = smb_password.password_candidates_for_account(
            {"user": "bob", "domain": "CORP"}, {"base_words": "alice"})
        joined = "\n".join(cands)
        # 基础词大小写形式
        self.assertIn("alice", joined)
        self.assertIn("Alice", joined)
        self.assertIn("ALICE", joined)
        # 数字后缀
        self.assertIn("alice123", joined)
        self.assertIn("alice123456", joined)
        # 符号后缀
        self.assertIn("alice@", joined)
        self.assertIn("Alice!", joined)

    def test_candidates_include_account_derived_words(self):
        cands = smb_password.password_candidates_for_account(
            {"user": "jdoe", "domain": "ACME",
             "share": r"\\server\share", "file": "secret.txt"}, {})
        joined = "\n".join(cands)
        self.assertIn("jdoe123", joined)
        self.assertIn("acme123", joined)
        # 共享名取末段
        self.assertIn("share123", joined)
        # 文件名去路径/扩展名
        self.assertIn("secret123", joined)

    def test_append_digits_false_drops_suffixes(self):
        cands = smb_password.password_candidates_for_account(
            {"user": "bob"}, {"append_digits": False})
        self.assertIn("bob", cands)
        self.assertNotIn("bob123", cands)

    def test_robust_to_send_only_and_empty(self):
        # 只有 direction 方向的流（send-only）应当健壮返回。
        cands = smb_password.password_candidates_for_account({}, {})
        self.assertIsInstance(cands, list)
        cands2 = smb_password.password_candidates_for_account(
            None, None)
        self.assertIsInstance(cands2, list)

    def _smb_password_streams(self):
        nt = b"\xaa" * 16 + b"\xbb" * 32
        client = (nbss(negotiate_request())
                  + nbss(session_setup_request("alice", "CORP", nt))
                  + nbss(transform_payload()))
        server = nbss(session_setup_challenge(bytes.fromhex(
            "1122334455667788")))
        # stream 0 带完整的 NTLM 身份；stream 1 只有协商，没有账号。
        return [FakeStream("0", client, "a"),
                FakeStream("0", server, "b", "10.0.0.10", "445"),
                FakeStream("1", nbss(negotiate_request()), "a")]

    def test_analyze_emits_no_candidate_password_finding(self):
        """候选密码只进日志与 smb_password_candidates.txt 工件，不再
        作为结构化发现出现在 分析结果 里。"""
        ctx = _WriteRecordingContext()
        with mock.patch("fnet.features.common.protocol_streams",
                        return_value=self._smb_password_streams()):
            smb_password.analyze(ctx)
        # 任何一条都不能再以 "SMB 候选密码 流" 作为结构化发现。
        noisy = [f for f in ctx.findings
                 if f["summary"].startswith("SMB 候选密码 流")]
        self.assertFalse(noisy, f"意外的结构化发现: {noisy}")
        # 带账号的流与不带账号的流都应留下 info 级日志行。
        info_lines = [text for text, level in ctx.reports if level == "info"]
        self.assertTrue(any("账号=CORP\\alice" in t for t in info_lines),
                        ctx.reports)
        self.assertTrue(any("账号=?" in t for t in info_lines),
                        ctx.reports)
        # 工件仍落盘且包含完整候选列表。
        artifacts = dict(ctx.writes)
        self.assertIn("smb_password_candidates.txt", artifacts)
        self.assertTrue(artifacts["smb_password_candidates.txt"].strip())


class SmbIntelTest(unittest.TestCase):
    def _ctx(self, params=None):
        return FakeContext(params=params)

    def test_analyze_no_smb_flows_reports_warn(self):
        ctx = self._ctx({"password": "x"})
        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[]):
            smb_intel.analyze(ctx)  # 不抛异常
        self.assertTrue(any("没有 SMB" in text for text, _ in ctx.reports))

    def test_analyze_report_ok_from_mocked_decrypt(self):
        ctx = self._ctx({"password": "Password123"})
        accounts = [{"stream": "0", "user": "alice", "domain": "LAB",
                     "workstation": "", "challenge": b"", "nt_response": b""}]
        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[FakeStream("0", b"")]), \
             mock.patch.object(smb_intel, "_collect_accounts",
                               return_value=(accounts, True)), \
             mock.patch.object(smb_intel.smb3, "decrypt_capture") as dec:
            dec.return_value = {
                "ok": True, "decrypted": 4,
                "flags": ["flag{ok}"], "files": [], "sessions": [],
                "text": "ok", "log": [], "error": ""}
            smb_intel.analyze(ctx)

        # decrypt_capture 被调用且传入了 password
        self.assertEqual(dec.call_count, 1)
        self.assertEqual(dec.call_args.kwargs["password"], "Password123")
        # 汇报了解密成功 + flag
        self.assertIn("解密成功", " ".join(text for text, _ in ctx.reports))
        self.assertTrue(any("flag{ok}" in text for text, _ in ctx.reports))
        # 结构化结果里至少有一条 grade
        self.assertTrue(any(f["kind"] == "grade" for f in ctx.findings))

    def test_analyze_falls_back_to_next_candidate(self):
        ctx = self._ctx({"passwords": "wrong;good"})
        accounts = [{"stream": "0", "user": "alice", "domain": "LAB",
                     "workstation": "", "challenge": b"", "nt_response": b""}]
        calls = {"n": 0}

        def fake_decrypt(pcap, tshark, **kwargs):
            calls["n"] += 1
            if kwargs.get("password") == "good":
                return {"ok": True, "decrypted": 2, "flags": ["flag{fb}"],
                        "files": [], "sessions": [], "text": "", "log": [],
                        "error": ""}
            return {"ok": False, "decrypted": 0, "flags": [],
                    "files": [], "sessions": [], "text": "", "log": [],
                    "error": "密钥不匹配"}

        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[FakeStream("0", b"")]), \
             mock.patch.object(smb_intel, "_collect_accounts",
                               return_value=(accounts, True)), \
             mock.patch.object(smb_intel.smb3, "decrypt_capture",
                               side_effect=fake_decrypt):
            smb_intel.analyze(ctx)
        # 尝试了 wrong 和 good 两次，最终成功。
        self.assertEqual(calls["n"], 2)
        self.assertTrue(any("flag{fb}" in text for text, _ in ctx.reports))

    def test_analyze_all_candidates_fail_hints_hashcat(self):
        ctx = self._ctx({"password": "nope"})
        accounts = [{"stream": "0", "user": "alice", "domain": "LAB",
                     "workstation": "", "challenge": b"", "nt_response": b""}]
        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[FakeStream("0", b"")]), \
             mock.patch.object(smb_intel, "_collect_accounts",
                               return_value=(accounts, True)), \
             mock.patch.object(smb_intel.smb3, "decrypt_capture",
                               return_value={"ok": False, "decrypted": 0,
                                             "flags": [], "files": [],
                                             "sessions": [], "text": "",
                                             "log": [], "error": "不匹配"}):
            smb_intel.analyze(ctx)
        self.assertTrue(any("hashcat" in text or "5600" in text
                            for text, _ in ctx.reports))

    # ------------------------------------------------------------------
    # 非阻塞契约：暴力枚举绝不能进入流水线。
    # ------------------------------------------------------------------
    def test_pipeline_caps_explicit_candidates(self):
        """超过上限的显式候选被截断并告警，解密只跑上限个。"""
        ctx = self._ctx({"passwords": ";".join(f"p{i}" for i in range(20))})
        accounts = [{"stream": "0", "user": "alice", "domain": "LAB",
                     "workstation": "", "challenge": b"", "nt_response": b""}]
        tried: list[str] = []

        def fake_decrypt(pcap, tshark, **kwargs):
            tried.append(kwargs.get("password"))
            return {"ok": False, "decrypted": 0, "flags": [], "files": [],
                    "sessions": [], "text": "", "log": [], "error": "x"}

        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[FakeStream("0", b"")]), \
             mock.patch.object(smb_intel, "_collect_accounts",
                               return_value=(accounts, True)), \
             mock.patch.object(smb_intel.smb3, "decrypt_capture",
                               side_effect=fake_decrypt):
            smb_intel.analyze(ctx)
        self.assertEqual(len(tried), smb_intel.MAX_PIPELINE_CANDIDATES)
        self.assertTrue(any("仅用前" in text for text, _ in ctx.reports))

    def test_pipeline_never_enumerates_candidates(self):
        """账号派生候选/bruteforce 生成器绝不能被流水线调用。"""
        ctx = self._ctx({"password": "only", "bruteforce": 1})
        accounts = [{"stream": "0", "user": "alice", "domain": "LAB",
                     "workstation": "", "challenge": b"1122334455667788",
                     "nt_response": b"x" * 32}]
        generator = mock.Mock()
        with mock.patch.object(smb_intel, "protocol_streams",
                               return_value=[FakeStream("0", b"")]), \
             mock.patch.object(smb_intel, "_collect_accounts",
                               return_value=(accounts, True)), \
             mock.patch.object(smb_intel.smb3, "decrypt_capture",
                               return_value={"ok": False, "decrypted": 0,
                                             "flags": [], "files": [],
                                             "sessions": [], "text": "",
                                             "log": [], "error": "x"}) as dec, \
             mock.patch.dict("sys.modules",
                             {"fnet.features.smb_password": None}):
            smb_intel.analyze(ctx)
            generator.assert_not_called()
            # 只有显式候选参与了试解密。
            tried = [call.kwargs.get("password")
                     for call in dec.call_args_list]
        self.assertEqual(tried, ["only"])


if __name__ == "__main__":
    unittest.main()