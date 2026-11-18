"""回归护栏：日常排查噪声不得再混入结构化的 分析结果。

已移除的两类 info 级发现（SMB 协商 / SMB 候选密码 流）只属于分析日志与
工件；这里用统一的助手扫描 finding summary，一旦有人把它们加回去立即失败。
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from fnet.features import smb, smb_password

# 复用 tests/test_smb_feature.py 里的纯报文构建器（不依赖 tshark）。
from tests.test_smb_feature import (  # noqa: E402
    nbss, negotiate_request, session_setup_challenge,
    session_setup_request, transform_payload,
)

REMOVED_FINDING_PREFIXES = ("SMB 协商", "SMB 候选密码 流")


def assert_no_removed_noise(findings, label="findings"):
    """扫描 finding 列表，拒绝任何已移除的常规发现前缀。"""
    summaries = [str(item.get("summary", "")) for item in findings]
    noisy = [text for text in summaries
             if text.startswith(REMOVED_FINDING_PREFIXES)]
    if noisy:
        raise AssertionError(
            f"{label}: 以下常规信息不应出现在 分析结果 里: {noisy}")
    return summaries


class _Ctx:
    """最小的 FeatureContext 替身，记录 findings / reports / artifacts。"""

    def __init__(self):
        self.params = {}
        self.findings = []
        self.reports = []
        self.writes = []

    def report(self, text, level="info"):
        self.reports.append((text, level))

    def add_finding(self, kind, summary, *, frame="", detail="",
                    level="info", extra=None):
        self.findings.append({"kind": kind, "summary": summary,
                              "frame": frame, "detail": detail,
                              "level": level, "extra": extra or {}})

    def set_progress(self, value):
        return None

    def check_cancel(self):
        return None

    def cancelled(self):
        return False

    def write_output(self, name, data):
        self.writes.append((name, data))
        return Path("/tmp") / name


class _Stream:
    """协议流替身；frame_at 只需给出稳定的帧号字符串。"""

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


class FindingNoiseGuardTest(unittest.TestCase):
    def _smb_ctx(self):
        nt = b"\xaa" * 16 + b"\xbb" * 32
        client = (nbss(negotiate_request())
                  + nbss(session_setup_request("alice", "CORP", nt))
                  + nbss(transform_payload()))
        server = nbss(session_setup_challenge(bytes.fromhex(
            "1122334455667788")))
        streams = [_Stream("0", client, "a"),
                   _Stream("0", server, "b", "10.0.0.10", "445")]
        ctx = _Ctx()
        with mock.patch.object(smb, "protocol_streams", return_value=streams):
            smb.analyze(ctx)
        return ctx

    def test_smb_negotiate_stays_in_log(self):
        ctx = self._smb_ctx()
        assert_no_removed_noise(ctx.findings, "smb.analyze")
        self.assertTrue(any(text.startswith("SMB 方言:") for text,
                            _ in ctx.reports), ctx.reports)
        # 关键的 SMB3 加密发现及其自动填入字段仍须保留。
        encrypted = [f for f in ctx.findings
                     if f["summary"] == "SMB3 加密流量"]
        self.assertEqual(len(encrypted), 1, ctx.findings)
        extra = encrypted[0]["extra"]
        for key in ("account", "user", "domain", "hash", "mode"):
            self.assertIn(key, extra, extra)
        self.assertEqual(extra["account"], "CORP\\alice")

    def test_smb_password_candidates_stay_in_log_and_artifact(self):
        ctx = _Ctx()
        streams = [_Stream("0", nbss(negotiate_request())
                           + nbss(session_setup_request(
                               "alice", "CORP", b"\xaa" * 16 + b"\xbb" * 32))
                           + nbss(transform_payload())),
                   _Stream("0", nbss(session_setup_challenge(
                       bytes.fromhex("1122334455667788"))), "b"),
                   _Stream("1", nbss(negotiate_request()))]
        with mock.patch("fnet.features.common.protocol_streams",
                        return_value=streams):
            smb_password.analyze(ctx)
        assert_no_removed_noise(ctx.findings, "smb_password.analyze")
        self.assertTrue(any("生成" in text and "候选密码" in text
                            for text, _ in ctx.reports), ctx.reports)
        self.assertIn("smb_password_candidates.txt",
                      [name for name, _ in ctx.writes])


if __name__ == "__main__":
    unittest.main()
