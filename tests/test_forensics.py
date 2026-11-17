"""Unit tests for credential correlation and the authentication timeline."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import forensics
from fnet.features.registry import FeatureContext
from fnet.logger import Logger


def finding(kind: str, summary: str, *, frame: str = "1", detail: str = "",
            feature: str = "测试功能", extra: dict | None = None,
            level: str = "good", time: str = "12:00:00") -> dict:
    return {
        "kind": kind,
        "summary": summary,
        "detail": detail,
        "frame": frame,
        "feature": feature,
        "level": level,
        "time": time,
        "extra": extra or {},
    }


class ParseCredentialTest(unittest.TestCase):
    def test_basic_auth(self):
        record = forensics.parse_credential(
            finding("credential", "Basic 认证 admin:P@ssw0rd",
                    detail="GET /admin/", extra={"host": "ctf.local"}))
        self.assertEqual(record["protocol"], "http")
        self.assertEqual(record["account"], "admin")
        self.assertEqual(record["secret"], "P@ssw0rd")
        self.assertEqual(record["host"], "ctf.local")

    def test_ftp_combined(self):
        record = forensics.parse_credential(
            finding("credential", "FTP 登录 alice:s3cr3t",
                    extra={"protocol": "ftp", "account": "alice",
                           "secret": "s3cr3t"}))
        self.assertEqual(record["protocol"], "ftp")
        self.assertEqual(record["account"], "alice")
        self.assertEqual(record["secret"], "s3cr3t")

    def test_ntlm_hash_account(self):
        detail = ("Administrator::WORKGROUP:aabbccddeeff0011:"
                  "11223344556677889900aabbccddeeff:1122334455667788")
        record = forensics.parse_credential(
            finding("hash", "Administrator::WORKGROUP NetNTLMv1",
                    detail=detail, extra={"protocol": "ntlm"}))
        self.assertEqual(record["protocol"], "ntlm")
        self.assertEqual(record["account"], "WORKGROUP\\Administrator")
        self.assertEqual(record["hash"], detail)

    def test_ldap_from_extra(self):
        record = forensics.parse_credential(
            finding("credential", "LDAP cn=admin:secret",
                    extra={"protocol": "ldap", "account": "cn=admin",
                           "secret": "secret"}))
        self.assertEqual(record["protocol"], "ldap")
        self.assertEqual(record["account"], "cn=admin")

    def test_non_credential_is_ignored(self):
        self.assertIsNone(forensics.parse_credential(
            finding("file", "SMB2 写入 a.txt")))


class CorrelateTest(unittest.TestCase):
    def test_merge_same_account_and_frames(self):
        items = [
            finding("credential", "Basic 认证 admin:pw", frame="1",
                    feature="HTTP数据提取"),
            finding("credential", "HTTP/2 Basic admin:pw", frame="2",
                    feature="多协议凭据提取"),
        ]
        records = forensics.correlate_credentials(items)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["frames"], ["1", "2"])
        self.assertEqual(records[0]["sources"],
                         ["HTTP数据提取", "多协议凭据提取"])

    def test_account_only_is_dropped_when_secret_exists(self):
        items = [
            finding("credential", "FTP USER alice", frame="1",
                    extra={"protocol": "ftp", "account": "alice"}),
            finding("credential", "FTP 登录 alice:s3cr3t", frame="2",
                    extra={"protocol": "ftp", "account": "alice",
                           "secret": "s3cr3t"}),
        ]
        records = forensics.correlate_credentials(items)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["secret"], "s3cr3t")
        self.assertEqual(records[0]["frames"], ["1", "2"])

    def test_allowlist_and_min_secret(self):
        items = [
            finding("credential", "Basic 认证 guest:guest",
                    extra={"protocol": "http", "account": "guest",
                           "secret": "guest"}),
            finding("credential", "Basic 认证 admin:abc",
                    extra={"protocol": "http", "account": "admin",
                           "secret": "abc"}),
            finding("credential", "Basic 认证 root:strongpass",
                    extra={"protocol": "http", "account": "root",
                           "secret": "strongpass"}),
        ]
        records = forensics.correlate_credentials(items, ["guest"], 5)
        self.assertEqual([item["account"] for item in records], ["root"])

    def test_separate_hosts_are_not_merged(self):
        items = [
            finding("credential", "Basic 认证 admin:pw", frame="1",
                    extra={"protocol": "http", "account": "admin",
                           "secret": "pw", "host": "a"}),
            finding("credential", "Basic 认证 admin:pw", frame="2",
                    extra={"protocol": "http", "account": "admin",
                           "secret": "pw", "host": "b"}),
        ]
        self.assertEqual(len(forensics.correlate_credentials(items)), 2)


class TimelineTest(unittest.TestCase):
    def test_events_are_frame_sorted_and_deduplicated(self):
        items = [
            finding("credential", "Basic 认证 admin:pw", frame="10"),
            finding("file", "SMB2 写入 \\share\\a.txt", frame="2"),
            finding("file", "SMB2 写入 \\share\\a.txt", frame="2"),
            finding("webshell", "Behinder 解密 /shell.jsp", frame="5"),
        ]
        events = forensics.build_timeline(items)
        self.assertEqual([item["frame"] for item in events], ["2", "5", "10"])
        self.assertEqual(events[0]["event"], "文件写入")
        self.assertEqual(events[1]["event"], "Webshell 活动")

    def test_login_success_from_http_extra(self):
        event = forensics._event_for(finding(
            "credential", "POST /login",
            detail="表单: user=admin&pass=pw\n状态: 200",
            extra={"success": "1"}))
        self.assertEqual(event["event"], "登录成功")

    def test_ignores_unrelated_kinds(self):
        self.assertIsNone(forensics._event_for(finding("other", "long name")))


class HandlerTest(unittest.TestCase):
    def test_correlate_writes_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=None,
                pcap=str(root / "x.pcap"),
                params={},
                output_dir=root / "out",
                findings=[
                    finding("credential", "Basic 认证 admin:pw", frame="1"),
                    finding("credential", "HTTP/2 Basic admin:pw", frame="2"),
                    finding("file", "SMB2 写入 \\share\\a.txt", frame="3"),
                ],
            )
            before = len(ctx.findings)
            forensics.correlate(ctx)
            self.assertGreater(len(ctx.findings), before)
            self.assertTrue((root / "out" / "credentials_correlated.csv").is_file())
            self.assertTrue((root / "out" / "auth_timeline.txt").is_file())

    def test_timeline_handler_writes_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=None,
                pcap=str(root / "x.pcap"),
                params={},
                output_dir=root / "out",
                findings=[finding("file", "SMB2 读取 \\share\\a.txt", frame="3")],
            )
            forensics.timeline(ctx)
            self.assertTrue((root / "out" / "auth_timeline.txt").is_file())


if __name__ == "__main__":
    unittest.main()
