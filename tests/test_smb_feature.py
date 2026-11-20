"""Tests for the ``smb.analyze`` feature (checkBox_49).

The first class is an end-to-end run over the sample capture and needs
``tshark``; the second one drives the handler with fake reassembled streams
so the SMB3 解密 auto-fill hints (账号/域/NetNTLMv2 挂在加密流量 finding 上)
stay covered offline.
"""
from __future__ import annotations

import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.features import smb as smb_feature
from fnet.tools.runner import find_tool
from fnet.utils import smb
from tests.support import patch_cache_dirs

DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")


def header(command: int, *, status: int = 0, flags: int = 0,
           message_id: int = 1, tree_id: int = 0, session_id: int = 1) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s", smb.SMB2_MAGIC, 64, 1, status, command, 1,
        flags, 0, message_id, 0, tree_id, session_id, b"\x00" * 16)


def nbss(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def negotiate_request(message_id: int = 1) -> bytes:
    body = struct.pack("<HHHHI16sII", 36, 2, 0, 0, 0x40, b"\x00" * 16, 0,
                       0) + struct.pack("<HH", 0x0311, 0x0302)
    return header(0, message_id=message_id) + body


def session_setup_request(user: str, domain: str, nt: bytes) -> bytes:
    """A SESSION_SETUP carrying an NTLMSSP type 3 message."""
    encoded_user = user.encode("utf-16le")
    encoded_domain = domain.encode("utf-16le")
    blob = bytearray(b"NTLMSSP\x00" + (3).to_bytes(4, "little") + b"\x00" * 52)
    offset = 64
    for (length_at, offset_at), value in (
            ((20, 24), nt), ((28, 32), encoded_domain),
            ((36, 40), encoded_user)):
        struct.pack_into("<HHI", blob, length_at, len(value), len(value),
                         offset)
        offset += len(value)
    blob = bytes(blob) + nt + encoded_domain + encoded_user
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob),
                       0) + blob
    return header(1, message_id=2) + body


def session_setup_challenge(challenge: bytes) -> bytes:
    """The SESSION_SETUP response that carries the NTLMSSP type 2 server
    challenge (bytes 24..32 of the blob)."""
    blob = (b"NTLMSSP\x00" + (2).to_bytes(4, "little") + b"\x00" * 12
            + challenge + b"\x00" * 16)
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob),
                       0) + blob
    return header(1, flags=0x1, message_id=1) + body


def transform_payload(session_id: int = 7) -> bytes:
    return (smb.SMB3_TRANSFORM + b"\x11" * 16 + b"\x22" * 16
            + (4096).to_bytes(4, "little") + b"\x00\x00" + b"\x01\x00"
            + (session_id).to_bytes(8, "little") + b"cipher")


class FakeContext:
    """Minimal ``FeatureContext`` stand-in (report / add_finding / params)."""

    def __init__(self):
        self.params = {}
        self.pcap = "fake.pcapng"
        self.tshark = None
        self.output_dir = None
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
        return None

    def check_cancel(self):
        return None

    def cancelled(self):
        return False

    def write_output(self, name, data):
        return Path("/tmp") / name


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


@unittest.skipUnless(TSHARK, "需要 tshark")
class SmbFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.patches = patch_cache_dirs(cls.tmp.name)
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str]):
        job = self.runtime.jobs.submit(str(DATA / pcap), features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_smb_share_ntlm_and_file_recovery(self):
        job, log = self.run_job("smb2_deep.pcap", ["checkBox_49"])
        self.assertIn("SMB 会话认证", log)
        self.assertIn("账号=CTF\\alice", log)
        self.assertIn("连接共享 \\\\FS01\\share", log)
        self.assertIn("打开文件 \\\\FS01\\share\\flag.txt", log)
        self.assertIn("写入文件 \\\\FS01\\share\\flag.txt", log)
        self.assertIn("SMB 方言: SMB 3.1.1", log)
        self.assertIn("SMB 文件 \\\\FS01\\share\\flag.txt 已还原 15 字节",
                      log)
        self.assertTrue((job.output_dir / "smb_shared_files.txt").is_file())
        exported = list(job.output_dir.glob("smb_file_*_flag.txt.bin"))
        self.assertTrue(exported)
        self.assertEqual(exported[0].read_bytes(), b"flag{smb2_file}")
        summary = (job.output_dir / "smb_shared_files.txt").read_text(
            encoding="utf-8")
        self.assertIn("md5=", summary)
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)
        self.assertIn("file", kinds)

    def test_smb_without_traffic_warns(self):
        job, log = self.run_job("dns_arp_icmp.pcap", ["checkBox_49"])
        self.assertIn("没有发现 SMB 流量", log)


class SmbEncryptedHintTest(unittest.TestCase):
    """The SMB3 加密流量 finding must carry the stream's NTLM identity."""

    def _analyze(self, client_data: bytes, server_data: bytes):
        ctx = FakeContext()
        streams = [FakeStream("0", client_data, "a"),
                   FakeStream("0", server_data, "b", "10.0.0.10", "445")]
        with mock.patch.object(smb_feature, "protocol_streams",
                               return_value=streams):
            smb_feature.analyze(ctx)
        return ctx

    def _encrypted(self, ctx):
        return next((item for item in ctx.findings
                     if item["summary"] == "SMB3 加密流量"), None)

    def test_encrypted_finding_carries_account_and_hash(self):
        nt = b"\xaa" * 16 + b"\xbb" * 32
        # 真实顺序：客户端先协商，服务端回 NTLMSSP type2 挑战，客户端再发
        # type3——挑战必须先于 type3 被看到，NetNTLMv2 哈希才拼得出来。
        client = (nbss(negotiate_request())
                  + nbss(session_setup_request("alice", "CORP", nt))
                  + nbss(transform_payload()))
        server = nbss(session_setup_challenge(bytes.fromhex(
            "1122334455667788")))
        ctx = self._analyze(client, server)
        item = self._encrypted(ctx)
        self.assertIsNotNone(item, [text for text, _ in ctx.reports])
        extra = item["extra"]
        self.assertEqual(extra["stream"], "0")
        self.assertEqual(extra["account"], "CORP\\alice")
        self.assertEqual(extra["user"], "alice")
        self.assertEqual(extra["domain"], "CORP")
        # NetNTLMv2 哈希一并挂上，供 SMB3 解密对话框提示先破解。
        self.assertEqual(extra["mode"], "5600")
        self.assertTrue(extra["hash"].startswith("alice::CORP:"))
        self.assertIn("账号=CORP\\alice", item["detail"])
        self.assertTrue(any("可自动填入" in text for text, _ in ctx.reports))
        # 协商只进日志，不再作为结构化发现出现在 分析结果 里。
        self.assertFalse(any(f["summary"].startswith("SMB 协商")
                             for f in ctx.findings), ctx.findings)
        self.assertTrue(any(text.startswith("SMB 方言:") for text,
                            _ in ctx.reports), ctx.reports)

    def test_encrypted_finding_without_identity_stays_clean(self):
        ctx = self._analyze(nbss(negotiate_request()) + nbss(
            transform_payload()), b"")
        item = self._encrypted(ctx)
        self.assertIsNotNone(item)
        for key in ("account", "user", "domain", "hash", "mode"):
            self.assertNotIn(key, item["extra"])
        self.assertNotIn("账号=", item["detail"])
        self.assertFalse(any(f["summary"].startswith("SMB 协商")
                             for f in ctx.findings), ctx.findings)
        self.assertTrue(any(text.startswith("SMB 方言:") for text,
                            _ in ctx.reports), ctx.reports)


if __name__ == "__main__":
    unittest.main()
