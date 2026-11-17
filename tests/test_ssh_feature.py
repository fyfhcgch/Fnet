"""End-to-end test for the ``ssh.analyze`` feature (checkBox_53).

The capture is built in-process with :mod:`tests.pcap_build`: version
exchange, KEXINIT negotiation and a password brute-force against ``root``.
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
from fnet.tools.runner import find_tool
from tests.pcap_build import tcp_session, write_pcap

TSHARK = find_tool("tshark", "")


def ssh_packet(payload: bytes) -> bytes:
    pad = (8 - ((4 + 1 + len(payload)) % 8))
    if pad < 4:
        pad += 8
    packet_len = 1 + len(payload) + pad
    return struct.pack(">I", packet_len) + bytes([pad]) + payload + \
        b"\x00" * pad


def name_list(names: list[str]) -> bytes:
    raw = ",".join(names).encode()
    return struct.pack(">I", len(raw)) + raw


def kexinit() -> bytes:
    return (b"\x14" + b"\x11" * 16
            + name_list(["curve25519-sha256"])
            + name_list(["ssh-ed25519"])
            + name_list(["chacha20-poly1305@openssh.com"])
            + name_list(["chacha20-poly1305@openssh.com"])
            + name_list(["umac-64-etm@openssh.com"])
            + name_list(["umac-64-etm@openssh.com"])
            + name_list(["none"]) + name_list(["none"])
            + name_list([]) + name_list([])
            + b"\x00" + struct.pack(">I", 0))


def userauth_request(user: str, method: str, password: str | None = None,
                     algorithm: str | None = None) -> bytes:
    body = (struct.pack(">I", len(user)) + user.encode()
            + struct.pack(">I", 14) + b"ssh-connection"
            + struct.pack(">I", len(method)) + method.encode())
    if method == "password":
        body += b"\x00" + struct.pack(">I", len(password)) + password.encode()
    elif method == "publickey":
        blob = b"\x01\x02\x03\x04"
        body += (b"\x01" + struct.pack(">I", len(algorithm))
                 + algorithm.encode()
                 + struct.pack(">I", len(blob)) + blob)
    return b"\x32" + body


def userauth_failure(methods: str = "password") -> bytes:
    raw = methods.encode()
    return b"\x33" + struct.pack(">I", len(raw)) + raw + b"\x00"


def build_ssh_pcap(path: Path) -> None:
    client = [b"SSH-2.0-OpenSSH_9.6\r\n", ssh_packet(kexinit()),
              ssh_packet(userauth_request("root", "password", "wrongpass")),
              ssh_packet(userauth_failure()),
              ssh_packet(userauth_request("root", "password", "hunter2")),
              ssh_packet(userauth_request("root", "password", "toor")),
              ssh_packet(userauth_request("root", "password", "root123")),
              ssh_packet(userauth_request("root", "password", "admin123")),
              ssh_packet(userauth_request("root", "password", "P@ssw0rd!")),
              ssh_packet(userauth_request("root", "password", "letmein")),
              ssh_packet(userauth_failure()),
              ssh_packet(b"\x34")]
    server = [b"SSH-2.0-OpenSSH_8.4p1 Debian\r\n", ssh_packet(kexinit()),
              ssh_packet(b"\x06")] + [ssh_packet(userauth_failure())] * 10 \
        + [ssh_packet(b"\x34")]
    write_pcap(path, tcp_session("10.0.0.7", 40052, "10.0.0.32", 22,
                                 client, server))


@unittest.skipUnless(TSHARK, "需要 tshark")
class SshFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = Path(cls.tmp.name) / "ssh.pcap"
        build_ssh_pcap(cls.pcap)
        cls.patch = mock.patch("fnet.jobs.CACHE_DIR", Path(cls.tmp.name))
        cls.patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str],
                params: dict | None = None):
        job = self.runtime.jobs.submit(pcap, features, params or {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_ssh_banner_kex_password_and_brute(self):
        job, log = self.run_job(str(self.pcap), ["checkBox_53"])
        self.assertIn("SSH 版本交换", log)
        self.assertIn("OpenSSH_9.6", log)
        self.assertIn("OpenSSH_8.4p1", log)
        self.assertIn("SSH 算法协商", log)
        self.assertIn("KEX: curve25519-sha256", log)
        self.assertIn("主机密钥: ssh-ed25519", log)
        self.assertIn("SSH 口令认证", log)
        self.assertIn("用户=root 密码=hunter2", log)
        self.assertIn("SSH 认证失败", log)
        self.assertIn("SSH 用户 root 认证失败 10 次，疑似爆破", log)
        self.assertIn("SSH 认证成功", log)
        self.assertIn("SSH 认证时间线", log)
        self.assertIn("提取到 7 个 SSH 明文口令", log)
        self.assertTrue(
            (job.output_dir / "ssh_auth_timeline.txt").is_file())
        timeline = (job.output_dir / "ssh_auth_timeline.txt").read_text(
            encoding="utf-8")
        self.assertIn("\tsuccess\troot\t", timeline)
        self.assertIn("\tfailure\troot\t", timeline)
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)

    def test_ssh_brute_threshold_parameter(self):
        _job, log = self.run_job(str(self.pcap), ["checkBox_53"],
                                 {"ssh_brute_threshold": "99"})
        self.assertNotIn("疑似爆破", log)

    def test_ssh_without_traffic_warns(self):
        job, log = self.run_job(
            str(Path(__file__).resolve().parent / "data"
                / "dns_arp_icmp.pcap"), ["checkBox_53"])
        self.assertIn("没有发现 SSH 流量", log)


if __name__ == "__main__":
    unittest.main()
