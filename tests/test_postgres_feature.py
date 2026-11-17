"""End-to-end test for the ``postgres.analyze`` feature (checkBox_51).

The capture is built in-process with :mod:`tests.pcap_build`: startup
message, cleartext password, simple query and a small result set.
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


def pg_message(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack(">i", len(body) + 4) + body


def pg_startup(params: dict) -> bytes:
    payload = struct.pack(">i", 196608)
    for key, value in params.items():
        payload += key.encode() + b"\x00" + str(value).encode() + b"\x00"
    payload += b"\x00"
    return struct.pack(">i", len(payload) + 4) + payload


def build_postgres_pcap(path: Path) -> None:
    row_desc = (struct.pack(">h", 1) + b"secret\x00"
                + struct.pack(">iHihiH", 0, 0, 25, -1, -1, 0))
    data_row = (struct.pack(">h", 1) + struct.pack(">i", 14)
                + b"flag{pg_query}")
    client = [
        pg_startup({"user": "appuser", "database": "appdb"}),
        pg_message(b"p", b"pgpass\x00"),
        pg_message(b"Q", b"SELECT secret FROM flags\x00"),
    ]
    server = [
        pg_message(b"R", struct.pack(">i", 3)),
        pg_message(b"R", struct.pack(">i", 0)),
        pg_message(b"T", row_desc),
        pg_message(b"D", data_row),
        pg_message(b"C", b"SELECT 1\x00"),
        pg_message(b"Z", b"I"),
    ]
    write_pcap(path, tcp_session("10.0.0.6", 40051, "10.0.0.31", 5432,
                                 client, server))


@unittest.skipUnless(TSHARK, "需要 tshark")
class PostgresFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = Path(cls.tmp.name) / "postgres.pcap"
        build_postgres_pcap(cls.pcap)
        cls.patch = mock.patch("fnet.jobs.CACHE_DIR", Path(cls.tmp.name))
        cls.patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str]):
        job = self.runtime.jobs.submit(pcap, features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_postgres_startup_password_query_result(self):
        job, log = self.run_job(str(self.pcap), ["checkBox_51"])
        self.assertIn("PostgreSQL 连接", log)
        self.assertIn("用户=appuser 数据库=appdb", log)
        self.assertIn("PostgreSQL 认证方式: cleartext", log)
        self.assertIn("PostgreSQL 明文口令: pgpass", log)
        self.assertIn("PostgreSQL 查询", log)
        self.assertIn("SELECT secret FROM flags", log)
        self.assertIn("PostgreSQL 完成: SELECT 1 (1 行)", log)
        self.assertIn("列: secret", log)
        self.assertIn("flag{pg_query}", log)
        self.assertIn("提取到 1 个 PostgreSQL 明文口令", log)
        self.assertTrue((job.output_dir / "pg_queries.txt").is_file())
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)

    def test_postgres_without_traffic_warns(self):
        job, log = self.run_job(
            str(Path(__file__).resolve().parent / "data"
                / "dns_arp_icmp.pcap"), ["checkBox_51"])
        self.assertIn("没有发现 PostgreSQL 流量", log)


if __name__ == "__main__":
    unittest.main()
