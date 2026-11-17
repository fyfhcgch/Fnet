"""End-to-end test for the ``mongodb.analyze`` feature (checkBox_50).

The capture is built in-process with :mod:`tests.pcap_build` (no scapy):
OP_MSG saslStart/find + OP_REPLY with sensitive fields + GridFS chunks.
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


def bson(values: dict) -> bytes:
    body = bytearray()
    for key, value in values.items():
        name = key.encode() + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + name + bytes([1 if value else 0])
        elif isinstance(value, int):
            body += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, str):
            raw = value.encode() + b"\x00"
            body += b"\x02" + name + struct.pack("<i", len(raw)) + raw
        elif isinstance(value, tuple) and value and value[0] == "oid":
            body += b"\x07" + name + bytes.fromhex(value[1])
        elif isinstance(value, dict):
            body += b"\x03" + name + bson(value)
        elif isinstance(value, (list, tuple)):
            body += b"\x04" + name + bson(
                {str(index): item for index, item in enumerate(value)})
        elif isinstance(value, bytes):
            body += (b"\x05" + name + struct.pack("<i", len(value))
                     + b"\x00" + value)
        elif value is None:
            body += b"\x0A" + name
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + bytes(body)


def op_msg(command: dict, documents=()) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + bson(command)
    if documents:
        payload = b"documents\x00" + b"".join(bson(d) for d in documents)
        body += b"\x01" + struct.pack("<i", len(payload) + 4) + payload
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2013) + body


def op_reply(documents) -> bytes:
    body = struct.pack("<iqii", 0, 0, 0, len(documents)) + b"".join(
        bson(d) for d in documents)
    return struct.pack("<iiii", 16 + len(body), 2, 1, 1) + body


GRIDFS_DATA = b"gridfs-flag-content"


def build_mongo_pcap(path: Path) -> None:
    client = [
        op_msg({"saslStart": 1, "mechanism": "SCRAM-SHA-256",
                "payload": "n,,n=admin,r=abc123", "$db": "admin"}),
        op_msg({"find": "users", "filter": {}, "$db": "app"}),
        op_msg({"insert": "fs.files", "$db": "test"},
               [{"_id": ("oid", "64" * 12), "filename": "secret.txt",
                 "length": len(GRIDFS_DATA), "chunkSize": 255}]),
        op_msg({"insert": "fs.chunks", "$db": "test"},
               [{"files_id": ("oid", "64" * 12), "n": 0,
                 "data": GRIDFS_DATA}]),
    ]
    server = [
        op_msg({"conversationId": 1, "done": False,
                "payload": "r=abc123def,s=c2FsdA==,i=15000", "ok": 1.0}),
        op_reply([{"user": "alice", "password": "mongopass"}]),
        op_msg({"ok": 1.0}),
        op_msg({"ok": 1.0}),
    ]
    write_pcap(path, tcp_session("10.0.0.5", 40050, "10.0.0.30", 27017,
                                 client, server))


@unittest.skipUnless(TSHARK, "需要 tshark")
class MongoDbFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = Path(cls.tmp.name) / "mongo.pcap"
        build_mongo_pcap(cls.pcap)
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

    def test_mongodb_commands_scram_and_gridfs(self):
        job, log = self.run_job(str(self.pcap), ["checkBox_50"])
        self.assertIn("MongoDB OP_MSG saslStart admin", log)
        self.assertIn("MongoDB OP_MSG find app.users", log)
        self.assertIn("MongoDB SCRAM 认证", log)
        self.assertIn("用户=admin 机制=SCRAM-SHA-256", log)
        self.assertIn("帧敏感字段: user=alice", log)
        self.assertIn("帧敏感字段: password=mongopass", log)
        self.assertIn("GridFS 文件 secret.txt 已还原: "
                      f"{len(GRIDFS_DATA)} 字节 (完整, 1 个分块)", log)
        self.assertIn("MongoDB 命令 6 条，已写入 mongodb_commands.txt", log)
        self.assertTrue((job.output_dir / "mongodb_commands.txt").is_file())
        exported = list(job.output_dir.glob("gridfs_secret.txt"))
        self.assertTrue(exported)
        self.assertEqual(exported[0].read_bytes(), GRIDFS_DATA)
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)
        self.assertIn("file", kinds)

    def test_mongodb_without_traffic_warns(self):
        job, log = self.run_job(
            str(Path(__file__).resolve().parent / "data"
                / "dns_arp_icmp.pcap"), ["checkBox_50"])
        self.assertIn("没有发现 MongoDB 流量", log)


if __name__ == "__main__":
    unittest.main()
