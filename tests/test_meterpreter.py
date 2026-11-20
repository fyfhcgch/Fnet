"""Tests for the Meterpreter TLV parser and the ``meterpreter.analyze``
feature (checkBox_55).

The pure parser unit tests build TLV chains directly; the end-to-end test
constructs a pcap with :mod:`tests.pcap_build` that carries an unencrypted
Meterpreter request/response exchange over port 31337.
"""
from __future__ import annotations

import struct
import tempfile
import time
import unittest
from pathlib import Path

from fnet.app import build
from fnet.config import Config
from fnet.tools.runner import find_tool
from fnet.utils import meterpreter as mt
from tests.support import patch_cache_dirs
from tests.pcap_build import tcp_session, write_pcap

TSHARK = find_tool("tshark", "")

TLV_META_STRING = mt.TLV_META_TYPE_STRING
TLV_META_UINT = mt.TLV_META_TYPE_UINT
COMMAND_ID_TYPE = TLV_META_UINT | 1
REQUEST_ID_TYPE = TLV_META_STRING | 2
STRING_TYPE = TLV_META_STRING | 10
UINT_TYPE = TLV_META_UINT | 12
RESULT_TYPE = TLV_META_UINT | 4


def tlv(tlv_type: int, value: bytes, endian: str = ">") -> bytes:
    return struct.pack(f"{endian}II", len(value) + 8, tlv_type) + value


def request(command_id: int, request_id: str = "1234567890123456",
            strings: list[bytes] | None = None,
            uints: list[int] | None = None, endian: str = ">") -> bytes:
    inner = tlv(COMMAND_ID_TYPE, struct.pack(f"{endian}I", command_id),
                endian)
    inner += tlv(REQUEST_ID_TYPE, request_id.encode() + b"\x00", endian)
    for item in strings or []:
        inner += tlv(STRING_TYPE, item + b"\x00", endian)
    for item in uints or []:
        inner += tlv(UINT_TYPE, struct.pack(f"{endian}I", item), endian)
    return tlv(0, inner, endian)  # PACKET_TYPE_REQUEST


def response(request_id: str = "1234567890123456",
             result: int = 0, strings: list[bytes] | None = None,
             endian: str = ">") -> bytes:
    inner = tlv(RESULT_TYPE, struct.pack(f"{endian}I", result), endian)
    inner += tlv(REQUEST_ID_TYPE, request_id.encode() + b"\x00", endian)
    for item in strings or []:
        inner += tlv(STRING_TYPE, item + b"\x00", endian)
    return tlv(1, inner, endian)  # PACKET_TYPE_RESPONSE


def frames(data: bytes):
    """Fake frame mapping for offset -> frame lookups."""
    return lambda offset: str(offset // 40 + 1)


class MeterpreterParserTest(unittest.TestCase):
    def test_request_and_response_big_endian(self):
        data = request(0x1a, strings=[b"whoami"], uints=[1]) \
            + response(strings=[b"root"])
        parsed = mt.parse(data)
        self.assertEqual(len(parsed.packets), 2)
        self.assertEqual(parsed.leftover, 0)
        self.assertEqual(parsed.endianness, "big")
        req = parsed.packets[0]
        self.assertEqual(req.kind, "request")
        self.assertEqual(req.command_id, 0x1a)
        self.assertEqual(req.command_hex, "0x0000001a")
        self.assertEqual(req.request_id, "1234567890123456")
        self.assertEqual(req.strings, ["whoami"])
        self.assertEqual(req.uints, [1])
        resp = parsed.packets[1]
        self.assertEqual(resp.kind, "response")
        self.assertEqual(resp.result, 0)
        self.assertEqual(resp.strings, ["root"])

    def test_unknown_tlv_type_shows_hex(self):
        inner = tlv(COMMAND_ID_TYPE, struct.pack(">I", 0x7f))
        inner += tlv(0x12345678, b"\x01\x02")
        data = tlv(0, inner) + tlv(0x12345678, b"\x01\x02")
        parsed = mt.parse(data)
        self.assertEqual(len(parsed.packets), 1)
        self.assertEqual(len(parsed.extra_tlvs), 1)
        self.assertEqual(parsed.extra_tlvs[0].name, "0x12345678")
        self.assertIn("0x12345678", parsed.packets[0].unknown[0])
        self.assertIn("0x12345678", mt.summary_line(parsed.packets[0]))

    def test_little_endian_fallback(self):
        data = request(0x21, strings=[b"metsvc"], endian="<") \
            + response(strings=[b"ok"], endian="<")
        parsed = mt.parse(data)
        self.assertEqual(len(parsed.packets), 2)
        self.assertEqual(parsed.endianness, "little")
        self.assertEqual(parsed.packets[0].command_id, 0x21)
        self.assertEqual(parsed.packets[0].strings, ["metsvc"])

    def test_looks_like_meterpreter(self):
        self.assertTrue(mt.looks_like_meterpreter(request(1)))
        self.assertFalse(mt.looks_like_meterpreter(b"hello world"))
        self.assertFalse(mt.looks_like_meterpreter(b""))
        self.assertFalse(mt.looks_like_meterpreter(b"\x00\x00\x00\x01"))

    def test_summary_line_has_strings(self):
        parsed = mt.parse(request(0x2a, strings=[b"cmd.exe /c whoami"]))
        line = mt.summary_line(parsed.packets[0])
        self.assertIn("0x0000002a", line)
        self.assertIn("cmd.exe", line)


@unittest.skipUnless(TSHARK, "需要 tshark")
class MeterpreterFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        request_payload = request(0x1a, strings=[b"whoami"], uints=[1])
        response_payload = response(strings=[b"root"])
        pcap_path = Path(cls.tmp.name) / "meterpreter.pcap"
        write_pcap(pcap_path, tcp_session("10.10.10.5", 40921,
                                          "10.10.10.2", 31337,
                                          [request_payload],
                                          [response_payload]))
        cls.pcap = str(pcap_path)
        cls.patches = patch_cache_dirs(cls.tmp.name)
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    def run_job(self, features: list[str]):
        job = self.runtime.jobs.submit(self.pcap, features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_meterpreter_session_detected(self):
        job, text = self.run_job(["checkBox_55"])
        self.assertIn("Meterpreter 会话", text)
        self.assertIn("0x0000001a", text)
        self.assertIn("whoami", text)
        self.assertIn("request", text)
        self.assertIn("response", text)
        self.assertIn("meterpreter_timeline.csv", text)
        protocols = [item for item in job.findings
                     if item["kind"] == "protocol"
                     and item.get("extra", {}).get("protocol") == "meterpreter"]
        self.assertEqual(len(protocols), 2)
        command_ids = {item["extra"]["command_id"] for item in protocols}
        self.assertEqual(command_ids, {"0x0000001a", "-"})  # 响应无命令 ID
        csv_path = Path(job.output_dir) / "meterpreter_timeline.csv"
        self.assertTrue(csv_path.is_file())
        self.assertIn("whoami", csv_path.read_text(encoding="utf-8"))

    def test_no_meterpreter_traffic_hint(self):
        plain_pcap = Path(self.tmp.name) / "plain.pcap"
        write_pcap(plain_pcap, tcp_session("10.0.0.1", 12345, "10.0.0.2", 9999,
                                           [b"plain text\n"], [b"hi\n"]))
        job = self.runtime.jobs.submit(str(plain_pcap), ["checkBox_55"], {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        self.assertIn("没有发现 Meterpreter TLV 流量", text)
        self.assertIn("31337", text)


if __name__ == "__main__":
    unittest.main()
