"""Unit tests for the extra protocol extractors (no tshark needed)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import protocols
from fnet.features.registry import FeatureContext
from fnet.logger import Logger


class RedisParserTest(unittest.TestCase):
    def test_resp_array_commands(self):
        payload = (b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
                   b"*1\r\n$4\r\nPING\r\n")
        self.assertEqual(protocols.redis_commands(payload),
                         [["AUTH", "password"], ["PING"]])

    def test_inline_commands(self):
        payload = b"PING\r\nSET foo bar\r\n"
        self.assertEqual(protocols.redis_commands(payload),
                         [["PING"], ["SET", "foo", "bar"]])

    def test_truncated_array_is_ignored(self):
        self.assertEqual(protocols.redis_commands(b"*2\r\n$3\r\nGET\r\n$5\r\nab"),
                         [])

    def test_empty_payload(self):
        self.assertEqual(protocols.redis_commands(b""), [])


class Smb2CommandTest(unittest.TestCase):
    def test_numeric_and_text_commands(self):
        self.assertEqual(protocols.smb2_command_name("5"), "CREATE")
        self.assertEqual(protocols.smb2_command_name("9"), "WRITE")
        self.assertEqual(protocols.smb2_command_name("create"), "CREATE")
        self.assertEqual(protocols.smb2_command_name("99"), "CMD_99")
        self.assertEqual(protocols.smb2_command_name(""), "")


class HelperTest(unittest.TestCase):
    def test_interesting_tokens(self):
        text = '{"username": "admin", "password": "s3cr3t", "n": 1}'
        tokens = protocols._interesting_tokens(text)
        self.assertIn("username=admin", tokens)
        self.assertIn("password=s3cr3t", tokens)

    def test_decode_basic(self):
        self.assertEqual(protocols._decode_basic("Basic YWRtaW46cHc="), "admin:pw")
        self.assertEqual(protocols._decode_basic("Bearer token"), "")

    def test_decoded_candidates_base64_and_hex(self):
        base64_items = protocols._decoded_candidates("ZmxhZ3t3c30=")
        self.assertIn(("base64", "flag{ws}"), base64_items)
        hex_items = protocols._decoded_candidates("666c61677b77737d")
        self.assertIn(("hex", "flag{ws}"), hex_items)

    def test_looks_readable(self):
        self.assertTrue(protocols._looks_readable("hello world"))
        self.assertFalse(protocols._looks_readable("\x00\x01"))


class _FakeTshark:
    def __init__(self, rows):
        self.rows = rows
        self.calls = 0

    def fields(self, pcap, fields, display_filter="", extra=None, cancel=None):
        self.calls += 1
        return self.rows


class DetectionTest(unittest.TestCase):
    def test_non_default_port_and_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "x.pcap"
            pcap.write_bytes(b"")
            resp = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
            fake = _FakeTshark([[ "1", "0", "50000", "16379", resp.hex() ]])
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=fake,
                pcap=str(pcap),
                output_dir=root / "out",
            )
            protocols.clear_detection_cache()
            detections = protocols.detect_streams(ctx)
            self.assertEqual(len(detections), 1)
            self.assertEqual(detections[0]["protocol"], "redis")
            self.assertEqual(detections[0]["port"], 16379)
            self.assertTrue(detections[0]["non_default"])
            protocols.detect_streams(ctx)
            self.assertEqual(fake.calls, 1, "第二次检测应命中缓存")

    def test_detect_handler_writes_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "x.pcap"
            pcap.write_bytes(b"")
            startup = (b"\x00\x00\x00\x08\x00\x03\x00\x00")
            fake = _FakeTshark([["3", "1", "50000", "15432", startup.hex()]])
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=fake,
                pcap=str(pcap),
                output_dir=root / "out",
            )
            protocols.clear_detection_cache()
            protocols.detect(ctx)
            self.assertTrue((root / "out" / "protocol_detection.csv").is_file())
            kinds = [item["kind"] for item in ctx.findings]
            self.assertIn("protocol", kinds)


if __name__ == "__main__":
    unittest.main()
