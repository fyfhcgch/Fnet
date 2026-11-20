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

    def test_cache_key_includes_detection_params(self):
        """回归（B11.11）：改了 ``protocol_min_confidence`` 不能命中旧结果。

        早期缓存只以 ``(路径, mtime, size)`` 为键，同一次任务里先跑
        ``min_confidence=95`` 再跑默认值会复用前者的结果。
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "x.pcap"
            pcap.write_bytes(b"")
            # Redis AUTH 的置信度不足以过 90，但能过默认 60。
            resp = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
            fake = _FakeTshark([["1", "0", "50000", "16379", resp.hex()]])
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=fake,
                pcap=str(pcap),
                output_dir=root / "out",
                params={"protocol_min_confidence": "95"},
            )
            protocols.clear_detection_cache()
            self.assertEqual(protocols.detect_streams(ctx), [],
                             "门槛 95 时不应报 redis（实测置信度 90）")
            ctx.params = {}
            self.assertEqual(len(protocols.detect_streams(ctx)), 1,
                             "默认门槛必须重新检测，而不是命中 95 的缓存")
            self.assertEqual(fake.calls, 2)

    def test_cache_key_includes_ignore_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "x.pcap"
            pcap.write_bytes(b"")
            resp = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
            fake = _FakeTshark([["1", "0", "50000", "16379", resp.hex()]])
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=fake,
                pcap=str(pcap),
                output_dir=root / "out",
            )
            protocols.clear_detection_cache()
            self.assertEqual(len(protocols.detect_streams(ctx)), 1)
            ctx.params = {"protocol_ignore": "redis"}
            self.assertEqual(protocols.detect_streams(ctx), [],
                             "忽略 redis 后必须重算")

    def test_cache_is_bounded(self):
        """``--all`` / 批量分析时缓存不能无限增长。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = _FakeTshark([["1", "0", "50000", "16379", b""]])
            protocols.clear_detection_cache()
            for index in range(protocols._DETECT_CACHE_LIMIT + 3):
                pcap = root / f"{index}.pcap"
                pcap.write_bytes(b"")
                protocols.detect_streams(FeatureContext(
                    config=Config(root / "config.ini"),
                    logger=Logger(root / "fnet.log"),
                    tshark=fake,
                    pcap=str(pcap),
                    output_dir=root / "out"))
            self.assertLessEqual(len(protocols._DETECT_CACHE),
                                 protocols._DETECT_CACHE_LIMIT)

    def test_cached_entries_are_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "x.pcap"
            pcap.write_bytes(b"")
            resp = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
            fake = _FakeTshark([["1", "0", "50000", "16379", resp.hex()]])
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=fake,
                pcap=str(pcap),
                output_dir=root / "out")
            protocols.clear_detection_cache()
            first = protocols.detect_streams(ctx)
            first[0]["protocol"] = "污染"
            second = protocols.detect_streams(ctx)
            self.assertEqual(second[0]["protocol"], "redis")

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
