"""Tests for PCAP-over-IP (``fnet.pcapoip``) and ``fnet --pcap-over-ip``.

Covered here:

* the stream parser: full pcap, pcapng, split/half packets, byte-at-a-time
  feeds, bad magic and truncated global headers;
* an end-to-end run: a minimal pcap (built in-test) is sent over a real
  socket to a listening ``PcapOverIPServer``, asserting the capture is saved
  under the patched cache dir and a job is created through ``JobManager``;
* invalid streams (bad magic / truncated header) must not create jobs.

All cache paths (``fnet.jobs.CACHE_DIR``, ``fnet.paths.CACHE_DIR`` and
``fnet.pcapoip.CACHE_DIR``) are patched to a temp dir.
"""
from __future__ import annotations

import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.features.registry import FEATURES
from fnet.pcapoip import (
    PCAPNG_HEADER_LEN,
    PCAP_HEADER_LEN,
    PcapOverIPServer,
    PcapStreamParser,
    detect_magic,
)

# 24-byte little-endian pcap global header (Ethernet link type).
GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
FRAME = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + b"\x08\x00" \
    + b"GET /flag HTTP/1.1\r\nHost: example.test\r\n\r\n"
PACKET_RECORD = struct.pack("<IIII", 1700000000, 123456, len(FRAME), len(FRAME)) + FRAME


def minimal_pcap() -> bytes:
    return GLOBAL_HEADER + PACKET_RECORD


def minimal_pcapng() -> bytes:
    # Minimal Section Header Block: type + total length + byte-order magic
    # + version + 0 + total length again.
    block = struct.pack("<IIIII", 0x0A0D0D0A, 28, 0x1A2B3C4D, 0x00000001,
                        0xFFFFFFFF) + b"\x00\x00\x00\x00" + struct.pack("<I", 28)
    return block


class DetectMagicTest(unittest.TestCase):
    def test_all_variants(self):
        self.assertEqual(detect_magic(b"\xd4\xc3\xb2\xa1"), "pcap")
        self.assertEqual(detect_magic(b"\xa1\xb2\xc3\xd4"), "pcap")
        self.assertEqual(detect_magic(b"\x4d\x3c\xb2\xa1"), "pcap-ns")
        self.assertEqual(detect_magic(b"\xa1\xb2\x3c\x4d"), "pcap-ns")
        self.assertEqual(detect_magic(b"\x0a\x0d\x0d\x0a"), "pcapng")

    def test_unknown_and_short(self):
        self.assertIsNone(detect_magic(b"NOPE"))
        self.assertIsNone(detect_magic(b"NO"))
        self.assertIsNone(detect_magic(b""))


class PcapStreamParserTest(unittest.TestCase):
    def test_full_feed(self):
        parser = PcapStreamParser()
        data = minimal_pcap()
        parser.feed(data)
        self.assertEqual(parser.kind, "pcap")
        self.assertEqual(parser.finish(), data)

    def test_pcapng_magic_accepted(self):
        parser = PcapStreamParser()
        data = minimal_pcapng()
        parser.feed(data)
        self.assertEqual(parser.kind, "pcapng")
        self.assertEqual(parser.finish(), data)

    def test_split_feed_in_random_chunks(self):
        data = minimal_pcap() + PACKET_RECORD
        parser = PcapStreamParser()
        step = 7
        for index in range(0, len(data), step):
            parser.feed(data[index:index + step])
        self.assertEqual(parser.finish(), data)

    def test_byte_by_byte_feed(self):
        data = minimal_pcap()
        parser = PcapStreamParser()
        for byte in data:
            parser.feed(bytes([byte]))  # 半包：魔数收齐前不允许报错
        self.assertEqual(parser.kind, "pcap")
        self.assertEqual(parser.finish(), data)

    def test_bad_magic_raises_on_feed(self):
        parser = PcapStreamParser()
        with self.assertRaises(ValueError):
            parser.feed(b"NOT A PCAP AT ALL")
        self.assertIn("魔数", str(parser.broken))
        with self.assertRaises(ValueError):
            parser.feed(b"more garbage")
        with self.assertRaises(ValueError):
            parser.finish()

    def test_short_stream_without_magic_is_incomplete(self):
        parser = PcapStreamParser()
        parser.feed(b"\xd4\xc3")
        with self.assertRaises(ValueError):
            parser.finish()

    def test_truncated_global_header(self):
        parser = PcapStreamParser()
        parser.feed(GLOBAL_HEADER[:PCAP_HEADER_LEN - 6])
        with self.assertRaises(ValueError):
            parser.finish()
        self.assertIn("不完整", str(parser.broken))

    def test_truncated_pcapng_header(self):
        parser = PcapStreamParser()
        parser.feed(minimal_pcapng()[:PCAPNG_HEADER_LEN - 4])
        with self.assertRaises(ValueError):
            parser.finish()

    def test_empty_stream(self):
        parser = PcapStreamParser()
        parser.feed(b"")
        with self.assertRaises(ValueError):
            parser.finish()


class PcapOverIPServerTest(unittest.TestCase):
    """End-to-end: real socket -> save under patched cache -> JobManager job."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name) / "cache"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", self.cache),
            mock.patch("fnet.paths.CACHE_DIR", self.cache),
            mock.patch("fnet.pcapoip.CACHE_DIR", self.cache),
        ]
        for patch in self.patches:
            patch.start()
        self.runtime = build(Config(Path(self.tmp.name) / "config.ini"))
        self.job_event = threading.Event()
        self.server = PcapOverIPServer(
            self.runtime, 0, host="127.0.0.1",
            features=["checkBox_10"],
            on_job=lambda job: self.job_event.set())
        self.server.start()

    def tearDown(self):
        try:
            for job in self.server.jobs:
                if job.thread is not None:
                    job.thread.join(timeout=120)
        finally:
            self.server.stop()
            for patch in reversed(self.patches):
                patch.stop()
            self.tmp.cleanup()

    def _send(self, payload: bytes) -> None:
        with socket.create_connection((self.server.host, self.server.port),
                                      timeout=10) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            # 等服务器读走全部字节再关闭连接。
            deadline = time.time() + 10
            while time.time() < deadline:
                if self.job_event.is_set() or self.server.errors:
                    break
                time.sleep(0.02)

    def test_stream_creates_job_and_saves_capture(self):
        data = minimal_pcap()
        self._send(data)
        self.assertTrue(self.job_event.wait(timeout=15), "任务未被创建")
        self.assertEqual(len(self.server.jobs), 1)
        job = self.server.jobs[0]
        self.assertIs(self.runtime.jobs.get(job.id), job)
        saved = Path(job.pcap)
        self.assertEqual(saved.parent, self.cache / "pcap-over-ip")
        self.assertEqual(saved.suffix, ".pcap")
        self.assertTrue(saved.is_file())
        self.assertEqual(saved.read_bytes(), data)
        self.assertEqual(job.features[0].checkbox, "checkBox_10")

    def test_bad_magic_creates_no_job(self):
        self._send(b"this is not a pcap stream")
        deadline = time.time() + 5
        while time.time() < deadline and not self.server.errors:
            time.sleep(0.05)
        self.assertTrue(self.server.errors)
        self.assertIn("魔数", self.server.errors[-1])
        self.assertEqual(self.server.jobs, [])

    def test_truncated_header_creates_no_job(self):
        self._send(GLOBAL_HEADER[:10])
        deadline = time.time() + 5
        while time.time() < deadline and not self.server.errors:
            time.sleep(0.05)
        self.assertTrue(self.server.errors)
        self.assertEqual(self.server.jobs, [])

    def test_default_features_are_registry_defaults(self):
        server = PcapOverIPServer(self.runtime, 0, host="127.0.0.1")
        defaults = [feature.checkbox for feature in FEATURES if feature.default]
        self.assertEqual(server.features, defaults)
        # 缺省监听地址不写死 0.0.0.0
        self.assertEqual(server.host, "127.0.0.1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
