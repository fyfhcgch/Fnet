"""Unit tests for the WebUI service helpers (no tshark needed)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet import services


class FakeToolbox:
    def __init__(self, wireshark: str | None) -> None:
        self.wireshark = wireshark

    def path(self, key: str) -> str | None:
        return self.wireshark if key == "wireshark" else None


class ServicesTest(unittest.TestCase):
    def test_clamp_frame(self):
        self.assertEqual(services.clamp_frame("12"), 12)
        self.assertEqual(services.clamp_frame(1), 1)
        self.assertIsNone(services.clamp_frame("0"))
        self.assertIsNone(services.clamp_frame("-3"))
        self.assertIsNone(services.clamp_frame("abc"))
        self.assertIsNone(services.clamp_frame(""))
        self.assertIsNone(services.clamp_frame("1000000001"))

    def test_clamp_context(self):
        self.assertEqual(services.clamp_context("3"), 3)
        self.assertEqual(services.clamp_context("abc"), 2)
        self.assertEqual(services.clamp_context("-1"), 0)
        self.assertEqual(services.clamp_context("999"), 20)
        self.assertEqual(services.clamp_context("4", default=1, maximum=5), 4)

    def test_frame_range_stops_at_one(self):
        self.assertEqual(services.frame_range(2, 2), (1, 4))
        self.assertEqual(services.frame_range(10, 3), (7, 13))

    def test_open_wireshark_uses_argument_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
            with mock.patch.object(services.subprocess, "Popen") as popen:
                result = services.open_wireshark(
                    str(pcap), "7", FakeToolbox("/usr/bin/wireshark"))
        self.assertTrue(result["ok"])
        args, kwargs = popen.call_args
        self.assertEqual(args[0][:2], ["/usr/bin/wireshark", "-r"])
        self.assertIn("frame.number == 7", args[0])
        self.assertFalse(kwargs.get("shell", False))

    def test_open_wireshark_requires_tool_and_capture(self):
        result = services.open_wireshark(
            "/nonexistent/sample.pcap", 7, FakeToolbox("/usr/bin/wireshark"))
        self.assertFalse(result["ok"])
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
            result = services.open_wireshark(str(pcap), 7, FakeToolbox(None))
        self.assertFalse(result["ok"])
        self.assertIn("Wireshark", result["text"])

    def test_bucket_timeline_aggregates_samples(self):
        points, low, high = services.bucket_timeline(
            [("0.0", "100"), ("1.0", "200"), ("2.0", "300")], buckets=3)
        self.assertEqual((low, high), (0.0, 2.0))
        self.assertEqual(len(points), 3)
        self.assertEqual(sum(point["frames"] for point in points), 3)
        self.assertEqual(sum(point["bytes"] for point in points), 600)
        self.assertEqual(points[0]["time"], 0.0)
        self.assertAlmostEqual(points[2]["time"], 4 / 3)

    def test_bucket_timeline_skips_invalid_rows(self):
        points, low, high = services.bucket_timeline(
            [("abc", "1"), ("", ""), ("3.0", "bad")], buckets=4)
        self.assertEqual(len(points), 4)
        self.assertEqual((low, high), (3.0, 3.0))
        self.assertEqual(sum(point["frames"] for point in points), 1)
        self.assertEqual(points[0]["frames"], 1)
        self.assertEqual(points[0]["bytes"], 0)

    def test_bucket_timeline_empty_and_clamped(self):
        self.assertEqual(services.bucket_timeline([], 10), ([], 0.0, 0.0))
        points, _low, _high = services.bucket_timeline([("1", "1")], buckets=0)
        self.assertEqual(len(points), 1)
        points, _low, _high = services.bucket_timeline([("1", "1")], buckets=999)
        self.assertEqual(len(points), 240)


if __name__ == "__main__":
    unittest.main()
