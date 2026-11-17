"""Deep flag scan helpers and end-to-end assertions."""
from __future__ import annotations

import base64
import tempfile
import time
import unittest
from pathlib import Path

from fnet.features import flag_deep
from fnet.tools.runner import find_tool
from fnet.utils import protocol_detect

DATA = Path(__file__).resolve().parent / "data"


class FlagCollectorTest(unittest.TestCase):
    def test_placeholder_suppression(self):
        self.assertTrue(flag_deep.is_placeholder("flag{test}"))
        self.assertTrue(flag_deep.is_placeholder("flag{example}"))
        self.assertTrue(flag_deep.is_placeholder("flag{xxxx}"))
        self.assertFalse(flag_deep.is_placeholder("flag{real_value}"))
        collector = flag_deep.FlagCollector()
        self.assertFalse(collector.add("flag{test}", source="x", confidence="高"))
        self.assertTrue(collector.add("flag{real_value}", source="x",
                                     confidence="高"))

    def test_collector_prefers_high_confidence(self):
        collector = flag_deep.FlagCollector()
        collector.add("flag{abc}", source="strings", confidence="中", frame="1")
        collector.add("flag{abc}", source="stream", confidence="高", frame="2")
        collector.add("flag{abc}", source="stream", confidence="高", frame="3")
        items = collector.sorted()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["confidence"], "高")
        self.assertEqual(items[0]["source"], "stream")
        self.assertIn("2", items[0]["frame"])

    def test_decoded_views_base64_and_hex(self):
        flag = b"flag{deep_view}"
        views = flag_deep.decoded_views(base64.b64encode(flag))
        self.assertTrue(any("base64" == label for label, _text in views))
        self.assertTrue(any("flag{deep_view}" in text for _l, text in views))
        hex_views = flag_deep.decoded_views(flag.hex().encode())
        self.assertTrue(any("hex" == label for label, _text in hex_views))

    def test_decoded_views_strings_and_url(self):
        views = flag_deep.decoded_views(b"\x00\x01flag%7Burl_view%7D\x00")
        self.assertTrue(any(label == "url" for label, _text in views))
        self.assertTrue(any("flag{url_view}" in text for _l, text in views))


class ConfidenceTest(unittest.TestCase):
    def test_strong_and_weak_scores(self):
        self.assertEqual(protocol_detect.detect_protocol_scored(
            b"\xfeSMB" + b"\x00" * 20)[1], 95)
        self.assertGreaterEqual(protocol_detect.detect_protocol_scored(
            b"*1\r\n$4\r\nPING\r\n")[1], 60)
        self.assertEqual(protocol_detect.detect_protocol_scored(
            b"\x00" * 4), ("", 0))


@unittest.skipUnless(find_tool("tshark", ""), "需要 tshark")
class DeepScanJobTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from unittest import mock

        from fnet.app import build
        from fnet.config import Config

        cls.tmp = tempfile.TemporaryDirectory()
        cls.cache = Path(cls.tmp.name) / "cache"
        cls.cache.mkdir()
        cls.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cls.cache),
            mock.patch("fnet.paths.CACHE_DIR", cls.cache),
        ]
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        for patch in cls.patches:
            patch.stop()
        cls.tmp.cleanup()

    def run_job(self, features):
        job = self.runtime.jobs.submit(str(DATA / "ftp_smtp_telnet.pcap"),
                                       features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        log = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, log

    def test_deep_scan_after_ftp(self):
        job, log = self.run_job(["checkBox_27", "text_scan.deep"])
        self.assertIn("深度 flag 扫描结果", log)
        self.assertIn("flag{ftp_download}", log)
        output = job.output_dir / "flags_deep.txt"
        self.assertTrue(output.is_file())
        text = output.read_text(encoding="utf-8")
        self.assertIn("flag{ftp_download}", text)
        self.assertIn("置信度", text)


if __name__ == "__main__":
    unittest.main()
