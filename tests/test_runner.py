"""Tests for the tshark disk cache, retry path and field caps."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.tools import runner
from fnet.tools.runner import TShark, find_tool

DATA = Path(__file__).resolve().parent / "data" / "http_ntlm.pcap"
TSHARK = find_tool("tshark", "")


@unittest.skipUnless(TSHARK, "需要 tshark")
class TSharkCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name) / "cache"
        self.cache.mkdir()
        self.patch = mock.patch("fnet.paths.CACHE_DIR", self.cache)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_second_query_hits_disk_cache(self):
        sh = TShark(TSHARK, cache=True, retries=0)
        first = sh.fields(DATA, ["frame.number", "frame.protocols"],
                          "http.request")
        self.assertTrue(first)
        cache_files = list((self.cache / "tshark").glob("*.tsv"))
        self.assertEqual(len(cache_files), 1)
        # Any further tshark spawn must be unnecessary: fail loudly if it is.
        with mock.patch.object(runner, "run",
                               side_effect=AssertionError("cache miss")):
            second = sh.fields(DATA, ["frame.number", "frame.protocols"],
                               "http.request")
        self.assertEqual(first, second)

    def test_cache_can_be_disabled(self):
        sh = TShark(TSHARK, cache=False, retries=0)
        sh.fields(DATA, ["frame.number"], "http.request")
        self.assertFalse((self.cache / "tshark").exists()
                         and any((self.cache / "tshark").iterdir()))


class TSharkRetryTest(unittest.TestCase):
    def test_retry_after_timeout(self):
        sh = TShark("/usr/bin/tshark", cache=False, retries=2)
        sh.known_fields = lambda: {"frame.number"}  # type: ignore[method-assign]
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if len(calls) == 1:
                return 124, ""
            return 0, '"1"\n"2"\n'

        with mock.patch.object(runner, "run", side_effect=fake_run):
            rows = sh.fields("capture.pcap", ["frame.number"])
        self.assertEqual(rows, [["1"], ["2"]])
        self.assertEqual(len(calls), 2)

    def test_retry_gives_up_and_reports(self):
        sh = TShark("/usr/bin/tshark", cache=False, retries=1)
        sh.known_fields = lambda: {"frame.number"}  # type: ignore[method-assign]
        with mock.patch.object(runner, "run", return_value=(124, "")):
            self.assertEqual(sh.fields("capture.pcap", ["frame.number"]), [])


class TSharkCapTest(unittest.TestCase):
    def setUp(self):
        self.sh = TShark("/usr/bin/tshark", cache=False, retries=0,
                         max_field_bytes=8, max_rows=2)
        self.sh.known_fields = lambda: {"frame.number"}  # type: ignore[method-assign]

    def test_field_truncation(self):
        with mock.patch.object(
                runner, "run",
                return_value=(0, '"' + "a" * 40 + '"\n')):
            rows = self.sh.fields("capture.pcap", ["frame.number"])
        self.assertEqual(rows, [["aaaaaaaa…[已截断]"]])

    def test_row_cap(self):
        with mock.patch.object(
                runner, "run",
                return_value=(0, '"1"\n"2"\n"3"\n')):
            rows = self.sh.fields("capture.pcap", ["frame.number"])
        self.assertEqual(rows, [["1"], ["2"]])


if __name__ == "__main__":
    unittest.main()
