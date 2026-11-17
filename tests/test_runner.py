"""Tests for the tshark disk cache, retry path and field caps."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.tools import runner
from fnet.tools.runner import TShark, ToolBox, find_tool

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


class ToolBoxPathTest(unittest.TestCase):
    """用户路径配置的解析：``[config].tshark`` 优先，``[paths]`` 兜底。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = Config(self.root / "config.ini")
        self.toolbox = ToolBox(self.config)

    def _fake_tool(self, name: str) -> Path:
        exe = self.root / name
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
        return exe

    def test_config_section_override_is_honoured(self):
        """WebUI 把 tshark 路径写进 ``[config].tshark``，必须生效。"""
        exe = self._fake_tool("ui-tshark")
        self.config.set("tshark", str(exe), "config")
        self.assertEqual(self.toolbox.configured("tshark"), str(exe))
        self.assertEqual(self.toolbox.path("tshark"), str(exe))

    def test_paths_section_still_works_as_fallback(self):
        """旧配置文件用 ``[paths].tshark`` 时应继续生效。"""
        exe = self._fake_tool("legacy-tshark")
        self.config.set("tshark", "", "config")
        self.config.set("tshark", str(exe), "paths")
        self.assertEqual(self.toolbox.path("tshark"), str(exe))

    def test_config_section_wins_over_paths_section(self):
        """两处都填写时以 ``[config].tshark`` 为准。"""
        ui = self._fake_tool("ui-tshark")
        legacy = self._fake_tool("legacy-tshark")
        self.config.set("tshark", str(ui), "config")
        self.config.set("tshark", str(legacy), "paths")
        self.assertEqual(self.toolbox.path("tshark"), str(ui))

    def test_other_tools_keep_using_paths_section(self):
        """hashcat/john 等仍只读 ``[paths]``，不受 tshark 特殊处理影响。"""
        exe = self._fake_tool("fake-hashcat")
        self.config.set("hashcat", str(exe), "paths")
        # 写进 [config] 不应被采用（与改动前行为一致）。
        self.config.set("hashcat", str(self._fake_tool("wrong-hashcat")), "config")
        self.assertEqual(self.toolbox.configured("hashcat"), str(exe))
        self.assertEqual(self.toolbox.path("hashcat"), str(exe))

    def test_empty_override_falls_back_to_path_probe(self):
        """两处都为空时回落到 PATH 探测（不传用户路径）。"""
        self.config.set("tshark", "", "config")
        self.config.set("tshark", "", "paths")
        self.assertEqual(self.toolbox.configured("tshark"), "")
        with mock.patch.object(runner.shutil, "which",
                               return_value="/usr/bin/tshark"):
            self.assertEqual(self.toolbox.path("tshark"), "/usr/bin/tshark")


if __name__ == "__main__":
    unittest.main()
