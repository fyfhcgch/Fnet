"""Tests for the tshark disk cache, retry path and field caps."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.tools import runner
from fnet.tools.runner import TShark, ToolBox, find_tool
from fnet.utils.pcap import hex_to_bytes

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


class CachePruneTest(unittest.TestCase):
    """B6：tshark 磁盘缓存必须有 TTL 与容量上限。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.now = time.time()

    def _touch(self, name: str, size: int, age: float) -> Path:
        path = self.dir / name
        path.write_text("x" * size, encoding="utf-8")
        stamp = self.now - age
        os.utime(path, (stamp, stamp))
        return path

    def test_ttl_evicts_only_stale_files(self):
        old = self._touch("old.tsv", 100, age=40 * 86_400)
        fresh = self._touch("fresh.tsv", 100, age=60)
        removed, freed = runner.prune_cache(self.dir, ttl_seconds=14 * 86_400,
                                           now=self.now)
        self.assertEqual((removed, freed), (1, 100))
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())

    def test_size_cap_evicts_least_recently_used(self):
        first = self._touch("a.tsv", 1000, age=300)
        second = self._touch("b.tsv", 1000, age=200)
        third = self._touch("c.tsv", 1000, age=100)
        removed, _ = runner.prune_cache(self.dir, max_bytes=2000, now=self.now)
        self.assertEqual(removed, 1)
        self.assertFalse(first.exists())
        self.assertTrue(second.exists() and third.exists())

    def test_non_tsv_files_are_never_deleted(self):
        keep = self.dir / "notes.txt"
        keep.write_text("important", encoding="utf-8")
        self._touch("a.tsv", 5000, age=0)
        runner.prune_cache(self.dir, max_bytes=1, now=self.now)
        self.assertTrue(keep.exists())

    def test_zero_limits_disable_eviction(self):
        self._touch("a.tsv", 5000, age=90 * 86_400)
        self.assertEqual(runner.prune_cache(self.dir, max_bytes=0,
                                            ttl_seconds=0, now=self.now),
                         (0, 0))

    def test_missing_directory_is_harmless(self):
        self.assertEqual(runner.prune_cache(self.dir / "nope", max_bytes=1),
                         (0, 0))

    def test_cache_hit_refreshes_mtime_for_lru(self):
        """命中缓存要刷新 mtime，否则常用条目会被当成最旧的淘汰掉。"""
        sh = TShark("/usr/bin/tshark", cache=True)
        path = self._touch("hit.tsv", 10, age=30 * 86_400)
        before = path.stat().st_mtime
        self.assertEqual(sh._read_cache(path), "x" * 10)
        self.assertGreater(path.stat().st_mtime, before)

    def test_write_triggers_prune_with_configured_limits(self):
        sh = TShark("/usr/bin/tshark", cache=True, cache_max_bytes=1000,
                    cache_ttl_seconds=0)
        self._touch("stale.tsv", 5000, age=1000)
        with mock.patch.object(runner, "_CACHE_LAST_PRUNE", {}):
            sh._write_cache(self.dir / "new.tsv", "data")
        # 刚写入的条目必须保留，最旧的被淘汰到容量上限以内。
        self.assertEqual([p.name for p in self.dir.glob("*.tsv")],
                         ["new.tsv"])


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

    def test_truncation_counts_bytes_not_characters(self):
        """CJK 文本按字节截断，不能超过 max_field_bytes。"""
        sh = TShark("/usr/bin/tshark", cache=False, retries=0,
                    max_field_bytes=8)
        sh.known_fields = lambda: {"frame.number"}  # type: ignore[method-assign]
        with mock.patch.object(
                runner, "run",
                return_value=(0, '"' + "中" * 10 + '"\n')):
            rows = sh.fields("capture.pcap", ["frame.number"])
        value = rows[0][0]
        self.assertTrue(value.endswith(runner.TRUNCATION_MARKER))
        body = value[:-len(runner.TRUNCATION_MARKER)]
        self.assertLessEqual(len(body.encode("utf-8")), 8)
        self.assertEqual(body, "中中")
        self.assertNotIn("\ufffd", value)

    def test_row_cap(self):
        with mock.patch.object(
                runner, "run",
                return_value=(0, '"1"\n"2"\n"3"\n')):
            rows = self.sh.fields("capture.pcap", ["frame.number"])
        self.assertEqual(rows, [["1"], ["2"]])

    def test_tool_warning_is_not_a_data_row(self):
        """root 警告（stderr 合并进 stdout）不能被当成一条记录。"""
        sh = TShark("/usr/bin/tshark", cache=False, retries=0)
        sh.known_fields = lambda: {"frame.number", "http.request.uri"}  # type: ignore[method-assign]
        output = ('Running as user "root" and group "root". '
                  'This could be dangerous.\n"1"\t"GET /"\n')
        with mock.patch.object(runner, "run", return_value=(0, output)):
            rows = sh.fields("capture.pcap",
                             ["frame.number", "http.request.uri"])
        self.assertEqual(rows, [["1", "GET /"]])

    def test_tshark_error_line_is_not_a_data_row(self):
        output = 'tshark: Some fields aren\'t valid\n"1"\n'
        with mock.patch.object(runner, "run", return_value=(0, output)):
            rows = self.sh.fields("capture.pcap", ["frame.number"])
        self.assertEqual(rows, [["1"]])


class KnownFieldsCacheTest(unittest.TestCase):
    """B1.1: 失败的 ``tshark -G fields`` 不得缓存空集合。"""

    def setUp(self):
        self.path = "/nonexistent/stub-tshark"
        runner._FIELD_CACHE.pop(self.path, None)
        self.addCleanup(runner._FIELD_CACHE.pop, self.path, None)

    def test_failure_is_not_cached_and_returns_none(self):
        sh = TShark(self.path, cache=False, retries=0)
        with mock.patch.object(runner, "run", return_value=(1, "")):
            self.assertIsNone(sh.known_fields())
        self.assertNotIn(self.path, runner._FIELD_CACHE)
        # 第二次仍会重试探测，而不是拿到缓存的空集合。
        good = "F\t0\tframe.number\tFT_UINT32\tframe\t0x0\n"
        with mock.patch.object(runner, "run",
                               return_value=(0, good)) as fake:
            self.assertEqual(sh.known_fields(), {"frame.number"})
        fake.assert_called_once()
        self.assertEqual(runner._FIELD_CACHE[self.path], {"frame.number"})

    def test_empty_success_is_cached_and_means_known_empty(self):
        sh = TShark(self.path, cache=False, retries=0)
        with mock.patch.object(runner, "run", return_value=(0, "")):
            self.assertEqual(sh.known_fields(), set())
        self.assertEqual(runner._FIELD_CACHE[self.path], set())
        with mock.patch.object(runner, "run",
                               side_effect=AssertionError("重新探测")):
            self.assertEqual(sh.known_fields(), set())

    def test_unknown_fields_queries_everything(self):
        """探测失败（None）时保持旧行为：不筛选字段。"""
        sh = TShark(self.path, cache=False, retries=0)
        sh.known_fields = lambda: None  # type: ignore[method-assign]
        with mock.patch.object(
                runner, "run", return_value=(0, '"1"\t"x"\n')) as fake:
            rows = sh.fields("capture.pcap", ["frame.number", "made.up"])
        self.assertEqual(rows, [["1", "x"]])
        self.assertIn("-e", fake.call_args[0][0])

    def test_stub_binary_reports_fields(self):
        """真实子进程桩：失败的 -G fields 不写缓存，之后恢复即生效。"""
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "stub-tshark"
            state = Path(tmp) / "state"
            stub.write_text(
                "#!/bin/sh\n"
                f"if [ -f {state} ]; then\n"
                "  printf 'F\\t0\\tframe.number\\tFT_UINT32\\tframe\\t0x0\\n'\n"
                "  exit 0\n"
                "fi\n"
                "exit 1\n",
                encoding="utf-8")
            stub.chmod(0o755)
            sh = TShark(str(stub), cache=False, retries=0)
            self.assertIsNone(sh.known_fields())
            self.assertNotIn(str(stub), runner._FIELD_CACHE)
            state.write_text("ok", encoding="utf-8")
            self.assertEqual(sh.known_fields(), {"frame.number"})
            runner._FIELD_CACHE.pop(str(stub), None)


class RunStdinTest(unittest.TestCase):
    """B1.3: ``stdin`` 只写一次，超时/取消不留孤儿进程。"""

    def test_stdin_is_written_once_and_child_exits(self):
        code, out = runner.run(
            [sys.executable, "-c",
             "import sys; data = sys.stdin.buffer.read(); print(len(data))"],
            stdin=b"hello", timeout=30, echo=False)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "5")

    def test_polling_does_not_raise_with_slow_child(self):
        start = time.monotonic()
        code, out = runner.run(
            [sys.executable, "-c",
             "import sys, time; sys.stdin.buffer.read(); time.sleep(0.7); "
             "print('done')"],
            stdin=b"x", timeout=30, echo=False)
        self.assertEqual(code, 0)
        self.assertIn("done", out)
        self.assertGreaterEqual(time.monotonic() - start, 0.5)

    def test_large_stdin_larger_than_pipe_buffer(self):
        """stdin 超过管道缓冲区（64K）也不能死锁或抛错。"""
        payload = b"x" * 300_000
        code, out = runner.run(
            [sys.executable, "-c",
             "import sys, time; time.sleep(0.3); "
             "print(len(sys.stdin.buffer.read()))"],
            stdin=payload, timeout=60, echo=False)
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "300000")

    def test_timeout_kills_child(self):
        code, out = runner.run(
            [sys.executable, "-c",
             "import sys, time; sys.stdin.buffer.read(); time.sleep(30)"],
            stdin=b"x", timeout=1, echo=False)
        self.assertEqual(code, 124)
        self.assertIn("超时", out)

    def test_cancel_kills_child(self):
        import threading

        cancel = threading.Event()
        cancel.set()
        code, out = runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cancel=cancel, timeout=60, echo=False)
        self.assertEqual(code, 130)
        self.assertIn("已取消", out)


class HexToBytesTest(unittest.TestCase):
    """B1.4: ``hex_to_bytes`` 统一语义。"""

    def test_plain_hex(self):
        self.assertEqual(hex_to_bytes("41"), b"A")
        self.assertEqual(hex_to_bytes("4142"), b"AB")

    def test_prefixed_hex(self):
        self.assertEqual(hex_to_bytes("0x41"), b"A")
        self.assertEqual(hex_to_bytes("0X4142"), b"AB")

    def test_separators_are_ignored(self):
        self.assertEqual(hex_to_bytes("41:42"), b"AB")
        self.assertEqual(hex_to_bytes("41-42"), b"AB")
        self.assertEqual(hex_to_bytes(" 41 42 "), b"AB")
        self.assertEqual(hex_to_bytes("41,42"), b"AB")
        self.assertEqual(hex_to_bytes("aa:bb:cc:dd:ee:ff"),
                         bytes.fromhex("aabbccddeeff"))

    def test_per_value_prefix_is_stripped(self):
        """tshark 多值字段 ``0x1301,0xc02f`` 每个片段都带前缀。"""
        self.assertEqual(hex_to_bytes("0x1301,0xc02f"),
                         bytes.fromhex("1301c02f"))
        self.assertEqual(hex_to_bytes("0x41,0x42"), b"AB")

    def test_odd_length_returns_empty(self):
        self.assertEqual(hex_to_bytes("414"), b"")
        self.assertEqual(hex_to_bytes("0x4"), b"")

    def test_invalid_input_returns_empty(self):
        self.assertEqual(hex_to_bytes(""), b"")
        self.assertEqual(hex_to_bytes("0x"), b"")
        self.assertEqual(hex_to_bytes("zz"), b"")
        self.assertEqual(hex_to_bytes(None), b"")


class FindToolTest(unittest.TestCase):
    """B11.13: CWD 同名文件不得覆盖系统路径，且必须可执行。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "cwd"
        self.cwd.mkdir()
        self.previous = os.getcwd()
        os.chdir(self.cwd)
        self.addCleanup(os.chdir, self.previous)
        patcher = mock.patch.object(runner, "TOOLS_DIR", self.root / "tools")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cwd_file_does_not_shadow_path_tool(self):
        decoy = self.cwd / "tshark"
        decoy.write_text("#!/bin/sh\necho evil\n", encoding="utf-8")
        decoy.chmod(0o755)
        with mock.patch.object(runner.shutil, "which",
                               return_value="/usr/bin/tshark"):
            self.assertEqual(find_tool("tshark", ""), "/usr/bin/tshark")

    def test_candidate_must_be_executable(self):
        tools = self.root / "tools"
        tools.mkdir()
        plain = tools / "fake-tool"
        plain.write_text("not executable", encoding="utf-8")
        plain.chmod(0o644)
        with mock.patch.object(runner.shutil, "which", return_value=None):
            self.assertIsNone(find_tool("fake-tool", ""))
        plain.chmod(0o755)
        with mock.patch.object(runner.shutil, "which", return_value=None):
            self.assertEqual(find_tool("fake-tool", ""), str(plain))

    def test_configured_override_must_be_executable(self):
        exe = self.root / "configured"
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o644)
        with mock.patch.object(runner.shutil, "which", return_value=None):
            self.assertIsNone(find_tool("configured", str(exe)))


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
