"""核心层补齐测试。

覆盖此前缺少直接测试的核心模块：

* ``fnet/cli.py``     —— 参数解析、``--json``/``--compare``/``--resume`` 的函数级
  测试（不起 WebUI server，用 ``build(Config(...))`` 直连 runtime）；
* ``fnet/plugins.py`` —— 用户工具的增删、持久化与运行（临时 config.ini）；
* ``fnet/paths.py``   —— ``FNET_HOME``/``FNET_ASSETS``/``FNET_TOOLS`` 环境变量契约
  （``mock.patch.dict`` + ``importlib.reload``，测试后恢复）；
* ``fnet/config.py``  —— 内置默认值 + 用户覆盖 + 类型化访问器；
* ``fnet/logger.py``  —— 线程安全、历史缓冲上限、监听器与 JobLog 恢复。
"""
from __future__ import annotations

import argparse
import contextlib
import importlib
import io
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.tools.runner import find_tool

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data"
TSHARK = find_tool("tshark", "")

ENV_KEYS = ("FNET_HOME", "FNET_ASSETS", "FNET_TOOLS",
            "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME")


def reload_paths():
    import fnet.paths

    return importlib.reload(fnet.paths)


class _EnvReloader:
    """在修改过的环境下 reload ``fnet.paths``，退出时恢复原环境并再次 reload。"""

    def __init__(self, **overrides):
        self.saved = {key: os.environ.get(key) for key in ENV_KEYS}
        self.overrides = overrides

    def __enter__(self):
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        for key, value in self.overrides.items():
            os.environ[key] = value
        return reload_paths()

    def __exit__(self, *exc):
        for key in ENV_KEYS:
            os.environ.pop(key, None)
            if self.saved.get(key) is not None:
                os.environ[key] = self.saved[key]
        reload_paths()
        return False


# --------------------------------------------------------------------- cli
class ParseParamsTest(unittest.TestCase):
    def test_key_value_pairs(self):
        from fnet.cli import parse_params

        self.assertEqual(parse_params(["chunk_frames=5000", "sql_success=SUCCESS"]),
                         {"chunk_frames": "5000", "sql_success": "SUCCESS"})

    def test_boolean_conversion(self):
        from fnet.cli import parse_params

        params = parse_params(["sql_reverse=true", "decode=no", "on=yes", "off=off"])
        self.assertIs(params["sql_reverse"], True)
        self.assertIs(params["decode"], False)
        self.assertIs(params["on"], True)
        self.assertIs(params["off"], False)

    def test_flag_without_value_defaults_to_1(self):
        from fnet.cli import parse_params

        self.assertEqual(parse_params(["verbose"]), {"verbose": "1"})

    def test_empty_keys_are_dropped(self):
        from fnet.cli import parse_params

        self.assertEqual(parse_params(["=x", "  ", "k=1"]), {"k": "1"})


class SelectFeaturesTest(unittest.TestCase):
    def test_defaults_when_no_spec(self):
        from fnet.cli import select_features
        from fnet.features.registry import FEATURES

        expected = [feature.checkbox for feature in FEATURES if feature.default]
        self.assertEqual(select_features("", False), expected)

    def test_run_all_returns_every_checkbox(self):
        from fnet.cli import select_features
        from fnet.features.registry import FEATURES

        self.assertEqual(len(select_features("", True)), len(FEATURES))

    def test_checkbox_and_handler_names(self):
        from fnet.cli import select_features

        self.assertEqual(select_features("checkBox_39,checkBox_30", False),
                         ["checkBox_39", "checkBox_30"])
        self.assertEqual(select_features("ntlm.extract", False), ["checkBox_39"])
        self.assertEqual(select_features("checkBox_39,checkBox_39", False),
                         ["checkBox_39"])

    def test_unknown_token_without_dot_exits(self):
        from fnet.cli import select_features

        with self.assertRaises(SystemExit):
            select_features("checkBox_99", False)

    def test_dotted_unknown_handler_is_passthrough(self):
        from fnet.cli import select_features

        self.assertEqual(select_features("webshell.decrypt", False),
                         ["webshell.decrypt"])


class CollectParamsTest(unittest.TestCase):
    def test_cli_options_map_to_params(self):
        from fnet.cli import _collect_params

        args = argparse.Namespace(
            param=["sql_reverse=true"], rules="r.yar", wpa_psk="psk",
            keytab="kt", kerberos_password="pw", kerberos_key="abcd")
        params = _collect_params(args)
        self.assertEqual(params["sql_reverse"], True)
        self.assertEqual(params["rules"], "r.yar")
        self.assertEqual(params["wifi_psk"], "psk")
        self.assertEqual(params["kerberos_keytab"], "kt")
        self.assertEqual(params["kerberos_password"], "pw")
        self.assertEqual(params["kerberos_key"], "abcd")

    def test_empty_options_are_omitted(self):
        from fnet.cli import _collect_params

        args = argparse.Namespace(param=[], rules="", wpa_psk="",
                                  keytab="", kerberos_password="", kerberos_key="")
        self.assertEqual(_collect_params(args), {})


class BuildParserTest(unittest.TestCase):
    def test_defaults(self):
        from fnet.cli import build_parser

        args = build_parser().parse_args([])
        self.assertFalse(args.cli)
        self.assertEqual(args.features, "")
        self.assertEqual(args.shards, 1)
        self.assertIsNone(args.compare)
        self.assertFalse(args.json)

    def test_compare_takes_two_values(self):
        from fnet.cli import build_parser

        args = build_parser().parse_args(["--compare", "a", "b"])
        self.assertEqual(args.compare, ["a", "b"])

    def test_param_is_repeatable(self):
        from fnet.cli import build_parser

        args = build_parser().parse_args(
            ["--param", "a=1", "--param", "b=2"])
        self.assertEqual(args.param, ["a=1", "b=2"])


class CliHeadlessFunctionTest(unittest.TestCase):
    """``run_headless``/``run_resume``/``run_compare`` 的函数级测试（无 server）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = Path(self.tmp.name) / "cache"
        cache.mkdir()
        self.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cache),
            mock.patch("fnet.paths.CACHE_DIR", cache),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.runtime = build(Config(Path(self.tmp.name) / "config.ini"))
        self.runtime.config.set("tshark_cache", "0")

    def _args(self, **kwargs):
        base = dict(capture="", cli=True, host=None, port=None,
                    no_browser=False, config=None, features="checkBox_39",
                    all=False, param=[], json=False, rules="", shards=1,
                    resume="", compare=None, wpa_psk="", mcp=False,
                    pcap_over_ip=None, keytab="", kerberos_password="",
                    kerberos_key="", list_features=False, list_tools=False,
                    doctor=False, version=False)
        base.update(kwargs)
        return argparse.Namespace(**base)

    def test_headless_requires_capture(self):
        from fnet.cli import run_headless

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run_headless(self._args(), self.runtime), 2)
        self.assertEqual(run_headless(self._args(capture="nope.pcap"),
                                     self.runtime), 2)

    @unittest.skipUnless(TSHARK, "需要 tshark")
    def test_headless_plain_output_and_exit_code(self):
        from fnet.cli import run_headless

        stdout = io.StringIO()
        args = self._args(capture=str(DATA / "http_ntlm.pcap"))
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(run_headless(args, self.runtime), 0)
        text = stdout.getvalue()
        self.assertIn("报告", text)
        self.assertIn("结构化结果", text)

    @unittest.skipUnless(TSHARK, "需要 tshark")
    def test_headless_json_output(self):
        from fnet.cli import run_headless

        stdout = io.StringIO()
        args = self._args(capture=str(DATA / "http_ntlm.pcap"), json=True)
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(run_headless(args, self.runtime), 0)
        import json

        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["job"]["status"], "done")
        self.assertIn("artifacts", payload)
        self.assertGreater(payload["count"], 0)

    def test_resume_unknown_job(self):
        from fnet.cli import run_resume

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(
                run_resume(self._args(resume="0" * 16), self.runtime), 2)
        self.assertIn("不可恢复", stderr.getvalue())

    @unittest.skipUnless(TSHARK, "需要 tshark")
    def test_compare_two_jobs(self):
        from fnet.cli import run_compare

        first = self.runtime.jobs.submit(str(DATA / "http_ntlm.pcap"),
                                         ["checkBox_39"], {})
        second = self.runtime.jobs.submit(str(DATA / "http_ntlm.pcap"),
                                          ["checkBox_30"], {})
        for job in (first, second):
            deadline = time.time() + 120
            while job.status not in ("done", "error") and time.time() < deadline:
                time.sleep(0.05)
            self.assertEqual(job.status, "done", job.error)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(
                run_compare(self._args(compare=[first.id, second.id]),
                            self.runtime), 0)
        text = stdout.getvalue()
        self.assertIn("新增", text)
        self.assertIn("消失", text)
        self.assertIn("共有", text)

    def test_compare_unknown_jobs(self):
        from fnet.cli import run_compare

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(
                run_compare(self._args(compare=["0" * 16, "1" * 16]),
                            self.runtime), 2)
        self.assertIn("任务不存在", stderr.getvalue())

    # -- compare with human annotations ---------------------------------
    def _compare_job(self, findings):
        job = self.runtime.jobs.create(str(DATA / "http_ntlm.pcap"),
                                       ["checkBox_10"], {})
        job.findings = [dict(item) for item in findings]
        return job

    @staticmethod
    def _compare_findings():
        from fnet.findings import make

        return [make("credential", "Administrator::WORKGROUP", frame="4",
                     detail="NTLMv1"),
                make("flag", "flag{compare_same}", frame="9")]

    def test_compare_includes_annotation_differences(self):
        findings = self._compare_findings()
        base = self._compare_job(findings)
        target = self._compare_job(findings)
        self.runtime.jobs.set_annotation(
            target.id, 1, status="false_positive", note="同一条为误报")
        diff = self.runtime.jobs.compare(base.id, target.id)
        self.assertEqual(diff["counts"]["common"], 1)  # 未标注的 flag 仍共有
        self.assertEqual(diff["counts"]["added"], 1)
        self.assertEqual(diff["counts"]["removed"], 1)
        self.assertEqual(diff["added"][0]["summary"],
                         "Administrator::WORKGROUP")
        self.assertEqual(diff["added"][0]["annotation"]["status"],
                         "false_positive")
        self.assertIsNone(diff["removed"][0].get("annotation"))

    def test_compare_without_annotations_is_unchanged(self):
        findings = self._compare_findings()
        base = self._compare_job(findings)
        target = self._compare_job(findings)
        diff = self.runtime.jobs.compare(base.id, target.id)
        self.assertEqual(diff["counts"], {"base": 2, "target": 2,
                                          "added": 0, "removed": 0,
                                          "common": 2})
        self.assertTrue(all("annotation" not in item
                            for item in diff["common"]))


# ----------------------------------------------------------------- plugins
class PluginManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = Path(self.tmp.name) / "config.ini"

    def _manager(self):
        from fnet.plugins import PluginManager

        return PluginManager(Config(self.config_path))

    def test_add_remove_and_persistence(self):
        manager = self._manager()
        manager.add("mytool", "echo hello world")
        self.assertEqual(manager.user_tools()["mytool"],
                         ["echo", "hello", "world"])
        # 重新读取同一 config 文件确认已持久化。
        self.assertEqual(self._manager().user_tools()["mytool"],
                         ["echo", "hello", "world"])
        self.assertTrue(manager.remove("mytool"))
        self.assertEqual(manager.user_tools(), {})
        self.assertFalse(manager.remove("mytool"))

    def test_add_uses_shlex_split(self):
        manager = self._manager()
        manager.add("quoted", 'wireshark -r "my file.pcap"')
        self.assertEqual(manager.user_tools()["quoted"],
                         ["wireshark", "-r", "my file.pcap"])

    def test_user_tools_with_corrupted_json(self):
        config = Config(self.config_path)
        config.set("execute_cmd", "{not json", "plugins")
        config.save()
        self.assertEqual(self._manager().user_tools(), {})

    def test_user_tools_accepts_list_specs(self):
        config = Config(self.config_path)
        config.set("execute_cmd", '{"t": ["ls", "-la"]}', "plugins")
        config.save()
        self.assertEqual(self._manager().user_tools()["t"], ["ls", "-la"])

    def test_as_list_contains_builtin_and_user_tools(self):
        from fnet.plugins import BUILTIN_TOOLS

        manager = self._manager()
        self.assertEqual([item["key"] for item in manager.as_list()][:1],
                         [BUILTIN_TOOLS[0]["key"]])
        manager.add("user1", "ls")
        items = manager.as_list()
        user = [item for item in items if item.get("source") == "user"]
        self.assertEqual(len(user), 1)
        self.assertEqual(user[0]["key"], "user1")

    def test_run_unregistered_tool(self):
        manager = self._manager()
        self.assertIn("未注册的工具", manager.run("ghost"))

    def test_run_executes_user_command(self):
        manager = self._manager()
        manager.add("hello", "echo fnet-plugin-ok")
        self.assertIn("fnet-plugin-ok", manager.run("hello"))
        self.assertIn("fnet-plugin-ok", manager.run("hello", "extra-target"))

    def test_run_reports_nonzero_exit(self):
        manager = self._manager()
        manager.add("false", "false")
        output = manager.run("false")
        self.assertIn("退出码", output)

    def test_run_cyberchef(self):
        manager = self._manager()
        with mock.patch("fnet.plugins.open_url", return_value=True) as opener:
            self.assertIn("CyberChef", manager.run("cyberchef"))
            opener.assert_called_once()

    def test_plugin_url_encodes_unsafe_characters(self):
        from fnet.plugins import plugin_url

        self.assertEqual(plugin_url("http://a.b/c d?x=1"),
                         "http://a.b/c%20d?x=1")


# ------------------------------------------------------------------- paths
class PathsEnvContractTest(unittest.TestCase):
    """FNET_HOME / FNET_ASSETS / FNET_TOOLS 环境变量契约。"""

    def test_fnet_home_relocates_user_log_and_cache_dirs(self):
        with _EnvReloader(FNET_HOME="/tmp/opencode/fnet-paths-home") as paths:
            self.assertEqual(paths.USER_DIR, Path("/tmp/opencode/fnet-paths-home"))
            self.assertEqual(paths.LOG_DIR,
                             Path("/tmp/opencode/fnet-paths-home/logs"))
            self.assertEqual(paths.CACHE_DIR,
                             Path("/tmp/opencode/fnet-paths-home/cache"))
            self.assertEqual(paths.USER_CONFIG,
                             Path("/tmp/opencode/fnet-paths-home/config.ini"))

    def test_fnet_assets_and_tools_override(self):
        with _EnvReloader(FNET_ASSETS="/tmp/opencode/assets",
                          FNET_TOOLS="/tmp/opencode/tools") as paths:
            self.assertEqual(paths.ASSETS_DIR, Path("/tmp/opencode/assets"))
            self.assertEqual(paths.TOOLS_DIR, Path("/tmp/opencode/tools"))
            self.assertEqual(paths.DEFAULT_CONFIG,
                             Path("/tmp/opencode/assets/config.ini"))

    def test_linux_xdg_fallback_without_fnet_home(self):
        with _EnvReloader(XDG_CONFIG_HOME="/tmp/opencode/xdg-config",
                          XDG_STATE_HOME="/tmp/opencode/xdg-state",
                          XDG_CACHE_HOME="/tmp/opencode/xdg-cache") as paths:
            self.assertEqual(paths.USER_DIR,
                             Path("/tmp/opencode/xdg-config/fnet"))
            self.assertEqual(paths.LOG_DIR,
                             Path("/tmp/opencode/xdg-state/fnet/logs"))
            self.assertEqual(paths.CACHE_DIR,
                             Path("/tmp/opencode/xdg-cache/fnet"))

    def test_default_layout_points_at_package_assets(self):
        with _EnvReloader() as paths:
            self.assertEqual(paths.ASSETS_DIR,
                             Path(paths.PACKAGE_DIR) / "assets")
            self.assertTrue(paths.DEFAULT_CONFIG.is_file())

    def test_ensure_dirs_creates_layout(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as base:
            home = Path(base) / "nested" / "home"
            with _EnvReloader(FNET_HOME=str(home)) as paths:
                paths.ensure_dirs()
                self.assertTrue(paths.LOG_DIR.is_dir())
                self.assertTrue(paths.CACHE_DIR.is_dir())

    def test_resource_and_wordlist_resolution(self):
        with _EnvReloader() as paths:
            self.assertTrue(paths.resource("config.ini").is_file())
            top = paths.wordlist("top25000.txt")
            self.assertIsNotNone(top)
            self.assertEqual(Path(top).name, "top25000.txt")
            self.assertIsNone(paths.wordlist("definitely-missing.txt"))
            absolute = Path(tempfile.mkdtemp()) / "w.txt"
            absolute.write_text("abc\n")
            self.assertEqual(paths.wordlist(str(absolute)), absolute)
            default = paths.wordlist(None)
            self.assertTrue(default is None or Path(default).is_file())


# ------------------------------------------------------------------ config
class ConfigDefaultsTest(unittest.TestCase):
    def test_builtin_defaults_are_present(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        self.assertEqual(config.get("host"), "127.0.0.1")
        self.assertEqual(config.get_int("port"), 8765)
        self.assertEqual(config.get_int("thread_count"), 50)
        self.assertTrue(config.get_bool("open_browser"))
        self.assertGreater(len(config.regmatch()), 20)
        self.assertTrue(any("flag" in pattern for pattern in config.regmatch()))

    def test_typed_accessors_fall_back_on_garbage(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        config.set("port", "not-a-number")
        self.assertEqual(config.get_int("port", fallback=99), 99)
        config.set("tshark_timeout", "abc")
        self.assertEqual(config.get_float("tshark_timeout", fallback=1.5), 1.5)
        config.set("port", "9000")
        self.assertEqual(config.get_int("port"), 9000)
        self.assertEqual(config.get_float("sql_time_threshold"), 1.0)

    def test_get_bool_parsing(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        for raw, expected in (("1", True), ("true", True), ("yes", True),
                              ("0", False), ("no", False), ("garbage", False)):
            config.set("flag", raw)
            self.assertEqual(config.get_bool("flag"), expected, raw)

    def test_unknown_section_get_returns_fallback(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        self.assertEqual(config.get("anything", "no-such-section", "fb"), "fb")
        self.assertEqual(config.as_dict("no-such-section"), {})


class ConfigUserOverrideTest(unittest.TestCase):
    def test_user_file_overrides_defaults_only(self):
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / "config.ini"
        path.write_text("[config]\nport = 9999\ntheme = light\n",
                        encoding="utf-8")
        config = Config(path)
        self.assertEqual(config.get_int("port"), 9999)
        self.assertEqual(config.get("theme"), "light")
        # 其余键仍来自内置默认。
        self.assertEqual(config.get("host"), "127.0.0.1")
        self.assertGreater(len(config.regmatch()), 0)

    def test_missing_user_file_copies_default_config(self):
        tmp = Path(tempfile.mkdtemp())
        path = tmp / "config.ini"
        config = Config(path)
        self.assertTrue(path.is_file())
        self.assertEqual(config.get_int("port"), 8765)

    def test_save_set_roundtrip_and_new_section(self):
        path = Path(tempfile.mkdtemp()) / "config.ini"
        config = Config(path)
        config.set("font_size", "14")
        config.set("mykey", "v", "brand-new-section")
        config.save()
        again = Config(path)
        self.assertEqual(again.get("font_size"), "14")
        self.assertEqual(again.get("mykey", "brand-new-section"), "v")

    def test_set_many_and_as_dict(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        config.set_many({"a": "1", "b": "2"})
        data = config.as_dict()
        self.assertEqual(data["a"], "1")
        self.assertEqual(data["b"], "2")


class ConfigRecentFilesTest(unittest.TestCase):
    def test_recent_files_order_and_dedup(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        config.add_recent("/a.pcap")
        config.add_recent("/b.pcap")
        config.add_recent("/a.pcap")
        self.assertEqual(config.recent_files(), ["/a.pcap", "/b.pcap"])

    def test_recent_files_capped_at_twelve(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        for index in range(20):
            config.add_recent(f"/{index}.pcap")
        self.assertEqual(len(config.recent_files()), 12)
        self.assertEqual(config.recent_files()[0], "/19.pcap")

    def test_recent_files_empty(self):
        config = Config(Path(tempfile.mkdtemp()) / "config.ini")
        self.assertEqual(config.recent_files(), [])


# ------------------------------------------------------------------ logger
class LoggerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "test.log"

    def _logger(self, **kwargs):
        from fnet.logger import Logger

        return Logger(path=self.path, **kwargs)

    def test_log_records_levels_and_file_output(self):
        from fnet.logger import LEVEL_TAGS

        logger = self._logger()
        logger.debug("调试")
        logger.good("成功")
        logger.warn("警告")
        logger.error("错误")
        logger.log("无效级别文本", "bogus-level")  # 未知级别回落到 info
        records = logger.records_since(0)
        self.assertEqual([r.level for r in records],
                         ["debug", "good", "warn", "error", "info"])
        self.assertEqual(records[1].tag, "[+]")
        self.assertEqual(LEVEL_TAGS["good"], "[+]")
        self.assertTrue(all(r.tag == "[*]" for r in records[4:]))
        content = self.path.read_text(encoding="utf-8")
        self.assertIn("[-] 错误", content)

    def test_records_since_cursor_and_limit(self):
        logger = self._logger()
        for index in range(10):
            logger.info(str(index))
        first_two = logger.records_since(0, limit=2)
        self.assertEqual([r.text for r in first_two], ["0", "1"])
        later = logger.records_since(first_two[-1].seq)
        self.assertEqual(later[0].text, "2")
        self.assertEqual(len(logger.records_since(0, limit=3)), 3)

    def test_history_and_tail(self):
        logger = self._logger()
        for index in range(12):
            logger.info(f"msg-{index}")
        history = logger.history(limit=5)
        self.assertEqual(len(history), 5)
        self.assertIn("msg-11", history[-1])
        self.assertEqual(logger.tail(2)[-1].text, "msg-11")
        self.assertEqual(logger.last_seq, 12)

    def test_history_buffer_is_capped(self):
        logger = self._logger(keep=5)
        for index in range(20):
            logger.info(str(index))
        self.assertEqual(len(logger.records_since(0)), 5)
        self.assertEqual(logger.records_since(0)[0].text, "15")

    def test_thread_safety_sequence_and_count(self):
        logger = self._logger()
        errors: list[Exception] = []

        def worker(worker_id: int) -> None:
            try:
                for index in range(25):
                    logger.log(f"w{worker_id}-{index}", "info")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(errors, [])
        records = logger.records_since(0, limit=5000)
        self.assertEqual(len(records), 200)
        seqs = [r.seq for r in records]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), 200)
        self.assertEqual(logger.last_seq, 200)

    def test_subscribe_and_unsubscribe(self):
        logger = self._logger()
        seen: list[str] = []
        logger.subscribe(seen.append)
        logger.info("one")
        logger.unsubscribe(seen.append)
        logger.info("two")
        self.assertEqual([r.text for r in seen], ["one"])

    def test_bad_listener_does_not_break_logging(self):
        logger = self._logger()
        logger.subscribe(lambda _record: 1 / 0)
        logger.info("still logged")
        self.assertEqual(logger.records_since(0)[-1].text, "still logged")

    def test_clear_removes_memory_and_file(self):
        logger = self._logger()
        logger.info("bye")
        logger.clear()
        self.assertEqual(logger.records_since(0), [])
        self.assertFalse(self.path.exists())

    def test_echo_prints_to_stdout(self):
        logger = self._logger(echo=True)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            logger.info("echoed")
        self.assertIn("[*] echoed", stdout.getvalue())


class JobLogTest(unittest.TestCase):
    def setUp(self):
        from fnet.logger import JobLog, Logger

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sink = Logger(Path(self.tmp.name) / "sink.log")
        self.joblog = JobLog(self.sink, prefix="abc123")

    def test_log_forwards_to_sink_with_prefix(self):
        self.joblog.info("hello")
        records = self.joblog.records_since(0)
        self.assertEqual(records[0].text, "hello")
        self.assertEqual(records[0].seq, 1)
        sink_texts = [r.text for r in self.sink.records_since(0)]
        self.assertIn("[job:abc123] hello", sink_texts)

    def test_cursor_semantics(self):
        for index in range(5):
            self.joblog.info(str(index))
        self.assertEqual([r.text for r in self.joblog.records_since(0, limit=2)],
                         ["0", "1"])
        self.assertEqual(self.joblog.records_since(2)[0].text, "2")
        self.assertEqual(self.joblog.last_seq, 5)

    def test_seed_restores_dict_transcripts(self):
        self.joblog.seed([
            {"seq": 3, "time": "10:00:01", "level": "info", "text": "restored-3"},
            {"seq": 0, "time": "10:00:02", "level": "warn", "text": "restored-x"},
        ])
        records = self.joblog.records_since(0)
        self.assertEqual([r.text for r in records], ["restored-3", "restored-x"])
        self.assertEqual(records[0].seq, 3)
        self.assertEqual(records[1].seq, 4)  # 缺失 seq 的记录重新编号
        self.assertEqual(self.joblog.last_seq, 4)
        # 恢复后继续写日志，游标保持稳定。
        self.joblog.info("new")
        self.assertEqual(self.joblog.records_since(4)[0].text, "new")

    def test_seed_keeps_max_seq(self):
        self.joblog.seed([{"seq": 10, "time": "", "level": "info", "text": "a"}])
        self.joblog.info("b")
        self.assertEqual([r.seq for r in self.joblog.records_since(0)], [10, 11])

    def test_invalid_level_falls_back_to_info(self):
        self.joblog.log("text", "nope")
        self.assertEqual(self.joblog.records_since(0)[0].level, "info")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
