"""Unit tests for the CLI argument layer (no jobs are actually run)."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet import __version__
from fnet.cli import (
    FeatureSelectionError,
    _collect_params,
    _ensure_utf8_streams,
    build_parser,
    list_features,
    main,
    parse_params,
    select_features,
)
from fnet.features.registry import FEATURES


class ParseParamsTest(unittest.TestCase):
    def test_key_value_pairs(self):
        self.assertEqual(parse_params(["key=value", "n=42"]),
                         {"key": "value", "n": "42"})

    def test_boolean_values(self):
        params = parse_params(["a=true", "b=yes", "c=on", "d=false",
                               "e=no", "f=off"])
        self.assertEqual(params, {"a": True, "b": True, "c": True,
                                  "d": False, "e": False, "f": False})

    def test_flag_without_value_defaults_to_one(self):
        self.assertEqual(parse_params(["decode"]), {"decode": "1"})

    def test_empty_key_is_skipped(self):
        self.assertEqual(parse_params(["=value", "  =x"]), {})

    def test_value_may_contain_equals(self):
        self.assertEqual(parse_params(["regex=flag\\{.+\\}"]),
                         {"regex": "flag\\{.+\\}"})


class SelectFeaturesTest(unittest.TestCase):
    def test_empty_spec_selects_defaults(self):
        expected = [f.checkbox for f in FEATURES if f.default]
        self.assertEqual(select_features("", False), expected)

    def test_run_all_selects_every_checkbox(self):
        self.assertEqual(select_features("", True),
                         [f.checkbox for f in FEATURES])

    def test_checkbox_and_handler_names(self):
        checkbox = next(f for f in FEATURES
                        if f.handler == "http.extract").checkbox
        self.assertEqual(select_features(checkbox, False), [checkbox])
        self.assertEqual(select_features("http.extract", False), [checkbox])

    def test_deduplicates_and_keeps_order(self):
        features = select_features("checkBox_10, checkBox_10", False)
        self.assertEqual(features, ["checkBox_10"])

    def test_unknown_name_raises(self):
        with self.assertRaises(SystemExit):
            select_features("no_such_feature", False)

    def test_unknown_dotted_handler_raises(self):
        # ``foo.bar`` 曾经被无条件放行，只在运行时才失败。
        with self.assertRaises(FeatureSelectionError):
            select_features("foo.bar", False)
        # 同一个异常类型也是 ValueError，所有调用方都能映射到退出码 2。
        with self.assertRaises(ValueError):
            select_features("foo.bar", False)

    def test_unregistered_handler_name_is_kept(self):
        self.assertEqual(select_features("webshell.decrypt", False),
                         ["webshell.decrypt"])

    def test_other_checkboxless_handlers_still_resolve(self):
        self.assertEqual(select_features("flows.http_login", False),
                         ["flows.http_login"])


class BuildParserTest(unittest.TestCase):
    def test_feature_and_params(self):
        args = build_parser().parse_args(
            ["-C", "a.pcap", "--features", "checkBox_10,http.extract",
             "--param", "sql_regex=(\\d+)", "--param", "decode=false"])
        self.assertTrue(args.cli)
        self.assertEqual(args.capture, "a.pcap")
        self.assertEqual(args.features, "checkBox_10,http.extract")
        self.assertEqual(args.param, ["sql_regex=(\\d+)", "decode=false"])

    def test_compare_takes_two_jobs(self):
        args = build_parser().parse_args(["--compare", "job1", "job2"])
        self.assertEqual(args.compare, ["job1", "job2"])

    def test_pcap_over_ip_port(self):
        args = build_parser().parse_args(["--pcap-over-ip", "18000"])
        self.assertEqual(args.pcap_over_ip, 18000)

    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertFalse(args.cli)
        self.assertFalse(args.all)
        self.assertFalse(args.json)
        self.assertEqual(args.shards, 1)


class CollectParamsTest(unittest.TestCase):
    def test_flags_map_to_handler_params(self):
        args = build_parser().parse_args([
            "--param", "sql_success=TRUE",
            "--rules", "rules.json",
            "--wpa-psk", "secret",
            "--keytab", "krb.keytab",
            "--kerberos-password", "pw",
            "--kerberos-key", "aabb",
        ])
        params = _collect_params(args)
        # --param values go through parse_params, so booleans are coerced.
        self.assertEqual(params["sql_success"], True)
        self.assertEqual(params["rules"], "rules.json")
        self.assertEqual(params["wifi_psk"], "secret")
        self.assertEqual(params["kerberos_keytab"], "krb.keytab")
        self.assertEqual(params["kerberos_password"], "pw")
        self.assertEqual(params["kerberos_key"], "aabb")


class ListFeaturesTest(unittest.TestCase):
    def test_lists_every_feature(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            list_features()
        output = buffer.getvalue()
        for feature in FEATURES:
            self.assertIn(feature.checkbox, output)
            self.assertIn(feature.title, output)
        self.assertIn("* = 默认勾选", output)


class Utf8ConsoleTest(unittest.TestCase):
    """Windows cp1252 控制台下中文输出不应触发 UnicodeEncodeError。"""

    def test_main_reconfigures_stdout_and_stderr(self):
        class Stream(io.StringIO):
            def __init__(self):
                super().__init__()
                self.calls = []

            def reconfigure(self, **kwargs):
                self.calls.append(kwargs)

        out, err = Stream(), Stream()
        with mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", err):
            self.assertEqual(main(["--version"]), 0)
        expected = {"encoding": "utf-8", "errors": "replace"}
        self.assertIn(expected, out.calls)
        self.assertIn(expected, err.calls)

    def test_streams_without_reconfigure_are_tolerated(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--version"]), 0)
        self.assertIn(f"Fnet {__version__}", buffer.getvalue())


class MainEarlyExitTest(unittest.TestCase):
    def test_version(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(main(["--version"]), 0)
        self.assertIn(f"Fnet {__version__}", buffer.getvalue())

    def test_list_features(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(main(["--list-features"]), 0)
        self.assertIn("checkBox_10", buffer.getvalue())


class ConfigSafetyTest(unittest.TestCase):
    """``Config`` 的原子保存与坏路径诊断。

    归属限制下这里只改 ``tests/test_cli.py``；这两个用例逻辑上属于
    ``tests/test_config.py``，后续可平移过去。
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-config-"))
        self.path = self.tmp / "config.ini"

    def test_save_is_atomic_and_leaves_no_temp_files(self):
        from fnet.config import Config

        config = Config(self.path)
        config.set("port", "9123")
        self.assertTrue(config.save())
        self.assertEqual(config.save_error, "")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()),
                         ["config.ini"])
        self.assertEqual(Config(self.path).get("port"), "9123")

    def test_unreadable_path_reports_load_error(self):
        from fnet.config import Config

        config = Config(Path("/nonexistent/dir/config.ini"))
        self.assertIn("无法读取配置文件", config.load_error)

    def test_unwritable_path_reports_save_error(self):
        from fnet.config import Config

        config = Config(self.path)
        config.path = Path("/nonexistent/dir/config.ini")
        self.assertFalse(config.save())
        self.assertIn("无法保存配置文件", config.save_error)


class BadConfigTest(unittest.TestCase):
    def test_unwritable_config_path_exits_2_with_chinese_message(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["--config", "/nonexistent/x.ini", "--doctor"])
        self.assertEqual(code, 2)
        text = buffer.getvalue()
        self.assertIn("无法读取配置文件", text)
        self.assertIn("/nonexistent/x.ini", text)

    def test_config_path_is_expanded(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["--config", "~/fnet-no-such-dir/x.ini", "--doctor"])
        self.assertEqual(code, 2)
        self.assertNotIn("~", buffer.getvalue())
        self.assertIn("fnet-no-such-dir", buffer.getvalue())


class BuildOnceTest(unittest.TestCase):
    def test_doctor_builds_once_and_passes_config(self):
        tmp = Path(tempfile.mkdtemp(prefix="fnet-cli-"))
        path = tmp / "config.ini"
        with mock.patch("fnet.cli.build") as fake_build:
            runtime = mock.Mock()
            runtime.config.path = path
            runtime.toolbox.TOOL_NAMES = []
            fake_build.return_value = runtime
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--config", str(path), "--doctor"]), 0)
        self.assertEqual(fake_build.call_count, 1)
        config = fake_build.call_args.args[0]
        self.assertIsNotNone(config)
        self.assertEqual(config.path, path)


if __name__ == "__main__":
    unittest.main()
