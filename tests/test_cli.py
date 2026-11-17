"""Unit tests for the CLI argument layer (no jobs are actually run)."""
from __future__ import annotations

import contextlib
import io
import unittest

from fnet import __version__
from fnet.cli import (
    _collect_params,
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

    def test_unregistered_handler_name_is_kept(self):
        self.assertEqual(select_features("webshell.decrypt", False),
                         ["webshell.decrypt"])


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


if __name__ == "__main__":
    unittest.main()
