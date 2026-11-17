"""utils 层补齐测试。

覆盖此前缺少直接测试的工具模块（webshell 规则引擎已由
``tests/test_webshell_rules.py`` 覆盖，此处不重复）：

* ``fnet/utils/rules.py``  —— 正则/YARA 子集规则解析、规则文件加载与回退、
  规则匹配输出，以及 ``scan_pcap`` 对真实流量包的扫描；
* ``fnet/utils/system.py`` —— 可离线测试的纯函数部分（字体探测、桌面打开
  助手的平台分支，全部通过 mock 验证）。
"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fnet.tools.runner import find_tool
from fnet.utils import rules as rules_mod
from fnet.utils import system as system_mod

DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")

YARA_TEXT = """
rule credential_leak : credential
{
    meta:
        description = "password in clear text"
        severity = "warn"
    strings:
        $a = "password=" nocase
        $b = /passwd\\s*[:=]/ nocase
        $c = "PEPA" wide
    condition:
        any of them
}

rule strict_pair
{
    meta:
        desc = "both markers required"
        level = "good"
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        all of them
}

rule two_of_three
{
    strings:
        $a = "one"
        $b = "two"
        $c = "three"
    condition:
        2 of them
}

rule expr_rule
{
    strings:
        $a = "user"
        $b = "token"
    condition:
        $a and $b
}
"""

JSON_TEXT = """
{"rules": [
    {"name": "json_rule", "pattern": "flag\\\\{[^}]+\\\\}", "level": "good",
     "tags": ["ctf"], "description": "flag literal"},
    {"name": "multi_all", "patterns": ["foo", "bar"], "mode": "all"},
    {"name": "bad_pattern", "pattern": "("},
    {"no_name": true}
]}
"""


class RuleMatchesTest(unittest.TestCase):
    def _rule(self, **kwargs):
        patterns = kwargs.pop("patterns", ["alpha"])
        return rules_mod.Rule(name="r", patterns=[
            rules_mod._compile(p) for p in patterns], **kwargs)

    def test_mode_any(self):
        rule = self._rule(patterns=["alpha", "beta"], mode="any")
        self.assertEqual(rule.matches("has alpha here"), (True, 1))
        self.assertEqual(rule.matches("nothing"), (False, 0))
        self.assertEqual(rule.matches("alpha beta"), (True, 2))

    def test_mode_all(self):
        rule = self._rule(patterns=["alpha", "beta"], mode="all")
        self.assertEqual(rule.matches("alpha"), (False, 1))
        self.assertEqual(rule.matches("alpha and beta"), (True, 2))

    def test_mode_count(self):
        rule = self._rule(patterns=["x1", "x2", "x3", "x4"], mode="count", count=3)
        self.assertEqual(rule.matches("x1 x2"), (False, 2))
        self.assertEqual(rule.matches("x1 x2 x3"), (True, 3))

    def test_mode_expr_and_or_not(self):
        rule = self._rule(patterns=["user", "token"], mode="expr",
                          expression="$a and $b")
        self.assertEqual(rule.matches("user token"), (True, 2))
        self.assertEqual(rule.matches("user only"), (False, 1))
        rule.expression = "$a or not $b"
        self.assertEqual(rule.matches("user only"), (True, 1))
        self.assertEqual(rule.matches("token only"), (False, 1))

    def test_malformed_expression_falls_back_to_any(self):
        rule = self._rule(patterns=["user", "token"], mode="expr",
                          expression="$a and ($b or")
        self.assertEqual(rule.matches("user token"), (True, 2))
        self.assertEqual(rule.matches("user"), (True, 1))

    def test_no_patterns_never_matches(self):
        rule = rules_mod.Rule(name="empty", patterns=[], mode="any")
        self.assertEqual(rule.matches("anything"), (False, 0))

    def test_invalid_regex_compiles_to_none(self):
        self.assertIsNone(rules_mod._compile("("))


class ParseLineRulesTest(unittest.TestCase):
    def test_named_and_unnamed_rules(self):
        text = ("# 注释行\n"
                "ntlm = NTLMSSP\n"
                "http_auth: Authorization\n"
                "plainword\n")
        found = rules_mod.parse_line_rules(text)
        self.assertEqual([rule.name for rule in found],
                         ["ntlm", "http_auth", "line_4"])
        self.assertTrue(found[0].matches("NTLMSSP token"))
        self.assertEqual(len(found[0].patterns), 1)

    def test_invalid_lines_skipped(self):
        text = "bad = (\nok = valid\n"
        found = rules_mod.parse_line_rules(text)
        self.assertEqual([rule.name for rule in found], ["ok"])

    def test_comment_only_file_yields_nothing(self):
        self.assertEqual(rules_mod.parse_line_rules("# nothing\n\n"), [])


class ParseYaraTest(unittest.TestCase):
    def test_rules_are_parsed(self):
        found = rules_mod.parse_yara(YARA_TEXT)
        self.assertEqual([rule.name for rule in found],
                         ["credential_leak", "strict_pair", "two_of_three",
                          "expr_rule"])

    def test_meta_and_tags(self):
        rule = rules_mod.parse_yara(YARA_TEXT)[0]
        self.assertEqual(rule.tags, ["credential"])
        self.assertEqual(rule.description, "password in clear text")
        self.assertEqual(rule.level, "warn")
        strict = rules_mod.parse_yara(YARA_TEXT)[1]
        self.assertEqual(strict.description, "both markers required")
        self.assertEqual(strict.level, "good")

    def test_string_modifiers(self):
        rule = rules_mod.parse_yara(YARA_TEXT)[0]
        self.assertEqual(len(rule.patterns), 3)
        self.assertTrue(rule.patterns[0].search("PASSWORD=root"))
        self.assertTrue(rule.patterns[1].search("passwd: secret"))
        self.assertTrue(rule.patterns[2].search("P\x00E\x00P\x00A\x00"))

    def test_conditions(self):
        found = rules_mod.parse_yara(YARA_TEXT)
        self.assertEqual(found[0].mode, "any")
        self.assertEqual(found[1].mode, "all")
        self.assertEqual((found[2].mode, found[2].count), ("count", 2))
        self.assertEqual(found[3].mode, "expr")
        self.assertEqual(found[3].expression, "$a and $b")
        # 行为验证：2 of them / all of them / 布尔表达式。
        self.assertTrue(found[2].matches("one two"))
        self.assertEqual(found[2].matches("one only")[0], False)
        self.assertEqual(found[1].matches("alpha")[0], False)
        self.assertTrue(found[3].matches("user token"))
        self.assertEqual(found[3].matches("alpha beta")[0], False)

    def test_rule_without_strings_is_dropped(self):
        text = ("rule empty\n{\n    condition:\n        true\n}\n")
        self.assertEqual(rules_mod.parse_yara(text), [])


class ParseJsonTest(unittest.TestCase):
    def test_dict_with_rules_key(self):
        found = rules_mod.parse_json(JSON_TEXT)
        self.assertEqual([rule.name for rule in found],
                         ["json_rule", "multi_all"])
        self.assertEqual(found[0].level, "good")
        self.assertEqual(found[0].tags, ["ctf"])
        self.assertEqual(found[0].description, "flag literal")
        self.assertEqual(found[1].mode, "all")
        self.assertTrue(found[0].matches("flag{json_rule}"))
        self.assertEqual(found[1].matches("foo only")[0], False)

    def test_bare_list_and_bad_items(self):
        text = '[{"name": "solo", "pattern": "abc"}]'
        found = rules_mod.parse_json(text)
        self.assertEqual([rule.name for rule in found], ["solo"])
        self.assertEqual(rules_mod.parse_json('{"nope": 1}'), [])
        # parse_json 对非法 JSON 会抛出 JSONDecodeError，由入口 parse_rules 兜底。
        self.assertEqual(rules_mod.parse_rules("not json at all", ".json"), [])

    def test_unknown_mode_coerced_to_any(self):
        found = rules_mod.parse_json(
            '[{"name": "m", "pattern": "a", "mode": "weird"}]')
        self.assertEqual(found[0].mode, "any")


class ParseRulesDispatchTest(unittest.TestCase):
    def test_json_detected_by_brace_or_suffix(self):
        self.assertEqual([r.name for r in rules_mod.parse_rules(JSON_TEXT)],
                         ["json_rule", "multi_all"])
        self.assertEqual(
            [r.name for r in rules_mod.parse_rules(JSON_TEXT, ".json")],
            ["json_rule", "multi_all"])

    def test_yara_detected(self):
        found = rules_mod.parse_rules(YARA_TEXT, ".yar")
        self.assertEqual(found[0].name, "credential_leak")

    def test_line_rules_are_the_fallback(self):
        found = rules_mod.parse_rules("alpha = NTLM\n", ".txt")
        self.assertEqual([r.name for r in found], ["alpha"])

    def test_empty_input(self):
        self.assertEqual(rules_mod.parse_rules(""), [])
        self.assertEqual(rules_mod.parse_rules(None), [])


class LoadRulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_load_line_file(self):
        path = self.base / "rules.txt"
        path.write_text("ntlm = NTLMSSP\n", encoding="utf-8")
        found = rules_mod.load_rules(path)
        self.assertEqual(found[0].name, "ntlm")

    def test_missing_file_raises(self):
        with self.assertRaises(ValueError) as ctx:
            rules_mod.load_rules(self.base / "nope.yar")
        self.assertIn("不存在", str(ctx.exception))

    def test_empty_rules_file_raises(self):
        path = self.base / "empty.txt"
        path.write_text("# 只有注释\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            rules_mod.load_rules(path)
        self.assertIn("没有可用的规则", str(ctx.exception))

    def test_oversized_file_raises(self):
        path = self.base / "big.txt"
        with open(path, "wb") as handle:
            handle.truncate(rules_mod.MAX_RULE_FILE + 1)
        with self.assertRaises(ValueError) as ctx:
            rules_mod.load_rules(path)
        self.assertIn("过大", str(ctx.exception))


class MatchTextTest(unittest.TestCase):
    def test_finding_shape_and_label(self):
        rule = rules_mod.Rule(
            name="cred", patterns=[rules_mod._compile("password")],
            mode="any", description="cleartext password", tags=["secret"],
            level="good")
        hits = rules_mod.match_text([rule], "password=hunter2", frame="7",
                                    time="12:00", protocol="HTTP")
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["rule"], "cred")
        self.assertEqual(hit["frame"], "7")
        self.assertEqual(hit["protocol"], "HTTP")
        self.assertEqual(hit["hits"], 1)
        self.assertEqual(hit["level"], "good")
        self.assertIn("cleartext password", hit["summary"])
        self.assertIn("password=hunter2", hit["detail"])

    def test_invalid_level_normalized_to_warn(self):
        rule = rules_mod.Rule(name="x", patterns=[rules_mod._compile("a")],
                              level="banana")
        hit = rules_mod.match_text([rule], "aaa")[0]
        self.assertEqual(hit["level"], "warn")

    def test_no_match_and_empty_text(self):
        rule = rules_mod.Rule(name="x", patterns=[rules_mod._compile("zzz")])
        self.assertEqual(rules_mod.match_text([rule], "hello"), [])
        self.assertEqual(rules_mod.match_text([rule], ""), [])

    def test_snippet_with_and_without_pattern(self):
        text = "x" * 60 + "needle" + "y" * 400
        short = rules_mod.snippet(text)
        self.assertLessEqual(len(short), rules_mod.MAX_SNIPPET)
        self.assertNotIn("\n", short)
        anchored = rules_mod.snippet(text, rules_mod._compile("needle"))
        self.assertIn("needle", anchored)


@unittest.skipUnless(TSHARK, "需要 tshark")
class ScanPcapTest(unittest.TestCase):
    def setUp(self):
        from fnet.tools.runner import TShark

        self.tshark = TShark(TSHARK, cache=False)

    def _rules(self, *patterns):
        return [rules_mod.Rule(name=name, patterns=[rules_mod._compile(pattern)])
                for name, pattern in patterns]

    def test_scan_pcap_finds_ntlm_payloads(self):
        found = rules_mod.scan_pcap(
            self._rules(("ntlm", "NTLM")),
            str(DATA / "http_ntlm.pcap"), self.tshark)
        self.assertTrue(found)
        hit = found[0]
        self.assertEqual(hit["rule"], "ntlm")
        self.assertTrue(hit["frame"])
        self.assertIn("命中", hit["detail"])

    def test_scan_pcap_no_rules_or_no_tshark(self):
        self.assertEqual(rules_mod.scan_pcap([], str(DATA / "http_ntlm.pcap"),
                                             self.tshark), [])
        self.assertEqual(rules_mod.scan_pcap(
            self._rules(("ntlm", "NTLM")),
            str(DATA / "http_ntlm.pcap"), None), [])

    def test_scan_pcap_honours_cancel_event(self):
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(rules_mod.scan_pcap(
            self._rules(("ntlm", "NTLM")),
            str(DATA / "http_ntlm.pcap"), self.tshark, cancel=cancel), [])

    def test_decode_payload_handles_hex_and_garbage(self):
        self.assertEqual(rules_mod._decode_payload("66:6c:61:67"), "flag")
        self.assertEqual(rules_mod._decode_payload("6x"), "")
        self.assertEqual(rules_mod._decode_payload(""), "")


class SystemHelpersTest(unittest.TestCase):
    def test_default_mono_font_without_fc_match(self):
        with mock.patch.object(system_mod.shutil, "which", return_value=None):
            self.assertEqual(system_mod.default_mono_font(), "monospace")

    def test_default_mono_font_prefers_installed_candidate(self):
        fake = mock.MagicMock()
        fake.returncode = 0
        fake.stdout = "DejaVu Sans Mono"
        with mock.patch.object(system_mod.shutil, "which",
                               return_value="/usr/bin/fc-match"), \
                mock.patch.object(system_mod.subprocess, "run",
                                  return_value=fake):
            self.assertEqual(system_mod.default_mono_font(), "DejaVu Sans Mono")

    def test_default_mono_font_survives_fc_match_failure(self):
        with mock.patch.object(system_mod.shutil, "which",
                               return_value="/usr/bin/fc-match"), \
                mock.patch.object(system_mod.subprocess, "run",
                                  side_effect=OSError("boom")):
            self.assertEqual(system_mod.default_mono_font(), "monospace")

    def test_default_mono_font_windows_shortcut(self):
        with mock.patch.object(system_mod, "IS_WINDOWS", True):
            self.assertEqual(system_mod.default_mono_font(), "JetBrains Mono")

    def test_open_path_windows_branch(self):
        with mock.patch.object(system_mod, "IS_WINDOWS", True), \
                mock.patch("os.startfile", create=True) as startfile:
            self.assertTrue(system_mod.open_path("/tmp/opencode"))
            startfile.assert_called_once_with("/tmp/opencode")

    def test_open_path_linux_branch(self):
        opened = []
        with mock.patch.object(system_mod, "IS_WINDOWS", False), \
                mock.patch.object(system_mod.shutil, "which",
                                  return_value="/usr/bin/xdg-open"), \
                mock.patch.object(system_mod.subprocess, "Popen",
                                  side_effect=lambda argv, **kw:
                                  opened.append(argv)):
            self.assertTrue(system_mod.open_path("/tmp/opencode"))
            self.assertEqual(opened, [["xdg-open", "/tmp/opencode"]])

    def test_open_path_falls_back_to_gio_without_xdg_open(self):
        opened = []
        with mock.patch.object(system_mod, "IS_WINDOWS", False), \
                mock.patch.object(system_mod.shutil, "which",
                                  return_value=None), \
                mock.patch.object(system_mod.subprocess, "Popen",
                                  side_effect=lambda argv, **kw:
                                  opened.append(argv)):
            self.assertTrue(system_mod.open_path("/tmp/opencode"))
            self.assertEqual(opened, [["gio", "open", "/tmp/opencode"]])

    def test_open_path_reports_oserror(self):
        with mock.patch.object(system_mod, "IS_WINDOWS", False), \
                mock.patch.object(system_mod.shutil, "which",
                                  return_value="/usr/bin/xdg-open"), \
                mock.patch.object(system_mod.subprocess, "Popen",
                                  side_effect=OSError("no display")):
            self.assertFalse(system_mod.open_path("/tmp/opencode"))

    def test_reveal_uses_platform_specific_commands(self):
        opened = []
        with mock.patch.object(system_mod, "IS_WINDOWS", True), \
                mock.patch.object(system_mod.subprocess, "Popen",
                                  side_effect=lambda argv, **kw:
                                  opened.append(argv)):
            self.assertTrue(system_mod.reveal("/tmp/opencode/x.bin"))
            self.assertEqual(opened, [["explorer", "/select,",
                                       "/tmp/opencode/x.bin"]])
        opened.clear()
        with mock.patch.object(system_mod, "IS_WINDOWS", False), \
                mock.patch.object(system_mod, "IS_MACOS", True), \
                mock.patch.object(system_mod.subprocess, "Popen",
                                  side_effect=lambda argv, **kw:
                                  opened.append(argv)):
            self.assertTrue(system_mod.reveal("/tmp/opencode/x.bin"))
            self.assertEqual(opened, [["open", "-R", "/tmp/opencode/x.bin"]])

    def test_reveal_on_linux_opens_parent_directory(self):
        with mock.patch.object(system_mod, "IS_WINDOWS", False), \
                mock.patch.object(system_mod, "IS_MACOS", False), \
                mock.patch.object(system_mod, "open_path",
                                  return_value=True) as open_path:
            self.assertTrue(system_mod.reveal("/tmp/opencode/x.bin"))
            open_path.assert_called_once_with(Path("/tmp/opencode"))

    def test_open_url_success_and_failure(self):
        import webbrowser

        with mock.patch.object(webbrowser, "open", return_value=True):
            self.assertTrue(system_mod.open_url("http://127.0.0.1:8765"))
        with mock.patch.object(webbrowser, "open",
                               side_effect=RuntimeError("no browser")):
            self.assertFalse(system_mod.open_url("http://127.0.0.1:8765"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
