"""Unit tests for fnet.utils.rules (regex / YARA-subset custom rules)."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from fnet.utils import rules
from fnet.utils import crypto  # noqa: F401  (ensure module import graph is fine)


class RuleMatchesTest(unittest.TestCase):
    def test_any_mode(self):
        rule = rules.Rule("r", patterns=[rules._compile("password="),
                                         rules._compile("token=")])
        self.assertEqual(rule.matches("see password=abc"), (True, 1))
        self.assertEqual(rule.matches("password= a token= b"), (True, 2))
        self.assertEqual(rule.matches("nothing"), (False, 0))

    def test_all_mode(self):
        rule = rules.Rule("r", patterns=[rules._compile("user"),
                                         rules._compile("pass")], mode="all")
        self.assertEqual(rule.matches("user pass"), (True, 2))
        self.assertEqual(rule.matches("user only"), (False, 1))

    def test_count_mode(self):
        rule = rules.Rule("r", patterns=[rules._compile("a"),
                                         rules._compile("b"),
                                         rules._compile("c")],
                          mode="count", count=2)
        self.assertEqual(rule.matches("a only"), (False, 1))
        self.assertEqual(rule.matches("a and b"), (True, 2))

    def test_expr_mode(self):
        rule = rules.Rule(
            "r",
            patterns=[rules._compile("user"), rules._compile("pass"),
                      rules._compile("admin")],
            mode="expr", expression="not $a or ($b and $c)")
        # user hit, pass+admin missed -> not True or ... -> False
        self.assertEqual(rule.matches("user"), (False, 1))
        # pass+admin hit -> not False or ... -> True
        self.assertEqual(rule.matches("pass admin"), (True, 2))

    def test_no_patterns_never_matches(self):
        rule = rules.Rule("r")
        self.assertEqual(rule.matches("anything"), (False, 0))

    def test_eval_expression_falls_back_on_malformed_rules(self):
        pattern = rules._compile("user")
        # "$a and" alone cannot be evaluated -> fallback to any()
        self.assertTrue(rules._eval_expression("$a and", [pattern], "user"))
        self.assertFalse(
            rules._eval_expression("$a and", [pattern], "nothing"))


class ParseLineRulesTest(unittest.TestCase):
    def test_one_regex_per_line(self):
        parsed = rules.parse_line_rules("flag\\{[^}]+\\}\n# comment\n\npassword=")
        self.assertEqual([rule.name for rule in parsed],
                         ["line_1", "line_4"])
        self.assertTrue(parsed[0].patterns[0].search("flag{abc}"))
        self.assertTrue(parsed[1].patterns[0].search("password=x"))

    def test_named_rules(self):
        parsed = rules.parse_line_rules("secret = password=\\w+\n"
                                        "other: token\\s*[:=]")
        self.assertEqual([rule.name for rule in parsed], ["secret", "other"])

    def test_invalid_regex_is_skipped(self):
        self.assertEqual(rules.parse_line_rules("bad ["), [])
        self.assertEqual(rules.parse_line_rules("ok123\nbad ["),
                         rules.parse_line_rules("ok123"))

    def test_name_regex_split_needs_escaped_literal_equals(self):
        # 文档化的拆分行为：`password=\w+` 是名为 password、正则 \w+ 的规则。
        parsed = rules.parse_line_rules("password=\\w+")
        self.assertEqual([rule.name for rule in parsed], ["password"])
        self.assertTrue(parsed[0].patterns[0].search("anything123"))
        # 想匹配字面量 `password=` 必须转义等号：`password\=`。
        escaped = rules.parse_line_rules("password\\=")
        self.assertNotEqual(escaped[0].name, "password")
        self.assertTrue(escaped[0].patterns[0].search("see password=x"))
        self.assertFalse(escaped[0].patterns[0].search("passwordx"))


class ParseJsonTest(unittest.TestCase):
    def test_dict_with_rules(self):
        text = json.dumps({"rules": [
            {"name": "cred", "pattern": "password=",
             "description": "clear text credential", "level": "error",
             "tags": ["credential"], "mode": "any"},
            {"name": "multi", "patterns": ["user=", "pass="], "mode": "all"},
        ]})
        parsed = rules.parse_json(text)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].level, "error")
        self.assertEqual(parsed[0].description, "clear text credential")
        self.assertEqual(parsed[0].tags, ["credential"])
        self.assertEqual(parsed[1].mode, "all")

    def test_bare_list_is_accepted(self):
        text = json.dumps([{"name": "r1", "regex": "abc"}])
        parsed = rules.parse_json(text)
        self.assertEqual([rule.name for rule in parsed], ["r1"])

    def test_invalid_entries_are_dropped(self):
        text = json.dumps([
            {"pattern": "no-name"},
            {"name": "no-patterns"},
            {"name": "bad-regex", "pattern": "["},
            "not-a-dict",
        ])
        self.assertEqual(rules.parse_json(text), [])

    def test_unknown_mode_falls_back_to_any(self):
        text = json.dumps({"rules": [{"name": "r", "pattern": "a",
                                      "mode": "weird"}]})
        self.assertEqual(rules.parse_json(text)[0].mode, "any")

    def test_invalid_json_yields_no_rules(self):
        self.assertEqual(rules.parse_json("{not json"), [])
        self.assertEqual(rules.parse_json("not json at all"), [])


class ParseYaraTest(unittest.TestCase):
    YARA = '''
    rule credential_leak : credential clear
    {
        meta:
            description = "password in clear text"
            severity = "error"
        strings:
            $a = "password=" nocase
            $b = /passwd\\s*[:=]/ nocase
        condition:
            any of them
    }

    rule two_strings
    {
        strings:
            $a = "alpha"
            $b = "beta"
        condition:
            2 of them
    }

    rule all_required
    {
        strings:
            $a = "user"
            $b = "pass"
        condition:
            all of them
    }

    rule expression_rule
    {
        strings:
            $a = "user"
            $b = "pass"
        condition:
            $a and not $b
    }
    '''

    def test_parse_four_rules(self):
        parsed = rules.parse_yara(self.YARA)
        self.assertEqual([rule.name for rule in parsed],
                         ["credential_leak", "two_strings", "all_required",
                          "expression_rule"])

    def test_tags_meta_and_case_insensitive_strings(self):
        rule = rules.parse_yara(self.YARA)[0]
        self.assertEqual(rule.tags, ["credential", "clear"])
        self.assertEqual(rule.description, "password in clear text")
        self.assertEqual(rule.level, "error")
        self.assertEqual(rule.mode, "any")
        self.assertTrue(rule.patterns[0].search("PASSWORD=admin"))
        self.assertTrue(rule.patterns[1].search("Passwd: secret"))

    def test_count_condition(self):
        rule = rules.parse_yara(self.YARA)[1]
        self.assertEqual(rule.mode, "count")
        self.assertEqual(rule.count, 2)
        self.assertEqual(rule.matches("alpha beta"), (True, 2))
        self.assertEqual(rule.matches("alpha only"), (False, 1))

    def test_all_condition(self):
        rule = rules.parse_yara(self.YARA)[2]
        self.assertEqual(rule.mode, "all")
        self.assertFalse(rule.matches("user only")[0])

    def test_expression_condition(self):
        rule = rules.parse_yara(self.YARA)[3]
        self.assertEqual(rule.mode, "expr")
        self.assertEqual(rule.expression, "$a and not $b")
        self.assertTrue(rule.matches("user")[0])
        self.assertFalse(rule.matches("user pass")[0])

    def test_wide_modifier(self):
        parsed = rules.parse_yara('''
        rule wide_rule
        {
            strings:
                $a = "AB" wide
            condition:
                any of them
        }
        ''')
        self.assertTrue(parsed[0].patterns[0].search("A\x00B"))

    def test_rules_without_strings_are_dropped(self):
        parsed = rules.parse_yara('''
        rule empty
        {
            condition:
                true
        }
        ''')
        self.assertEqual(parsed, [])

    def test_parse_rules_dispatches_by_content(self):
        self.assertEqual(len(rules.parse_rules(self.YARA)), 4)
        self.assertEqual([r.name for r in rules.parse_rules("flag\\{[^}]+\\}")],
                         ["line_1"])
        text = json.dumps({"rules": [{"name": "j", "pattern": "abc"}]})
        self.assertEqual([r.name for r in rules.parse_rules(text)], ["j"])
        # A JSON body is detected by its leading brace even without suffix.
        self.assertEqual([r.name for r in rules.parse_rules(text, suffix="")],
                         ["j"])


class LoadRulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-rules-"))

    def test_load_line_rules(self):
        path = self.tmp / "rules.txt"
        path.write_text("flag\\{[^}]+\\}\n", encoding="utf-8")
        parsed = rules.load_rules(path)
        self.assertEqual([rule.name for rule in parsed], ["line_1"])

    def test_load_json_by_suffix(self):
        path = self.tmp / "rules.json"
        path.write_text(json.dumps({"rules": [{"name": "j",
                                               "pattern": "abc"}]}),
                        encoding="utf-8")
        self.assertEqual([r.name for r in rules.load_rules(path)], ["j"])

    def test_missing_file_raises(self):
        with self.assertRaisesRegex(ValueError, "规则文件不存在"):
            rules.load_rules(self.tmp / "missing.txt")

    def test_empty_rules_raise(self):
        path = self.tmp / "empty.txt"
        path.write_text("# only a comment\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "没有可用的规则"):
            rules.load_rules(path)

    def test_oversized_file_raises(self):
        path = self.tmp / "big.txt"
        path.write_bytes(b"a" * (rules.MAX_RULE_FILE + 1))
        with self.assertRaisesRegex(ValueError, "规则文件过大"):
            rules.load_rules(path)


class MatchTextTest(unittest.TestCase):
    def test_match_and_snippet(self):
        rule = rules.Rule("cred", patterns=[rules._compile("password=\\w+")],
                          description="明文口令", level="good", tags=["tag"])
        text = "x" * 60 + "password=hunter2" + "y" * 80
        hits = rules.match_text([rule], text, frame="7", time="12:00:01",
                                protocol="HTTP")
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["rule"], "cred")
        self.assertEqual(hit["level"], "good")
        self.assertEqual(hit["frame"], "7")
        self.assertEqual(hit["hits"], 1)
        self.assertIn("明文口令", hit["summary"])
        self.assertIn("password=hunter2", hit["detail"])

    def test_invalid_level_is_coerced_to_warn(self):
        rule = rules.Rule("r", patterns=[rules._compile("a")], level="bogus")
        hit = rules.match_text([rule], "aaa")[0]
        self.assertEqual(hit["level"], "warn")

    def test_empty_payload_matches_nothing(self):
        self.assertEqual(rules.match_text([rules.Rule("r")], ""), [])

    def test_max_matches_limit(self):
        many = [rules.Rule(f"r{i}", patterns=[rules._compile("hit")])
                for i in range(20)]
        hits = rules.match_text(many, "hit", )
        rules.MAX_MATCHES = 5
        try:
            hits = rules.match_text(many, "hit")
            self.assertEqual(len(hits), 5)
        finally:
            rules.MAX_MATCHES = 2000


class DecodePayloadTest(unittest.TestCase):
    def test_plain_hex(self):
        self.assertEqual(rules._decode_payload(b"flag{r}".hex()), "flag{r}")

    def test_colon_separated_hex(self):
        self.assertEqual(rules._decode_payload("66:6c:61:67"), "flag")

    def test_odd_length_and_garbage(self):
        self.assertEqual(rules._decode_payload("abc"), "")
        self.assertEqual(rules._decode_payload(""), "")

    def test_latin1_fallback(self):
        self.assertEqual(rules._decode_payload(b"caf\xe9".hex()), "caf\xe9")


class ScanPcapTest(unittest.TestCase):
    class FakeTshark:
        def __init__(self, rows):
            self.rows = rows
            self.calls = []

        def fields(self, pcap, fields, display_filter="", extra=None,
                   cancel=None):
            self.calls.append(list(fields))
            return self.rows

    def test_scan_hex_payload_and_text_fields(self):
        rows = [
            ["5", "12.5", "HTTP", b"password=admin".hex(), "", "", "", "",
             ""],
            ["6", "12.6", "DNS", "", "", "", "evil.example.com", "", ""],
            ["7", "12.7", "TCP", "", "", "", "", "", ""],
        ]
        rule = rules.Rule("cred", patterns=[rules._compile("password=\\w+")])
        hits = rules.scan_pcap([rule], "x.pcap", self.FakeTshark(rows))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["frame"], "5")
        self.assertEqual(hits[0]["protocol"], "HTTP")

    def test_no_tshark_or_rules_returns_empty(self):
        self.assertEqual(rules.scan_pcap([], "x.pcap",
                                         self.FakeTshark([["1"]])), [])
        self.assertEqual(rules.scan_pcap([rules.Rule("r")], "x.pcap", None),
                         [])

    def test_cancel_event_stops_scan(self):
        rows = [["1", "", "", b"password=secret".hex(), "", "", "", "", ""]]
        rule = rules.Rule("cred", patterns=[rules._compile("password=\\w+")])
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(rules.scan_pcap([rule], "x.pcap",
                                         self.FakeTshark(rows), cancel=cancel),
                         [])

    def test_limit(self):
        rows = [[str(i), "", "", b"password=x".hex(), "", "", "", "", ""]
                for i in range(10)]
        rule = rules.parse_line_rules("password=\\w+\n")[0]
        hits = rules.scan_pcap([rule], "x.pcap", self.FakeTshark(rows),
                               limit=3)
        self.assertEqual(len(hits), 3)


class SnippetTest(unittest.TestCase):
    def test_snippet_around_match(self):
        text = "a" * 100 + "flag{here}" + "b" * 300
        result = rules.snippet(text, rules._compile("flag\\{[^}]+\\}"))
        self.assertIn("flag{here}", result)
        self.assertLessEqual(len(result), rules.MAX_SNIPPET)

    def test_snippet_without_match(self):
        self.assertEqual(rules.snippet("x" * 500, rules._compile("zzz")),
                         "x" * rules.MAX_SNIPPET)


if __name__ == "__main__":
    unittest.main()
