"""Webshell rule table, key derivation and Java class forensics tests."""
from __future__ import annotations

import base64
import hashlib
import struct
import unittest

from fnet.utils import webshell as rules
from fnet.utils.crypto import aes_cbc_encrypt


def java_class(name: str, super_name: str = "java/lang/Object") -> bytes:
    """Build the smallest class file with two UTF8/Class constant pairs."""
    entries = [
        b"\x01" + struct.pack(">H", len(name.encode())) + name.encode(),
        b"\x07" + struct.pack(">H", 1),
        b"\x01" + struct.pack(">H", len(super_name.encode())) + super_name.encode(),
        b"\x07" + struct.pack(">H", 3),
    ]
    body = (struct.pack(">H", 0x0021)          # access flags
            + struct.pack(">H", 2)             # this_class
            + struct.pack(">H", 4)             # super_class
            + struct.pack(">H", 0)             # interfaces
            + struct.pack(">H", 0)             # fields
            + struct.pack(">H", 0)             # methods
            + struct.pack(">H", 0))            # attributes
    return (b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52)
            + struct.pack(">H", len(entries) + 1) + b"".join(entries) + body)


class RuleTableTest(unittest.TestCase):
    def test_rule_table_covers_families(self):
        self.assertIn("godzilla", rules.FAMILIES)
        self.assertIn("behinder4", rules.FAMILIES)
        self.assertIn("caidao", rules.FAMILIES)
        self.assertGreaterEqual(len(rules.RULES), 8)
        for family in rules.FAMILIES:
            self.assertTrue(rules.RULE_TABLE[family])

    def test_rules_for_explicit_family(self):
        found = rules.rules_for("behinder4")
        self.assertTrue(found)
        self.assertTrue(all(rule.family == "behinder4" for rule in found))

    def test_rules_for_auto_scores_octet_stream(self):
        found = rules.rules_for("auto", content_type="application/octet-stream")
        self.assertTrue(found)
        self.assertIn(found[0].family, ("godzilla", "behinder4"))

    def test_rules_for_auto_uses_markers(self):
        found = rules.rules_for("auto", user_agent="Godzilla/1.0")
        self.assertEqual(found[0].family, "godzilla")


class DecryptTest(unittest.TestCase):
    def test_behinder4_round_trip(self):
        password = "s3cret"
        key = hashlib.md5(password.encode()).digest()[:16]
        iv = b"0123456789abcdef"
        plaintext = b"cmd=whoami\nflag{behinder4_ok}\n"
        blob = base64.b64encode(
            iv + aes_cbc_encrypt(plaintext, key, iv, pad=True))
        rule = rules.rules_for("behinder4")[0]
        keys = rules.derive_keys(password, rule)
        candidates = rules.decrypt_candidates(blob, keys, rule)
        self.assertTrue(any(plaintext in plain for _k, _v, plain in candidates))

    def test_godzilla_aes_base64_round_trip(self):
        password = "godzilla"
        key = hashlib.md5(password.encode()).digest()
        iv = b"abcdefghijklmnop"
        plaintext = b"whoami\nroot\n"
        blob = base64.b64encode(
            iv + aes_cbc_encrypt(plaintext, key, iv, pad=True))
        rule = rules.rules_for("godzilla")[0]
        self.assertEqual(rule.variant, "AES_BASE64")
        keys = rules.derive_keys(password, rule)
        candidates = rules.decrypt_candidates(blob, keys, rule)
        self.assertTrue(any(plaintext in plain for _k, _v, plain in candidates))

    def test_derive_keys_has_stable_labels(self):
        rule = rules.rules_for("godzilla")[0]
        keys = rules.derive_keys("pass", rule)
        labels = [label for label, _key in keys]
        self.assertIn("md5(pass)", labels)
        self.assertTrue(all(len(key) in (16, 24, 32) for _l, key in keys))
        self.assertEqual(rules.derive_keys("", rule), [])


class JavaClassTest(unittest.TestCase):
    def test_parse_plain_class(self):
        data = java_class("com/evil/TestFilter")
        info = rules.parse_java_class(data)
        self.assertIsNotNone(info)
        self.assertEqual(info["class_name"], "com.evil.TestFilter")
        self.assertEqual(info["super_class"], "java.lang.Object")

    def test_detect_filter_kind(self):
        data = java_class("com/evil/EvilFilter", "javax/servlet/Filter")
        info = rules.analyze_java_class(data)
        self.assertIsNotNone(info)
        self.assertEqual(info["kind"], "Filter")
        self.assertIn("内存马", info["summary"])
        self.assertIn("EvilFilter", info["summary"])

    def test_detect_servlet_kind(self):
        data = java_class("com/evil/EvilServlet",
                          "javax/servlet/http/HttpServlet")
        info = rules.analyze_java_class(data)
        self.assertEqual(info["kind"], "Servlet")

    def test_bad_class_returns_none(self):
        self.assertIsNone(rules.parse_java_class(b""))
        self.assertIsNone(rules.parse_java_class(b"\xca\xfe\xba\xbe"))
        self.assertIsNone(rules.parse_java_class(b"not a class"))


class RestoreOutputTest(unittest.TestCase):
    def test_commands_and_flags(self):
        info = rules.restore_output(
            "cmd=whoami\nwww-data\nflag{cmd_restore}\n")
        self.assertIn("whoami", info["commands"])
        self.assertIn("flag{cmd_restore}", info["flags"])
        self.assertIn("www-data", info["output"])

    def test_file_operations(self):
        info = rules.restore_output(
            "upload /var/www/html/shell.php\ncat /etc/passwd\n")
        self.assertIn("upload", info["operations"])
        self.assertIn("/etc/passwd", info["files"])
        self.assertIn("upload /var/www/html/shell.php", info["commands"])

    def test_empty(self):
        info = rules.restore_output("")
        self.assertEqual(info["commands"], [])
        self.assertEqual(info["flags"], [])


if __name__ == "__main__":
    unittest.main()
