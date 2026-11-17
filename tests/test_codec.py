"""Encoding/decoding helpers and CTF-oriented text extraction."""
from __future__ import annotations

import unittest

from fnet.utils import codec


class CodecTest(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(codec.b64decode_text("ZmxhZ3tiNjR9"), "flag{b64}")
        self.assertEqual(codec.b64decode_text("ZmxhZ3tiNjR9\n"), "flag{b64}")

    def test_base32(self):
        self.assertEqual(codec.b32decode_text("MZWGCZ33G56Q===="), "flag{7}")

    def test_hex(self):
        self.assertEqual(codec.hexdecode_text("666c61677b6865787d"),
                         "flag{hex}")
        self.assertEqual(codec.hexdecode_text("66 6c 61 67"), "flag")

    def test_url(self):
        self.assertEqual(codec.urldecode_text("flag%7Burl%7D"), "flag{url}")

    def test_rot13(self):
        self.assertEqual(codec.rot13("synt{ebg13}"), "flag{rot13}")

    def test_single_byte_xor(self):
        plain = b"flag{xor}"
        encrypted = bytes(byte ^ 0x42 for byte in plain)
        recovered = [out for _, out in
                     codec.single_byte_xor_candidates(encrypted, limit=256)]
        self.assertIn(plain, recovered)


class FlagTest(unittest.TestCase):
    def test_common_prefixes(self):
        self.assertEqual(codec.find_flags("xx flag{abc} yy"),
                         ["flag{abc}"])
        self.assertEqual(codec.find_flags("ctfshow{1} nssctf{2}"),
                         ["ctfshow{1}", "nssctf{2}"])

    def test_trim_webshell_echo_prefix(self):
        self.assertEqual(codec.find_flags("X@Yflag{This_is_a_f10g} [S]"),
                         ["flag{This_is_a_f10g}"])

    def test_no_false_positive_for_words_ending_in_flag(self):
        self.assertEqual(codec.find_flags("notaflag{show}"), ["notaflag{show}"])

    def test_multiline_value_is_not_matched(self):
        self.assertEqual(codec.find_flags("flag{broken\nvalue}"), [])

    def test_decode_chain(self):
        # base64 -> flag
        self.assertIn("flag{chain}", codec.decode_chain("ZmxhZ3tjaGFpbn0="))

    def test_hex_string_extraction(self):
        values = codec.extract_hex_strings("666c6167 00112233")
        self.assertEqual(values, ["666c616700112233"])
        self.assertEqual(codec.from_hex("66 6c:61,67"), b"flag")
        self.assertEqual(codec.to_hex(b"flag"), "666c6167")


if __name__ == "__main__":
    unittest.main()
