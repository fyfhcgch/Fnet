"""Flag-quality policy (docs/IMPROVEMENT_PLAN.md A1).

On 44 real CTF captures the old ``FLAG_RE``-only behaviour produced 1,485
"flag" findings of which 1,484 were CSS rules, PHP snippets or TLS
ciphertext.  These tests pin the tiered policy that replaced it:

* tier 1 — known competition prefixes (``flag``/``ctf``/``nssctf`` …) are
  flags;
* tier 2 — source-code/CSS bodies are dropped;
* tier 3 — ciphertext/binary bodies are dropped;
* everything else is a *candidate*: available through
  :func:`fnet.utils.codec.find_flag_candidates`, never emitted by
  :func:`fnet.utils.codec.find_flags`.
"""
from __future__ import annotations

import unittest

from fnet.utils import codec

#: The only true flag in the 44-capture corpus (9.3.1 HTTP 流量分析).
REAL_FLAG = "flag{This_is_a_f10g}"

#: The junk that made up 1,484 of the 1,485 findings.
CSS_JUNK = "img{width: 40px;}"
CSS_JUNK_IMPORTANT = "bx{width: 90% !important;}"
PHP_JUNK = 'else{$R.="/";}'
PHP_JUNK_MAP = "else{$d=array_map('trim',"
#: A TLS record body: latin-1 mojibake, mostly non-ASCII, high entropy.
TLS_JUNK = "YU{\u00d7B\u00ad\u00cc\u00cd\u00bd\u00ebrg\u00b7J\u00cc\u00a2Ox}"


class RealFlagTest(unittest.TestCase):
    def test_real_flag_is_accepted(self):
        self.assertEqual(codec.find_flags(REAL_FLAG), [REAL_FLAG])
        self.assertEqual(codec.find_flags(f"xx {REAL_FLAG} yy"), [REAL_FLAG])
        self.assertEqual(codec.find_flag_candidates(REAL_FLAG), [])

    def test_known_competition_prefixes(self):
        for value in ("flag{abc}", "CTF{abc}", "ctfshow{1}", "nssctf{2}",
                      "newstar{3}", "dasctf{4}", "dest0g3{5}", "hgame{6}",
                      "moectf{7}", "n1ctf{8}", "picoctf{9}", "idf{10}",
                      "flagx{11}", "begin{12}", "glacier{13}", "iscc{14}",
                      "buu{15}", "suctf{16}", "xman{17}", "utctf{18}",
                      "vnctf{19}", "nss{20}", "bsidesSF{21}"):
            with self.subTest(value=value):
                self.assertEqual(codec.find_flags(value), [value])

    def test_flag_body_may_contain_code_punctuation(self):
        # A known prefix wins over the code heuristic: base64 padding and
        # parentheses are legitimate inside a real flag.
        for value in ("flag{base64==}", "flag{a(b)}", "flag{x=y}"):
            with self.subTest(value=value):
                self.assertEqual(codec.find_flags(value), [value])


class SourceCodeJunkTest(unittest.TestCase):
    def test_css_declarations_are_rejected(self):
        for value in (CSS_JUNK, CSS_JUNK_IMPORTANT,
                      "img{margin-top: -13px !important;}",
                      "table{background-color:#fff}",
                      "th{padding:.75rem}",
                      "section{display:block}",
                      "h6{margin-top:0;margin-bottom:.5rem}"):
            with self.subTest(value=value):
                self.assertEqual(codec.find_flags(value), [])
                self.assertEqual(codec.find_flag_candidates(value), [])

    def test_php_and_js_snippets_are_rejected(self):
        for value in (PHP_JUNK, PHP_JUNK_MAP, "else{$d=strtolower($x);}",
                      "function{return 1}", "document{style}",
                      "foo{var x = 1}", "bar{<script>}"):
            with self.subTest(value=value):
                self.assertEqual(codec.find_flags(value), [])
                self.assertEqual(codec.find_flag_candidates(value), [])

    def test_trailing_semicolon_body_is_code(self):
        self.assertEqual(codec.classify_flag("abc{something;"),
                         codec.FLAG_TIER_CODE)
        self.assertEqual(codec.find_flags("abc{something;"), [])


class CiphertextJunkTest(unittest.TestCase):
    def test_tls_ciphertext_blob_is_rejected(self):
        self.assertEqual(codec.find_flags(TLS_JUNK), [])
        self.assertEqual(codec.find_flag_candidates(TLS_JUNK), [])
        self.assertEqual(codec.classify_flag(TLS_JUNK),
                         codec.FLAG_TIER_CIPHERTEXT)

    def test_low_printable_body_is_rejected(self):
        blob = "p0{\xfb\x01\x83\xc8<\xe5\xb1\xdb m\xba\xdf\xa3\xeb\xe9\xdd?}"
        self.assertEqual(codec.find_flags(blob), [])
        self.assertEqual(codec.find_flag_candidates(blob), [])

    def test_utf8_text_is_not_mistaken_for_ciphertext(self):
        # Real CJK text is not latin-1 mojibake, so it stays a flag.
        self.assertEqual(codec.find_flags("flag{中文答案}"),
                         ["flag{中文答案}"])


class EchoPrefixTest(unittest.TestCase):
    def test_webshell_echo_prefix_is_trimmed(self):
        self.assertEqual(codec.find_flags(f"X@Y{REAL_FLAG} [S]"), [REAL_FLAG])

    def test_trimmed_value_is_classified_after_trimming(self):
        # ``X@Y`` is junk, ``flag`` is a known prefix -> tier 1.
        self.assertEqual(codec.find_flags("X@Y" + REAL_FLAG), [REAL_FLAG])
        self.assertEqual(codec.find_flag_candidates("X@Y" + REAL_FLAG), [])


class CandidateTest(unittest.TestCase):
    """Unknown names must stay retrievable for recall, but not as flags."""

    def test_unknown_name_is_only_a_candidate(self):
        self.assertEqual(codec.find_flags("srv{index}"), [])
        self.assertEqual(codec.find_flag_candidates("srv{index}"),
                         ["srv{index}"])

    def test_plaintext_body_candidate(self):
        self.assertEqual(codec.find_flags("secret{readable_text}"), [])
        self.assertEqual(codec.find_flag_candidates("secret{readable_text}"),
                         ["secret{readable_text}"])

    def test_notaflag_still_ends_with_a_flag_name(self):
        # Existing ``before_ok`` semantics: a longer head is a real name, and
        # names ending in ``flag`` stay accepted (see tests/test_codec.py).
        self.assertEqual(codec.find_flags("notaflag{show}"),
                         ["notaflag{show}"])
        self.assertEqual(codec.find_flag_candidates("notaflag{show}"), [])

    def test_leet_flag_name_is_recognised(self):
        # ``fl4g{sql}`` is produced by the SQL blind-injection handler.
        self.assertEqual(codec.find_flags("fl4g{sql}"), ["fl4g{sql}"])
        self.assertEqual(codec.find_flags("sensorsflag{ow}"),
                         ["sensorsflag{ow}"])

    def test_flags_and_candidates_are_disjoint_and_ordered(self):
        text = f"{REAL_FLAG} srv{{index}} {CSS_JUNK} {TLS_JUNK} ctf{{ok}}"
        self.assertEqual(codec.find_flags(text), [REAL_FLAG, "ctf{ok}"])
        self.assertEqual(codec.find_flag_candidates(text), ["srv{index}"])


class SignatureTest(unittest.TestCase):
    def test_find_flags_keeps_its_return_type(self):
        self.assertIsInstance(codec.find_flags(REAL_FLAG), list)
        self.assertEqual(codec.find_flags(""), [])
        self.assertEqual(codec.find_flags(None), [])
        self.assertEqual(codec.find_flag_candidates(""), [])

    def test_multiline_value_is_not_matched(self):
        self.assertEqual(codec.find_flags("flag{broken\nvalue}"), [])
        self.assertEqual(codec.find_flag_candidates("flag{broken\nvalue}"), [])


if __name__ == "__main__":
    unittest.main()
