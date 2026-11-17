"""Webshell / Shiro helpers and the synthetic GCM capture."""
from __future__ import annotations

import base64
import unittest

from fnet.features.webshell import (
    JAVA_MAGIC, _decrypt_shiro, _plain_payload, load_shiro_keys,
    memory_shell_markers,
)
from fnet.utils.crypto import aes_cbc_encrypt, aes_gcm_encrypt

KEY_TEXT = "kPH+bIxk5D2deZiIxcaaaA=="
KEY = base64.b64decode(KEY_TEXT)
IV = b"0123456789abcdef"


class ShiroTest(unittest.TestCase):
    def test_gcm_payload(self):
        plain = b"flag{shiro_gcm_unit}"
        blob = IV + aes_gcm_encrypt(plain, KEY, IV)
        result = _decrypt_shiro(blob, [("test", KEY)])
        self.assertIsNotNone(result)
        label, decrypted, mode = result
        self.assertEqual(decrypted, plain)
        self.assertIn("GCM", mode)
        self.assertEqual(label, "test")

    def test_cbc_payload(self):
        plain = JAVA_MAGIC + b"\x00\x05t\x00\x04testflag{cbc}"
        blob = IV + aes_cbc_encrypt(plain, KEY, IV)
        result = _decrypt_shiro(blob, [("test", KEY)])
        self.assertIsNotNone(result)
        self.assertTrue(result[1].startswith(JAVA_MAGIC))
        self.assertIn("CBC", result[2])

    def test_wrong_key_fails(self):
        blob = IV + aes_gcm_encrypt(b"flag{nope}", KEY, IV)
        self.assertIsNone(_decrypt_shiro(blob, [("bad", b"0123456789abcdeF")]))

    def test_key_file_is_loaded(self):
        keys = load_shiro_keys()
        self.assertGreater(len(keys), 1000)
        self.assertTrue(any(key == KEY for _, key in keys))

    def test_plain_payload_detection(self):
        payload = (b"@ini_set('display_errors','0');$s='id';"
                   b"system($s);echo 'flag{x}';")
        self.assertTrue(_plain_payload(payload))
        self.assertFalse(_plain_payload(b"just some random text"))

    def test_memory_shell_markers(self):
        payload = (b"org.apache.catalina.core.StandardContext "
                   b"addFilter filterChain " + "内存马".encode("utf-8"))
        markers = memory_shell_markers(payload)
        self.assertIn("standardcontext", markers)
        self.assertIn("内存马", markers)
        self.assertEqual(memory_shell_markers(b"plain php code"), [])


if __name__ == "__main__":
    unittest.main()
