"""Pure-stdlib unit tests for the OpenSSL file crypto/entropy module.

No tshark required. Covers the new ``crypto.py`` helpers (AES-CTR +
EVP_BytesToKey), the ``entropy.py`` analysis, and the handler robustness.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from fnet.utils.crypto import (
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ctr_crypt, aes_ctr_decrypt,
    evp_bytes_to_key, openssl_derive,
)
from fnet.utils.entropy import classify, entropy_ratio, shannon_entropy


def _evp_ref(password: bytes, salt: bytes | None, key_len: int, iv_len: int,
             digest=hashlib.md5) -> tuple[bytes, bytes]:
    """Reference implementation of OpenSSL EVP_BytesToKey (MD5, 1 iter)."""
    material = b"" if not salt else salt
    total = key_len + iv_len
    data = b""
    d = b""
    while len(data) < total:
        d = digest(d + password + material).digest()
        data += d
    return data[:key_len], data[key_len:key_len + iv_len]


class AesCtrTest(unittest.TestCase):
    def test_roundtrip(self):
        key = b"\x01" * 32
        for size in (0, 1, 15, 16, 17, 31, 32, 100, 1024):
            with self.subTest(size=size):
                plain = os.urandom(size)
                ct = aes_ctr_crypt(plain, key)
                self.assertEqual(aes_ctr_decrypt(ct, key), plain)
                # CTR counter == start; re-encrypting the plaintext must
                # reproduce the same ciphertext (symmetric keystream).
                self.assertEqual(aes_ctr_crypt(plain, key), ct)

    def test_counter_increment(self):
        key = b"\x02" * 16
        first = aes_ctr_crypt(b"\x00" * 16, key, b"\x00" * 16)
        second = aes_ctr_crypt(b"\x00" * 16, key, b"\x00" * 15 + b"\x01")
        self.assertNotEqual(first, second)

    def test_bad_key_length(self):
        with self.assertRaises(ValueError):
            aes_ctr_crypt(b"\x00" * 16, b"short")


class EvpBytesToKeyTest(unittest.TestCase):
    def test_known_vector_nosalt(self):
        # openssl enc -aes-256-cbc -nosalt -pass pass:test
        # key is the first 32 bytes of MD5(password) iteration chain, salt empty.
        password = b"test"
        key, iv = evp_bytes_to_key(password, None, 32, 16, "md5")
        ref_key, ref_iv = _evp_ref(password, None, 32, 16)
        self.assertEqual(key, ref_key)
        self.assertEqual(iv, ref_iv)
        # Sanity: first 16 bytes equal md5("test").
        self.assertEqual(key[:16], hashlib.md5(b"test").digest())

    def test_known_vector_example(self):
        # password "example", no salt -> manually derived expected value.
        password = b"example"
        d1 = hashlib.md5(b"example").digest()
        d2 = hashlib.md5(d1 + b"example").digest()
        expected = d1 + d2
        key, iv = evp_bytes_to_key(password, None, 32, 16)
        self.assertEqual(key, expected)
        self.assertEqual(iv, hashlib.md5(d2 + b"example").digest()[:16])

    def test_with_salt(self):
        password = b"secret"
        salt = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        key, iv = evp_bytes_to_key(password, salt, 32, 16)
        ref_key, ref_iv = _evp_ref(password, salt, 32, 16)
        self.assertEqual((key, iv), (ref_key, ref_iv))

    def test_sha256_digest(self):
        password = b"pw"
        key, iv = evp_bytes_to_key(password, b"\x00" * 8, 32, 16, "sha256")
        ref_key, ref_iv = _evp_ref(password, b"\x00" * 8, 32, 16, hashlib.sha256)
        self.assertEqual((key, iv), (ref_key, ref_iv))

    def test_str_password(self):
        # A str password must be UTF-8 encoded consistently.
        a = evp_bytes_to_key("密码", None, 32, 16)
        b = evp_bytes_to_key("密码".encode("utf-8"), None, 32, 16)
        self.assertEqual(a, b)

    def test_openssl_derive_wrapper(self):
        key, iv = openssl_derive(b"pw", b"\x07" * 8)
        self.assertEqual((key, iv), evp_bytes_to_key(b"pw", b"\x07" * 8, 32, 16))

    def test_bad_digest(self):
        with self.assertRaises(ValueError):
            evp_bytes_to_key(b"p", None, 32, 16, "no-such-digest")


class OpenSslCipherTest(unittest.TestCase):
    def test_aes_ctr_real_roundtrip(self):
        # Recreate the CTF pattern: encrypt with derived key, decrypt back.
        password = b"haha"
        plaintext = b"flag{openssl-aes256ctr-ctf}\n" * 4
        key, iv = evp_bytes_to_key(password, None, 32, 16)
        cipher = aes_ctr_crypt(plaintext, key, iv)
        self.assertNotEqual(cipher, plaintext)
        self.assertEqual(aes_ctr_decrypt(cipher, key, iv), plaintext)

    def test_aes256_cbc_salted_roundtrip(self):
        # OpenSSL style: "Salted__" + 8-byte salt + AES-256-CBC ciphertext.
        password = b"s3cret"
        plaintext = b"CTF{AES-256-CBC salt decrypt}\n" * 2
        salt = b"\x9f\x00\xa1\xb2\xc3\xd4\xe5\xf6"
        key, iv = evp_bytes_to_key(password, salt, 32, 16)
        body = aes_cbc_encrypt(plaintext, key, iv)
        blob = b"Salted__" + salt + body
        # Recover salt + decrypt like the handler.
        self.assertTrue(blob.startswith(b"Salted__"))
        got_salt = blob[8:16]
        got_body = blob[16:]
        got_key, got_iv = evp_bytes_to_key(password, got_salt, 32, 16)
        self.assertEqual(aes_cbc_decrypt(got_body, got_key, got_iv), plaintext)


class EntropyTest(unittest.TestCase):
    def test_zero_bytes(self):
        self.assertEqual(shannon_entropy(b"\x00" * 100), 0.0)
        self.assertEqual(entropy_ratio(b"\x00" * 100), 0.0)

    def test_high_entropy(self):
        e = shannon_entropy(os.urandom(4096))
        self.assertGreater(e, 7.5)
        self.assertLessEqual(e, 8.0)

    def test_empty_safe(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(entropy_ratio(b""), 0.0)
        cls = classify(b"")
        self.assertFalse(cls["am_i_encrypted"])

    def test_classify_plaintext(self):
        cls = classify(b"A" * 100)
        self.assertLess(cls["entropy"], 5.0)
        self.assertFalse(cls["am_i_encrypted"])
        self.assertIn("明文", cls["hint"])

    def test_classify_encrypted(self):
        cls = classify(os.urandom(4096))
        self.assertGreater(cls["entropy"], 7.2)
        self.assertTrue(cls["am_i_encrypted"])
        self.assertIn("加密", cls["hint"])


class HandlerRobustnessTest(unittest.TestCase):
    def test_no_candidates_does_not_crash(self):
        from fnet.features.openssl_file import detect_encrypted_files
        logs = []

        class FakeOut:
            def is_dir(self):
                return True

            def iterdir(self):
                return iter([])

        class FakeCtx:
            output_dir = FakeOut()

            def __init__(self):
                self.params = {}
                self.calls = []

            def report(self, text, level="info"):
                logs.append((level, text))

            def check_cancel(self):
                pass

            def set_progress(self, value):
                self.calls.append(("progress", value))

            def add_finding(self, *a, **k):
                pass

            def write_output(self, name, data):
                return Path(name)

        fake = FakeCtx()
        detect_encrypted_files(fake)  # must not raise even with no files
        self.assertTrue(any("未找到可分析的二进制文件" in text for _, text in logs))

    def test_entropy_safe_without_file_param(self):
        from fnet.utils.entropy import classify
        # Default classify on arbitrary no-param data stays safe.
        self.assertIsInstance(classify(b""), dict)


if __name__ == "__main__":
    unittest.main()