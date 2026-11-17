"""Known-answer tests for the pure Python crypto helpers."""
from __future__ import annotations

import base64
import unittest

from fnet.utils import crypto


class AesTest(unittest.TestCase):
    def test_aes128_block_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(crypto.aes_encrypt_block(plain, key), cipher)
        self.assertEqual(crypto.aes_decrypt_block(cipher, key), plain)

    def test_aes256_block_vector(self):
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        cipher = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(crypto.aes_encrypt_block(plain, key), cipher)
        self.assertEqual(crypto.aes_decrypt_block(cipher, key), plain)

    def test_cbc_roundtrip_and_padding(self):
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        data = b"flag{cbc_roundtrip}\x00\x01\x02"
        encrypted = crypto.aes_cbc_encrypt(data, key, iv)
        self.assertEqual(len(encrypted) % 16, 0)
        self.assertEqual(crypto.aes_cbc_decrypt(encrypted, key, iv), data)

    def test_ecb_roundtrip(self):
        key = b"0123456789abcdef"
        data = b"the quick brown fox jumps over the lazy dog"
        self.assertEqual(
            crypto.aes_ecb_decrypt(crypto.aes_ecb_encrypt(data, key), key),
            data)


class GcmTest(unittest.TestCase):
    def test_nist_empty_plaintext(self):
        key = bytes(16)
        iv = bytes(12)
        self.assertEqual(crypto.aes_gcm_encrypt(b"", key, iv).hex(),
                         "58e2fccefa7e3061367f1d57a4e7455a")

    def test_nist_one_block(self):
        key = bytes(16)
        iv = bytes(12)
        sealed = crypto.aes_gcm_encrypt(bytes(16), key, iv)
        self.assertEqual(sealed[:16].hex(),
                         "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(sealed[16:].hex(),
                         "ab6e47d42cec13bdf53a67b21257bddf")
        plain, valid = crypto.aes_gcm_decrypt(sealed, key, iv)
        self.assertTrue(valid)
        self.assertEqual(plain, bytes(16))

    def test_16_byte_iv_roundtrip(self):
        key = b"0123456789abcdef"
        iv = b"0123456789abcdef"
        data = b"shiro gcm payload"
        sealed = crypto.aes_gcm_encrypt(data, key, iv)
        plain, valid = crypto.aes_gcm_decrypt(sealed, key, iv)
        self.assertTrue(valid)
        self.assertEqual(plain, data)

    def test_tampered_tag_is_reported(self):
        key = b"0123456789abcdef"
        iv = b"0123456789abcdef"
        sealed = bytearray(crypto.aes_gcm_encrypt(b"data", key, iv))
        sealed[-1] ^= 0xFF
        plain, valid = crypto.aes_gcm_decrypt(bytes(sealed), key, iv)
        self.assertFalse(valid)
        self.assertEqual(plain, b"data")


class HashAndRc4Test(unittest.TestCase):
    def test_md4_vectors(self):
        self.assertEqual(crypto.md4(b"").hex(),
                         "31d6cfe0d16ae931b73c59d7e0c089c0")
        self.assertEqual(crypto.md4(b"abc").hex(),
                         "a448017aaf21d8525fc10ae87aa6729d")

    def test_nt_hash(self):
        self.assertEqual(
            crypto.nt_hash("password").hex().upper(),
            "8846F7EAEE8FB117AD06BDD830B7586C")

    def test_rc4_vector(self):
        self.assertEqual(crypto.rc4(b"Key", b"Plaintext").hex(),
                         "bbf316e8d940af0ad3")
        self.assertEqual(crypto.rc4(b"Wiki", b"pedia").hex(),
                         "1021bf0420")
        self.assertEqual(crypto.rc4(b"Secret", b"Attack at dawn").hex(),
                         "45a01f645fc35b383552544b9bf5")

    def test_hmac_md5(self):
        self.assertEqual(
            crypto.hmac_md5(b"key", b"The quick brown fox jumps over the lazy dog").hex(),
            "80070713463e7749b90c2dc24911e275")


class RsaTest(unittest.TestCase):
    # 512-bit test key generated once for this repository.
    DER = base64.b64decode(
        "MIIBOgIBAAJBAIX2gqhJm0W2i1MhBoSAKvTSMhSkq4wdWzkVYj6wWgPkD0v5I1Om"
        "69EclRa2sRkrfwbCFzpH5wLW8tAPD13KtbkCAwEAAQJAcAaeasbrDxhBWKoUfjeE"
        "NKmWccbnIkvmXk0wlEX7cKZK3l66LR5FCzF/cwx5HTijSjCC1TFnCjqYbNGyYfig"
        "tQIhAN6O3guoXG5KAEtvq/z1YYjTLm3Ng7yUeN1qx7hneAQ7AiEAmheoOQRQxbCF"
        "odX1cdgePqpHp0lxOEX5Nm/lQT48EpsCIA7Ng9lUpmkzhNd/ovndPFKEcVceTz/Q"
        "xEU93/DU+PeXAiBzG1DypqKfymlIp0eeL08IiLLV6CrHWp37aELdJdxCGQIhAL9s"
        "bDevMyeIBqixcyf8tMSXawIRXbA4mysXvN5j/ot6")
    CIPHERTEXT = bytes.fromhex(
        "6d4e6e6db56a584def3c6d9f55f062d02e3103806b384a7e81bd66e4296096ce"
        "6a98938ff4c88b9d9f0797ffcaa571e44ba60b128f0f22663ec00184ec5aad91")

    def test_parse_pkcs1_der_and_decrypt(self):
        key = crypto.load_rsa_private_key(self.DER)
        self.assertIsNotNone(key)
        self.assertEqual(crypto.rsa_decrypt_pkcs1v15(self.CIPHERTEXT, key),
                         b"flag{rsa_pkcs1v15_test}")

    def test_garbage_returns_none(self):
        self.assertIsNone(crypto.load_rsa_private_key(b"not a key"))


if __name__ == "__main__":
    unittest.main()
