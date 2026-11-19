"""payload_bin 纯函数单测：提取载荷的分层分析（画像/编码剥离/解密尝试/内容提取）。

全部用 stdlib + 仓库自带的纯 Python AES 构造夹具，不需要 openssl CLI，
也不需要 tshark。
"""
from __future__ import annotations

import base64
import gzip
import random
import unittest

from fnet.utils import payload_bin
from fnet.utils.crypto import aes_cbc_encrypt
from fnet.utils.openssl_enc import derive_key_iv


def _random_bytes(seed: int, size: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(size))


class ProfileMagicTest(unittest.TestCase):
    def test_magic_detection(self):
        cases = [
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 100, "PNG"),
            (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 100, "JPEG"),
            (b"PK\x03\x04" + b"\x00" * 100, "ZIP"),
            (b"\x1f\x8b\x08\x00" + b"\x00" * 100, "GZIP"),
            (b"%PDF-1.7\n" + b"\x00" * 100, "PDF"),
            (b"hello world" * 5, ""),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(payload_bin.detect_magic(data), expected)
                prof = payload_bin.profile(data)
                self.assertEqual(prof["magic"], expected)
                for key in ("entropy", "printable_ratio", "aligned_16",
                            "length"):
                    self.assertIn(key, prof)

    def test_profile_counts_and_alignment(self):
        prof = payload_bin.profile(b"A" * 32)
        self.assertEqual(prof["length"], 32)
        self.assertTrue(prof["aligned_16"])
        self.assertFalse(payload_bin.profile(b"A" * 33)["aligned_16"])

    def test_bmp_and_pe_need_min_length(self):
        # 2 字节 magic 需要足够长度才可信，避免随机二进制误报。
        self.assertEqual(payload_bin.detect_magic(b"BM\x00\x00"), "")
        self.assertEqual(payload_bin.detect_magic(b"BM" + b"\x00" * 20), "BMP")
        self.assertEqual(payload_bin.detect_magic(b"MZ" + b"\x00" * 20), "PE")


class LayerStripTest(unittest.TestCase):
    def test_base64_gzip_two_layers(self):
        inner = b"flag{layered-payload}\n" * 20
        blob = base64.b64encode(gzip.compress(inner))
        layers, body = payload_bin.strip_layers(blob)
        self.assertEqual([item["encoding"] for item in layers],
                         ["base64", "gzip"])
        self.assertEqual(body, inner)
        self.assertEqual(layers[0]["in_bytes"], len(blob))
        self.assertEqual(layers[1]["out_bytes"], len(inner))

    def test_base64_wrapped_ciphertext_stops_at_cipher(self):
        blob = base64.b64encode(_random_bytes(7, 256))
        layers, body = payload_bin.strip_layers(blob)
        self.assertEqual([item["encoding"] for item in layers], ["base64"])
        self.assertEqual(body, base64.b64decode(blob))

    def test_wrapped_newlines_are_tolerated(self):
        # openssl enc -a 每 64 字符换行，剥离时必须容忍换行。
        blob = base64.encodebytes(gzip.compress(b"flag{wrapped-b64}\n" * 10))
        layers, body = payload_bin.strip_layers(blob)
        self.assertEqual([item["encoding"] for item in layers],
                         ["base64", "gzip"])
        self.assertEqual(body, b"flag{wrapped-b64}\n" * 10)

    def test_no_layers_on_plain_text_and_binary(self):
        text = b"just plain text " * 4
        layers, body = payload_bin.strip_layers(text)
        self.assertEqual((layers, body), ([], text))
        raw = _random_bytes(9, 512)
        layers, body = payload_bin.strip_layers(raw)
        self.assertEqual((layers, body), ([], raw))


class DecryptionAttemptTest(unittest.TestCase):
    def test_common_password_recipe_hit(self):
        plaintext = b"flag{icmp-auto-decrypt}\n" * 30
        key, iv = derive_key_iv("icmp", b"", key_len=16, iv_len=16,
                                digest="md5")
        ct = aes_cbc_encrypt(plaintext, key, iv)
        result = payload_bin.analyse_payload(ct, name="t.bin")
        self.assertTrue(result["decrypt"]["hit"])
        self.assertEqual(result["decrypt"]["password"], "icmp")
        self.assertEqual(result["decrypt"]["cipher"], "aes-128-cbc")
        self.assertEqual(result["decrypt"]["digest"], "md5")
        self.assertFalse(result["decrypt"]["salted"])
        self.assertLessEqual(result["decrypt"]["attempts"],
                             payload_bin.MAX_ATTEMPTS)
        self.assertEqual(result["content"]["flags"],
                         ["flag{icmp-auto-decrypt}"])
        self.assertTrue(result["encrypted"])

    def test_password_from_name_ip(self):
        plaintext = b"flag{password-from-name}\n" * 30
        key, iv = derive_key_iv("10.0.0.2", b"", key_len=32, iv_len=16,
                                digest="md5")
        ct = aes_cbc_encrypt(plaintext, key, iv)
        result = payload_bin.analyse_payload(
            ct, name="icmp_tunnel_10.0.0.1_10.0.0.2.bin")
        self.assertTrue(result["decrypt"]["hit"])
        self.assertEqual(result["decrypt"]["password"], "10.0.0.2")
        passwords = payload_bin.default_passwords(
            "icmp_tunnel_10.0.0.1_10.0.0.2.bin")
        self.assertIn("10.0.0.1", passwords)
        self.assertIn("10.0.0.2", passwords)
        self.assertIn("fetus", passwords)
        # 去重保序
        self.assertEqual(len(passwords), len(set(passwords)))

    def test_salted_envelope_hit(self):
        plaintext = b"flag{salted-envelope}\n" * 20
        salt = b"\x9f" * 8
        key, iv = derive_key_iv("toor", salt, key_len=32, iv_len=16,
                                digest="md5")
        blob = b"Salted__" + salt + aes_cbc_encrypt(plaintext, key, iv)
        result = payload_bin.analyse_payload(blob)
        self.assertTrue(result["decrypt"]["hit"])
        self.assertEqual(result["decrypt"]["password"], "toor")
        self.assertTrue(result["decrypt"]["salted"])

    def test_undecryptable_random_no_false_positive(self):
        result = payload_bin.analyse_payload(_random_bytes(11, 1024))
        self.assertTrue(result["encrypted"])
        self.assertFalse(result["decrypt"]["hit"])
        self.assertEqual(result["decrypt"]["attempts"],
                         payload_bin.MAX_ATTEMPTS)
        self.assertTrue(result["decrypt"]["exhausted"])
        self.assertEqual(result["layers"], [])
        # 失败路径给可直接复制的命令示例（无信封 -> -nosalt）
        self.assertIn("openssl enc -d", result["decrypt"]["example_command"])
        self.assertIn("-nosalt", result["decrypt"]["example_command"])

    def test_unknown_password_exhausts_cap(self):
        plaintext = b"flag{unknown-password}\n" * 30
        key, iv = derive_key_iv("no-such-password-here", b"", key_len=16,
                                iv_len=16, digest="md5")
        ct = aes_cbc_encrypt(plaintext, key, iv)
        result = payload_bin.analyse_payload(ct)
        self.assertFalse(result["decrypt"]["hit"])
        self.assertLessEqual(result["decrypt"]["attempts"],
                             payload_bin.MAX_ATTEMPTS)
        self.assertIn("<口令>", result["decrypt"]["example_command"])

    def test_attempt_cap_constant(self):
        # (cipher, digest) 组合 × 口令轮转展开，硬上限固定为 66。
        self.assertEqual(payload_bin.MAX_ATTEMPTS, 66)
        self.assertEqual(len(payload_bin.CIPHERS), 6)
        self.assertEqual(len(payload_bin.DIGESTS), 2)


class ContentAndSkipsTest(unittest.TestCase):
    def test_file_magic_skips_decryption(self):
        data = b"\x89PNG\r\n\x1a\n" + _random_bytes(3, 300)
        result = payload_bin.analyse_payload(data)
        self.assertFalse(result["encrypted"])
        self.assertEqual(result["decrypt"]["attempts"], 0)
        self.assertIn("文件类型", result["decrypt"]["skipped"])
        self.assertEqual(result["content"]["suggested_ext"], ".png")
        self.assertEqual(result["content"]["magic"], "PNG")

    def test_non_cipher_text_not_encrypted(self):
        result = payload_bin.analyse_payload(b"hello readable world\n" * 10)
        self.assertFalse(result["encrypted"])
        self.assertEqual(result["decrypt"]["attempts"], 0)
        self.assertIn("hello readable world", result["content"]["text"])

    def test_strings_extracted_and_capped(self):
        body = b"user=admin\tpassword=Secret123\n" + b"\x00" * 40
        result = payload_bin.analyse_payload(body)
        joined = "\n".join(result["content"]["strings"])
        self.assertIn("user", joined)
        self.assertIn("password", joined)
        self.assertLessEqual(len(result["content"]["strings"]),
                             payload_bin.MAX_STRINGS)

    def test_empty_input_safe(self):
        result = payload_bin.analyse_payload(b"")
        self.assertFalse(result["encrypted"])
        self.assertFalse(result["decrypt"]["hit"])
        self.assertIn("skipped", result["decrypt"])


class CrackPayloadTest(unittest.TestCase):
    """WebUI「破解」按钮背后的定向解密与口令挖掘。"""

    def _ciphertext(self, password: str, plain: bytes) -> bytes:
        key, iv = derive_key_iv(password, b"", key_len=16, iv_len=16,
                                kdf="evp", digest="md5")
        return aes_cbc_encrypt(plain, key, iv)

    def test_explicit_recipe_hits_and_reports_flags(self):
        plain = b"flag{crack_payload}\n" * 4
        blob = self._ciphertext("icmp", plain)
        result = payload_bin.crack_payload(
            blob, name="icmp_tunnel_1.1.1.1_2.2.2.2.bin",
            passwords=["wrong", "icmp"], cipher="aes-128-cbc",
            digest="md5", salted=False)
        self.assertTrue(result["hit"])
        self.assertEqual(result["password"], "icmp")
        self.assertEqual(result["attempts"], 2)
        self.assertIn("flag{crack_payload}", result["flags"])
        self.assertIn("aes-128-cbc", result["recipe"])

    def test_wrong_password_misses_with_command(self):
        blob = self._ciphertext("icmp", b"flag{never}\n" * 4)
        result = payload_bin.crack_payload(
            blob, passwords=["nope"], cipher="aes-128-cbc",
            digest="md5", salted=False)
        self.assertFalse(result["hit"])
        self.assertEqual(result["attempts"], 1)
        self.assertIn("openssl enc -d", result["example_command"])

    def test_salted_true_without_envelope_errors(self):
        result = payload_bin.crack_payload(
            b"A" * 32, passwords=["x"], cipher="aes-128-cbc",
            digest="md5", salted=True)
        self.assertFalse(result["hit"])
        self.assertIn("盐头", result["error"])

    def test_mine_passwords_from_keyvalue_and_basic(self):
        token = base64.b64encode(b"admin:S3cret!").decode()
        blob = (b"user=admin&password=hunter2\r\n"
                b"Authorization: Basic " + token.encode() + b"\r\n")
        mined = payload_bin.mine_passwords(blob)
        self.assertIn("hunter2", mined)
        self.assertIn("S3cret!", mined)
        self.assertLessEqual(len(mined), 20)


if __name__ == "__main__":
    unittest.main()
