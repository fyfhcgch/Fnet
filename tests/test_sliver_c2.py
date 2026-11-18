"""Sliver C2 解密核心自测：RFC 8439 向量、会话解密、编码器与分类。"""
from __future__ import annotations

import base64
import gzip
import struct
import unittest

from fnet.utils import sliver_c2 as c2
from fnet.utils.crypto import aes_gcm_encrypt


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _field(number: int, wire: int, payload: bytes) -> bytes:
    return _varint((number << 3) | wire) + payload


def _encrypt_chacha(
    key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes = b"\x01" * 12
) -> bytes:
    """测试专用加密助手：复用模块内部原语生成 nonce||ct||tag。"""
    otk = c2._poly1305_key(key, nonce)
    ciphertext = c2._chacha20_xor(key, 1, nonce, plaintext)
    mac = aad + c2._pad16(aad) + ciphertext + c2._pad16(ciphertext)
    mac += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    tag = c2._poly1305_mac(mac, otk)
    return nonce + ciphertext + tag


class ChaCha20Poly1305Test(unittest.TestCase):
    """RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 官方向量。"""

    KEY = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    NONCE = bytes.fromhex("070000004041424344454647")
    AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    PLAINTEXT = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    CIPHERTEXT = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )
    TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    def test_rfc8439_vector(self):
        blob = self.NONCE + self.CIPHERTEXT + self.TAG
        plaintext, reason = c2.chacha20_poly1305_decrypt(blob, self.KEY, self.AAD)
        self.assertIsNone(reason)
        self.assertEqual(plaintext, self.PLAINTEXT)

    def test_wrong_key_and_tag_rejected(self):
        blob = self.NONCE + self.CIPHERTEXT + self.TAG
        self.assertEqual(
            c2.chacha20_poly1305_decrypt(blob, bytes(32), self.AAD)[0], None
        )
        broken = blob[:-1] + bytes([blob[-1] ^ 1])
        self.assertEqual(
            c2.chacha20_poly1305_decrypt(broken, self.KEY, self.AAD)[0], None
        )

    def test_malformed_inputs_never_raise(self):
        for blob, key in ((b"", self.KEY), (b"short", self.KEY),
                          (b"\x00" * 40, b"bad"), (None, self.KEY)):
            plaintext, reason = c2.chacha20_poly1305_decrypt(blob, key)
            self.assertIsNone(plaintext)
            self.assertIsNotNone(reason)


class DecryptSessionTest(unittest.TestCase):
    KEY = bytes(range(32))

    def test_gzip_roundtrip(self):
        raw = b"flag{sliver_gzip} " + b"A" * 200
        blob = _encrypt_chacha(self.KEY, gzip.compress(raw))
        result = c2.decrypt_session(blob, self.KEY)
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], raw)
        self.assertEqual(result["cipher"], "chacha20-poly1305")
        self.assertFalse(result["signature_skipped"])
        self.assertTrue(result["compressed"])

    def test_raw_plaintext_accepted(self):
        raw = b"flag{sliver_raw}"
        result = c2.decrypt_session(_encrypt_chacha(self.KEY, raw), self.KEY)
        self.assertEqual(result["plaintext"], raw)
        self.assertFalse(result["compressed"])

    def test_minisign_signature_prefix_skipping(self):
        raw = b"signed session payload"
        blob = b"S" * 74 + _encrypt_chacha(self.KEY, gzip.compress(raw))
        result = c2.decrypt_session(blob, self.KEY)
        self.assertIsNotNone(result)
        self.assertTrue(result["signature_skipped"])
        self.assertEqual(result["plaintext"], raw)
        # 关闭签名跳过后，整段带签名的 blob 无法通过 tag 校验。
        self.assertIsNone(
            c2.decrypt_session(blob, self.KEY, allow_signature=False)
        )

    def test_legacy_aes_gcm_compatibility(self):
        key = bytes(range(16))
        nonce = b"\x09" * 12
        raw = b"legacy aes-gcm session"
        blob = nonce + aes_gcm_encrypt(gzip.compress(raw), key, nonce)
        result = c2.decrypt_session(blob, key)
        self.assertIsNotNone(result)
        self.assertEqual(result["cipher"], "aes-gcm")
        self.assertFalse(result["signature_skipped"])
        self.assertEqual(result["plaintext"], raw)
        self.assertTrue(result["compressed"])

    def test_all_failures_return_none(self):
        self.assertIsNone(c2.decrypt_session(b"garbage", self.KEY))
        self.assertIsNone(c2.decrypt_session(b"", b""))
        self.assertIsNone(c2.decrypt_session(None, self.KEY))


class BodyCandidatesTest(unittest.TestCase):
    PAYLOAD = b"flag{body_candidate}\x00\x01\x02\x03"

    def test_base64_hex_gzip(self):
        encoded = base64.b64encode(self.PAYLOAD)
        names = dict(c2.decode_body_candidates(encoded))
        self.assertIn(self.PAYLOAD, names)
        self.assertEqual(names[self.PAYLOAD], "base64")

        names = dict(c2.decode_body_candidates(self.PAYLOAD.hex().encode()))
        self.assertEqual(names.get(self.PAYLOAD), "hex")

        names = dict(c2.decode_body_candidates(gzip.compress(self.PAYLOAD)))
        self.assertEqual(names.get(self.PAYLOAD), "gzip")

    def test_custom_base64_and_modified_encoders(self):
        custom = base64.b64encode(self.PAYLOAD).decode().rstrip("=")
        custom = custom.translate(
            str.maketrans(
                c2._STD_B64, c2.SLIVER_BASE64_ALPHABET
            )
        )
        names = dict(c2.decode_body_candidates(custom.encode()))
        self.assertEqual(names.get(self.PAYLOAD), "custom-base64")

        b32 = base64.b32encode(self.PAYLOAD).decode().rstrip("=")
        b32 = b32.translate(
            str.maketrans(c2._STD_B32, c2.SLIVER_BASE32_ALPHABET)
        )
        names = dict(c2.decode_body_candidates(b32.encode()))
        self.assertEqual(names.get(self.PAYLOAD), "base32-sliver")

        b58 = c2._b58encode(self.PAYLOAD)
        names = dict(c2.decode_body_candidates(b58.encode()))
        self.assertEqual(names.get(self.PAYLOAD), "base58")

    def test_uri_nonce_and_unsupported_labels(self):
        names = dict(c2.decode_body_candidates(
            b"", "/x.php?_=" + base64.b64encode(self.PAYLOAD).decode()
        ))
        self.assertEqual(names.get(self.PAYLOAD), "base64")
        names = dict(c2.decode_body_candidates(
            b"rawdata", "/x.js?encoder=english"
        ))
        self.assertEqual(names.get(b"rawdata"), "unsupported:english")

    def test_cap_and_no_raise(self):
        candidates = c2.decode_body_candidates(b"x" * 4096)
        self.assertLessEqual(len(candidates), c2.MAX_CANDIDATES)
        self.assertEqual(c2.decode_body_candidates(None), [])


class EnvelopeTest(unittest.TestCase):
    def test_parse_known_and_unknown_fields(self):
        data = (
            _field(1, 0, _varint(42))
            + _field(2, 0, _varint(7))
            + _field(3, 2, _varint(3) + b"abc")  # 嵌套字节原样保留
            + _field(4, 0, _varint(1))
            + _field(99, 0, _varint(123))
        )
        envelope = c2.parse_envelope(data)
        self.assertEqual(envelope["id"], 42)
        self.assertEqual(envelope["type"], 7)
        self.assertEqual(envelope["data"], b"abc")
        self.assertTrue(envelope["unknown"])

    def test_negative_and_malformed(self):
        self.assertIsNone(c2.parse_envelope(b"not protobuf at all"))
        self.assertIsNone(c2.parse_envelope(b""))
        self.assertIsNone(c2.parse_envelope(b"\x1a\xff"))  # 截断长度


class KeyExchangeTest(unittest.TestCase):
    def test_v16_age_trimmed_marker(self):
        share = base64.b64encode(b"\x02" * 32).decode().rstrip("=")
        wrapped = base64.b64encode(b"\x03" * 32).decode().rstrip("=")
        age = (share + "\n" + wrapped + "\n--- aaaaaaaaaaaaaaaaaaaaaa\n"
               + "binary" * 20).encode()
        blob = b"\xaa" * 32 + age
        result = c2.classify_key_exchange(blob, "/x.html?_=abc")
        self.assertIsNotNone(result)
        self.assertEqual(result["version"], "v1.6")
        self.assertEqual(result["kind"], "age-x25519")
        self.assertGreaterEqual(result["confidence"], 75)

    def test_v15_totp_nacl_sealedbox(self):
        blob = b"12345678" + b"\x11" * 32 + b"\x22" * 80
        result = c2.classify_key_exchange(blob, "/x.html")
        self.assertEqual(result["version"], "v1.5")
        self.assertEqual(result["kind"], "totp-nacl-sealedbox")

    def test_legacy_rsa_der(self):
        blob = b"\x30\x82\x01\x00" + b"\x33" * 256
        result = c2.classify_key_exchange(blob, "/keyexchange.php")
        self.assertEqual(result["version"], "<=1.4")
        self.assertEqual(result["kind"], "rsa-key-exchange")

    def test_benign_negative(self):
        benign = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        self.assertIsNone(c2.classify_key_exchange(benign))
        self.assertIsNone(c2.classify_key_exchange(b"A" * 256))
        self.assertIsNone(c2.classify_key_exchange(b"short"))


class SummaryTest(unittest.TestCase):
    def test_flag_extraction_from_decrypted_plaintext(self):
        raw = b"header\x00flag{sliver_decrypted}\x00tail"
        result = c2.decrypt_session(_encrypt_chacha(bytes(range(32)), raw),
                                    bytes(range(32)))
        summary = c2.sliver_summary(result["plaintext"])
        self.assertIn("flag{sliver_decrypted}", summary["flags"])
        self.assertIn("flag{sliver_decrypted}", summary["text"])

    def test_envelope_and_tlv_summary(self):
        data = b"\x08\x2a\x10\x07"  # id=42, type=7
        summary = c2.sliver_summary(data)
        self.assertEqual(summary["envelope"]["id"], 42)
        self.assertFalse(summary["tlv_like"])
        tlv = b"\x01\x03abc\x02\x03def"
        summary = c2.sliver_summary(tlv)
        self.assertTrue(summary["tlv_like"])
        self.assertEqual(summary["tlv"][0]["tag"], 1)


if __name__ == "__main__":
    unittest.main()
