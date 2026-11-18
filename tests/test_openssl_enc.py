"""OpenSSL ``enc`` envelope 解析与解密核心的纯标准库测试。

不依赖 tshark / 第三方包：所有密文都用 ``fnet.utils.crypto`` 的原始 AES
原语现场构造，因此测试向量与实现相互独立（KDF 用 hashlib 参考实现校验）。
"""
from __future__ import annotations

import base64
import hashlib
import unittest
import zlib

from fnet.utils.crypto import (
    aes_cbc_encrypt,
    aes_ctr_crypt,
    aes_ecb_encrypt,
    evp_bytes_to_key,
)
from fnet.utils.openssl_enc import (
    BASE64_MAGIC,
    ENVELOPE_MAGIC,
    OpenSslEnvelope,
    classify_payload,
    decode_base64_candidates,
    decrypt_bytes,
    decrypt_envelope,
    derive_key_iv,
    detect_envelope,
    looks_like_generated_text,
    parse_cipher,
    recipe_candidates,
)

FLAG = b"flag{openssl-enc-stdlib-core}\n"


def _pw(password) -> bytes:
    return password.encode("utf-8") if isinstance(password, str) else bytes(password)


def _digest(name: str) -> str:
    return (name or "md5").lower().replace("-", "").replace("_", "")


def _evp_ref(password: bytes, salt: bytes | None, key_len: int, iv_len: int,
             digest=hashlib.md5) -> tuple[bytes, bytes]:
    """EVP_BytesToKey 的独立参考实现（D_i = H(D_{i-1} || pw || salt)）。"""
    material = b"" if not salt else salt
    data, d = b"", b""
    while len(data) < key_len + iv_len:
        d = digest(d + password + material).digest()
        data += d
    return data[:key_len], data[key_len:key_len + iv_len]


def _seal(plaintext: bytes, password="pw", *, cipher="aes-256-cbc",
          kdf="evp", digest="md5", iterations=1,
          salt=b"\x01\x02\x03\x04\x05\x06\x07\x08", base64_out=False,
          inner_zlib=False, outer_zlib=False, key=None, iv=None) -> bytes:
    """构造 OpenSSL 风格封装；可选内层/外层 zlib 与 Base64。"""
    info = parse_cipher(cipher)
    key_len, iv_len, mode = info["key_len"], info["iv_len"], info["mode"]
    if key is None:
        if kdf == "pbkdf2":
            material = hashlib.pbkdf2_hmac(
                _digest(digest), _pw(password), salt, iterations,
                key_len + iv_len)
            key, iv = material[:key_len], material[key_len:]
        else:
            key, iv = evp_bytes_to_key(_pw(password), salt or None,
                                       key_len, iv_len, digest)
    body_plain = zlib.compress(plaintext) if inner_zlib else plaintext
    if mode == "cbc":
        body = aes_cbc_encrypt(body_plain, key, iv)
    elif mode == "ecb":
        body = aes_ecb_encrypt(body_plain, key)
    else:
        body = aes_ctr_crypt(body_plain, key, iv)
    blob = ENVELOPE_MAGIC + salt + body
    if outer_zlib:
        blob = zlib.compress(blob)
    return base64.b64encode(blob) if base64_out else blob


class ConstantsAndCipherTest(unittest.TestCase):
    def test_magic_constants(self):
        self.assertEqual(ENVELOPE_MAGIC, b"Salted__")
        self.assertEqual(BASE64_MAGIC, "U2FsdGVkX1")
        self.assertTrue(base64.b64encode(ENVELOPE_MAGIC).startswith(
            BASE64_MAGIC.encode("ascii")))

    def test_dataclass_fields(self):
        env = OpenSslEnvelope(salt=b"s", ciphertext=b"c", salted=True,
                              encoding="raw", salt_len=1, marker="Salted__")
        self.assertEqual(env.trailing, b"")

    def test_parse_cipher_variants(self):
        for name, key_bits, mode, iv_len in (
            ("aes-256-cbc", 256, "cbc", 16),
            ("aes128ctr", 128, "ctr", 16),
            ("-aes-192-ecb", 192, "ecb", 0),
            ("AES_256_CBC", 256, "cbc", 16),
        ):
            with self.subTest(name=name):
                info = parse_cipher(name)
                self.assertEqual(info["key_len"], key_bits // 8)
                self.assertEqual(info["mode"], mode)
                self.assertEqual(info["iv_len"], iv_len)
                self.assertEqual(set(info), {"name", "key_len", "mode", "iv_len"})

    def test_unknown_cipher_does_not_raise(self):
        info = parse_cipher("des-ede3-cbc")
        self.assertEqual(info["mode"], "unknown")
        self.assertEqual(parse_cipher(None)["mode"], "unknown")
        self.assertEqual(parse_cipher("aes-256-gcm")["mode"], "unknown")

    def test_recipe_candidates_bounded_and_ordered(self):
        recipes = recipe_candidates()
        self.assertLessEqual(len(recipes), 24)
        self.assertGreater(len(recipes), 10)
        required = {"cipher", "key_len", "mode", "iv_len", "kdf", "digest",
                    "iterations", "salt_len", "nosalt", "base64", "zlib",
                    "nopad", "key_hex", "iv_hex"}
        self.assertTrue(all(required <= set(item) for item in recipes))
        kinds = {(r["kdf"], r["digest"], r["iterations"], r["salt_len"])
                 for r in recipes}
        self.assertIn(("evp", "md5", 1, 8), kinds)
        self.assertIn(("evp", "sha256", 1, 8), kinds)
        self.assertIn(("pbkdf2", "sha256", 10000, 8), kinds)
        self.assertIn(("pbkdf2", "sha256", 1000, 8), kinds)
        self.assertIn(("pbkdf2", "sha256", 100000, 8), kinds)
        self.assertIn(("pbkdf2", "sha256", 10000, 16), kinds)

    def test_recipe_spec_overrides_come_first(self):
        recipes = recipe_candidates({"cipher": "aes-192-ecb", "kdf": "pbkdf2",
                                     "digest": "sha256", "iterations": 500,
                                     "salt_len": 16, "zlib": True})
        first = recipes[0]
        self.assertEqual(first["cipher"], "aes-192-ecb")
        self.assertEqual(first["key_len"], 24)
        self.assertEqual(first["mode"], "ecb")
        self.assertEqual(first["iv_len"], 0)
        self.assertEqual(first["iterations"], 500)
        self.assertEqual(first["salt_len"], 16)
        self.assertTrue(first["zlib"])


class DeriveAndDecryptBytesTest(unittest.TestCase):
    def test_evp_md5_known_vector(self):
        password = b"test"
        key, iv = derive_key_iv(password, None, key_len=32, iv_len=16,
                                kdf="evp", digest="md5")
        ref_key, ref_iv = _evp_ref(password, None, 32, 16, hashlib.md5)
        self.assertEqual((key, iv), (ref_key, ref_iv))
        self.assertEqual(key[:16], hashlib.md5(b"test").digest())

    def test_evp_sha256_known_vector(self):
        password = b"password"
        salt = b"\xde\xad\xbe\xef\x01\x02\x03\x04"
        key, iv = derive_key_iv(password, salt, key_len=32, iv_len=16,
                                kdf="evp", digest="sha-256")
        ref_key, ref_iv = _evp_ref(password, salt, 32, 16, hashlib.sha256)
        self.assertEqual((key, iv), (ref_key, ref_iv))

    def test_pbkdf2_vector(self):
        password, salt = b"secret", b"\x00" * 8
        key, iv = derive_key_iv(password, salt, key_len=32, iv_len=16,
                                kdf="pbkdf2", digest="sha256", iterations=137)
        material = hashlib.pbkdf2_hmac("sha256", password, salt, 137, 48)
        self.assertEqual(key, material[:32])
        self.assertEqual(iv, material[32:])

    def test_str_password_is_utf8(self):
        a = derive_key_iv("密码", b"salt", digest="md5")
        b = derive_key_iv("密码".encode("utf-8"), b"salt", digest="md5")
        self.assertEqual(a, b)

    def test_programmer_errors_raise_value_error(self):
        with self.assertRaises(ValueError):
            derive_key_iv(b"p", b"", kdf="scrypt")
        with self.assertRaises(ValueError):
            derive_key_iv(b"p", b"", digest="no-such-hash")
        with self.assertRaises(ValueError):
            derive_key_iv(b"p", b"", kdf="pbkdf2", iterations=0)

    def test_bad_padding_returns_none(self):
        key, iv = b"\x11" * 32, b"\x22" * 16
        ct = bytearray(aes_cbc_encrypt(FLAG, key, iv))
        ct[-1] ^= 0xFF
        self.assertIsNone(decrypt_bytes(bytes(ct), key, iv, mode="cbc"))
        self.assertIsNotNone(decrypt_bytes(bytes(ct), key, iv,
                                           mode="cbc", unpad=False))
        self.assertIsNone(decrypt_bytes(b"\x00" * 15, key, iv, mode="cbc"))
        self.assertIsNone(decrypt_bytes(FLAG, key, iv, mode="unknown"))


class DetectEnvelopeTest(unittest.TestCase):
    def test_raw(self):
        blob = _seal(FLAG)
        env = detect_envelope(blob)
        self.assertIsInstance(env, OpenSslEnvelope)
        self.assertTrue(env.salted)
        self.assertEqual(env.encoding, "raw")
        self.assertEqual(env.marker, "Salted__")
        self.assertEqual(env.salt, b"\x01" * 0 + b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(ENVELOPE_MAGIC + env.salt + env.ciphertext, blob)

    def test_base64_with_and_without_linebreaks(self):
        raw = _seal(FLAG, cipher="aes-128-cbc")
        blob = base64.b64encode(raw)
        for form in (blob, base64.encodebytes(raw)):
            with self.subTest(linebreaks=b"\n" in form):
                env = detect_envelope(form)
                self.assertIsNotNone(env)
                self.assertEqual(env.encoding, "base64")
                self.assertEqual(env.marker, BASE64_MAGIC)
                self.assertEqual(env.salt, b"\x01\x02\x03\x04\x05\x06\x07\x08")

    def test_no_marker_returns_none(self):
        self.assertIsNone(detect_envelope(b"just plain text"))
        self.assertIsNone(detect_envelope(ENVELOPE_MAGIC))
        self.assertIsNone(detect_envelope(ENVELOPE_MAGIC + b"\x01" * 3))
        self.assertIsNone(detect_envelope(b""))
        self.assertIsNone(detect_envelope(None))

    def test_explicit_salt_without_header(self):
        # OpenSSL 3.x：显式 -S 不写 Salted__，整段都是密文。
        key, iv = evp_bytes_to_key(b"pw", b"\xaa" * 8, 32, 16, "md5")
        body = aes_cbc_encrypt(FLAG, key, iv)
        env = detect_envelope(body, spec={"salt_hex": ("aa" * 8)})
        self.assertIsNotNone(env)
        self.assertEqual(env.marker, "explicit-S")
        self.assertFalse(env.salted)
        self.assertEqual(env.salt, b"\xaa" * 8)
        self.assertEqual(env.ciphertext, body)

    def test_outer_zlib_before_marker(self):
        # 真实 CLI case 06：78 9c ... Salted__ ...，先 inflate 再识别。
        blob = _seal(FLAG, outer_zlib=True)
        self.assertTrue(blob.startswith(b"\x78\x9c"))
        env = detect_envelope(blob)
        self.assertIsNotNone(env)
        self.assertEqual(env.marker, "Salted__")
        self.assertEqual(env.encoding, "raw")

    def test_decode_base64_candidates_dedup_and_safe(self):
        cands = decode_base64_candidates(base64.encodebytes(_seal(FLAG,
                                                           base64_out=True)))
        self.assertGreaterEqual(len(cands), 2)
        self.assertEqual(cands[0][1], "raw")
        self.assertEqual(len({raw for raw, _ in cands}), len(cands))
        self.assertEqual(decode_base64_candidates(b"!!!")[0][0], b"!!!")
        self.assertEqual(decode_base64_candidates(None), [])


class DecryptEnvelopeTest(unittest.TestCase):
    def test_raw_aes256_cbc_md5(self):
        result = decrypt_envelope(_seal(FLAG), "pw")
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["recipe"]["digest"], "md5")
        self.assertEqual(result["recipe"]["mode"], "cbc")
        self.assertEqual(result["recipe"]["kdf"], "evp")
        self.assertIn("flag{openssl-enc-stdlib-core}", result["flags"])
        self.assertEqual(result["envelope"]["marker"], "Salted__")
        self.assertGreater(result["score"], 0)

    def test_raw_aes256_cbc_sha256(self):
        blob = _seal(FLAG, digest="sha256")
        result = decrypt_envelope(blob, "pw", spec={"digest": "sha256"})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["recipe"]["digest"], "sha256")

    def test_base64_aes128_cbc_with_and_without_linebreaks(self):
        raw = _seal(FLAG, cipher="aes-128-cbc")
        for form in (base64.b64encode(raw), base64.encodebytes(raw)):
            with self.subTest(linebreaks=b"\n" in form):
                result = decrypt_envelope(form, "pw",
                                          spec={"cipher": "aes-128-cbc"})
                self.assertIsNotNone(result)
                self.assertEqual(result["plaintext"], FLAG)
                self.assertEqual(result["recipe"]["key_len"], 16)

    def test_pbkdf2_iter10000_salt8(self):
        blob = _seal(FLAG, kdf="pbkdf2", digest="sha256", iterations=10000,
                     salt=b"\x00" * 8)
        result = decrypt_envelope(blob, "pw", spec={
            "cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256",
            "iterations": 10000, "salt_len": 8})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["recipe"]["iterations"], 10000)

    def test_pbkdf2_iter10000_salt16(self):
        salt = bytes(range(16))
        blob = _seal(FLAG, kdf="pbkdf2", digest="sha256", iterations=10000,
                     salt=salt)
        result = decrypt_envelope(blob, "pw", spec={
            "cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256",
            "iterations": 10000, "salt_len": 16})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["envelope"]["salt"], salt)

    def test_aes256_ctr_iv_is_counter(self):
        iv = b"\x00" * 15 + b"\x2a"
        blob = _seal(FLAG, cipher="aes-256-ctr", iv=iv)
        result = decrypt_envelope(blob, "pw", spec={"cipher": "aes-256-ctr"})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["recipe"]["mode"], "ctr")

    def test_aes192_ecb(self):
        blob = _seal(FLAG, cipher="aes-192-ecb")
        result = decrypt_envelope(blob, "pw", spec={"cipher": "aes-192-ecb"})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["recipe"]["key_len"], 24)
        self.assertEqual(result["recipe"]["iv_len"], 0)

    def test_explicit_key_iv_bypass(self):
        key, iv = b"\x33" * 32, b"\x44" * 16
        blob = aes_cbc_encrypt(FLAG, key, iv)  # -nosalt -K -iv
        result = decrypt_envelope(blob, "ignored", spec={
            "nosalt": True, "cipher": "aes-256-cbc",
            "key_hex": key.hex(), "iv_hex": iv.hex()})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["envelope"]["marker"], "nosalt")

    def test_inner_zlib(self):
        blob = _seal(FLAG, inner_zlib=True)
        result = decrypt_envelope(blob, "pw", spec={
            "cipher": "aes-256-cbc", "zlib": True})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)

    def test_outer_zlib_cli_compat(self):
        # case 06 形状：zlib 包裹整个 Salted__ 信封，无需显式 spec。
        blob = _seal(FLAG, outer_zlib=True)
        self.assertEqual(blob[:2], b"\x78\x9c")
        result = decrypt_envelope(blob, "pw")
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)

    def test_outer_zlib_with_zlib_spec(self):
        # spec 标记了 -z 但 zlib 实际套在信封外：不能因内层无法 inflate 而丢弃。
        blob = _seal(FLAG, outer_zlib=True)
        result = decrypt_envelope(blob, "pw", spec={"zlib": True})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)

    def test_explicit_salt_openssl3_no_header(self):
        salt = b"\xaa" * 8
        key, iv = evp_bytes_to_key(b"pw", salt, 32, 16, "md5")
        blob = aes_cbc_encrypt(FLAG, key, iv)  # 没有 Salted__
        result = decrypt_envelope(blob, "pw", spec={
            "cipher": "aes-256-cbc", "salt_hex": salt.hex()})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)
        self.assertEqual(result["envelope"]["salt"], salt)
        self.assertEqual(result["envelope"]["marker"], "explicit-S")

    def test_explicit_salt_openssl111_with_header(self):
        salt = b"\xbb" * 8
        blob = _seal(FLAG, salt=salt)
        result = decrypt_envelope(blob, "pw", spec={
            "cipher": "aes-256-cbc", "salt_hex": salt.hex()})
        self.assertIsNotNone(result)
        self.assertEqual(result["plaintext"], FLAG)

    def test_wrong_password_returns_none(self):
        self.assertIsNone(decrypt_envelope(_seal(FLAG), "wrong-password"))

    def test_malformed_inputs_never_raise(self):
        bad_inputs = [b"", b"x", b"Salted__", b"Salted__short",
                      ENVELOPE_MAGIC + b"\x00" * 8,
                      b"U2FsdGVkX1not base64 !!!", b"\x78\x9c\x00\x01",
                      os_urandom(64)]
        for blob in bad_inputs:
            with self.subTest(blob=blob[:16]):
                self.assertIsNone(decrypt_envelope(blob, "pw"))
                self.assertIsInstance(detect_envelope(blob),
                                      (OpenSslEnvelope, type(None)))
                self.assertIsInstance(classify_payload(blob), dict)
                self.assertIsInstance(decode_base64_candidates(blob), list)
                self.assertIsInstance(looks_like_generated_text("x", blob), bool)


class ClassifyAndNoiseTest(unittest.TestCase):
    def test_flag_text(self):
        cls = classify_payload(b"hello flag{abc123} world\n")
        self.assertTrue(cls["utf8_text"])
        self.assertTrue(cls["high_printable"])
        self.assertIn("flag{abc123}", cls["flags"])
        self.assertGreater(cls["score"], 10)

    def test_binary_magics(self):
        for data, name in (
            (b"PK\x03\x04rest", "zip"),
            (b"\x89PNG\r\n\x1a\nrest", "png"),
            (b"\x1f\x8b\x08rest", "gzip"),
            (b"%PDF-1.7 rest", "pdf"),
            (b"\x7fELFrest", "elf"),
            (b"SQLite format 3\x00rest", "sqlite"),
        ):
            with self.subTest(name=name):
                cls = classify_payload(data)
                self.assertTrue(cls[name])
                self.assertIn(name, cls["signatures"])
                self.assertGreaterEqual(cls["score"], 60)

    def test_json_xml_and_empty(self):
        self.assertTrue(classify_payload(b'{"a": 1}')["json"])
        self.assertTrue(classify_payload(b"<?xml version='1.0'?><a/>")["xml"])
        empty = classify_payload(b"")
        self.assertEqual(empty["score"], 0)
        self.assertFalse(empty["high_printable"])

    def test_generated_text(self):
        for name, data in (
            ("c2_README.txt", b"# C2 notes\nthis is generated help text\n"),
            ("logs/_README.txt", b"read me first\n"),
            ("findings.json", b"[]"),
            ("report.txt", b"Analysis report\n"),
            ("job.json", b"{}"),
            ("notes.txt", b"some ordinary utf8 text\n"),
        ):
            with self.subTest(name=name):
                self.assertTrue(looks_like_generated_text(name, data))

    def test_ciphertext_not_generated_text(self):
        self.assertFalse(looks_like_generated_text("blob.bin", _seal(FLAG)))
        self.assertFalse(looks_like_generated_text(
            "blob.txt", _seal(FLAG, base64_out=True)))
        self.assertFalse(looks_like_generated_text("blob.txt", os_urandom(64)))


def os_urandom(size: int) -> bytes:
    """用 hashlib 生成确定性伪随机字节，避免测试依赖 os.urandom 的可复现性。"""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"seed:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


if __name__ == "__main__":
    unittest.main()
