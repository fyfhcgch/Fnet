"""Pure-stdlib unit tests for the OpenSSL file crypto/entropy/handler module.

No tshark required. Covers the ``crypto.py`` helpers (AES-CTR +
EVP_BytesToKey), the ``entropy.py`` analysis, and the modern
``openssl_file`` handler (noise suppression, Base64/PBKDF2/zlib/raw key,
password_file, no-password path) through a minimal ``FeatureContext`` stand-in.

All encrypted fixtures are built with stdlib only (``hashlib.pbkdf2_hmac``,
``base64``, ``zlib`` and the repo's pure-Python AES helpers); no openssl CLI.
"""
from __future__ import annotations

import base64
import hashlib
import os
import tempfile
import unittest
import zlib
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


# ---------------------------------------------------------------------------
# Handler-level helpers (all stdlib; no openssl CLI required).
# ---------------------------------------------------------------------------
class _FakeCtx:
    """Minimal ``FeatureContext`` stand-in recording findings/logs/artifacts."""

    def __init__(self, output_dir: Path | None = None, params: dict | None = None):
        self.output_dir = output_dir
        self.params = params or {}
        self.findings: list[dict] = []
        self.reports: list[tuple[str, str]] = []
        self.writes: dict[str, bytes] = {}
        self.progress: list[int] = []
        self.cancels = 0

    def report(self, text, level="info"):
        self.reports.append((text, level))

    def add_finding(self, kind, summary, *, frame="", detail="",
                    level="info", extra=None):
        self.findings.append({"kind": kind, "summary": summary,
                              "frame": frame, "detail": detail,
                              "level": level, "extra": extra or {}})

    def set_progress(self, value):
        self.progress.append(value)

    def check_cancel(self):
        self.cancels += 1

    def cancelled(self):
        return False

    def write_output(self, name, data):
        self.writes[name] = data
        return Path(name)

    def summaries(self):
        return [item["summary"] for item in self.findings]

    def log_text(self):
        return "\n".join(text for text, _ in self.reports)


def _pbkdf2_cbc_blob(password: str, salt: bytes, plaintext: bytes,
                     *, iterations=10000, digest="sha256",
                     salted=True, b64=False) -> bytes:
    """Build an ``openssl enc -aes-256-cbc -pbkdf2`` compatible blob."""
    material = hashlib.pbkdf2_hmac(digest, password.encode("utf-8"), salt,
                                   iterations, dklen=48)
    key, iv = material[:32], material[32:]
    body = aes_cbc_encrypt(plaintext, key, iv)
    blob = (b"Salted__" + salt + body) if salted else body
    return base64.b64encode(blob) if b64 else blob


class HandlerRobustnessTest(unittest.TestCase):
    def test_no_candidates_does_not_crash(self):
        from fnet.features.openssl_file import detect_encrypted_files

        class FakeOut:
            def is_dir(self):
                return True

            def iterdir(self):
                return iter([])

        class BareCtx:
            output_dir = FakeOut()

            def __init__(self):
                self.params = {}

            def report(self, text, level="info"):
                pass

            def check_cancel(self):
                pass

            def set_progress(self, value):
                pass

            def add_finding(self, *a, **k):
                pass

            def write_output(self, name, data):
                return Path(name)

        detect_encrypted_files(BareCtx())  # must not raise even with no files

    def test_entropy_safe_without_file_param(self):
        from fnet.utils.entropy import classify
        self.assertIsInstance(classify(b""), dict)


class HandlerNoiseSuppressionTest(unittest.TestCase):
    def test_generated_c2_readme_creates_no_finding(self):
        """Screenshot case: medium-entropy generated text must not appear at all."""
        from fnet.features.openssl_file import detect_encrypted_files
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # A medium-entropy (~6) UTF-8 helper text like the C2 handler writes.
            text = ("C2 README\n" + "beacon task list: " +
                    "".join(chr(33 + (i * 7) % 90) for i in range(400)) + "\n")
            (root / "c2_README.txt").write_text(text, encoding="utf-8")
            ctx = _FakeCtx(output_dir=root, params={})
            detect_encrypted_files(ctx)
            self.assertEqual(ctx.findings, [],
                             f"生成文本不应产生任何发现: {ctx.summaries()}")
            self.assertTrue(any("跳过" in text and "生成" in text
                                for text, _ in ctx.reports),
                            "应给出跳过生成/明文工件的中文日志")

    def test_report_and_findings_are_skipped(self):
        from fnet.features.openssl_file import detect_encrypted_files
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("findings.json", "findings.csv", "report.md",
                         "job.json"):
                (root / name).write_text("x" * 200, encoding="utf-8")
            ctx = _FakeCtx(output_dir=root, params={})
            detect_encrypted_files(ctx)
            self.assertEqual(ctx.findings, [])

    def test_medium_entropy_text_without_marker_is_log_only(self):
        """Even if not recognised as generated, plain UTF-8 text has no finding."""
        from fnet.features.openssl_file import _entropy_report
        ctx = _FakeCtx()
        data = ("".join(chr(33 + (i * 13) % 90) for i in range(500))
                ).encode("utf-8")
        _entropy_report(ctx, [("notes.txt", data)])
        self.assertEqual(ctx.findings, [])


class HandlerIcmpTunnelSkipTest(unittest.TestCase):
    """icmp_tunnel_*.bin 及其产物由 flows.icmp 载荷分析覆盖，这里必须跳过。"""

    def test_icmp_tunnel_artifacts_are_skipped(self):
        from fnet.features.openssl_file import detect_encrypted_files

        blob = _pbkdf2_cbc_blob("pw", b"\x55" * 8, os.urandom(512))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "icmp_tunnel_1.2.3.4_5.6.7.8.bin").write_bytes(blob)
            (root / "icmp_tunnel_1.2.3.4_5.6.7.8_decoded.txt").write_text(
                "plain text artifact" * 20, encoding="utf-8")
            (root / "secret.enc").write_bytes(blob)
            ctx = _FakeCtx(output_dir=root, params={})
            detect_encrypted_files(ctx)
            summaries = ctx.summaries()
            # 普通 secret.enc 仍然产生发现
            self.assertTrue(any("secret.enc" in s for s in summaries),
                            summaries)
            # ICMP 隧道载荷及其产物不再重复告警
            self.assertFalse(any("icmp_tunnel" in s for s in summaries),
                             summaries)
            # 跳过清单里有中文日志说明
            self.assertTrue(any("icmp_tunnel" in text and "跳过" in text
                                for text, _ in ctx.reports),
                            ctx.log_text())

    def test_icmp_tunnel_bin_via_path_param_is_skipped(self):
        from fnet.features.openssl_file import detect_encrypted_files

        blob = _pbkdf2_cbc_blob("pw", b"\x66" * 8, os.urandom(512))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_path = root / "icmp_tunnel_10.0.0.1_10.0.0.2.bin"
            bin_path.write_bytes(blob)
            ctx = _FakeCtx(output_dir=root / "out", params={"path": str(bin_path)})
            detect_encrypted_files(ctx)
            self.assertEqual(ctx.findings, [], ctx.summaries())


class HandlerDecryptTest(unittest.TestCase):
    def _run(self, root: Path, params: dict) -> _FakeCtx:
        from fnet.features.openssl_file import detect_encrypted_files
        ctx = _FakeCtx(output_dir=root, params=params)
        detect_encrypted_files(ctx)
        return ctx

    def test_base64_pbkdf2_cbc_decrypts(self):
        password = "hunter2"
        plaintext = b"flag{base64-pbkdf2-aes256cbc}\n" * 3
        salt = b"\x11" * 8
        blob = _pbkdf2_cbc_blob(password, salt, plaintext,
                                b64=True)
        self.assertTrue(blob.startswith(b"U2FsdGVkX1"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "secret.enc").write_bytes(blob)
            ctx = self._run(root, {
                "password": password, "cipher": "aes-256-cbc",
                "kdf": "pbkdf2", "digest": "sha256", "iter": 10000,
                "base64": True, "saltlen": 8,
            })
            self.assertIn("OpenSSL 解密成功 secret.enc", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), plaintext)
            self.assertEqual(ctx.writes.get("secret.decrypted"), plaintext)
            self.assertNotIn(password, ctx.log_text())

    def test_evp_md5_nosalt_ctr_decrypts(self):
        password = "haha"
        plaintext = b"flag{evp-md5-nosalt-ctr}\n" * 2
        key, iv = evp_bytes_to_key(password.encode("utf-8"), None, 32, 16, "md5")
        body = aes_ctr_crypt(plaintext, key, iv)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "flag.bin").write_bytes(body)
            ctx = self._run(root, {
                "password": password, "cipher": "aes-256-ctr",
                "kdf": "evp", "md": "md5", "nosalt": True,
            })
            self.assertIn("OpenSSL 解密成功 flag.bin", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), plaintext)

    def test_zlib_decompression(self):
        password = "zip"
        raw = b"flag{zlib-decompressed}\n" * 10
        plaintext = zlib.compress(raw)
        salt = b"\x22" * 8
        blob = _pbkdf2_cbc_blob(password, salt, plaintext)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packed.enc").write_bytes(blob)
            ctx = self._run(root, {
                "password": password, "cipher": "aes-256-cbc",
                "kdf": "pbkdf2", "zlib": True,
            })
            self.assertIn("OpenSSL 解密成功 packed.enc", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), raw)

    def test_zlib_wraps_whole_envelope(self):
        """Real OpenSSL 4.x ``-z``: zlib(Salted__ + salt + AES(...))."""
        password = "zip-outer"
        raw = b"flag{zlib-wrapped-envelope}\n" * 8
        salt = b"\x55" * 8
        envelope = _pbkdf2_cbc_blob(password, salt, raw)
        self.assertTrue(envelope.startswith(b"Salted__"))
        blob = zlib.compress(envelope)
        self.assertTrue(blob.startswith(b"\x78"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wrapped.enc").write_bytes(blob)
            ctx = self._run(root, {
                "password": password, "cipher": "aes-256-cbc",
                "kdf": "pbkdf2", "zlib": True,
            })
            self.assertIn("OpenSSL 解密成功 wrapped.enc", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), raw)

    def test_explicit_key_and_iv(self):
        key = bytes(range(32))
        iv = bytes(range(16))
        plaintext = b"flag{raw-key-iv}\n"
        body = aes_cbc_encrypt(plaintext, key, iv)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "raw.enc").write_bytes(body)
            ctx = self._run(root, {
                "key": key.hex(), "iv": iv.hex(),
                "cipher": "aes-256-cbc", "nosalt": True,
            })
            self.assertIn("OpenSSL 解密成功 raw.enc", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), plaintext)

    def test_password_file(self):
        password = "from-file"
        plaintext = b"flag{password-file-ok}\n"
        salt = b"\x33" * 8
        blob = _pbkdf2_cbc_blob(password, salt, plaintext)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.enc").write_bytes(blob)
            pw_path = root / "pw.txt"
            pw_path.write_text(f"\n\n{password}\n", encoding="utf-8")
            ctx = self._run(root, {
                "password_file": str(pw_path), "cipher": "aes-256-cbc",
                "kdf": "pbkdf2",
            })
            self.assertIn("OpenSSL 解密成功 data.enc", ctx.summaries())
            self.assertEqual(ctx.writes.get("decrypted.bin"), plaintext)
            self.assertNotIn(password, ctx.log_text())

    def test_no_password_logs_without_crashing(self):
        from fnet.features.openssl_file import detect_encrypted_files
        blob = _pbkdf2_cbc_blob("pw", b"\x44" * 8, b"secret data" * 20)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "locked.enc").write_bytes(blob)
            ctx = _FakeCtx(output_dir=root, params={})
            detect_encrypted_files(ctx)  # must not raise
            self.assertTrue(any("仅执行检测" in text for text, _ in ctx.reports))
            self.assertFalse(any("解密成功" in s for s in ctx.summaries()))


if __name__ == "__main__":
    unittest.main()
