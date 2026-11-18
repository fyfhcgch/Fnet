"""NetNTLMv2 密码验证/枚举回退引擎的单测（纯标准库，无需 tshark）。"""
from __future__ import annotations

import unittest

from fnet.utils.crypto import hmac_md5, md4
from fnet.utils import ntlmcrack


def _build_v2_vector(user: str, domain: str, password: str,
                     challenge: bytes, blob: bytes):
    """按协议手工构造一条真实的 NTLMv2 响应。

    返回 ``(nt_hash, nt_response)``，用于自洽校验引擎的 HMAC 逻辑。
    """
    nt_hash = md4(password.encode("utf-16le"))
    response_key = hmac_md5(
        nt_hash, user.upper().encode("utf-16le") + domain.upper().encode("utf-16le"))
    proof = hmac_md5(response_key, challenge + blob)
    return nt_hash, proof + blob


class VerifyNtlmv2Test(unittest.TestCase):
    def setUp(self):
        self.user = "alice"
        self.domain = "LAB"
        self.password = "Password123"
        self.challenge = bytes.fromhex("0123456789abcdef")
        # 类似真实 NTLMv2 blob：8 字节 jpserver/challenge + 4 字节保留 +
        # 8 字节时间戳 + 8 字节 clientChallenge + 名称/内容
        self.blob = (bytearray(8) + b"\x00\x00\x00\x00"
                     + bytes.fromhex("0000000000000001")
                     + bytes.fromhex("1122334455667788"))
        self.blob += b"\x00" * 8
        self.nt_hash, self.nt_response = _build_v2_vector(
            self.user, self.domain, self.password, self.challenge, self.blob)

    def test_matches_constructed_vector(self):
        self.assertTrue(ntlmcrack.verify_ntlmv2(
            self.nt_hash, self.challenge, self.nt_response,
            self.user, self.domain))
        # 大小写不敏感 / 域前缀 / user@domain 写法都应正确解析
        self.assertTrue(ntlmcrack.verify_ntlmv2(
            self.nt_hash, self.challenge, self.nt_response,
            "LAB\\alice", self.domain))
        self.assertTrue(ntlmcrack.verify_ntlmv2(
            self.nt_hash, self.challenge, self.nt_response,
            "alice@company.com", self.domain))

    def test_wrong_password_fails(self):
        other_hash, _ = _build_v2_vector(
            self.user, self.domain, "WrongPass", self.challenge, self.blob)
        self.assertFalse(ntlmcrack.verify_ntlmv2(
            other_hash, self.challenge, self.nt_response,
            self.user, self.domain))

    def test_wrong_challenge_fails(self):
        other = bytes.fromhex("fedcba9876543210")
        self.assertFalse(ntlmcrack.verify_ntlmv2(
            self.nt_hash, other, self.nt_response, self.user, self.domain))

    def test_verify_password(self):
        self.assertTrue(ntlmcrack.verify_password(
            self.password, self.challenge, self.nt_response,
            self.user, self.domain))
        self.assertFalse(ntlmcrack.verify_password(
            "WrongPass", self.challenge, self.nt_response,
            self.user, self.domain))
        # 显式传入 nt_hash 也应一致
        self.assertTrue(ntlmcrack.verify_password(
            self.password, self.challenge, self.nt_response,
            self.user, self.domain, nt_hash=self.nt_hash))

    def test_malformed_inputs_no_throw(self):
        # 长度不足 / 非法类型一律返回 False / 空值，不抛异常
        self.assertFalse(ntlmcrack.verify_ntlmv2(b"", b"", b"", "u"))
        self.assertFalse(ntlmcrack.verify_ntlmv2(
            b"\x00" * 16, b"\x00" * 8, b"\x00" * 16, "u"))
        self.assertFalse(ntlmcrack.verify_ntlmv2(
            "not-bytes", self.challenge, self.nt_response, "u"))
        self.assertFalse(ntlmcrack.verify_ntlmv2(
            self.nt_hash, b"\x00" * 4, b"\x00" * 40, "u"))
        self.assertFalse(ntlmcrack.verify_password(
            None, None, None, None))
        self.assertEqual(ntlmcrack.nt_hash_from_hex("xyz"), b"")
        self.assertEqual(ntlmcrack.nt_hash_from_hex("abcd"), b"")
        self.assertEqual(ntlmcrack.nt_hash_from_hex(None), b"")
        self.assertIsNone(ntlmcrack.brute_force_ntlmv2(
            self.challenge, self.nt_response, self.user, self.domain,
            candidates=[]))
        self.assertFalse(ntlmcrack.verify_ntlmv1(b"\x00" * 16, b"\x00" * 8,
                                                 b"\x00" * 24))

    def test_normalize_account(self):
        self.assertEqual(ntlmcrack.normalize_account("LAB\\alice"), "ALICE")
        self.assertEqual(ntlmcrack.normalize_account("alice@corp"), "ALICE")
        self.assertEqual(ntlmcrack.normalize_account(" Alice "), "ALICE")

    def test_nt_hash_from_password(self):
        self.assertEqual(ntlmcrack.nt_hash_from_password(self.password),
                         md4(self.password.encode("utf-16le")))
        h = self.nt_hash.hex()
        self.assertEqual(ntlmcrack.nt_hash_from_hex(h), self.nt_hash)


class GenerateCandidatesTest(unittest.TestCase):
    def test_count_and_cancellation(self):
        # 长度为 1、字母表 "ab" => 恰好 2 个候选
        cases = list(ntlmcrack.generate_candidates(
            min_len=1, max_len=1, alphabet="ab"))
        self.assertEqual(cases, ["a", "b"])
        # 用 max_count 收敛（此处长度只到 2，成品为 a、aa）
        limited = list(ntlmcrack.generate_candidates(
            min_len=1, max_len=2, alphabet="a", max_count=3))
        self.assertEqual(limited, ["a", "aa"])

    def test_alphabet_stops_on_cancel(self):
        calls = []
        gen = ntlmcrack.generate_candidates(
            min_len=1, max_len=1, alphabet="abc",
            cancel=lambda: len(calls) < 2)
        out = []
        for word in gen:
            calls.append(len(out))
            out.append(word)
        # 前两个 yied 后又回调一次 cancel（第 3 次返回 False）后停止
        self.assertLessEqual(len(out), 3)

    def test_ascii_letters_digits_coverage(self):
        chars = set()
        for word in ntlmcrack.generate_candidates(
                min_len=1, max_len=1, alphabet="ascii_letters+digits",
                max_count=200):
            chars.update(word)
        self.assertTrue(any(c.islower() for c in chars))
        self.assertTrue(any(c.isupper() for c in chars))
        self.assertTrue(any(c.isdigit() for c in chars))


class BruteForceTest(unittest.TestCase):
    def _vector(self, password):
        return _build_v2_vector(
            "bob", "CORP", password, bytes.fromhex("0011223344556677"),
            bytes(16) + bytes.fromhex("aabbccddeeff0011"))

    def test_finds_short_password(self):
        _, resp = self._vector("ab12")
        found = ntlmcrack.brute_force_ntlmv2(
            bytes.fromhex("0011223344556677"), resp, "bob", "CORP",
            candidates=["aaa", "ab12", "zzz"])
        self.assertEqual(found, "ab12")

    def test_returns_none_when_not_found(self):
        _, resp = self._vector("ab12")
        found = ntlmcrack.brute_force_ntlmv2(
            bytes.fromhex("0011223344556677"), resp, "bob", "CORP",
            candidates=["aaa", "zzz"])
        self.assertIsNone(found)

    def test_max_attempts_limits(self):
        _, resp = self._vector("zz")
        found = ntlmcrack.brute_force_ntlmv2(
            bytes.fromhex("0011223344556677"), resp, "bob", "CORP",
            candidates=["aa", "bb", "zz"], max_attempts=1)
        self.assertIsNone(found)  # 只尝试 1 个，未到 "zz"


if __name__ == "__main__":
    unittest.main()