"""Meterpreter wire/staging 解析核心单元测试（纯手工字节构造，无需 pcap）。

覆盖现代/旧版 XOR 报文、AES-CBC 解密、HTTP base64 体、staging URI/stage
以及“看起来像头但没有合法 TLV”的误报回归。
"""
from __future__ import annotations

import base64
import itertools
import string
import struct
import unittest

from fnet.utils.crypto import aes_cbc_encrypt
from fnet.utils.meterpreter_wire import (
    checksum8,
    explain_packet,
    flag_strings,
    iter_packets,
    looks_like_xor_meterpreter,
    meterpreter_stage_uri,
    parse_stage_blob,
    wire_body_candidates,
)

AES256_KEY = bytes(range(1, 33))
AES128_KEY = bytes(range(1, 17))


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)]
                 for index, value in enumerate(data))


def tlv(tlv_type: int, value: bytes) -> bytes:
    """TLV 线格式：length(4, 自包含) | type(4) | value。"""
    return struct.pack(">II", len(value) + 8, tlv_type) + value


def build_tlvs(command_id: int = 10) -> bytes:
    return (
        tlv(0x00020001, struct.pack(">I", command_id)) +
        tlv(0x00010002, b"12345678901234567890123456789012\x00") +
        tlv(0x0001000A, b"C:\\windows\\system32\x00")
    )


def modern_packet(*, ptype: int = 0, flags: int = 0,
                  guid: bytes = bytes(range(16)),
                  xor_key: bytes = b"\x37\x41\x5e\x02",
                  tlvs: bytes | None = None) -> bytes:
    """现代报文：XOR_KEY | XOR[GUID|flags|length|type|body]。"""
    payload_tlvs = build_tlvs() if tlvs is None else tlvs
    inner = struct.pack(">II", len(payload_tlvs) + 8, ptype) + payload_tlvs
    wire = guid + struct.pack(">I", flags) + inner
    return xor_key + xor_bytes(wire, xor_key)


def legacy_packet(*, ptype: int = 1, xor_key: bytes = b"\xaa\x55\xaa\x55",
                  tlvs: bytes | None = None) -> bytes:
    """旧版报文：XOR_KEY | XOR[length|type|body]。"""
    payload_tlvs = build_tlvs() if tlvs is None else tlvs
    inner = struct.pack(">II", len(payload_tlvs) + 8, ptype) + payload_tlvs
    return xor_key + xor_bytes(inner, xor_key)


def encrypted_packet(*, flags: int, key: bytes,
                     xor_key: bytes = b"\x11\x22\x33\x44",
                     ptype: int = 0) -> bytes:
    """加密报文：明文 TLV 流用 AES-CBC(IV) 加密后放进 body。"""
    payload_tlvs = build_tlvs()
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(payload_tlvs, key, iv)  # PKCS#7
    length = len(iv) + len(ciphertext) + 8  # Metasploit to_r 约定
    wire = (bytes(range(16)) + struct.pack(">I", flags) +
            struct.pack(">II", length, ptype) + iv + ciphertext)
    return xor_key + xor_bytes(wire, xor_key)


class ModernPacketTest(unittest.TestCase):
    def test_modern_plain_packet(self):
        packets = iter_packets(modern_packet())
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual(packet.version, "modern")
        self.assertEqual(packet.kind, "request")
        self.assertEqual(packet.encrypt_flags, 0)
        self.assertFalse(packet.encrypted)
        self.assertEqual(packet.guid_hex, bytes(range(16)).hex())
        self.assertEqual(packet.command_id, 10)
        self.assertEqual(packet.command_hex, "0x0000000a")
        names = [tlv["name"] for tlv in packet.tlvs]
        self.assertIn("COMMAND_ID", names)
        self.assertIn("REQUEST_ID", names)
        self.assertIn("STRING", names)
        self.assertTrue(packet.plaintext.startswith(struct.pack(">I", 12)))
        self.assertEqual(packet.total, len(modern_packet()))
        self.assertEqual(packet.decrypt_reason, "")

    def test_concatenated_packets(self):
        first = modern_packet(ptype=0)
        second = modern_packet(ptype=1)
        packets = iter_packets(first + second)
        self.assertEqual([p.kind for p in packets], ["request", "response"])
        self.assertEqual([p.offset for p in packets], [0, len(first)])
        self.assertEqual([p.command_id for p in packets], [10, 10])

    def test_leading_junk_is_skipped(self):
        data = b"HTTP/1.1 200 OK\r\n" * 3 + modern_packet()
        packets = iter_packets(data, scan_limit=4096)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].kind, "request")


class LegacyPacketTest(unittest.TestCase):
    def test_legacy_plain_packet(self):
        packets = iter_packets(legacy_packet())
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual(packet.version, "legacy")
        self.assertEqual(packet.kind, "response")
        self.assertEqual(packet.command_id, 10)
        self.assertEqual(packet.command_hex, "0x0000000a")
        self.assertEqual(packet.session_guid, b"")
        self.assertEqual(packet.guid_hex, "-")
        self.assertEqual(packet.encrypt_flags, 0)
        self.assertTrue(packet.tlvs)
        self.assertTrue(looks_like_xor_meterpreter(legacy_packet()))

    def test_http_text_is_not_a_packet(self):
        text = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
                b"User-Agent: curl/8.0\r\n\r\n")
        self.assertEqual(iter_packets(text), [])
        self.assertFalse(looks_like_xor_meterpreter(text))
        self.assertFalse(looks_like_xor_meterpreter(b""))


class EncryptedPacketTest(unittest.TestCase):
    def test_aes256_and_aes128_with_correct_key(self):
        for flags, key, name in ((1, AES256_KEY, "AES-256-CBC"),
                                 (2, AES128_KEY, "AES-128-CBC")):
            with self.subTest(flags=flags):
                packets = iter_packets(encrypted_packet(flags=flags, key=key),
                                       key=key)
                self.assertEqual(len(packets), 1)
                packet = packets[0]
                self.assertTrue(packet.encrypted)
                self.assertEqual(packet.encryption_name, name)
                self.assertTrue(packet.decrypt_ok, packet.decrypt_reason)
                self.assertEqual(packet.command_id, 10)
                names = [tlv["name"] for tlv in packet.tlvs]
                self.assertIn("COMMAND_ID", names)
                self.assertTrue(packet.ciphertext)
                self.assertTrue(packet.plaintext.startswith(
                    struct.pack(">I", 12)))

    def test_wrong_key_keeps_ciphertext(self):
        data = encrypted_packet(flags=1, key=AES256_KEY)
        packets = iter_packets(data, key=b"\xff" * 32)
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertFalse(packet.decrypt_ok)
        self.assertTrue(packet.ciphertext)
        self.assertFalse(packet.tlvs)
        self.assertTrue(packet.decrypt_reason)

    def test_wrong_key_size_reports_reason(self):
        for flags, bad_key in ((1, AES128_KEY), (2, AES256_KEY)):
            with self.subTest(flags=flags):
                packet = iter_packets(
                    encrypted_packet(flags=flags,
                                     key=AES256_KEY if flags == 1 else AES128_KEY),
                    key=bad_key)[0]
                self.assertFalse(packet.decrypt_ok)
                self.assertTrue(packet.ciphertext)
                self.assertIn("长度", packet.decrypt_reason)

    def test_without_key_keeps_ciphertext(self):
        packet = iter_packets(encrypted_packet(flags=1, key=AES256_KEY))[0]
        self.assertTrue(packet.encrypted)
        self.assertFalse(packet.decrypt_ok)
        self.assertTrue(packet.ciphertext)
        self.assertFalse(packet.tlvs)
        self.assertIn("密钥", packet.decrypt_reason)


class WireBodyCandidatesTest(unittest.TestCase):
    def test_raw_standard_and_urlsafe_base64(self):
        # 该 XOR key 的 base64 同时包含 + 和 /，确保两种字母表不同。
        xor_key = b"\xfb\xff\xfe\xfd"
        data = modern_packet(xor_key=xor_key)
        standard = base64.b64encode(data)
        urlsafe = base64.urlsafe_b64encode(data)
        self.assertNotEqual(standard, urlsafe)

        for label, encoded in (("base64", standard), ("base64url", urlsafe)):
            with self.subTest(label=label):
                candidates = wire_body_candidates(encoded)
                self.assertTrue(any(raw == data for raw, _ in candidates),
                                f"{label} 解码候选缺失")
                self.assertIn("raw", {kind for _, kind in candidates})

        candidates = wire_body_candidates(data)
        self.assertEqual(candidates[0], (data, "raw"))
        # 去重 + 限量，且条目都是 (bytes, str)。
        self.assertLessEqual(len(candidates), 8)
        self.assertEqual(len({raw for raw, _ in candidates}), len(candidates))
        self.assertTrue(all(isinstance(raw, bytes) and isinstance(label, str)
                            for raw, label in candidates))


class StagingTest(unittest.TestCase):
    def test_stage_blob_length_prefixed_with_trailing_data(self):
        stage = b"MZ" + bytes(64) + b"metsrv.dll loaded" + bytes(16)
        body = struct.pack(">I", len(stage)) + stage + b"trailing junk"
        info = parse_stage_blob(body)
        self.assertIsNotNone(info)
        self.assertEqual(set(info), {"stage", "length_prefixed", "is_pe",
                                     "strings", "size"})
        self.assertEqual(info["stage"], stage)
        self.assertTrue(info["length_prefixed"])
        self.assertTrue(info["is_pe"])
        self.assertEqual(info["size"], len(stage))
        self.assertIn("metsrv.dll loaded", "".join(info["strings"]))

    def test_stage_blob_raw_and_short(self):
        stage = b"MZ" + bytes(80)
        info = parse_stage_blob(stage)
        self.assertFalse(info["length_prefixed"])
        self.assertEqual(info["stage"], stage)
        self.assertIsNone(parse_stage_blob(b""))

    def test_uri_checksum_and_initm(self):
        self.assertEqual(checksum8("/INITM"), 176)
        uri92 = uri93 = None
        alphabet = (string.ascii_lowercase + string.digits +
                    string.ascii_uppercase)
        for length in range(1, 4):
            for chars in itertools.product(alphabet, repeat=length):
                candidate = "/x" + "".join(chars)
                if uri92 is None and checksum8(candidate) == 92:
                    uri92 = candidate
                if uri93 is None and checksum8(candidate) == 93:
                    uri93 = candidate
            if uri92 and uri93:
                break
        self.assertTrue(uri92 and uri93)
        info92 = meterpreter_stage_uri(uri92)
        info93 = meterpreter_stage_uri(uri93)
        self.assertEqual(info92["checksum"], 92)
        self.assertEqual(info92["arch"], "x86")
        self.assertEqual(info93["checksum"], 93)
        self.assertEqual(info93["arch"], "x64")
        initm = meterpreter_stage_uri("/INITM?uuid=1")
        self.assertIn("INITM", initm["reason"])
        self.assertIsNone(meterpreter_stage_uri("/normal/page.html"))


class ExplainAndFlagsTest(unittest.TestCase):
    def test_explain_packet_is_actionable(self):
        packet = iter_packets(modern_packet())[0]
        detail = explain_packet(packet)
        self.assertEqual(detail["version"], "modern")
        self.assertEqual(detail["kind"], "request")
        self.assertNotEqual(detail["guid"], "-")
        self.assertEqual(detail["command_hex"], "0x0000000a")
        self.assertGreater(detail["tlv_count"], 0)
        self.assertIn("COMMAND_ID", detail["tlvs"])
        self.assertTrue(detail["decrypt_ok"])

        encrypted = iter_packets(encrypted_packet(flags=1, key=AES256_KEY),
                                 key=AES256_KEY)[0]
        detail = explain_packet(encrypted)
        self.assertEqual(detail["encryption"], "AES-256-CBC")
        self.assertNotEqual(detail["command_hex"], "-")

    def test_flag_strings_unique(self):
        data = b"junk flag{wire_test} tail flag{wire_test} flag{second}"
        self.assertEqual(flag_strings(data),
                         ["flag{wire_test}", "flag{second}"])


class FalsePositiveRegressionTest(unittest.TestCase):
    def test_xor_key_plus_fake_legacy_header_without_tlvs(self):
        # 截图形误报：前 4 字节像 XOR key，随后 8 字节像合法 legacy 头，
        # 但体部异或后根本不是 TLV 流，必须拒绝。
        xor_key = b"\x4d\x3a\x29\x5f"
        body = b"A" * 56
        inner = struct.pack(">II", 8 + len(body), 0) + body  # length=64, type=0
        data = xor_key + xor_bytes(inner, xor_key)
        self.assertEqual(len(data), 68)
        self.assertEqual(iter_packets(data), [])
        self.assertFalse(looks_like_xor_meterpreter(data))


if __name__ == "__main__":
    unittest.main()
