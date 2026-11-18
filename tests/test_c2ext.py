"""Tests for the Sliver / meterpreter extended C2 parsers and handler.

Follows the handcrafted-bytes style of ``tests/test_protocol_streams.py``:
meterpreter wire packets, DNS subdomain encodings and X.509 skeletons are
built byte by byte; the handler is exercised through a fake tshark that
returns canned rows (no capture file needed).
"""
from __future__ import annotations

import base64
import struct
import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import c2ext
from fnet.features.registry import FeatureContext
from fnet.logger import Logger
from fnet.utils import c2ext as c2
from fnet.utils import meterpreter_wire, sliver_c2
from fnet.utils.crypto import aes_cbc_encrypt, aes_gcm_encrypt

SLIVER_KEY = bytes(range(32))
SLIVER_KEY16 = bytes(range(16))
METERPRETER_KEY = bytes(range(1, 33))
METERPRETER_KEY128 = bytes(range(1, 17))


# ---------------------------------------------------------------------------
# byte builders
# ---------------------------------------------------------------------------
def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)]
                 for index, value in enumerate(data))


def _tlv(tlv_type: int, value: bytes) -> bytes:
    # wire order is length (self-inclusive) then type, per Tlv.to_r
    return struct.pack(">II", len(value) + 8, tlv_type) + value


def _build_tlvs() -> bytes:
    command_id = _tlv(0x00020001, struct.pack(">I", 10))  # COMMAND_ID 10
    request_id = _tlv(0x00010002, b"12345678901234567890123456789012\x00")
    string = _tlv(0x0001000A, b"C:\\windows\\system32\x00")
    return command_id + request_id + string


def modern_packet(ptype: int = 0, key: bytes = b"\x37\x41\x5e\x02",
                  guid: bytes = bytes(range(16)), flags: int = 0,
                  body: bytes | None = None) -> bytes:
    """XOR-obfuscated 32-byte-header meterpreter packet."""
    tlv_raw = _build_tlvs() if body is None else body
    inner = struct.pack(">II", len(tlv_raw) + 8, ptype) + tlv_raw
    payload = guid + struct.pack(">I", flags) + inner
    return key + _xor(payload, key)


def encrypted_packet(key: bytes = METERPRETER_KEY,
                     xor_key: bytes = b"\x11\x22\x33\x44",
                     flags: int = 1) -> bytes:
    """AES-CBC encrypted meterpreter packet (flags 1=256 / 2=128)."""
    tlv_raw = _build_tlvs()
    iv = bytes(range(16))
    cipher = aes_cbc_encrypt(tlv_raw, key, iv)  # encrypt the nested TLV stream
    payload = bytes(range(16)) + struct.pack(">I", flags) + \
        struct.pack(">II", len(cipher) + 16 + 8, 1) + iv + cipher
    return xor_key + _xor(payload, xor_key)


def legacy_packet(ptype: int = 1, key: bytes = b"\xaa\x55\xaa\x55") -> bytes:
    """Pre-4.11 meterpreter packet: XOR key + length + type (12-byte header)."""
    tlv_raw = _build_tlvs()
    inner = struct.pack(">II", len(tlv_raw) + 8, ptype) + tlv_raw
    return key + _xor(inner, key)


def dns_message(msg_type: int = 8, msg_id: int = 0x1abcdef,
                data: bytes = b"flag{sliver_dns}") -> bytes:
    """``dnspb.DNSMessage`` protobuf (Type=1 ID=2 Start=3 Stop=4 Size=5 Data=6)."""
    def varint(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    def field(number: int, wire: int, content: bytes) -> bytes:
        return varint(number << 3 | wire) + content

    out = field(1, 0, varint(msg_type)) + field(2, 0, varint(msg_id))
    out += field(5, 0, varint(len(data)))
    out += field(6, 2, varint(len(data)) + data)
    return out


# --- minimal DER builder for the mTLS certificate heuristic -----------------
def _der(tag: int, content: bytes) -> bytes:
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    raw = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def _oid(raw: bytes) -> bytes:
    return _der(0x06, raw)


def _seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _set(*items: bytes) -> bytes:
    return _der(0x31, b"".join(items))


def _utctime(value: str) -> bytes:
    return _der(0x17, value.encode())


ECDSA_SHA512_OID = b"\x2a\x86\x48\xce\x3d\x04\x03\x04"
RSA_SHA256_OID = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
EKU_CLIENT_OID = b"\x2b\x06\x01\x05\x05\x07\x03\x02"
EKU_SERVER_OID = b"\x2b\x06\x01\x05\x05\x07\x03\x01"


def build_cert(cn: bytes, ecdsa: bool = True, eku: bytes | None = None,
               org: bytes | None = None) -> bytes:
    """Assemble a minimal X.509 certificate skeleton."""
    def name(cn_value: bytes, org_value: bytes | None) -> bytes:
        rdns = [_set(_seq(_oid(b"\x55\x04\x03"),
                          _der(0x0C, cn_value)))]
        if org_value:
            rdns.insert(0, _set(_seq(_oid(b"\x55\x04\x0a"),
                                    _der(0x0C, org_value))))
        return _seq(*rdns)

    sig_alg = _seq(_oid(ECDSA_SHA512_OID if ecdsa else RSA_SHA256_OID))
    validity = _seq(_utctime("240101000000Z"), _utctime("261201000000Z"))
    spki = _seq(_seq(_oid(b"\x2a\x86\x48\xce\x3d\x02\x01")),
                _der(0x03, b"\x00" + bytes(range(1, 40))))
    extensions = b""
    if eku:
        ext_value = _seq(_oid(eku))
        extensions = _der(0xa3, _seq(_seq(_oid(b"\x55\x1d\x25"),
                                          _der(0x04, _der(0x04, ext_value)))))
    tbs = _seq(_der(0xa0, _der(0x02, b"\x02")),
               _der(0x02, b"\x01\x02\x03"),
               sig_alg, name(cn, None), validity,
               name(cn, org), spki, extensions)
    return _seq(tbs, sig_alg, _der(0x03, b"\x00" + b"\x55" * 16))


class _FakeTshark:
    """Return canned rows based on the display filter the handler uses."""

    def __init__(self, rows: dict[str, list]):
        self.rows = rows
        self.calls = []

    def fields(self, pcap, fields, display_filter="", extra=None, cancel=None):
        self.calls.append(display_filter)
        for key, value in self.rows.items():
            if display_filter == key:
                return value
        return []


def make_ctx(tmp: Path, fake: _FakeTshark,
             params: dict | None = None) -> FeatureContext:
    return FeatureContext(
        config=Config(tmp / "config.ini"),
        logger=Logger(tmp / "fnet.log"),
        tshark=fake,
        pcap=str(tmp / "x.pcap"),
        output_dir=tmp / "out",
        params=params or {},
    )


# ---------------------------------------------------------------------------
# meterpreter staging
# ---------------------------------------------------------------------------
class MeterpreterStagingTest(unittest.TestCase):
    def test_checksum8(self):
        self.assertEqual(c2.checksum8("/INITM"), 176)

    def test_initm_marker_uri(self):
        info = c2.meterpreter_stage_uri("/INITM?uuid=1")
        self.assertIsNotNone(info)
        self.assertEqual(info["arch"], "x86")

    def test_checksum_92_and_93(self):
        from itertools import product
        alphabet = ("abcdefghijklmnopqrstuvwxyz0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        uri92 = uri93 = None
        for length in range(1, 4):
            for chars in product(alphabet, repeat=length):
                candidate = "/x" + "".join(chars)
                if uri92 is None and c2.checksum8(candidate) == 92:
                    uri92 = candidate
                if uri93 is None and c2.checksum8(candidate) == 93:
                    uri93 = candidate
            if uri92 and uri93:
                break
        self.assertTrue(uri92 and uri93)
        self.assertEqual(c2.meterpreter_stage_uri(uri92)["checksum"], 92)
        self.assertEqual(c2.meterpreter_stage_uri(uri92)["arch"], "x86")
        self.assertEqual(c2.meterpreter_stage_uri(uri93)["arch"], "x64")

    def test_stage_blob_length_prefixed_pe(self):
        stage = b"MZ" + bytes(64) + b"flag{metsrv}" + bytes(16)
        body = struct.pack(">I", len(stage)) + stage
        parsed = c2.parse_stage_blob(body)
        self.assertTrue(parsed.length_prefixed)
        self.assertTrue(parsed.is_pe)
        self.assertIn("flag{metsrv}", "".join(parsed.strings))

    def test_stage_blob_raw(self):
        stage = b"MZ" + bytes(80)
        parsed = c2.parse_stage_blob(stage)
        self.assertFalse(parsed.length_prefixed)
        self.assertEqual(parsed.stage, stage)


# ---------------------------------------------------------------------------
# meterpreter XOR / encrypted wire packets
# ---------------------------------------------------------------------------
class MeterpreterWireTest(unittest.TestCase):
    def test_modern_packet_parse(self):
        packets = c2.iter_packets(modern_packet())
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual(packet.version, "modern")
        self.assertEqual(packet.kind, "request")
        self.assertFalse(packet.encrypted)
        self.assertEqual(packet.command_hex, "0x0000000a")
        self.assertIn("C:\\windows\\system32",
                      [tlv["value"] for tlv in packet.tlvs])
        names = [tlv["name"] for tlv in packet.tlvs]
        self.assertIn("COMMAND_ID", names)
        self.assertIn("REQUEST_ID", names)

    def test_concatenated_packets(self):
        data = modern_packet(ptype=0) + modern_packet(ptype=1)
        packets = c2.iter_packets(data)
        self.assertEqual([packet.kind for packet in packets],
                         ["request", "response"])

    def test_legacy_packet_parse(self):
        packets = c2.iter_packets(legacy_packet())
        self.assertEqual(len(packets), 1)
        packet = packets[0]
        self.assertEqual(packet.version, "legacy")
        self.assertEqual(packet.kind, "response")
        self.assertEqual(packet.command_hex, "0x0000000a")

    def test_encrypted_packet_needs_key(self):
        data = encrypted_packet()
        without_key = c2.iter_packets(data)
        self.assertEqual(len(without_key), 1)
        self.assertTrue(without_key[0].encrypted)
        self.assertFalse(without_key[0].tlvs)
        with_key = c2.iter_packets(data, key=METERPRETER_KEY)
        self.assertEqual(with_key[0].command_hex, "0x0000000a")
        self.assertIn("C:\\windows\\system32",
                      [tlv["value"] for tlv in with_key[0].tlvs])

    def test_wrong_key_size_rejected(self):
        packets = c2.iter_packets(encrypted_packet(), key=b"\x01" * 16)
        self.assertTrue(packets[0].encrypted)
        self.assertFalse(packets[0].tlvs)

    def test_garbage_is_not_meterpreter(self):
        self.assertFalse(c2.looks_like_xor_meterpreter(b"HTTP/1.1 200 OK" * 8))
        self.assertFalse(c2.looks_like_xor_meterpreter(b""))


# ---------------------------------------------------------------------------
# Sliver HTTP(S)
# ---------------------------------------------------------------------------
class SliverHttpTest(unittest.TestCase):
    def test_poll_uri_classification(self):
        info = c2.classify_sliver_uri("/umd/bootstrap.js?_=1a2b3c4d5e6f")
        self.assertEqual(info["ext"], ".js")
        self.assertEqual(info["message"], "长轮询拉取任务")
        self.assertTrue(info["nonce"])
        self.assertIn("bootstrap", info["word_hits"])
        self.assertGreaterEqual(info["score"], c2ext.SLIVER_URI_SCORE_MIN)

    def test_key_exchange_uri(self):
        info = c2.classify_sliver_uri("/login/signin.html")
        self.assertEqual(info["ext"], ".html")
        self.assertGreaterEqual(info["score"], c2ext.SLIVER_URI_SCORE_MIN)

    def test_stager_uri(self):
        info = c2.classify_sliver_uri("/assets/bundles/app.woff")
        self.assertEqual(info["ext"], ".woff")
        self.assertGreaterEqual(info["score"], c2ext.SLIVER_URI_SCORE_MIN)

    def test_normal_uri_not_flagged(self):
        self.assertIsNone(c2.classify_sliver_uri("/api/v1/users?page=2"))
        info = c2.classify_sliver_uri("/static/lib.js")
        self.assertLess(info["score"], c2ext.SLIVER_URI_SCORE_MIN)

    def test_aesgcm_roundtrip(self):
        iv = bytes(range(12))
        blob = iv + aes_gcm_encrypt(b"flag{sliver_http}", SLIVER_KEY, iv)
        self.assertEqual(c2.sliver_aesgcm_decrypt(blob, SLIVER_KEY),
                         b"flag{sliver_http}")
        self.assertIsNone(c2.sliver_aesgcm_decrypt(blob, b"\x00" * 32))
        self.assertIsNone(c2.sliver_aesgcm_decrypt(blob[:20], SLIVER_KEY))


# ---------------------------------------------------------------------------
# Sliver DNS
# ---------------------------------------------------------------------------
class SliverDnsTest(unittest.TestCase):
    def test_base32_roundtrip(self):
        data = dns_message()
        subdata = c2.sliver_base32_encode(data)
        self.assertEqual(c2.sliver_base32_decode(subdata), data)
        for char in subdata:
            self.assertIn(char, c2.SLIVER_BASE32)

    def test_base58_roundtrip(self):
        data = dns_message(data=b"flag{base58_dns}")
        subdata = c2.sliver_base58_encode(data)
        self.assertEqual(c2.sliver_base58_decode(subdata), data)

    def test_decode_base32_subdomain(self):
        qname = c2.sliver_base32_encode(dns_message()) + ".c2.example.com"
        decoded = c2.decode_sliver_dns_subdomain(qname, ("c2.example.com",))
        self.assertEqual(decoded["encoding"], "base32")
        self.assertEqual(decoded["message"]["type"], 8)
        self.assertEqual(decoded["message"]["data"], b"flag{sliver_dns}")
        self.assertEqual(decoded["message"]["id"], 0x1abcdef)

    def test_decode_without_parent_config(self):
        qname = c2.sliver_base32_encode(dns_message()) + ".example.com"
        decoded = c2.decode_sliver_dns_subdomain(qname)
        self.assertIsNotNone(decoded)

    def test_decode_base58_subdomain(self):
        data = dns_message(msg_type=3, data=b"flag{base58_dns}")
        qname = c2.sliver_base58_encode(data) + ".c2.example.com"
        decoded = c2.decode_sliver_dns_subdomain(qname, ("c2.example.com",))
        self.assertEqual(decoded["encoding"], "base58")
        self.assertEqual(decoded["message"]["type"], 3)
        self.assertEqual(decoded["message"]["data"], b"flag{base58_dns}")

    def test_benign_qname_rejected(self):
        self.assertIsNone(
            c2.decode_sliver_dns_subdomain("www.example.com"))
        self.assertIsNone(c2.decode_sliver_dns_subdomain(""))
        self.assertIsNone(c2.decode_sliver_dns_subdomain(
            "abcdefghij.example.com"))


# ---------------------------------------------------------------------------
# Sliver mTLS certificate heuristic
# ---------------------------------------------------------------------------
class SliverMtlsCertTest(unittest.TestCase):
    def test_sliver_like_cert_scores(self):
        profile = c2.sliver_mtls_cert_profile(
            build_cert(b"SLIVER7", ecdsa=True, eku=EKU_CLIENT_OID))
        self.assertGreaterEqual(profile.score, 4)
        self.assertTrue(profile.ecdsa_signature)
        self.assertTrue(profile.eku_client)
        self.assertFalse(profile.eku_server)
        self.assertIn("仅 clientAuth 扩展用途", profile.reasons)
        self.assertIsNotNone(c2.looks_like_sliver_mtls_cert(
            build_cert(b"SLIVER7", ecdsa=True, eku=EKU_CLIENT_OID)))

    def test_normal_cert_not_flagged(self):
        profile = c2.sliver_mtls_cert_profile(
            build_cert(b"web01.corp.example", ecdsa=False,
                       eku=EKU_SERVER_OID, org=b"Example Corp"))
        self.assertLess(profile.score, 4)
        self.assertIsNone(c2.looks_like_sliver_mtls_cert(
            build_cert(b"web01.corp.example", ecdsa=False,
                       eku=EKU_SERVER_OID, org=b"Example Corp")))

    def test_malformed_cert_is_safe(self):
        profile = c2.sliver_mtls_cert_profile(b"\x30\x10\xff\xffbroken")
        self.assertEqual(profile.score, 0)


# ---------------------------------------------------------------------------
# handler end to end with a fake tshark
# ---------------------------------------------------------------------------
class C2ExtHandlerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_handler(self, rows: dict[str, list],
                    params: dict | None = None):
        fake = _FakeTshark(rows)
        ctx = make_ctx(self.path, fake, params)
        c2ext.analyze(ctx)
        log = self.path / "fnet.log"
        text = log.read_text(encoding="utf-8") if log.is_file() else ""
        return ctx, text

    def test_meterpreter_stage_and_sliver_http(self):
        stage = b"MZ" + bytes(80) + b"flag{stage_dump}"
        rows = {
            "http.request": [
                ["1", "0", "GET", "/INITM", "10.0.0.9", "", "2"],
                ["5", "1", "GET", "/umd/bootstrap.js?_=1a2b3c4d5e6f",
                 "10.0.0.9", "", ""],
            ],
            "http.response": [["2", "0", "200", stage.hex(), "application/octet-stream"]],
            "dns.flags.response == 0": [],
            "tls.handshake.certificates": [],
        }
        ctx, text = self.run_handler(rows)
        self.assertIn("staging 请求", text)
        self.assertIn("Sliver HTTP beacon", text)
        kinds = {item["kind"] for item in ctx.findings}
        self.assertIn("protocol", kinds)
        artifacts = list((self.path / "out").glob("c2_meterpreter_stage_*.bin"))
        self.assertTrue(artifacts)
        self.assertTrue(artifacts[0].read_bytes().startswith(b"MZ"))

    def test_sliver_dns_and_gcm_decryption(self):
        iv = bytes(range(12))
        data = iv + aes_gcm_encrypt(b"flag{sliver_dns_gcm}", SLIVER_KEY, iv)
        msg = dns_message(msg_type=8, data=data)
        qname = c2.sliver_base32_encode(msg) + ".c2.example.com"
        rows = {
            "http.request": [],
            "http.response": [],
            "dns.flags.response == 0": [
                ["7", qname, "1"],
            ],
            "tls.handshake.certificates": [],
        }
        ctx, text = self.run_handler(rows,
                                     {"sliver_session_key": SLIVER_KEY.hex()})
        self.assertIn("Sliver DNS beacon", text)
        self.assertIn("Data 解密成功", text)
        self.assertIn("flag{sliver_dns_gcm}", text)
        kinds = {item["kind"] for item in ctx.findings}
        self.assertIn("dns", kinds)

    def test_meterpreter_xor_tcp_stream(self):
        data = modern_packet() + legacy_packet()
        rows = {
            "http.request": [],
            "http.response": [],
            "dns.flags.response == 0": [],
            "tls.handshake.certificates": [],
            "tcp.len > 0": [["1", "0", data.hex()]],
        }
        ctx, text = self.run_handler(rows)
        self.assertIn("XOR 编码的 meterpreter 包", text)
        self.assertEqual(len(ctx.findings), 2)

    def test_no_traffic_warns(self):
        rows = {
            "http.request": [],
            "http.response": [],
            "dns.flags.response == 0": [],
            "tls.handshake.certificates": [],
        }
        ctx, text = self.run_handler(rows)
        self.assertIn("未识别到 Sliver / meterpreter C2 特征", text)
        readme = self.path / "out" / "c2_README.txt"
        self.assertTrue(readme.is_file())
        content = readme.read_text(encoding="utf-8")
        self.assertIn("74 字节 minisign 签名前缀", content)
        self.assertIn("AES-128-CBC", content)
        self.assertIn("AES-256-CBC", content)

    def test_bad_key_param_reported(self):
        rows = {
            "http.request": [],
            "http.response": [],
            "dns.flags.response == 0": [],
            "tls.handshake.certificates": [],
        }
        ctx, text = self.run_handler(rows, {"sliver_session_key": "zzzz"})
        self.assertIn("不是有效的十六进制字符串", text)


# --- test-only RFC 8439 ChaCha20-Poly1305 sealer (no third-party deps) -------
def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state.extend(struct.unpack("<8I", key))
    state.append(counter)
    state.extend(struct.unpack("<3I", nonce))

    def quarter(word: list[int], a: int, b: int, c: int, d: int) -> None:
        word[a] = (word[a] + word[b]) & 0xFFFFFFFF
        word[d] = _rotl32(word[d] ^ word[a], 16)
        word[c] = (word[c] + word[d]) & 0xFFFFFFFF
        word[b] = _rotl32(word[b] ^ word[c], 12)
        word[a] = (word[a] + word[b]) & 0xFFFFFFFF
        word[d] = _rotl32(word[d] ^ word[a], 8)
        word[c] = (word[c] + word[d]) & 0xFFFFFFFF
        word[b] = _rotl32(word[b] ^ word[c], 7)

    rounds = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
              (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
    work = state[:]
    for _ in range(10):
        for indexes in rounds:
            quarter(work, *indexes)
    return struct.pack("<16I", *((word + original) & 0xFFFFFFFF
                                 for word, original in zip(work, state)))


def _poly1305_tag(message: bytes, one_time_key: bytes) -> bytes:
    prime = (1 << 130) - 5
    value = int.from_bytes(one_time_key[:16], "little")
    r = value & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        number = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        acc = ((acc + number) * r) % prime
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _chacha_seal(plaintext: bytes, key: bytes,
                 nonce: bytes = bytes(range(12))) -> bytes:
    otk = _chacha_block(key, 0, nonce)[:32]
    stream = bytearray()
    for offset in range(0, len(plaintext), 64):
        stream.extend(_chacha_block(key, 1 + offset // 64, nonce))
    sealed = bytes(a ^ b for a, b in zip(plaintext, stream))
    pad = lambda data: b"\x00" * (-len(data) % 16)
    mac_input = (sealed + pad(sealed) + struct.pack("<Q", 0)
                 + struct.pack("<Q", len(sealed)))
    tag = _poly1305_tag(mac_input, otk)
    return nonce + sealed + tag


def _sliver_envelope(env_id: int, env_type: int, data: bytes) -> bytes:
    def varint(number: int) -> bytes:
        out = bytearray()
        while True:
            byte = number & 0x7F
            number >>= 7
            if number:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                return bytes(out)

    return (b"\x08" + varint(env_id) + b"\x10" + varint(env_type)
            + b"\x1a" + varint(len(data)) + data)


# ---------------------------------------------------------------------------
# new-core integration through the handler
# ---------------------------------------------------------------------------
class C2ExtNewCoreTest(unittest.TestCase):
    """Fake-tshark tests exercising the new sliver/meterpreter cores."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_handler(self, rows: dict[str, list],
                    params: dict | None = None):
        fake = _FakeTshark(rows)
        ctx = make_ctx(self.path, fake, params)
        c2ext.analyze(ctx)
        log = self.path / "fnet.log"
        text = log.read_text(encoding="utf-8") if log.is_file() else ""
        return ctx, text

    @staticmethod
    def rows(body: bytes, uri: str = "/api/v1/data"):
        return {
            "http.request": [["3", "0", "POST", uri, "10.0.0.9",
                              body.hex(), ""]],
            "http.response": [],
            "dns.flags.response == 0": [],
            "tls.handshake.certificates": [],
        }

    def test_encrypted_packet_aes256_recipient(self):
        body = encrypted_packet(METERPRETER_KEY, flags=1)
        ctx, text = self.run_handler(
            self.rows(body),
            {"meterpreter_symkey": METERPRETER_KEY.hex()})
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and f["summary"].startswith("meterpreter")]
        self.assertTrue(findings)
        summary = findings[0]["summary"]
        self.assertIn("0x0000000a", summary)
        self.assertIn("response", summary)
        detail = findings[0]["detail"]
        for fragment in ("AES-256-CBC", "COMMAND_ID", "AES 解密校验通过"):
            self.assertIn(fragment, detail)
        self.assertIn("AES-256", text)

    def test_encrypted_packet_aes128_recipient(self):
        body = encrypted_packet(METERPRETER_KEY128, flags=2)
        ctx, text = self.run_handler(
            self.rows(body),
            {"meterpreter_symkey": METERPRETER_KEY128.hex()})
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and f["summary"].startswith("meterpreter")]
        self.assertTrue(findings)
        detail = findings[0]["detail"]
        self.assertIn("AES-128-CBC", detail)
        self.assertIn("AES 解密校验通过", detail)
        self.assertIn("AES-128", text)

    def test_encrypted_packet_without_key_has_ciphertext_artifact(self):
        body = encrypted_packet(METERPRETER_KEY, flags=1)
        ctx, text = self.run_handler(self.rows(body))
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and f["summary"].startswith("meterpreter")]
        self.assertTrue(findings)
        self.assertIn("缺少 meterpreter_symkey", findings[0]["detail"])
        artifacts = list((self.path / "out").glob("c2_meterpreter_enc_*.bin"))
        self.assertTrue(artifacts)

    def test_encrypted_packet_wrong_key_reports_failure(self):
        body = encrypted_packet(METERPRETER_KEY, flags=1)
        ctx, text = self.run_handler(
            self.rows(body),
            {"meterpreter_symkey": bytes(range(200, 232)).hex()})
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and f["summary"].startswith("meterpreter")]
        self.assertTrue(findings)
        self.assertIn("AES 解密校验失败", findings[0]["detail"])

    def test_base64_http_body_yields_meterpreter_packet(self):
        encoded = base64.b64encode(modern_packet()).decode("ascii")
        ctx, text = self.run_handler(self.rows(encoded.encode("ascii")))
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and f["summary"].startswith("meterpreter")]
        self.assertTrue(findings)
        self.assertIn("0x0000000a", findings[0]["summary"])

    def test_bogus_legacy_header_creates_no_finding(self):
        bogus = (b"\x00\x00\x00\x00" + struct.pack(">II", 20, 0)
                 + b"junkjunkjunkjunkjunkjunk")
        ctx, text = self.run_handler(self.rows(bogus))
        self.assertFalse([f for f in ctx.findings
                          if "meterpreter" in f["summary"]])

    def test_sliver_v16_chacha_gzip_signature(self):
        import gzip
        inner = _sliver_envelope(42, 1, b"flag{v16_chacha}")
        sealed = _chacha_seal(gzip.compress(inner), SLIVER_KEY)
        # Sanity check: the core decrypts what this test helper sealed.
        self.assertEqual(
            sliver_c2.chacha20_poly1305_decrypt(sealed, SLIVER_KEY)[0],
            gzip.compress(inner))
        blob = b"S" * 74 + sealed  # minisign signature prefix
        ctx, text = self.run_handler(
            self.rows(blob, "/umd/bootstrap.js?_=1a2b3c4d5e6f"),
            {"sliver_session_key": SLIVER_KEY.hex()})
        self.assertIn("Sliver 会话载荷解密成功", text)
        self.assertIn("ChaCha20-Poly1305", text)
        self.assertIn("gzip 已解压", text)
        self.assertIn("已跳过签名前缀", text)
        self.assertIn("flag{v16_chacha}", text)
        findings = [f for f in ctx.findings
                    if f["kind"] == "protocol"
                    and "Sliver 会话载荷解密" in f["summary"]]
        self.assertTrue(findings)
        self.assertIn("ID=42", findings[0]["detail"])
        self.assertIn("Type=1", findings[0]["detail"])
        artifacts = list((self.path / "out").glob("c2_sliver_session_*.bin"))
        self.assertTrue(artifacts)
        self.assertEqual(artifacts[0].read_bytes(), inner)

    def test_sliver_v16_chacha_unsigned(self):
        import gzip
        inner = _sliver_envelope(7, 2, b"flag{v16_unsigned}")
        blob = _chacha_seal(gzip.compress(inner), SLIVER_KEY)
        ctx, text = self.run_handler(
            self.rows(blob, "/umd/bootstrap.js?_=1a2b3c4d5e6f"),
            {"sliver_session_key": SLIVER_KEY.hex()})
        self.assertIn("ChaCha20-Poly1305", text)
        self.assertIn("无签名前缀", text)
        self.assertIn("flag{v16_unsigned}", text)

    def test_sliver_legacy_aes_gcm_16_byte_key(self):
        iv = bytes(range(12))
        blob = iv + aes_gcm_encrypt(b"flag{legacy_aes_gcm}", SLIVER_KEY16, iv)
        ctx, text = self.run_handler(
            self.rows(blob, "/umd/bootstrap.js?_=1a2b3c4d5e6f"),
            {"sliver_session_key": SLIVER_KEY16.hex()})
        self.assertIn("AES-GCM", text)
        self.assertIn("flag{legacy_aes_gcm}", text)

    def test_sliver_key_exchange_classification(self):
        age = (bytes(range(32)) + b"age-encryption.org/v1\n"
               b"-> X25519 " + b"A" * 43 + b"\n"
               + b"B" * 43 + b"\n--- MAC\n")
        ctx, text = self.run_handler(
            self.rows(age, "/login/signin.html"))
        self.assertIn("Sliver 密钥交换", text)
        self.assertIn("v1.6", text)
        self.assertIn("age-x25519", text)
        findings = [f for f in ctx.findings
                    if f["summary"].startswith("Sliver 密钥交换")]
        self.assertTrue(findings)
        self.assertIn("age-x25519", findings[0]["detail"])

    def test_recv_poll_has_no_finding(self):
        ctx, text = self.run_handler(self.rows(b"RECV"))
        self.assertIn("RECV body", text)
        self.assertFalse([f for f in ctx.findings
                          if "meterpreter" in f["summary"]])


if __name__ == "__main__":
    unittest.main()
