"""quicinit 单元测试。

用三组材料验证无 keylog 的 QUIC Initial 取证：

* RFC 9001 §5.2/Appendix A 与 RFC 9369 §3.3/Appendix A 的官方向量
  （密钥派生 + 客户端/服务端 Initial + Retry 完整性标签）；
* 自构造的 Initial 包（任意 DCID、合并包、版本协商），覆盖
  ``initial_forensics`` 的端到端提取路径；
* ``tests/data/quic.pcap`` 夹具（tshark 提取 UDP 载荷后的端到端比对）。
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import unittest
from pathlib import Path

from fnet.utils import quicinit
from fnet.utils.crypto import aes_encrypt_block, aes_gcm_encrypt
from fnet.utils.tlsdeep import parse_client_hello

REPO = Path(__file__).resolve().parent.parent
TSHARK = shutil.which("tshark")

#: RFC 9001 / RFC 9369 Appendix A 的公共测试连接 ID。
ODCID = bytes.fromhex("8394c8f03e515708")
#: RFC 9001 A.2/A.3 里的服务端临时 CID（出现在 Retry 与服务器 Initial 中）。
SERVER_CID = bytes.fromhex("f067a5502a4262b5")

# RFC 9001 A.2：客户端 Initial 明文载荷（CRYPTO 帧 + 后补 PADDING 到 1162 字节）。
V1_CH_PAYLOAD = bytes.fromhex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff")
#: RFC 9369 A.2：v2 客户端 Initial 明文载荷（同样的握手，SNI=example.com）。
V2_CH_PAYLOAD = bytes.fromhex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
    "75300901100f088394c8f03e51570806048000ffff")
#: RFC 9001 A.3：服务端 Initial 完整保护包（DCID 为空，需提供原始 DCID）。
V1_SERVER_INITIAL = bytes.fromhex(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"
    "2158407dd074ee")
#: RFC 9001 A.4 / RFC 9369 A.4：Retry 官方向量（回应 ODCID 的那个连接）。
V1_RETRY = bytes.fromhex(
    "ff000000010008f067a5502a4262b5746f6b656e"
    "04a265ba2eff4d829058fb3f0f2496ba")
V2_RETRY = bytes.fromhex(
    "cf6b3343cf0008f067a5502a4262b5746f6b656e"
    "c8646ce8bfe33952d955543665dcc7b6")


def _varint(value: int) -> bytes:
    """QUIC 变长整数编码（测试用）。"""
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def _seal_initial(version: int, dcid: bytes, scid: bytes,
                  payload: bytes, *, role: str = "client", pn: int = 0,
                  token: bytes = b"") -> bytes:
    """按 RFC 9001 §5.4 加封一个 Initial 长包头（测试辅助）。

    与 quicinit 的解密路径互为镜像：AEAD 密钥/nonce 加密载荷，hp 密钥
    AES-ECB 掩码保护头部；keylog 无关，密钥全部由 DCID 公开派生。
    """
    secrets = quicinit.initial_secrets(version, dcid)
    keys = secrets[role]
    type_bits = 1 if version in quicinit.QUIC_V2_VERSIONS else 0
    pn_len = 4
    first = 0xC0 | (type_bits << 4) | (pn_len - 1)
    header = (bytes([first]) + struct.pack("!I", version)
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + _varint(len(token)) + token)
    header += _varint(pn_len + len(payload) + 16) + pn.to_bytes(pn_len, "big")
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    packet = bytearray(header + aes_gcm_encrypt(payload, keys["key"],
                                                nonce, header))
    sample = packet[len(header) - pn_len + 4:len(header) - pn_len + 20]
    mask = aes_encrypt_block(sample, keys["hp"])
    packet[0] ^= mask[0] & 0x0F
    for index in range(pn_len):
        packet[len(header) - pn_len + index] ^= mask[1 + index]
    return bytes(packet)


def _client_hello(sni: str, alpn: str = "h3") -> bytes:
    """构造一个最小 TLS 1.3 ClientHello 握手消息（SNI + ALPN + 版本）。"""
    name = sni.encode()
    sni_ext = struct.pack("!H", len(name) + 3) + b"\x00" \
        + struct.pack("!H", len(name)) + name
    proto = alpn.encode()
    alpn_ext = struct.pack("!H", len(proto) + 1) + bytes([len(proto)]) + proto
    versions_ext = b"\x02" + b"\x03\x04" + b"\x03\x03"
    ext = (struct.pack("!HH", 0, len(sni_ext)) + sni_ext
           + struct.pack("!HH", 16, len(alpn_ext)) + alpn_ext
           + struct.pack("!HH", 43, len(versions_ext)) + versions_ext)
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def _crypto_payload(data: bytes, offset: int = 0) -> bytes:
    """把握手字节包成 CRYPTO 帧（offset 用 varint 编码）。"""
    return b"\x06" + _varint(offset) + _varint(len(data)) + data


def _version_negotiation(scid: bytes, dcid: bytes, versions) -> bytes:
    """构造一个版本协商长包头（version=0，DCID/SCID 镜像客户端的）。"""
    body = bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    for version in versions:
        body += struct.pack("!I", version)
    return bytes([0xC0]) + struct.pack("!I", 0) + body + b"\xde\xad\xbe\xef"


class InitialSecretsTest(unittest.TestCase):
    """RFC 9001 A.1 / RFC 9369 A.1 的密钥派生向量。"""

    def test_rfc9001_v1_keys(self):
        secrets = quicinit.initial_secrets(1, ODCID)
        self.assertEqual(secrets["client"]["secret"].hex(),
                         "c00cf151ca5be075ed0ebfb5c80323c4"
                         "2d6b7db67881289af4008f1f6c357aea")
        self.assertEqual(secrets["client"]["key"].hex(),
                         "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(secrets["client"]["iv"].hex(),
                         "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(secrets["client"]["hp"].hex(),
                         "9f50449e04a0e810283a1e9933adedd2")
        self.assertEqual(secrets["server"]["key"].hex(),
                         "cf3a5331653c364c88f0f379b6067e37")

    def test_rfc9369_v2_keys(self):
        secrets = quicinit.initial_secrets(0x6B3343CF, ODCID)
        self.assertEqual(secrets["client"]["secret"].hex(),
                         "14ec9d6eb9fd7af83bf5a668bc17a7e2"
                         "83766aade7ecd0891f70f9ff7f4bf47b")
        self.assertEqual(secrets["client"]["key"].hex(),
                         "8b1a0bc121284290a29e0971b5cd045d")
        self.assertEqual(secrets["client"]["iv"].hex(),
                         "91f73e2351d8fa91660e909f")
        self.assertEqual(secrets["server"]["key"].hex(),
                         "82db637861d55e1d011f19ea71d5d2a7")

    def test_unsupported_version_raises(self):
        with self.assertRaises(ValueError):
            quicinit.initial_secrets(0x1A2B3C4D, ODCID)


class DecryptInitialTest(unittest.TestCase):
    """Initial 包解密：官方向量 + 自构造包。"""

    def test_v1_client_initial_rfc9001(self):
        packet = _seal_initial(1, ODCID, SERVER_CID,
                               V1_CH_PAYLOAD.ljust(1162, b"\x00"))
        parsed = quicinit.decrypt_initial(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["role"], "client")
        self.assertEqual(parsed["packet_number"], 0)
        self.assertEqual(parsed["dcid"], ODCID.hex())
        self.assertEqual(parsed["scid"], SERVER_CID.hex())
        stream = quicinit.reassemble_crypto(parsed["crypto"])
        hello = parse_client_hello(stream)
        self.assertEqual(hello["sni"], "example.com")
        self.assertEqual(hello["alpn"], ["alpn"])
        self.assertIn(0x1301, hello["ciphers"])

    def test_v2_client_initial_rfc9369(self):
        packet = _seal_initial(0x6B3343CF, ODCID, SERVER_CID,
                               V2_CH_PAYLOAD.ljust(1162, b"\x00"))
        parsed = quicinit.decrypt_initial(packet)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["version"], 0x6B3343CF)
        self.assertEqual(parsed["role"], "client")
        stream = quicinit.reassemble_crypto(parsed["crypto"])
        self.assertEqual(parse_client_hello(stream)["sni"], "example.com")

    def test_v1_server_initial_rfc9001_vector(self):
        """官方向量的服务器 Initial：派生输入是原始 DCID 而非包头 DCID。"""
        parsed = quicinit.decrypt_initial(V1_SERVER_INITIAL, ODCID)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["role"], "server")
        self.assertEqual(parsed["dcid"], "")            # 服务器包 DCID 为空
        self.assertEqual(parsed["packet_number"], 1)
        stream = quicinit.reassemble_crypto(parsed["crypto"])
        self.assertTrue(stream.startswith(b"\x02"))     # ServerHello 握手消息
        self.assertIn(bytes.fromhex("0303eefce7f7b37ba1d1632e9667"), stream)

    def test_server_initial_without_odcid_fails(self):
        self.assertIsNone(quicinit.decrypt_initial(V1_SERVER_INITIAL))

    def test_custom_dcid_roundtrip(self):
        dcid = bytes(range(8))
        packet = _seal_initial(1, dcid, b"\x11" * 4,
                               _crypto_payload(_client_hello("test.example")))
        parsed = quicinit.decrypt_initial(packet)
        stream = quicinit.reassemble_crypto(parsed["crypto"])
        self.assertEqual(parse_client_hello(stream)["sni"], "test.example")

    def test_corrupted_payload_fails(self):
        packet = bytearray(_seal_initial(1, ODCID, b"", V1_CH_PAYLOAD))
        packet[40] ^= 0xFF                              # 破坏 GCM 密文
        self.assertIsNone(quicinit.decrypt_initial(bytes(packet)))

    def test_unsupported_version(self):
        header = bytes([0xC3]) + struct.pack("!I", 0x1A2B3C4D) \
            + bytes([8]) + ODCID + bytes([0])
        self.assertIsNone(quicinit.decrypt_initial(header + bytes(64)))

    def test_short_header_and_garbage(self):
        self.assertIsNone(quicinit.decrypt_initial(b""))
        self.assertIsNone(quicinit.decrypt_initial(bytes([0x40]) + bytes(30)))


class RetryTest(unittest.TestCase):
    """Retry 完整性标签校验（RFC 9001 §5.8 / RFC 9369 A.4）。"""

    def test_v1_retry_vector(self):
        result = quicinit.verify_retry(V1_RETRY, ODCID)
        self.assertTrue(result["integrity"])
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["scid"], SERVER_CID.hex())
        self.assertEqual(result["token"], b"token".hex())

    def test_v2_retry_vector(self):
        result = quicinit.verify_retry(V2_RETRY, ODCID)
        self.assertTrue(result["integrity"])
        self.assertEqual(result["version"], 0x6B3343CF)

    def test_wrong_odcid_fails(self):
        other = bytes(8)
        self.assertFalse(quicinit.verify_retry(V1_RETRY, other)["integrity"])

    def test_corrupted_tag_fails(self):
        broken = bytearray(V1_RETRY)
        broken[-1] ^= 0x01
        self.assertFalse(
            quicinit.verify_retry(bytes(broken), ODCID)["integrity"])

    def test_non_retry_returns_none(self):
        packet = _seal_initial(1, ODCID, b"", _client_hello("a.example"))
        self.assertIsNone(quicinit.verify_retry(packet, ODCID))


class VersionNegotiationTest(unittest.TestCase):
    """版本协商包解析（RFC 8999 §6）。"""

    def test_parse_and_grease_filter(self):
        packet = _version_negotiation(SERVER_CID, ODCID,
                                      [1, 0x6B3343CF, 0x0A0A0A0A, 0])
        parsed = quicinit.parse_version_negotiation(packet)
        self.assertIsNotNone(parsed)
        # 0 与 grease（0x?a?a?a?）被过滤；末尾随机填充可能被当作版本（见已知限制）。
        self.assertEqual(parsed["versions"][:2], [1, 0x6B3343CF])
        self.assertEqual(parsed["scid"], SERVER_CID.hex())
        self.assertEqual(parsed["dcid"], ODCID.hex())

    def test_initial_is_not_negotiation(self):
        packet = _seal_initial(1, ODCID, b"", _client_hello("a.example"))
        self.assertIsNone(quicinit.parse_version_negotiation(packet))


class InitialForensicsTest(unittest.TestCase):
    """端到端：initial_forensics 的连接汇总/合并包/Retry/版本协商。"""

    def test_client_hello_extraction(self):
        packet = _seal_initial(1, ODCID, SERVER_CID,
                               _crypto_payload(
                                   _client_hello("forensic.example", "h3")))
        result = quicinit.initial_forensics([(7, packet)])
        conn = result["connections"][0]
        self.assertEqual(conn["sni"], "forensic.example")
        self.assertEqual(conn["alpn"], ["h3"])
        self.assertIn("QUIC v1", conn["version_name"])
        self.assertEqual(conn["frames"], ["7"])
        self.assertTrue(conn["hello_decrypted"])
        self.assertEqual(conn["tls_versions"], ["TLS 1.3", "TLS 1.2"])
        self.assertEqual(conn["cipher_suites"], [0x1301])

    def test_coalesced_datagram_two_connections(self):
        first = _seal_initial(1, ODCID, b"",
                              _crypto_payload(_client_hello("a.example")))
        second_dcid = bytes(range(10, 18))
        second = _seal_initial(1, second_dcid, b"",
                               _crypto_payload(_client_hello("b.example")))
        result = quicinit.initial_forensics([first + second])
        self.assertEqual(result["packets_seen"], 2)
        self.assertEqual(len(result["connections"]), 2)
        snis = {item["sni"] for item in result["connections"]}
        self.assertEqual(snis, {"a.example", "b.example"})

    def test_retry_and_negotiation_recorded(self):
        packet = _seal_initial(1, ODCID, SERVER_CID,
                               _crypto_payload(_client_hello("a.example")))
        result = quicinit.initial_forensics(
            [packet, V1_RETRY, _version_negotiation(SERVER_CID, ODCID, [1])])
        self.assertTrue(result["retries"][0]["integrity"])
        self.assertEqual(result["version_negotiations"][0]["versions"][:1], [1])
        self.assertEqual(result["connections"][0]["sni"], "a.example")

    def test_undecrypted_counted(self):
        header = bytes([0xC3]) + struct.pack("!I", 1) + bytes([8]) + ODCID \
            + bytes([0]) + b"\x01\x40\x30" + bytes(50)  # 载荷无有效密文
        result = quicinit.initial_forensics([header])
        self.assertEqual(result["undecrypted"], 1)
        self.assertEqual(result["connections"], [])

    def test_hello_split_across_packets(self):
        """ClientHello 分片在两个 Initial 包里时按 offset 重组。"""
        hello = _client_hello("split.example")
        first, second = hello[:60], hello[60:]
        crypto1 = b"\x06\x00" + _varint(len(first)) + first
        crypto2 = b"\x06" + _varint(60) + _varint(len(second)) + second
        dcid = bytes(range(20, 28))
        packets = [
            _seal_initial(1, dcid, b"", crypto1 + b"\x00" * 1100, pn=0),
            _seal_initial(1, dcid, b"", crypto2, pn=1),
        ]
        result = quicinit.initial_forensics([("1", packets[0]),
                                             ("2", packets[1])])
        self.assertEqual(len(result["connections"]), 1)
        self.assertEqual(result["connections"][0]["sni"], "split.example")
        self.assertEqual(len(result["connections"][0]["frames"]), 2)


@unittest.skipUnless(TSHARK, "需要 tshark 才能读取 QUIC 夹具")
class FixtureTest(unittest.TestCase):
    """tests/data/quic.pcap 端到端比对（v1 + v2 各一条流）。"""

    def test_quic_pcap(self):
        path = REPO / "tests" / "data" / "quic.pcap"
        proc = subprocess.run(
            [TSHARK, "-r", str(path), "-Y", "quic", "-T", "fields",
             "-e", "frame.number", "-e", "udp.payload"],
            capture_output=True, text=True, check=True)
        packets = []
        for line in proc.stdout.splitlines():
            frame, _, payload = line.strip().partition("\t")
            if payload:
                packets.append((frame, bytes.fromhex(payload)))
        self.assertEqual(len(packets), 2)
        result = quicinit.initial_forensics(packets)
        self.assertEqual(len(result["connections"]), 2)
        self.assertEqual(result["undecrypted"], 0)
        snis = {item["sni"] for item in result["connections"]}
        self.assertEqual(snis, {"quic.example.org", "cdn.example.org"})
        versions = {item["version"] for item in result["connections"]}
        self.assertEqual(versions, {1, 0x6B3343CF})
        for item in result["connections"]:
            self.assertTrue(item["hello_decrypted"])
            self.assertEqual(item["tls_versions"], ["TLS 1.3"])


if __name__ == "__main__":
    unittest.main()
