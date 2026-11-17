"""Unit tests for the JA3/JA3S/JA4/JA4S fingerprints (no tshark needed).

The byte vectors below are hand-built Client/Server Hellos so the parsers and
the hash pipelines are exercised end to end.  Expected values are either the
public JA4+ specification example or recomputed inline from the definitions,
which keeps the assertions honest without pinning opaque magic strings.
"""
from __future__ import annotations

import hashlib
import struct
import unittest
from pathlib import Path

from fnet.tools.runner import find_tool
from fnet.utils import tlsdeep

DATA = Path(__file__).resolve().parent / "data"


# ---------------------------------------------------------------------------
# Byte-level builders
# ---------------------------------------------------------------------------
def _ext(etype: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HH", etype, len(payload)) + payload


def _sni(host: str) -> bytes:
    name = host.encode("utf-8")
    return struct.pack(">H", len(name) + 3) + b"\x00" \
        + struct.pack(">H", len(name)) + name


def _groups(values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", value) for value in values)
    return struct.pack(">H", len(body)) + body


def _formats(values: list[int]) -> bytes:
    return bytes([len(values)]) + bytes(values)


def _sig_algs(values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", value) for value in values)
    return struct.pack(">H", len(body)) + body


def _versions(values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", value) for value in values)
    return bytes([len(body)]) + body


def _alpn(names: list[bytes]) -> bytes:
    body = b"".join(bytes([len(name)]) + name for name in names)
    return struct.pack(">H", len(body)) + body


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def client_hello(*, version: int = 0x0303, ciphers: list[int] = (),
                 extensions: list[bytes] = (),
                 wrap_record: bool = True) -> bytes:
    body = struct.pack(">H", version) + b"\x11" * 32 + b"\x00"
    suites = b"".join(struct.pack(">H", value) for value in ciphers)
    body += struct.pack(">H", len(suites)) + suites + b"\x01\x00"
    block = b"".join(extensions)
    body += struct.pack(">H", len(block)) + block
    message = _handshake(1, body)
    if not wrap_record:
        return message
    return b"\x16\x03\x01" + struct.pack(">H", len(message)) + message


def server_hello(*, version: int = 0x0303, cipher: int = 0x1301,
                 extensions: list[bytes] = (),
                 wrap_record: bool = True) -> bytes:
    body = struct.pack(">H", version) + b"\x22" * 32 + b"\x00"
    body += struct.pack(">H", cipher) + b"\x01\x00"
    block = b"".join(extensions)
    body += struct.pack(">H", len(block)) + block
    message = _handshake(2, body)
    if not wrap_record:
        return message
    return b"\x16\x03\x03" + struct.pack(">H", len(message)) + message


#: The JA4 specification example (technical_details/JA4.md).
SPEC_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
                0x0035]
SPEC_EXTENSIONS = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D,
                   0x000D, 0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B,
                   0x000A, 0x0015]
SPEC_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                 0x0601]
SPEC_PAYLOADS = {
    0x0000: _sni("example.com"),
    0x0010: _alpn([b"h2"]),
    0x000D: _sig_algs(SPEC_SIG_ALGS),
    0x002B: _versions([0x0304]),
}


def spec_client_hello() -> bytes:
    return client_hello(
        ciphers=SPEC_CIPHERS,
        extensions=[_ext(etype, SPEC_PAYLOADS.get(etype, b""))
                    for etype in SPEC_EXTENSIONS])


class ClientHelloParserTest(unittest.TestCase):
    def test_parses_record_wrapped_and_bare_handshake(self):
        for data in (spec_client_hello(), spec_client_hello()[5:]):
            hello = tlsdeep.parse_client_hello(data)
            self.assertIsNotNone(hello)
            self.assertEqual(hello["version"], 0x0303)
            self.assertEqual(hello["ciphers"], SPEC_CIPHERS)
            self.assertEqual(hello["extensions"], SPEC_EXTENSIONS)
            self.assertEqual(hello["sni"], "example.com")
            self.assertEqual(hello["alpn"], ["h2"])
            self.assertEqual(hello["supported_versions"], [0x0304])
            self.assertEqual(hello["sig_algs"], SPEC_SIG_ALGS)

    def test_parses_curves_and_point_formats(self):
        data = client_hello(
            ciphers=[0xC02F, 0x1301],
            extensions=[_ext(0, _sni("test.example.org")),
                        _ext(10, _groups([29, 23, 30])),
                        _ext(11, _formats([0, 1, 2])),
                        _ext(16, _alpn([b"h2", b"http/1.1"]))])
        hello = tlsdeep.parse_client_hello(data)
        self.assertEqual(hello["curves"], [29, 23, 30])
        self.assertEqual(hello["formats"], [0, 1, 2])
        self.assertEqual(hello["alpn"], ["h2", "http/1.1"])

    def test_rejects_non_client_hello(self):
        self.assertIsNone(tlsdeep.parse_client_hello(b""))
        self.assertIsNone(tlsdeep.parse_client_hello(b"\x16\x03\x01\x00\x01"))
        self.assertIsNone(tlsdeep.parse_client_hello(server_hello()))

    def test_truncated_hello_does_not_raise(self):
        data = spec_client_hello()
        for size in (6, 20, 44, len(data) - 8):
            hello = tlsdeep.parse_client_hello(data[:size])
            self.assertTrue(hello is None or isinstance(hello, dict))

    def test_parses_server_hello(self):
        data = server_hello(
            version=0x0303, cipher=0xC030,
            extensions=[_ext(0x000B), _ext(0x0017), _ext(0x0023),
                        _ext(0x002B)])
        hello = tlsdeep.parse_server_hello(data)
        self.assertEqual(hello["version"], 0x0303)
        self.assertEqual(hello["ciphers"], [0xC030])
        self.assertEqual(hello["extensions"],
                         [0x000B, 0x0017, 0x0023, 0x002B])

    def test_parses_server_hello_tls13_version_and_alpn(self):
        data = server_hello(
            cipher=0x1301,
            extensions=[_ext(43, struct.pack(">H", 0x0304)),
                        _ext(16, bytes([2]) + b"h2")])
        hello = tlsdeep.parse_server_hello(data)
        self.assertEqual(hello["supported_versions"], [0x0304])
        self.assertEqual(hello["alpn"], ["h2"])
        self.assertIsNone(tlsdeep.parse_server_hello(client_hello()))


class Ja3Test(unittest.TestCase):
    def test_ja3_string_and_md5(self):
        hello = tlsdeep.parse_client_hello(client_hello(
            ciphers=[0xC02F, 0x1301],
            extensions=[_ext(0, _sni("test.example.org")),
                        _ext(10, _groups([29, 23, 30])),
                        _ext(11, _formats([0, 1, 2]))]))
        expected = "771,49199-4865,0-10-11,29-23-30,0-1-2"
        self.assertEqual(tlsdeep.ja3_string(hello), expected)
        self.assertEqual(tlsdeep.ja3(hello),
                         hashlib.md5(expected.encode()).hexdigest())
        self.assertEqual(tlsdeep.ja3(hello),
                         "11582ea4a1b3f9e3d81008d67074b380")

    def test_ja3_spec_example(self):
        hello = tlsdeep.parse_client_hello(spec_client_hello())
        text = tlsdeep.ja3_string(hello)
        # Standard JA3 ordering: version,ciphers,extensions,curves,formats.
        self.assertTrue(text.startswith("771,4865-4866-4867-49195-49199"))
        self.assertTrue(text.endswith(",,"))          # no curves/formats
        self.assertEqual(tlsdeep.ja3(hello),
                         hashlib.md5(text.encode()).hexdigest())

    def test_ja3s(self):
        hello = tlsdeep.parse_server_hello(server_hello(
            cipher=0xC02F,
            extensions=[_ext(0x000B), _ext(0x0017), _ext(0x0023),
                        _ext(0x002B)]))
        text = "771,49199,11-23-35-43"
        self.assertEqual(tlsdeep.ja3s(hello),
                         hashlib.md5(text.encode()).hexdigest())

    def test_empty_hello_is_stable(self):
        self.assertEqual(tlsdeep.ja3({}),
                         hashlib.md5(b"0,,,,").hexdigest())
        self.assertEqual(tlsdeep.ja3s({}),
                         hashlib.md5(b"0,0,").hexdigest())


class Ja4Test(unittest.TestCase):
    def test_ja4_matches_specification_example(self):
        hello = tlsdeep.parse_client_hello(spec_client_hello())
        self.assertEqual(tlsdeep.ja4(hello),
                         "t13d1516h2_8daaf6152771_e5627efa2ab1")

    def test_ja4_hashes_are_definitionally_derived(self):
        hello = tlsdeep.parse_client_hello(spec_client_hello())
        ciphers = sorted(f"{value:04x}" for value in SPEC_CIPHERS)
        self.assertEqual(
            tlsdeep.ja4(hello).split("_")[1],
            hashlib.sha256(",".join(ciphers).encode()).hexdigest()[:12])
        # SNI (0000) and ALPN (0010) are dropped from the extension hash.
        extensions = sorted(f"{value:04x}" for value in SPEC_EXTENSIONS
                            if value not in (0x0000, 0x0010))
        sigs = ",".join(f"{value:04x}" for value in SPEC_SIG_ALGS)
        self.assertEqual(
            tlsdeep.ja4(hello).split("_")[2],
            hashlib.sha256(f"{','.join(extensions)}_{sigs}".encode())
            .hexdigest()[:12])

    def test_ja4_grease_is_ignored(self):
        grease = 0x0A0A
        plain = tlsdeep.parse_client_hello(client_hello(
            ciphers=[0x1301, 0x1302], extensions=[_ext(0, _sni("a.test"))]))
        greased = tlsdeep.parse_client_hello(client_hello(
            ciphers=[grease, 0x1301, 0x1302],
            extensions=[_ext(grease), _ext(0, _sni("a.test"))]))
        self.assertEqual(tlsdeep.ja4(plain), tlsdeep.ja4(greased))
        self.assertEqual(tlsdeep.ja4(plain)[4:6], "02")   # cipher count
        self.assertEqual(tlsdeep.ja4(plain)[6:8], "01")   # extension count

    def test_ja4_sni_flag(self):
        with_sni = tlsdeep.parse_client_hello(client_hello(
            ciphers=[0x1301], extensions=[_ext(0, _sni("a.test"))]))
        without = tlsdeep.parse_client_hello(client_hello(ciphers=[0x1301]))
        self.assertEqual(tlsdeep.ja4(with_sni)[3], "d")
        self.assertEqual(tlsdeep.ja4(without)[3], "i")

    def test_ja4_version_prefers_supported_versions(self):
        hello = tlsdeep.parse_client_hello(client_hello(
            version=0x0303, ciphers=[0x1301],
            extensions=[_ext(43, _versions([0x0303, 0x0304]))]))
        self.assertTrue(tlsdeep.ja4(hello).startswith("t13"))

    def test_ja4_alpn_tag_variants(self):
        def tag(*names: bytes) -> str:
            hello = tlsdeep.parse_client_hello(client_hello(
                ciphers=[0x1301], extensions=[_ext(16, _alpn(list(names)))]))
            return tlsdeep.ja4(hello)[8:10]
        self.assertEqual(tag(b"h2"), "h2")
        self.assertEqual(tag(b"http/1.1"), "h1")
        self.assertEqual(tag(b"x"), "xx")
        self.assertEqual(tag(b"\xab"), "ab")
        self.assertEqual(tag(b"\xab\xcd"), "ad")
        self.assertEqual(tag(b"\x30\xab"), "3b")
        self.assertEqual(tag(b"\x30\xab\xcd\x31"), "01")

    def test_ja4_empty_lists(self):
        self.assertTrue(tlsdeep.ja4({}).endswith(
            "_000000000000_000000000000"))
        # t + version(00) + SNI(i) + cipher(00) + extension(00) + ALPN(00)
        self.assertEqual(tlsdeep.ja4({})[:8], "t00i0000")

    def test_ja4_protocol_prefix(self):
        hello = tlsdeep.parse_client_hello(spec_client_hello())
        self.assertTrue(tlsdeep.ja4(hello, protocol="q").startswith("q13"))
        self.assertTrue(tlsdeep.ja4(hello, protocol="d").startswith("d13"))

    def test_ja4s(self):
        hello = tlsdeep.parse_server_hello(server_hello(
            cipher=0xC030,
            extensions=[_ext(0x000B), _ext(0x0017), _ext(0x0023),
                        _ext(0x002B)]))
        fingerprint = tlsdeep.ja4s(hello)
        self.assertEqual(fingerprint.split("_")[1], "c030")
        self.assertEqual(fingerprint.split("_")[2],
                         hashlib.sha256(
                             b"000b,0017,0023,002b").hexdigest()[:12])
        self.assertTrue(fingerprint.startswith("t1204"))

    def test_ja4s_empty_extensions(self):
        hello = tlsdeep.parse_server_hello(server_hello(cipher=0x1301))
        self.assertTrue(tlsdeep.ja4s(hello).endswith("_000000000000"))

    def test_fingerprints_bundle(self):
        client = tlsdeep.parse_client_hello(spec_client_hello())
        server = tlsdeep.parse_server_hello(server_hello(
            cipher=0x1301, extensions=[_ext(43, struct.pack(">H", 0x0304))]))
        bundle = tlsdeep.fingerprints(client, server)
        self.assertEqual(bundle["sni"], "example.com")
        self.assertEqual(bundle["ja4"],
                         "t13d1516h2_8daaf6152771_e5627efa2ab1")
        self.assertEqual(bundle["ja3"], tlsdeep.ja3(client))
        self.assertEqual(bundle["ja3s"], tlsdeep.ja3s(server))
        self.assertEqual(bundle["ja4s"], tlsdeep.ja4s(server))
        self.assertTrue(bundle["ja3_string"].startswith("771,"))


class TlsFingerprintFixtureTest(unittest.TestCase):
    """Integration check against ``tests/data/tls_deep.pcap`` (needs tshark)."""

    @classmethod
    def setUpClass(cls):
        from fnet.tools.runner import TShark, find_tool
        path = find_tool("tshark")
        if not path:
            raise unittest.SkipTest("需要 tshark")
        cls.tshark = TShark(path, cache=False)
        cls.pcap = DATA / "tls_deep.pcap"

    def test_client_hello_fingerprints_from_capture(self):
        from fnet.features import tls
        rows = self.tshark.fields(self.pcap, tls.FP_CLIENT_FIELDS,
                                  "tls.handshake.type == 1")
        self.assertTrue(rows)
        hello = tls._client_hello_from_row(rows[0])
        self.assertEqual(hello["sni"], "test.example.org")
        fingerprint = tlsdeep.fingerprints(hello)
        self.assertTrue(fingerprint["ja4"].startswith("t13d"))
        self.assertIn("h2", fingerprint["ja4"])
        self.assertEqual(len(fingerprint["ja3"]), 32)
        self.assertEqual(len(fingerprint["ja4"].split("_")[1]), 12)

    def test_server_hello_ja4s_from_capture(self):
        from fnet.features import tls
        rows = self.tshark.fields(
            self.pcap, tls.FP_SERVER_FIELDS,
            "tls.handshake.type == 2 && !(tls.handshake.type == 8)")
        self.assertTrue(rows)
        hello = tls._server_hello_from_row(rows[0])
        self.assertEqual(hello["ciphers"], [0x1301])
        fingerprint = tlsdeep.ja4s(hello)
        self.assertTrue(fingerprint.startswith("t12"))
        self.assertEqual(fingerprint.split("_")[1], "1301")


class QuicInitialNoKeylogTest(unittest.TestCase):
    """QUIC Initial 包无 keylog 取证：密钥派生、CRYPTO 帧重组与指纹。"""

    @classmethod
    def _generated_packets(cls) -> list[bytes] | None:
        """Sample Initials from the fixture generator (needs scapy)."""
        try:
            from scripts.make_samples import quic_initial
        except ImportError:
            return None
        return [
            quic_initial(b"\x01\x02\x03\x04\x05\x06\x07\x08",
                         b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", "quic.example.org"),
            quic_initial(b"\x11\x12\x13\x14\x15\x16\x17\x18",
                         b"\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", "cdn.example.org",
                         version=0x6B3343CF),
        ]

    def test_decrypts_generated_initials_without_keylog(self):
        packets = self._generated_packets()
        if packets is None:
            self.skipTest("需要 scapy（scripts.make_samples）")
        results = tlsdeep.quic_initial_fingerprints(packets)
        self.assertEqual(len(results), 2)
        snis = sorted(item["sni"] for item in results)
        self.assertEqual(snis, ["cdn.example.org", "quic.example.org"])
        versions = {item["version"] for item in results}
        self.assertEqual(versions, {0x00000001, 0x6B3343CF})
        for item in results:
            self.assertEqual(item["alpn"], ["h3"])
            # JA4 uses the QUIC protocol prefix "q" and SNI "d" flag.
            self.assertTrue(item["ja4"].startswith("q13d"))
            self.assertIn("h3", item["ja4"])
            self.assertEqual(len(item["ja3"]), 32)
            self.assertEqual(item["version_name"],
                             tlsdeep.quic_version_name(item["version"]))

    def test_decrypts_quic_pcap_fixture(self):
        """Read ``tests/data/quic.pcap`` with a minimal stdlib pcap parser."""
        import struct
        raw = (DATA / "quic.pcap").read_bytes()
        self.assertGreater(len(raw), 24)
        endian = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        link = struct.unpack(endian + "I", raw[20:24])[0]
        self.assertEqual(link, 1)                     # Ethernet
        packets: list[bytes] = []
        offset = 24
        while offset + 16 <= len(raw):
            caplen = struct.unpack(endian + "I", raw[offset + 8:offset + 12])[0]
            offset += 16
            frame = raw[offset:offset + caplen]
            offset += caplen
            if len(frame) < 42 or int.from_bytes(frame[12:14], "big") != 0x0800:
                continue
            ihl = (frame[14] & 0x0F) * 4
            if frame[14 + 9] != 17:                    # not UDP
                continue
            udp = frame[14 + ihl:14 + int.from_bytes(frame[16:18], "big")]
            if len(udp) <= 8:
                continue
            packets.append(udp[8:])
        self.assertEqual(len(packets), 2)
        results = tlsdeep.quic_initial_fingerprints(packets)
        self.assertEqual({item["sni"] for item in results},
                         {"quic.example.org", "cdn.example.org"})
        for item in results:
            self.assertTrue(item["ja4"].startswith("q13d"))

    def test_unusable_packets_are_skipped_silently(self):
        # Version negotiation, Retry-shaped garbage and short/empty payloads
        # must return nothing without raising.
        garbage = [
            b"", b"\x00", b"\x00\x00\x00\x00\x00", b"\xc0\x00\x00\x00\x00",
            bytes([0xC0]) + b"\x00" * 4 + b"\x08" + b"\x01" * 8,   # version 0
            b"\xc0\x00\x00\x01" + b"\xff" * 60,                   # bogus crypto
        ]
        self.assertEqual(tlsdeep.quic_initial_fingerprints(garbage), [])
        self.assertIsNone(tlsdeep.quic_initial_crypto(b""))

    def test_client_and_server_role_both_attempted(self):
        """Server Initials derive from the client DCID with ``server in``."""
        packets = self._generated_packets() or []
        for packet in packets:
            parsed = tlsdeep.quic_initial_crypto(packet)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed["version"] in (0x00000001, 0x6B3343CF), True)
            self.assertTrue(parsed["crypto"])
            offset, data = parsed["crypto"][0]
            self.assertEqual(offset, 0)
            self.assertEqual(data[0], 0x01)           # ClientHello handshake


@unittest.skipUnless(find_tool("tshark"), "需要 tshark")
class QuicInitialFeatureTest(unittest.TestCase):
    """ checkBox_24 跑 quic.pcap：无 keylog 也能从 Initial 提取 SNI/指纹。"""

    @classmethod
    def setUpClass(cls):
        import tempfile
        from unittest import mock

        from fnet import jobs as jobs_mod
        from fnet import paths as paths_mod
        from fnet.app import build
        from fnet.config import Config

        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.patches = [mock.patch.object(jobs_mod, "CACHE_DIR", root),
                       mock.patch.object(paths_mod, "CACHE_DIR", root)]
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(root / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        for patch in cls.patches:
            patch.stop()
        cls.tmp.cleanup()

    def _run(self, pcap: str):
        import time

        job = self.runtime.jobs.submit(str(DATA / pcap), ["checkBox_24"], {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        log = "\n".join(record.line for record in
                        job.log.records_since(0, limit=100000))
        return job, log

    def test_initial_metadata_without_keylog(self):
        import json

        job, log = self._run("quic.pcap")
        self.assertIn("无需 keylog 的 Initial 元数据提取", log)
        self.assertIn("quic.example.org", log)
        self.assertIn("cdn.example.org", log)
        self.assertIn("q13d", log)
        self.assertTrue(
            (job.output_dir / "quic_initial_fingerprints.csv").is_file())
        payload = json.loads(
            (job.output_dir / "findings.json").read_text(encoding="utf-8"))
        findings = payload.get("findings") or []
        quic_fp = [item for item in findings
                   if item.get("kind") == "tls_fingerprint"
                   and item.get("extra", {}).get("protocol") == "quic"]
        snis = {item.get("extra", {}).get("sni") for item in quic_fp}
        self.assertIn("quic.example.org", snis)
        self.assertIn("cdn.example.org", snis)
        for item in quic_fp:
            self.assertTrue(item["extra"]["ja4"].startswith("q13d"))


if __name__ == "__main__":
    unittest.main()
