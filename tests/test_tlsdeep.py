"""Unit tests for the Wireshark-free TLS/QUIC helpers."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fnet.utils import tlsdeep

DATA = Path(__file__).resolve().parent / "data"


class PemTest(unittest.TestCase):
    def test_pem_blocks_and_encryption_marker(self):
        cert = (DATA / "tls_test_cert.pem").read_text(encoding="utf-8")
        blocks = tlsdeep.pem_blocks(cert)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["label"], "CERTIFICATE")
        self.assertFalse(blocks[0]["encrypted"])
        encrypted = (DATA / "tls_test_key_encrypted.pem").read_text(
            encoding="utf-8")
        self.assertTrue(tlsdeep.is_encrypted_pem(encrypted))
        self.assertFalse(tlsdeep.is_encrypted_pem(
            (DATA / "tls_test_key.pem").read_text(encoding="utf-8")))

    def test_certificate_info(self):
        der = tlsdeep.pem_blocks(
            (DATA / "tls_test_cert.pem").read_text(encoding="utf-8"))[0]["der"]
        info = tlsdeep.certificate_info(der)
        self.assertEqual(info["subject"], "test.example.org")
        self.assertEqual(info["issuer"], "test.example.org")
        self.assertIn("alt.example.org", info["san"])
        self.assertTrue(info["serial"].startswith("0FFF17AF"))
        self.assertEqual(info["not_before"], "2026-11-17")
        self.assertEqual(info["not_after"], "2026-12-17")
        self.assertTrue(info["spki"])

    def test_private_key_matches_certificate(self):
        text = (DATA / "tls_test_key.pem").read_text(encoding="utf-8")
        key_spki = tlsdeep.private_key_spki_from_pem(text)
        cert_spki = tlsdeep.certificate_spki(tlsdeep.pem_blocks(
            (DATA / "tls_test_cert.pem").read_text(encoding="utf-8"))[0]["der"])
        self.assertEqual(key_spki, cert_spki)
        self.assertEqual(tlsdeep.key_fingerprint(key_spki),
                         tlsdeep.key_fingerprint(cert_spki))
        self.assertEqual(len(tlsdeep.key_fingerprint(key_spki)), 16)

    @unittest.skipUnless(tlsdeep.openssl_path(), "需要 openssl")
    def test_decrypt_private_key(self):
        source = DATA / "tls_test_key_encrypted.pem"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain.pem"
            wrong, message = tlsdeep.decrypt_private_key(
                source, "wrong", target)
            self.assertIsNone(wrong)
            self.assertIn("口令", message)
            path, message = tlsdeep.decrypt_private_key(
                source, "secret", target)
            self.assertIsNotNone(path)
            self.assertIn("已解密", message)
            spki = tlsdeep.spki_from_private_key(path, "secret")
            self.assertTrue(spki)

    @unittest.skipUnless(tlsdeep.openssl_path(), "需要 openssl")
    def test_spki_from_private_key_file(self):
        spki = tlsdeep.spki_from_private_key(DATA / "tls_test_key.pem")
        cert_spki = tlsdeep.certificate_spki(tlsdeep.pem_blocks(
            (DATA / "tls_test_cert.pem").read_text(encoding="utf-8"))[0]["der"])
        self.assertEqual(spki, cert_spki)


class KeylogTest(unittest.TestCase):
    def test_keylog_entries_and_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a.log"
            second = Path(tmp) / "b.log"
            first.write_text(
                "CLIENT_RANDOM aa11 bb22\n"
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET aa11 cc33\n",
                encoding="utf-8")
            second.write_text(
                "CLIENT_RANDOM aa11 bb22\n"
                "CLIENT_RANDOM dd44 ee55\n"
                "not a keylog line\n", encoding="utf-8")
            entries = tlsdeep.keylog_entries([first, second])
        self.assertEqual(entries["lines"], 3)
        self.assertEqual(entries["labels"]["CLIENT_RANDOM"], 2)
        self.assertIn("aa11", entries["randoms"])
        coverage = tlsdeep.keylog_coverage(entries, ["AA11", "ffff"])
        self.assertEqual(coverage["covered"], 1)
        self.assertEqual(coverage["total"], 2)
        self.assertAlmostEqual(coverage["percent"], 50.0)
        self.assertEqual(coverage["missing"], ["ffff"])

    def test_key_update_rows(self):
        rows = [
            ["10", "10.0.0.1", "443", "10.0.0.2", "5000"],
            ["11", "10.0.0.1", "443", "10.0.0.2", "5000"],
            ["12", "10.0.0.2", "5000", "10.0.0.1", "443"],
        ]
        updates = tlsdeep.key_update_rows(rows)
        self.assertEqual(len(updates), 2)
        self.assertEqual(updates[0]["count"], 2)
        self.assertEqual(updates[0]["frames"], ["10", "11"])


class QuicTest(unittest.TestCase):
    def test_version_names(self):
        self.assertIn("QUIC v1", tlsdeep.quic_version_name("0x00000001"))
        self.assertIn("QUIC v2", tlsdeep.quic_version_name(0x6B3343CF))
        self.assertEqual(tlsdeep.quic_version_name(""), "")
        self.assertIn("0x12345678", tlsdeep.quic_version_name("0x12345678"))

    def test_packet_type_names(self):
        self.assertEqual(tlsdeep.packet_type_name("0"), "Initial")
        self.assertEqual(tlsdeep.packet_type_name("0x04"), "1-RTT")
        self.assertEqual(tlsdeep.packet_type_name("9"), "9")

    def test_packet_type_names_v2(self):
        v2 = "0x6b3343cf"
        self.assertEqual(tlsdeep.packet_type_name("1", v2), "Initial")
        self.assertEqual(tlsdeep.packet_type_name("0", v2), "Retry")
        self.assertEqual(tlsdeep.packet_type_name("3", v2), "0-RTT")
        # Short-header/other values still fall back to the shared table.
        self.assertEqual(tlsdeep.packet_type_name("4", v2), "1-RTT")

    def test_quic_connections_uses_v2_packet_type(self):
        rows = [
            ["1", "0.1", "10.0.0.1", "5000", "10.0.0.2", "443",
             "0x6b3343cf", "aabb", "ccdd", "", "1", "quic.example.org",
             "h3", "7", "1200"],
        ]
        item = tlsdeep.quic_connections(rows)[0]
        self.assertEqual(item["packet_types"], {"Initial": 1})
        self.assertEqual(item["versions"], ["0x6b3343cf"])

    def test_quic_connections_aggregates(self):
        rows = [
            ["1", "0.1", "10.0.0.1", "5000", "10.0.0.2", "443",
             "0x00000001", "aabb", "ccdd", "0", "quic.example.org", "h3",
             "7", "1200"],
            ["2", "0.2", "10.0.0.2", "443", "10.0.0.1", "5000",
             "0x00000001", "ccdd", "aabb", "4", "quic.example.org", "h3",
             "7", "900"],
        ]
        connections = tlsdeep.quic_connections(rows)
        self.assertEqual(len(connections), 1)
        item = connections[0]
        self.assertEqual(item["frames"], 2)
        self.assertEqual(item["bytes"], 2100)
        self.assertEqual(item["client"], "10.0.0.1:5000")
        self.assertEqual(item["server"], "10.0.0.2:443")
        self.assertEqual(item["sni"], ["quic.example.org"])
        self.assertEqual(item["alpn"], ["h3"])
        self.assertIn("Initial", item["packet_types"])
        self.assertIn("1-RTT", item["packet_types"])
        self.assertEqual(item["frames_list"], ["1", "2"])


if __name__ == "__main__":
    unittest.main()
