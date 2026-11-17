"""Tests for PMK/PTK derivation and CCMP frame decryption (no tshark needed)."""
from __future__ import annotations

import unittest

from fnet.utils import wifi

AP = "02:00:00:00:01:00"
STA = "02:00:00:00:02:00"
DST = "aa:bb:cc:dd:ee:ff"
TK = bytes(range(16))


def _mac(value: str) -> bytes:
    return bytes.fromhex(wifi.normalize_mac(value))


def _data_frame(payload: bytes, *, to_ds: bool = True,
                from_ds: bool = False, qos: bool = False,
                protected: bool = False) -> bytes:
    """Build a data frame with 3 (or 4) addresses and optional QoS control."""
    subtype = 8 if qos else 0
    fc = 0x0008 | (subtype << 4)
    if to_ds:
        fc |= 0x0100
    if from_ds:
        fc |= 0x0200
    if protected:
        fc |= 0x4000
    if to_ds and from_ds:
        addr1, addr2, addr3, addr4 = AP, STA, DST, "02:00:00:00:03:00"
    elif to_ds:
        addr1, addr2, addr3, addr4 = AP, STA, DST, ""
    else:
        addr1, addr2, addr3, addr4 = STA, AP, DST, ""
    header = (bytes([fc & 0xFF, fc >> 8, 0x00, 0x00])
              + _mac(addr1) + _mac(addr2) + _mac(addr3)
              + b"\x10\x00")
    if addr4:
        header += _mac(addr4)
    if qos:
        header += b"\x05\x00"
    return header + payload


class PmkPtkTest(unittest.TestCase):
    def test_derive_pmk_ieee_vector(self):
        # Well-known IEEE 802.11i vector: passphrase "password", SSID "IEEE".
        expected = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
        pmk = wifi.derive_pmk("password", "IEEE")
        self.assertEqual(len(pmk), 32)
        self.assertEqual(pmk.hex(), expected)

    def test_derive_pmk_depends_on_ssid(self):
        self.assertNotEqual(wifi.derive_pmk("password", "IEEE"),
                            wifi.derive_pmk("password", "IEEE2"))

    def test_derive_ptk_is_deterministic_and_splits(self):
        pmk = wifi.derive_pmk("password", "IEEE")
        anonce = b"\x11" * 32
        snonce = b"\x22" * 32
        first = wifi.derive_ptk(pmk, anonce, snonce, AP, STA)
        second = wifi.derive_ptk(pmk, anonce, snonce, AP, STA)
        self.assertEqual(first, second)
        self.assertEqual(len(first["ptk"]), 48)
        self.assertEqual(first["kck"], first["ptk"][0:16])
        self.assertEqual(first["kek"], first["ptk"][16:32])
        self.assertEqual(first["tk"], first["ptk"][32:48])
        for name in ("kck", "kek", "tk"):
            self.assertEqual(len(first[name]), 16)

    def test_derive_ptk_is_order_independent(self):
        pmk = wifi.derive_pmk("password", "IEEE")
        anonce = bytes.fromhex("aa" * 32)
        snonce = bytes.fromhex("11" * 32)
        forward = wifi.derive_ptk(pmk, anonce, snonce, AP, STA)
        swapped = wifi.derive_ptk(pmk, snonce, anonce, STA, AP)
        self.assertEqual(forward["ptk"], swapped["ptk"])

    def test_derive_ptk_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            wifi.derive_ptk(b"\x00" * 31, b"\x00" * 32, b"\x00" * 32, AP, STA)
        with self.assertRaises(ValueError):
            wifi.derive_ptk(b"\x00" * 32, b"\x00" * 32, b"\x00" * 32,
                            "nope", STA)


class CcmTest(unittest.TestCase):
    def test_rfc3610_vector_1(self):
        key = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
        nonce = bytes.fromhex("00000003020100a0a1a2a3a4a5")
        aad = bytes.fromhex("0001020304050607")
        plaintext = bytes.fromhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
        expected = bytes.fromhex(
            "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")
        encrypted = wifi.ccm_encrypt(key, nonce, aad, plaintext, tag_len=8)
        self.assertEqual(encrypted, expected)
        decrypted, valid = wifi.ccm_decrypt(key, nonce, aad, encrypted, 8)
        self.assertTrue(valid)
        self.assertEqual(decrypted, plaintext)

    def test_ccm_roundtrip_and_tamper(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        nonce = bytes.fromhex("00000000000000000000000000")
        aad = b"header"
        plaintext = b"flag{rfc3610_roundtrip}"
        encrypted = wifi.ccm_encrypt(key, nonce, aad, plaintext, 8)
        self.assertEqual(len(encrypted), len(plaintext) + 8)
        decrypted, valid = wifi.ccm_decrypt(key, nonce, aad, encrypted, 8)
        self.assertEqual(decrypted, plaintext)
        self.assertTrue(valid)
        self.assertEqual(wifi.ccm_mac(key, nonce, aad, plaintext, 8),
                         encrypted[-8:])
        tampered = bytearray(encrypted)
        tampered[0] ^= 0x01
        _, bad = wifi.ccm_decrypt(key, nonce, aad, bytes(tampered), 8)
        self.assertFalse(bad)

    def test_ccm_short_ciphertext(self):
        key = b"\x00" * 16
        nonce = b"\x00" * 13
        self.assertEqual(wifi.ccm_decrypt(key, nonce, b"", b"\x00\x01", 8),
                         (b"", False))


class Dot11HeaderTest(unittest.TestCase):
    def test_parse_qos_data_frame(self):
        header = _data_frame(b"payload", to_ds=True, qos=True, protected=True)
        info = wifi.parse_dot11_header(header)
        self.assertIsNotNone(info)
        self.assertEqual(info["type"], 2)
        self.assertEqual(info["subtype"], 8)
        self.assertTrue(info["protected"])
        self.assertTrue(info["qos"])
        self.assertFalse(info["has_addr4"])
        self.assertEqual(info["header_len"], 26)
        self.assertEqual(info["a1"], AP)
        self.assertEqual(info["a2"], STA)
        self.assertEqual(info["a3"], DST)
        self.assertEqual(info["priority"], 5)
        self.assertIsNone(wifi.parse_dot11_header(b"\x88\x42"))

    def test_parse_wds_frame_has_addr4(self):
        header = _data_frame(b"payload", to_ds=True, from_ds=True, qos=True)
        info = wifi.parse_dot11_header(header)
        self.assertIsNotNone(info)
        self.assertTrue(info["has_addr4"])
        self.assertEqual(info["header_len"], 32)
        self.assertEqual(info["a1"], AP)
        self.assertEqual(info["a3"], DST)


class CcmpFrameTest(unittest.TestCase):
    def _payload(self) -> bytes:
        return b"\xaa\xaa\x03\x00\x00\x00\x08\x00flag{ccmp_frame}"

    def test_ccmp_frame_roundtrip(self):
        plaintext = self._payload()
        frame = _data_frame(plaintext, to_ds=True, qos=True)
        encrypted = wifi.ccmp_encrypt_frame(TK, frame, 0x0102)
        self.assertTrue(encrypted[1] & 0x40)
        self.assertEqual(len(encrypted), len(frame) + 16)
        decrypted = wifi.ccmp_decrypt_frame(TK, encrypted)
        self.assertIsNotNone(decrypted)
        self.assertEqual(decrypted["plaintext"], plaintext)
        self.assertTrue(decrypted["tag_valid"])
        self.assertEqual(decrypted["pn"], 0x0102)
        self.assertEqual(decrypted["key_id"], 0)
        self.assertEqual(decrypted["a2"], STA)
        ethernet = wifi.to_ethernet(
            decrypted["plaintext"], decrypted["a1"], decrypted["a2"])
        self.assertIsNotNone(ethernet)
        self.assertEqual(ethernet[0:6], _mac(AP))
        self.assertEqual(ethernet[6:12], _mac(STA))
        self.assertEqual(ethernet[12:14], b"\x08\x00")
        self.assertEqual(ethernet[14:], b"flag{ccmp_frame}")

    def test_ccmp_tampered_ciphertext_fails(self):
        frame = _data_frame(self._payload(), to_ds=True, qos=True)
        encrypted = bytearray(wifi.ccmp_encrypt_frame(TK, frame, 7))
        header_len = 26
        encrypted[header_len + 8] ^= 0x80
        decrypted = wifi.ccmp_decrypt_frame(TK, bytes(encrypted))
        self.assertIsNotNone(decrypted)
        self.assertFalse(decrypted["tag_valid"])
        tampered_mic = bytearray(
            wifi.ccmp_encrypt_frame(TK, frame, 7))
        tampered_mic[-1] ^= 0x01
        self.assertFalse(
            wifi.ccmp_decrypt_frame(TK, bytes(tampered_mic))["tag_valid"])

    def test_non_ccmp_frames_are_rejected(self):
        frame = _data_frame(self._payload(), to_ds=True)
        self.assertIsNone(wifi.ccmp_decrypt_frame(TK, frame))
        self.assertIsNone(wifi.ccmp_decrypt_frame(TK, b"\x00\x01"))

    def test_to_ethernet_rejects_non_snap(self):
        self.assertIsNone(wifi.to_ethernet(b"flag{no_snap}", AP, STA))
        self.assertIsNone(
            wifi.to_ethernet(b"\xaa\xaa\x03\x00\x00\x00\x08\x00x", "bad", STA))

    def test_key_id_roundtrip(self):
        frame = _data_frame(self._payload(), to_ds=True)
        encrypted = wifi.ccmp_encrypt_frame(TK, frame, 9, key_id=2)
        decrypted = wifi.ccmp_decrypt_frame(TK, encrypted)
        self.assertEqual(decrypted["key_id"], 2)
        self.assertTrue(decrypted["tag_valid"])

    def test_decrypt_frames_rows(self):
        frame = _data_frame(self._payload(), to_ds=True, qos=True)
        encrypted = wifi.ccmp_encrypt_frame(TK, frame, 0x0110)
        radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
        rows = [
            ["12", (radiotap + encrypted).hex(), "1.5"],
            ["13", "not-hex", "1.6"],
            ["14", _data_frame(b"plain", to_ds=True).hex(), "1.7"],
        ]
        results = wifi.decrypt_frames(TK, rows)
        self.assertEqual(len(results), 1)
        entry = results[0]
        self.assertEqual(entry["frame"], "12")
        self.assertAlmostEqual(entry["time"], 1.5)
        self.assertTrue(entry["tag_valid"])
        self.assertEqual(entry["pn"], 0x0110)
        self.assertEqual(entry["a1"], AP)
        self.assertEqual(entry["ethernet"][14:], b"flag{ccmp_frame}")


if __name__ == "__main__":
    unittest.main()
