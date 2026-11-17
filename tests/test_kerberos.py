"""Unit tests for the Kerberos helpers (no tshark required)."""
from __future__ import annotations

import hashlib
import hmac
import struct
import unittest

from fnet.utils import crypto, kerberos


# ---------------------------------------------------------------------------
# DER fixture builders (RFC 4120 uses explicit tags)
# ---------------------------------------------------------------------------
def tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        header = bytes([len(value)])
    else:
        raw = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + value


def der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8),
                         "big", signed=True)
    return tlv(0x02, raw)


def context(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


def kerberos_string(text: str) -> bytes:
    return tlv(0x1B, text.encode())


def make_principal(*parts: str) -> bytes:
    strings = tlv(0x30, b"".join(kerberos_string(part) for part in parts))
    return tlv(0x30, context(0, der_int(1)) + context(1, strings))


def make_encrypted(etype: int, cipher: bytes, kvno: int | None = None) -> bytes:
    body = context(0, der_int(etype))
    if kvno is not None:
        body += context(1, der_int(kvno))
    body += context(2, tlv(0x04, cipher))
    return tlv(0x30, body)


def make_ticket(realm: str, sname: tuple[str, ...], enc: bytes) -> bytes:
    body = (context(0, der_int(5))
            + context(1, kerberos_string(realm))
            + context(2, make_principal(*sname))
            + context(3, enc))
    return tlv(0x61, tlv(0x30, body))


def make_rep(app_tag: int, msg_type: int, etype: int = 23,
             cipher: bytes = b"\x11" * 72) -> bytes:
    realm = "EXAMPLE.COM"
    enc = make_encrypted(etype, cipher, kvno=2)
    body = context(0, der_int(5)) + context(1, der_int(msg_type))
    body += context(3, kerberos_string(realm))
    body += context(4, make_principal("alice"))
    body += context(5, make_ticket(realm, ("krbtgt", realm), enc))
    body += context(6, enc)
    return tlv(app_tag, tlv(0x30, body))


def make_req(app_tag: int, msg_type: int, etype: int = 23,
             cipher: bytes = b"\x22" * 72) -> bytes:
    realm = "EXAMPLE.COM"
    enc = make_encrypted(etype, cipher)
    req_body = (
        context(0, tlv(0x03, b"\x00"))
        + context(1, make_principal("alice"))
        + context(2, kerberos_string(realm))
        + context(3, make_principal("krbtgt", realm))
        + context(7, der_int(0x1234))
        + context(8, tlv(0x30, der_int(23) + der_int(18)))
    )
    padata_entry = tlv(0x30, context(1, der_int(2))
                       + context(2, tlv(0x04, enc)))
    body = context(1, der_int(5)) + context(2, der_int(msg_type))
    body += context(3, tlv(0x30, padata_entry))
    body += context(4, tlv(0x30, req_body))
    return tlv(app_tag, tlv(0x30, body))


class DerTest(unittest.TestCase):
    def test_read_tlv_short_and_long_length(self):
        short = tlv(0x04, b"abc")
        tag, value, end = kerberos.read_tlv(short)
        self.assertEqual((tag, value, end), (0x04, b"abc", len(short)))
        long_value = bytes(range(256)) * 2
        long_tlv = tlv(0x04, long_value)
        tag, value, end = kerberos.read_tlv(long_tlv)
        self.assertEqual(tag, 0x04)
        self.assertEqual(value, long_value)
        self.assertEqual(end, len(long_tlv))

    def test_sequence_int_octet_and_general_string(self):
        sequence = tlv(0x30, der_int(23) + tlv(0x04, b"abc")
                       + kerberos_string("EXAMPLE.COM"))
        children, end = kerberos.parse_sequence(sequence)
        self.assertEqual(end, len(sequence))
        self.assertEqual([tag for tag, _value in children], [0x02, 0x04, 0x1B])
        self.assertEqual(kerberos.parse_int(der_int(23))[0], 23)
        self.assertEqual(kerberos.parse_octet_string(tlv(0x04, b"abc"))[0],
                         b"abc")
        self.assertEqual(
            kerberos.parse_general_string(kerberos_string("EXAMPLE.COM"))[0],
            "EXAMPLE.COM")

    def test_find_context(self):
        children, _end = kerberos.parse_sequence(
            tlv(0x30, context(0, der_int(5)) + context(3, kerberos_string("X"))))
        self.assertEqual(kerberos.find_context(children, 0), der_int(5))
        self.assertIsNone(kerberos.find_context(children, 9))

    def test_truncated_and_invalid_input_raises(self):
        with self.assertRaises(kerberos.DerError):
            kerberos.read_tlv(tlv(0x04, b"abc")[:-1])
        with self.assertRaises(kerberos.DerError):
            kerberos.read_tlv(b"")
        with self.assertRaises(kerberos.DerError):
            kerberos.parse_sequence(der_int(1))
        with self.assertRaises(kerberos.DerError):
            kerberos.parse_int(tlv(0x04, b"x"))


class CryptoTest(unittest.TestCase):
    def test_rc4_roundtrip_and_checksum_layout(self):
        key = crypto.nt_hash("Password123!")
        plaintext = b"hello kerberos"
        confounder = b"12345678"
        cipher = kerberos.rc4_hmac_encrypt(
            key, 3, plaintext, confounder=confounder)
        # Usage 3 maps to 8 for RC4-HMAC (RFC 4757).
        k1 = hmac.new(key, struct.pack("<I", 8), hashlib.md5).digest()
        data = confounder + plaintext
        checksum = hmac.new(k1, data, hashlib.md5).digest()
        self.assertEqual(cipher[:16], checksum)
        k3 = hmac.new(k1, checksum, hashlib.md5).digest()
        self.assertEqual(cipher[16:], crypto.rc4(k3, data))
        decrypted, valid = kerberos.rc4_hmac_decrypt(key, 3, cipher)
        self.assertTrue(valid)
        self.assertEqual(decrypted, plaintext)

    def test_rc4_bad_checksum(self):
        key = crypto.nt_hash("Password123!")
        cipher = bytearray(kerberos.rc4_hmac_encrypt(
            key, 3, b"payload", confounder=b"abcdefgh"))
        cipher[0] ^= 0xFF
        _plain, valid = kerberos.rc4_hmac_decrypt(key, 3, bytes(cipher))
        self.assertFalse(valid)

    def test_aes_cts_roundtrip(self):
        for key_len in (16, 32):
            key = bytes(range(key_len))
            for length in (17, 33, 48):
                plain = bytes((index * 7 + 1) & 0xFF for index in range(length))
                cipher = kerberos.aes_cts_encrypt(plain, key)
                self.assertEqual(len(cipher), length)
                self.assertEqual(kerberos.aes_cts_decrypt(cipher, key), plain)

    def test_aes_cts_rfc3962_vectors(self):
        key = b"chicken teriyaki"
        short = b"I would like the "
        self.assertEqual(kerberos.aes_cts_encrypt(short, key).hex(),
                         "c6353568f2bf8cb4d8a580362da7ff7f97")
        full = (b"I would like the General Gau's Chicken, please, "
                b"and wonton soup.")
        self.assertEqual(len(full), 64)
        self.assertEqual(
            kerberos.aes_cts_encrypt(full, key).hex(),
            "97687268d6ecccc0c07b25e25ecfe584"
            "39312523a78662d5be7fcbcc98ebf5a8"
            "4807efe836ee89a526730dbc2f7bc840"
            "9dad8bbb96c4cdc03bc103e1a194bbd8")

    def test_aes_hmac_roundtrip_and_bad_checksum(self):
        key = bytes(range(32))
        plain = b"encrypted part payload"
        confounder = bytes(range(16))
        cipher = kerberos.aes_hmac_sha1_encrypt(
            key, 3, plain, confounder=confounder)
        ki = kerberos.derive_random(key, 3, 0x55)
        expected = hmac.new(ki, confounder + plain, hashlib.sha1).digest()[:12]
        self.assertEqual(cipher[-12:], expected)
        decrypted, valid = kerberos.aes_hmac_sha1_decrypt(key, 3, cipher)
        self.assertTrue(valid)
        self.assertEqual(decrypted, plain)
        bad = bytearray(cipher)
        bad[-1] ^= 0x01
        _plain, valid = kerberos.aes_hmac_sha1_decrypt(key, 3, bytes(bad))
        self.assertFalse(valid)

    def test_string_to_key_rfc3962(self):
        # Iteration count 1 vectors from RFC 3962 appendix B.
        self.assertEqual(
            kerberos.string_to_key("password", "ATHENA.MIT.EDUraeburn", 17,
                                   iterations=1).hex(),
            "42263c6e89f4fc28b8df68ee09799f15")
        self.assertEqual(
            kerberos.string_to_key("password", "ATHENA.MIT.EDUraeburn", 18,
                                   iterations=1).hex(),
            "fe697b52bc0d3ce14432ba036a92e65b"
            "bb52280990a2fa27883998d72af30161")

    def test_derive_key_matches_pbkdf2(self):
        salt = "EXAMPLE.COMalice"
        self.assertEqual(
            kerberos.derive_key("password", salt, 17),
            hashlib.pbkdf2_hmac("sha1", b"password", salt.encode(),
                                4096, 16))
        self.assertEqual(
            kerberos.derive_key("password", salt, 18),
            hashlib.pbkdf2_hmac("sha1", b"password", salt.encode(),
                                4096, 32))
        self.assertEqual(kerberos.derive_key("Password123!", salt, 23),
                         crypto.nt_hash("Password123!"))
        self.assertEqual(kerberos.password_salt("example.com", "alice"),
                         "EXAMPLE.COMalice")

    def test_encrypted_part_roundtrip(self):
        key = bytes(range(16))
        enc_part = kerberos.encrypt_encrypted_part(
            17, key, 3, b"timestamps", confounder=b"\x00" * 16)
        result = kerberos.decrypt_encrypted_part(enc_part, key, 3)
        self.assertTrue(result["ok"])
        self.assertEqual(result["plaintext"], b"timestamps")
        tampered = dict(enc_part)
        tampered["cipher"] = enc_part["cipher"][:-1] + bytes(
            [enc_part["cipher"][-1] ^ 1])
        result = kerberos.decrypt_encrypted_part(tampered, key, 3)
        self.assertFalse(result["ok"])
        self.assertFalse(result["checksum_ok"])


class MessageParseTest(unittest.TestCase):
    def test_parse_encrypted_part(self):
        enc = make_encrypted(23, b"\x11" * 72, kvno=2)
        parsed = kerberos.parse_encrypted_part(enc)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["etype"], 23)
        self.assertEqual(parsed["kvno"], 2)
        self.assertEqual(parsed["cipher"], b"\x11" * 72)
        self.assertIsNone(kerberos.parse_encrypted_part(b""))
        self.assertIsNone(kerberos.parse_encrypted_part(b"not der at all"))

    def test_parse_as_rep(self):
        data = make_rep(0x6B, 11, etype=23, cipher=b"\x44" * 80)
        parsed = kerberos.parse_as_rep(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["msg_type"], 11)
        self.assertEqual(parsed["cname"], "alice")
        self.assertEqual(parsed["realm"], "EXAMPLE.COM")
        self.assertEqual(parsed["sname"], "krbtgt/EXAMPLE.COM")
        self.assertEqual(parsed["etypes"], [23])
        self.assertEqual(parsed["padata"], [])
        self.assertEqual(parsed["enc_part"]["cipher"], b"\x44" * 80)
        self.assertIsNone(parsed["error"])

    def test_parse_tgs_rep(self):
        data = make_rep(0x6D, 13, etype=18, cipher=b"\x55" * 96)
        parsed = kerberos.parse_tgs_rep(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["msg_type"], 13)
        self.assertEqual(parsed["cname"], "alice")
        self.assertEqual(parsed["sname"], "krbtgt/EXAMPLE.COM")
        self.assertEqual(parsed["etypes"], [18])

    def test_rep_app_tag_and_msg_type_are_enforced(self):
        as_rep = make_rep(0x6B, 11)
        self.assertIsNone(kerberos.parse_tgs_rep(as_rep))
        tgs_rep = make_rep(0x6D, 13)
        self.assertIsNone(kerberos.parse_as_rep(tgs_rep))
        wrong_type = make_rep(0x6B, 13)
        self.assertIsNone(kerberos.parse_as_rep(wrong_type))

    def test_parse_as_req_with_pa_enc_timestamp(self):
        data = make_req(0x6A, 10, etype=23, cipher=b"\x66" * 72)
        parsed = kerberos.parse_as_req(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["msg_type"], 10)
        self.assertEqual(parsed["cname"], "alice")
        self.assertEqual(parsed["realm"], "EXAMPLE.COM")
        self.assertEqual(parsed["sname"], "krbtgt/EXAMPLE.COM")
        self.assertEqual(parsed["etypes"], [23, 18])
        self.assertEqual([entry["type"] for entry in parsed["padata"]], [2])
        self.assertEqual(parsed["padata"][0]["name"], "PA-ENC-TIMESTAMP")
        self.assertEqual(parsed["enc_part"]["etype"], 23)
        self.assertEqual(parsed["enc_part"]["cipher"], b"\x66" * 72)

    def test_parse_tgs_req(self):
        data = make_req(0x6C, 12, etype=18, cipher=b"\x77" * 72)
        parsed = kerberos.parse_tgs_req(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["msg_type"], 12)
        self.assertEqual(parsed["etypes"], [23, 18])
        self.assertEqual(parsed["enc_part"]["etype"], 18)
        self.assertIsNone(kerberos.parse_as_req(data))

    def test_malformed_messages_return_none(self):
        for parser in (kerberos.parse_as_rep, kerberos.parse_tgs_rep,
                       kerberos.parse_as_req, kerberos.parse_tgs_req):
            self.assertIsNone(parser(b""))
            self.assertIsNone(parser(b"\x30\x03\x02\x01\x05"))
            self.assertIsNone(parser(b"\x6b\x82\xff\xff"))
            self.assertIsNone(parser(b"\x00" * 32))


def keytab_entry(realm, components, etype, key, kvno8=1, kvno32=0):
    def counted(raw):
        return struct.pack(">H", len(raw)) + raw

    body = struct.pack(">H", len(components)) + counted(realm.encode())
    for component in components:
        body += counted(component.encode())
    body += struct.pack(">II", 1, 0)
    body += struct.pack(">B", kvno8)
    body += struct.pack(">HH", etype, len(key)) + key
    if kvno32:
        body += struct.pack(">I", kvno32)
    return struct.pack(">i", len(body)) + body


class KeytabTest(unittest.TestCase):
    def setUp(self):
        self.rc4_key = bytes(range(16))
        self.aes_key = bytes(range(32))
        self.data = (
            struct.pack(">H", 0x0502)
            + keytab_entry("EXAMPLE.COM", ["alice"], 23, self.rc4_key,
                           kvno8=1)
            + keytab_entry("EXAMPLE.COM", ["alice"], 18, self.aes_key,
                           kvno8=3, kvno32=7)
            + keytab_entry("EXAMPLE.COM", ["bob"], 17, b"\xaa" * 16)
        )

    def test_parse_keytab_entries(self):
        entries = kerberos.parse_keytab(self.data)
        self.assertEqual(len(entries), 3)
        first, second, third = entries
        self.assertEqual(first["principal"], "alice@EXAMPLE.COM")
        self.assertEqual(first["realm"], "EXAMPLE.COM")
        self.assertEqual(first["components"], ["alice"])
        self.assertEqual(first["etype"], 23)
        self.assertEqual(first["key"], self.rc4_key)
        self.assertEqual(first["kvno"], 1)
        # A 32-bit kvno wins over the legacy byte when both are present.
        self.assertEqual(second["kvno"], 7)
        self.assertEqual(second["key"], self.aes_key)
        self.assertEqual(third["principal"], "bob@EXAMPLE.COM")
        self.assertEqual(third["etype"], 17)

    def test_keytab_keys_groups_by_principal(self):
        keys = kerberos.keytab_keys(self.data)
        self.assertEqual(set(keys), {"alice@EXAMPLE.COM", "bob@EXAMPLE.COM"})
        self.assertEqual(keys["alice@EXAMPLE.COM"][23], self.rc4_key)
        self.assertEqual(keys["alice@EXAMPLE.COM"][18], self.aes_key)
        self.assertEqual(keys["bob@EXAMPLE.COM"][17], b"\xaa" * 16)

    def test_keytab_holes_are_skipped(self):
        hole = struct.pack(">i", -16) + b"\x00" * 16
        data = (struct.pack(">H", 0x0502)
                + keytab_entry("EXAMPLE.COM", ["alice"], 23, self.rc4_key)
                + hole
                + keytab_entry("EXAMPLE.COM", ["bob"], 23, b"\xbb" * 16))
        entries = kerberos.parse_keytab(data)
        self.assertEqual([entry["principal"] for entry in entries],
                         ["alice@EXAMPLE.COM", "bob@EXAMPLE.COM"])

    def test_keytab_garbage_is_empty(self):
        self.assertEqual(kerberos.parse_keytab(b""), [])
        self.assertEqual(kerberos.parse_keytab(b"\x05\x02"), [])
        self.assertEqual(kerberos.parse_keytab(b"\x05\x02\xff\xff\xff"),
                         [])
        self.assertEqual(kerberos.keytab_keys(b"junk"), {})


LOGON_LEN = 172


def build_pac(user="alice", domain="EXAMPLE", password="Password123!"):
    user_raw = user.encode("utf-16-le")
    domain_raw = domain.encode("utf-16-le")
    client_raw = "carol".encode("utf-16-le")

    lm_hash = b"\x11" * 16
    nt_hash = crypto.nt_hash(password)
    serialized = (struct.pack("<II", 1, 2) + struct.pack("<I", 40)
                  + struct.pack("<II", 0, 0) + lm_hash + nt_hash)
    credential_blob = (struct.pack("<III", 0, 0, len(serialized))
                       + serialized)
    client_blob = struct.pack("<QH", 0x1122334455667788,
                              len(client_raw)) + client_raw

    count = 3
    logon_offset = 8 + 12 * count
    credential_offset = logon_offset + LOGON_LEN
    client_offset = credential_offset + len(credential_blob)
    strings_offset = client_offset + len(client_blob)
    user_pointer = strings_offset
    domain_pointer = strings_offset + len(user_raw)

    logon = bytearray(LOGON_LEN)
    struct.pack_into("<HHI", logon, 48, len(user_raw), len(user_raw),
                     user_pointer)
    struct.pack_into("<HH", logon, 96, 3, 1)
    struct.pack_into("<III", logon, 100, 1105, 513, 0)
    struct.pack_into("<HHI", logon, 140, len(domain_raw), len(domain_raw),
                     domain_pointer)
    sid = (bytes([1, 4]) + (5).to_bytes(6, "big")
           + struct.pack("<IIII", 21, 1, 2, 3))
    logon[148:148 + len(sid)] = sid

    descriptors = [
        (1, LOGON_LEN, logon_offset),
        (2, len(credential_blob), credential_offset),
        (10, len(client_blob), client_offset),
    ]
    header = struct.pack("<II", count, 0) + b"".join(
        struct.pack("<III", *descriptor) for descriptor in descriptors)
    return (header + bytes(logon) + credential_blob + client_blob
            + user_raw + domain_raw)


class PacTest(unittest.TestCase):
    def test_parse_pac_logon_and_credential(self):
        pac = kerberos.parse_pac(build_pac())
        self.assertEqual(len(pac["buffers"]), 3)
        self.assertEqual([buffer["type"] for buffer in pac["buffers"]],
                         [1, 2, 10])
        logon = pac["logon_info"]
        self.assertEqual(logon["user"], "alice")
        self.assertEqual(logon["domain"], "EXAMPLE")
        self.assertEqual(logon["user_id"], 1105)
        self.assertEqual(logon["primary_group_id"], 513)
        self.assertEqual(logon["logon_count"], 3)
        self.assertEqual(logon["bad_password_count"], 1)
        self.assertEqual(logon["domain_sid"], "S-1-5-21-1-2-3")
        self.assertEqual(logon["user_sid"], "S-1-5-21-1-2-3-1105")
        self.assertEqual(pac["user"], "alice")
        self.assertEqual(pac["domain"], "EXAMPLE")
        self.assertIn("S-1-5-21-1-2-3", pac["sids"])
        self.assertIn("S-1-5-21-1-2-3-1105", pac["sids"])
        self.assertEqual(pac["client_info"]["name"], "carol")
        expected = crypto.nt_hash("Password123!").hex().upper()
        self.assertEqual(pac["credential_info"]["ntlm_hash"], expected)
        self.assertEqual(pac["ntlm_hash"], expected)
        self.assertEqual(pac["lm_hash"], (b"\x11" * 16).hex().upper())
        self.assertEqual(pac["server_checksum"], {})

    def test_parse_pac_server_checksum(self):
        base = build_pac()
        blob = struct.pack("<I", 16) + b"\x99" * 16
        count = 2
        header = struct.pack("<II", count, 0)
        logon_offset = 8 + 12 * count
        checksum_offset = logon_offset + LOGON_LEN
        header += struct.pack("<III", 1, LOGON_LEN, logon_offset)
        header += struct.pack("<III", 6, len(blob), checksum_offset)
        logon = base[8 + 12 * 3:8 + 12 * 3 + LOGON_LEN]
        pac = kerberos.parse_pac(header + logon + blob)
        self.assertEqual(pac["server_checksum"]["signature_type"], 16)
        self.assertEqual(pac["server_checksum"]["signature"], b"\x99" * 16)

    def test_parse_pac_garbage_returns_defaults(self):
        for blob in (b"", b"junk", b"\x00" * 8, b"\x05\x00\x00\x00" + b"\xff" * 9):
            pac = kerberos.parse_pac(blob)
            self.assertEqual(pac["buffers"], [])
            self.assertIsNone(pac["logon_info"])
            self.assertEqual(pac["user"], "")
            self.assertEqual(pac["sids"], [])
            self.assertEqual(pac["ntlm_hash"], "")


class HashcatTest(unittest.TestCase):
    def test_as_rep_rc4_line(self):
        cipher = b"\xaa" * 16 + b"\xbb" * 8
        lines = kerberos.hashcat_lines(
            11, "alice", "example.com", "", 23, cipher)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("$krb5asrep$23$alice@EXAMPLE.COM:"))
        checksum, edata = lines[0].split(":", 1)[1].split("$")
        self.assertEqual(checksum, (b"\xaa" * 16).hex())
        self.assertEqual(edata, (b"\xbb" * 8).hex())

    def test_tgs_rc4_line(self):
        cipher = b"\xcc" * 16 + b"\xdd" * 24
        lines = kerberos.hashcat_lines(
            13, "alice", "EXAMPLE.COM", "cifs/fileserver", 23, cipher)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(
            "$krb5tgs$23$*alice$EXAMPLE.COM$cifs/fileserver*$"))
        checksum, edata = lines[0].split("*$", 1)[1].split("$")
        self.assertEqual(checksum, (b"\xcc" * 16).hex())
        self.assertEqual(edata, (b"\xdd" * 24).hex())

    def test_aes_lines_split_trailing_checksum(self):
        cipher = b"\x01" * 40 + b"\x02" * 12
        for etype in (17, 18):
            as_line = kerberos.hashcat_lines(
                11, "alice", "EXAMPLE.COM", "", etype, cipher)[0]
            self.assertTrue(as_line.startswith(
                f"$krb5asrep${etype}$alice@EXAMPLE.COM:"))
            checksum, edata = as_line.split(":", 1)[1].split("$")
            self.assertEqual(checksum, (b"\x02" * 12).hex())
            self.assertEqual(edata, (b"\x01" * 40).hex())

            tgs_line = kerberos.hashcat_lines(
                13, "alice", "EXAMPLE.COM", "host/server", etype, cipher)[0]
            self.assertTrue(tgs_line.startswith(
                f"$krb5tgs${etype}$*alice$EXAMPLE.COM$host/server*$"))
            checksum, edata = tgs_line.split("*$", 1)[1].split("$")
            self.assertEqual(checksum, (b"\x02" * 12).hex())
            self.assertEqual(edata, (b"\x01" * 40).hex())

    def test_hashcat_modes(self):
        self.assertEqual(kerberos.hashcat_modes(11, 23), [18200])
        self.assertEqual(kerberos.hashcat_modes(13, 23), [13100])
        self.assertEqual(kerberos.hashcat_modes(11, 17), [19800])
        self.assertEqual(kerberos.hashcat_modes(11, 18), [19900])
        self.assertEqual(kerberos.hashcat_modes(13, 17), [19600])
        self.assertEqual(kerberos.hashcat_modes(13, 18), [19700])
        self.assertEqual(kerberos.hashcat_modes(11, 16), [])
        self.assertEqual(kerberos.hashcat_modes(14, 23), [])
        self.assertEqual(kerberos.hashcat_modes("bad", 23), [])

    def test_unsupported_combinations_return_empty(self):
        self.assertEqual(kerberos.hashcat_lines(11, "a", "R", "", 16, b"\x00" * 40), [])
        self.assertEqual(kerberos.hashcat_lines(12, "a", "R", "", 23, b"\x00" * 40), [])
        self.assertEqual(kerberos.hashcat_lines(11, "a", "R", "", 23, b"\x00" * 16), [])
        self.assertEqual(kerberos.hashcat_lines(11, "a", "R", "", 18, b"\x00" * 12), [])
        self.assertEqual(kerberos.hashcat_lines(11, "a", "R", "", 23, b""), [])
        self.assertEqual(kerberos.hashcat_lines("bad", "a", "R", "", 23, b"\x00" * 40), [])


class TimelineTest(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"time": 30, "frame": 3, "msg_type": 13, "user": "alice",
             "realm": "EXAMPLE.COM", "spn": "cifs/fs", "etype": 23},
            {"time": 10, "frame": 1, "msg_type": 10, "user": "alice",
             "realm": "EXAMPLE.COM", "etype": 23},
            {"time": 20, "frame": 2, "msg_type": 11, "user": "alice",
             "realm": "EXAMPLE.COM", "etype": 23, "error": 24},
            "not an event",
        ]

    def test_build_timeline_sorts_and_labels(self):
        timeline = kerberos.build_timeline(self.events)
        self.assertEqual(len(timeline), 3)
        self.assertEqual([item["frame"] for item in timeline], [1, 2, 3])
        self.assertEqual([item["message"] for item in timeline],
                         ["AS-REQ", "AS-REP", "TGS-REP"])
        self.assertEqual(timeline[1]["error"], 24)
        self.assertEqual(timeline[2]["spn"], "cifs/fs")
        self.assertIsNone(timeline[0]["error"])

    def test_timeline_uses_frame_as_tiebreaker(self):
        events = [
            {"time": 5, "frame": 9, "msg_type": 11},
            {"time": 5, "frame": 2, "msg_type": 10},
        ]
        timeline = kerberos.build_timeline(events)
        self.assertEqual([item["frame"] for item in timeline], [2, 9])

    def test_summarise_timeline(self):
        summary = kerberos.summarise_timeline(self.events)
        self.assertEqual(summary["count"], 3)
        self.assertEqual(summary["first"], 10.0)
        self.assertEqual(summary["last"], 30.0)
        self.assertEqual(summary["duration"], 20.0)
        self.assertEqual(summary["messages"],
                         {"AS-REQ": 1, "AS-REP": 1, "TGS-REP": 1})
        self.assertEqual(summary["users"], {"alice@EXAMPLE.COM": 3})
        self.assertEqual(summary["etypes"], {"23": 3})
        self.assertEqual(summary["errors"], {"24": 1})

    def test_empty_timeline(self):
        self.assertEqual(kerberos.build_timeline([]), [])
        summary = kerberos.summarise_timeline([])
        self.assertEqual(summary["count"], 0)
        self.assertIsNone(summary["first"])
        self.assertIsNone(summary["last"])
        self.assertEqual(summary["duration"], 0.0)


if __name__ == "__main__":
    unittest.main()
