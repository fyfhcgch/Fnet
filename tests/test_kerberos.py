"""Unit tests for the pure-Python Kerberos helpers (no network/tshark)."""
from __future__ import annotations

import hashlib
import struct
import unittest

from fnet.utils import crypto, kerberos


def tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        header = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + value


def der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big",
                         signed=True)
    return tlv(0x02, raw)


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def general_string(value: str) -> bytes:
    return tlv(0x1B, value.encode())


def ctx(number: int, content: bytes, constructed: bool = True) -> bytes:
    return tlv((0xA0 if constructed else 0x80) + number, content)


def principal(name: str, name_type: int = 1) -> bytes:
    parts = [general_string(part) for part in name.split("/")]
    return seq(ctx(0, der_int(name_type)), ctx(1, seq(*parts)))


def encrypted_data(etype: int, cipher: bytes, kvno: int | None = None) -> bytes:
    items = [ctx(0, der_int(etype))]
    if kvno is not None:
        items.append(ctx(1, der_int(kvno)))
    items.append(ctx(2, octets(cipher)))
    return seq(*items)


class DerTest(unittest.TestCase):
    def test_read_tlv(self):
        data = b"\x30\x03\x02\x01\x05"
        self.assertEqual(kerberos.read_tlv(data, 0),
                         (0x30, b"\x02\x01\x05", 5))
        self.assertEqual(kerberos.read_tlv(data, 2),
                         (0x02, b"\x05", 5))

    def test_long_form_length(self):
        body = b"A" * 200
        data = tlv(0x04, body)
        tag, value, nxt = kerberos.read_tlv(data, 0)
        self.assertEqual(tag, 0x04)
        self.assertEqual(value, body)
        self.assertEqual(nxt, len(data))

    def test_truncated_raises(self):
        for data in (b"", b"\x30", b"\x30\x05\x02\x01", b"\x04\x82\x01"):
            with self.assertRaises(ValueError):
                kerberos.read_tlv(data, 0)

    def test_scalar_helpers(self):
        self.assertEqual(kerberos.parse_sequence(seq(der_int(7))),
                         der_int(7))
        self.assertEqual(kerberos.parse_int(der_int(42)), 42)
        self.assertEqual(kerberos.parse_int(der_int(-3)), -3)
        self.assertEqual(kerberos.parse_octet_string(octets(b"abcd")),
                         b"abcd")
        self.assertEqual(
            kerberos.parse_bit_string(tlv(0x03, b"\x00\xde\xad")),
            b"\xde\xad")
        self.assertEqual(
            kerberos.parse_general_string(general_string("CTF.LOCAL")),
            "CTF.LOCAL")

    def test_find_context(self):
        inner = ctx(0, der_int(5)) + ctx(2, octets(b"abc"))
        self.assertEqual(kerberos.find_context(inner, 0), der_int(5))
        self.assertEqual(kerberos.find_context(inner, 2), octets(b"abc"))
        self.assertIsNone(kerberos.find_context(inner, 9))
        primitive = tlv(0x82, b"raw")
        self.assertEqual(kerberos.find_context(primitive, 2), b"raw")


class Rc4HmacTest(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(16))
        self.usage = 3
        self.confounder = b"\xa5" * 8
        self.plaintext = b"kerberos preauth"

    def test_roundtrip(self):
        blob = kerberos.encrypt_encrypted_part(
            self.plaintext, 23, self.key, self.usage,
            confounder=self.confounder)
        self.assertEqual(len(blob), 16 + 8 + len(self.plaintext))
        plain = kerberos.rc4_hmac_decrypt(self.key, blob, self.usage)
        self.assertEqual(plain, self.confounder + self.plaintext)
        self.assertEqual(kerberos.decrypt_encrypted_part(
            blob, 23, self.key, self.usage), self.confounder + self.plaintext)

    def test_checksum_rejection(self):
        blob = kerberos.encrypt_encrypted_part(
            self.plaintext, 23, self.key, self.usage,
            confounder=self.confounder)
        self.assertIsNone(
            kerberos.rc4_hmac_decrypt(self.key, blob, self.usage + 1))
        tampered = bytearray(blob)
        tampered[0] ^= 0x01
        self.assertIsNone(
            kerberos.rc4_hmac_decrypt(self.key, bytes(tampered), self.usage))
        tampered = bytearray(blob)
        tampered[-1] ^= 0x80
        self.assertIsNone(
            kerberos.rc4_hmac_decrypt(self.key, bytes(tampered), self.usage))
        self.assertIsNone(kerberos.rc4_hmac_decrypt(self.key, b"short", 3))


class AesCtsTest(unittest.TestCase):
    def test_roundtrip_both_key_sizes(self):
        for key_len, etype in ((16, 17), (32, 18)):
            key = bytes(range(key_len))
            for size in (17, 33, 48):
                plaintext = bytes((i * 7 + 1) & 0xFF for i in range(size))
                confounder = b"\x42" * 16
                blob = kerberos.encrypt_encrypted_part(
                    plaintext, etype, key, 3, confounder=confounder)
                self.assertEqual(len(blob), 16 + size + 12)
                plain = kerberos.aes_decrypt(key, blob, 3, etype)
                self.assertEqual(plain, confounder + plaintext)
                tampered = bytearray(blob)
                tampered[-1] ^= 0x80
                self.assertIsNone(
                    kerberos.aes_decrypt(key, bytes(tampered), 3, etype))
                self.assertIsNone(kerberos.aes_decrypt(key, blob, 4, etype))

    def test_cs3_block_ordering(self):
        key = bytes(range(32))
        basic = b"\x10" * 16 + b"x" * 17  # 33 bytes: one stolen block
        ciphertext = kerberos.aes_cts_encrypt(basic, key)
        self.assertEqual(len(ciphertext), len(basic))
        self.assertEqual(kerberos.aes_cts_decrypt(ciphertext, key), basic)
        plain_cbc = crypto.aes_cbc_encrypt(
            basic + b"\x00" * 15, key, b"\x00" * 16, pad=False)
        self.assertNotEqual(ciphertext, plain_cbc[:len(ciphertext)])

    def test_decrypt_rejects_short_and_bad_etype(self):
        self.assertIsNone(kerberos.aes_decrypt(b"k" * 16, b"x" * 20, 1, 17))
        self.assertIsNone(kerberos.aes_decrypt(b"k" * 16, b"x" * 40, 1, 16))


class KeyDerivationTest(unittest.TestCase):
    def test_derive_key_matches_pbkdf2(self):
        password = "Password123!"
        salt = b"CTF.LOCALalice"
        expected16 = hashlib.pbkdf2_hmac("sha1", password.encode(), salt,
                                        4096, dklen=16)
        expected32 = hashlib.pbkdf2_hmac("sha1", password.encode(), salt,
                                        4096, dklen=32)
        self.assertEqual(kerberos.derive_key(password, salt, 17), expected16)
        self.assertEqual(kerberos.derive_key(password, salt, 18), expected32)
        self.assertEqual(len(kerberos.derive_key(password, salt, 17)), 16)
        self.assertEqual(len(kerberos.derive_key(password, salt, 18)), 32)

    def test_password_salt(self):
        self.assertEqual(
            kerberos.password_salt("CTF.LOCAL", "alice"),
            b"CTF.LOCALalice")
        self.assertEqual(
            kerberos.password_salt("CTF.LOCAL", "alice/admin"),
            b"CTF.LOCALaliceadmin")


def counted(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def build_keytab(realm: str = "CTF.LOCAL", name: str = "alice",
                 enctype: int = 18, key: bytes | None = None) -> bytes:
    key = key if key is not None else bytes(range(32))
    entry = struct.pack(">H", 1) + counted(realm.encode())
    entry += counted(name.encode())
    entry += struct.pack(">II", 1, 0)
    entry += bytes([1]) + struct.pack(">HH", enctype, len(key)) + key
    entry += struct.pack(">I", 1)
    return b"\x05\x02" + struct.pack(">I", 1) + entry


def build_logon_info() -> bytes:
    buf = bytearray(256)

    def put_string(field_offset: int, text: str) -> None:
        offset = len(buf)
        raw = text.encode("utf-16-le")
        buf.extend(raw)
        buf[field_offset:field_offset + 2] = struct.pack("<H", len(raw))
        buf[field_offset + 2:field_offset + 4] = struct.pack("<H", len(raw))
        buf[field_offset + 4:field_offset + 8] = struct.pack("<I", offset)

    put_string(48, "alice")
    put_string(136, "dc01")
    put_string(144, "CTF.LOCAL")
    buf[96:98] = struct.pack("<H", 7)
    buf[98:100] = struct.pack("<H", 2)
    buf[100:104] = struct.pack("<I", 1104)
    buf[104:108] = struct.pack("<I", 513)
    buf[108:112] = struct.pack("<I", 1)
    buf[112:116] = struct.pack("<I", len(buf))
    buf.extend(struct.pack("<I", 513))
    sid_offset = len(buf)
    buf.extend(bytes([1, 5]) + (5).to_bytes(6, "big"))
    buf.extend(b"".join(struct.pack("<I", part) for part in (21, 1, 2, 3, 4)))
    buf[152:156] = struct.pack("<I", sid_offset)
    return bytes(buf)


def build_pac() -> tuple[bytes, bytes]:
    logon = build_logon_info()
    lm = b"\x11" * 16
    nt = b"\x22" * 16
    credential = struct.pack("<II", 0, 0) + lm + nt
    count = 2
    header_length = 8 + count * 12
    logon_offset = header_length
    credential_offset = logon_offset + len(logon)
    header = struct.pack("<II", count, 0)
    header += struct.pack("<III", 1, logon_offset, len(logon))
    header += struct.pack("<III", 2, credential_offset, len(credential))
    return header + logon + credential, nt


class KeytabTest(unittest.TestCase):
    def test_parse_keytab(self):
        data = build_keytab()
        entries = kerberos.parse_keytab(data)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["realm"], "CTF.LOCAL")
        self.assertEqual(entry["components"], ["alice"])
        self.assertEqual(entry["principal"], "alice")
        self.assertEqual(entry["enctype"], 18)
        self.assertEqual(entry["kvno"], 1)
        self.assertEqual(entry["key"], bytes(range(32)))
        self.assertEqual(entry["key_hex"], bytes(range(32)).hex())

    def test_keytab_keys(self):
        keytab = kerberos.parse_keytab(build_keytab())
        self.assertEqual(len(kerberos.keytab_keys(keytab, "ctf.local")), 1)
        self.assertEqual(
            len(kerberos.keytab_keys(keytab, "CTF.LOCAL", ["alice"])), 1)
        self.assertEqual(
            len(kerberos.keytab_keys(keytab, "CTF.LOCAL", "alice")), 1)
        self.assertEqual(
            kerberos.keytab_keys(keytab, "CTF.LOCAL", ["bob"]), [])

    def test_bad_versions(self):
        self.assertEqual(kerberos.parse_keytab(b""), [])
        self.assertEqual(kerberos.parse_keytab(b"\x05\x01" + b"\x00" * 8), [])


class PacTest(unittest.TestCase):
    def test_logon_and_credential(self):
        data, nt_hash = build_pac()
        pac = kerberos.parse_pac(data)
        self.assertEqual(len(pac["buffers"]), 2)
        self.assertEqual(pac["buffers"][0]["name"], "LOGON_INFO")
        logon = pac["logon"]
        self.assertEqual(logon["user"], "alice")
        self.assertEqual(logon["domain"], "CTF.LOCAL")
        self.assertEqual(logon["logon_server"], "dc01")
        self.assertEqual(logon["logon_count"], 7)
        self.assertEqual(logon["bad_password_count"], 2)
        self.assertEqual(logon["user_id"], 1104)
        self.assertEqual(logon["group_ids"], [513])
        self.assertIn("S-1-5-21-1-2-3-4", logon["sids"])
        self.assertEqual(logon["domain_sid"], "S-1-5-21-1-2-3-4")
        credential = pac["credential"]
        self.assertEqual(credential["version"], 0)
        self.assertEqual(credential["nt_hash"], nt_hash.hex().upper())
        self.assertEqual(credential["hash"], nt_hash.hex().upper())

    def test_short_input_is_tolerated(self):
        self.assertEqual(kerberos.parse_pac(b"")["buffers"], [])
        self.assertEqual(kerberos.parse_pac(b"\x01\x00")["logon"], None)
        pac = kerberos.parse_pac(struct.pack("<II", 2, 0) + b"\x00" * 16)
        self.assertEqual(pac["logon"], None)


def build_as_rep(etype: int = 17, cipher: bytes = b"\xaa" * 32,
                 cname: str = "alice", realm: str = "CTF.LOCAL") -> bytes:
    padata = seq(seq(ctx(1, der_int(19)),
                     ctx(2, octets(b"\x01\x02"))))
    body = seq(
        ctx(0, der_int(5)),
        ctx(1, der_int(11)),
        ctx(2, padata),
        ctx(3, general_string(realm)),
        ctx(4, principal(cname)),
        ctx(6, encrypted_data(etype, cipher, 3)),
    )
    return tlv(0x6B, body)


def build_tgs_rep(etype: int = 23, cipher: bytes = b"\x33" * 64
                  ) -> bytes:
    ticket = seq(
        ctx(0, der_int(5)),
        ctx(1, general_string("CTF.LOCAL")),
        ctx(2, principal("host/server")),
    )
    body = seq(
        ctx(0, der_int(5)),
        ctx(1, der_int(13)),
        ctx(3, general_string("CTF.LOCAL")),
        ctx(4, principal("alice")),
        ctx(5, ticket),
        ctx(6, encrypted_data(etype, cipher)),
    )
    return tlv(0x6D, body)


def build_as_req() -> bytes:
    padata = seq(seq(ctx(1, der_int(2)),
                     ctx(2, octets(encrypted_data(23, b"\x44" * 64)))))
    req_body = seq(
        ctx(0, tlv(0x03, b"\x00\x00")),
        ctx(1, principal("alice")),
        ctx(2, general_string("CTF.LOCAL")),
        ctx(3, principal("krbtgt/CTF.LOCAL")),
        ctx(6, der_int(12345)),
        ctx(7, seq(der_int(23), der_int(18))),
    )
    body = seq(
        ctx(1, der_int(5)),
        ctx(2, der_int(10)),
        ctx(3, padata),
        ctx(4, req_body),
    )
    return tlv(0x6A, body)


class MessageTest(unittest.TestCase):
    def test_parse_encrypted_part(self):
        cipher = b"\x01" * 48
        part = kerberos.parse_encrypted_part(
            encrypted_data(18, cipher, kvno=2))
        self.assertEqual(part["etype"], 18)
        self.assertEqual(part["kvno"], 2)
        self.assertEqual(part["cipher"], cipher)
        self.assertEqual(part["cipher_len"], 48)

    def test_parse_as_rep(self):
        result = kerberos.parse_as_rep(build_as_rep())
        self.assertIsNotNone(result)
        self.assertEqual(result["pvno"], 5)
        self.assertEqual(result["msg_type"], 11)
        self.assertEqual(result["realm"], "CTF.LOCAL")
        self.assertEqual(result["cname"], "alice")
        self.assertEqual(result["etypes"], [17])
        self.assertEqual(result["enc_part"]["etype"], 17)
        self.assertEqual(len(result["padata"]), 1)
        self.assertEqual(result["padata"][0]["type"], 19)
        self.assertEqual(result["padata"][0]["name"], "PA-ETYPE-INFO2")

    def test_parse_tgs_rep(self):
        result = kerberos.parse_tgs_rep(build_tgs_rep())
        self.assertIsNotNone(result)
        self.assertEqual(result["realm"], "CTF.LOCAL")
        self.assertEqual(result["cname"], "alice")
        self.assertEqual(result["sname"], "host/server")
        self.assertEqual(result["sname_components"], ["host", "server"])
        self.assertEqual(result["enc_part"]["etype"], 23)

    def test_parse_as_req(self):
        result = kerberos.parse_as_req(build_as_req())
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], 10)
        self.assertEqual(result["realm"], "CTF.LOCAL")
        self.assertEqual(result["cname"], "alice")
        self.assertEqual(result["sname"], "krbtgt/CTF.LOCAL")
        self.assertEqual(result["etypes"], [23, 18])
        self.assertEqual(result["nonce"], 12345)
        self.assertEqual(result["padata"][0]["type"], 2)
        self.assertEqual(result["enc_part"]["etype"], 23)

    def test_krb_error(self):
        body = seq(
            ctx(0, der_int(5)),
            ctx(1, der_int(30)),
            ctx(6, der_int(24)),
            ctx(9, general_string("CTF.LOCAL")),
            ctx(10, principal("alice")),
        )
        result = kerberos.parse_as_rep(tlv(0x7E, body))
        self.assertIsNotNone(result)
        self.assertEqual(result["error_code"], 24)
        self.assertIn("PREAUTH", result["error"])
        self.assertEqual(result["cname"], "alice")

    def test_bad_input_returns_none(self):
        self.assertIsNone(kerberos.parse_as_rep(b"\x00\x01"))
        self.assertIsNone(kerberos.parse_tgs_rep(b"\x30\x00"))
        self.assertIsNone(kerberos.parse_as_req(general_string("x")))


class HashcatTest(unittest.TestCase):
    def test_rc4_as_rep(self):
        cipher = bytes(range(40))
        line = kerberos.hashcat_lines(11, "alice", "ctf.local", "", 23,
                                      cipher)[0]
        checksum = cipher[-16:].hex()
        edata = cipher[:-16].hex()
        self.assertEqual(
            line, f"$krb5asrep$23$alice@CTF.LOCAL:{checksum}${edata}")
        self.assertEqual(kerberos.hashcat_modes(11, 23), [18200])

    def test_rc4_tgs_rep(self):
        cipher = bytes(range(48))
        line = kerberos.hashcat_lines(13, "alice", "CTF.LOCAL",
                                      "host/server", 23, cipher)[0]
        self.assertTrue(line.startswith(
            "$krb5tgs$23$*alice$CTF.LOCAL$host/server*$"))
        self.assertTrue(line.endswith(cipher[:-16].hex()))
        self.assertEqual(kerberos.hashcat_modes(13, 23), [13100])

    def test_aes_as_rep_split(self):
        cipher = bytes(range(48))
        for etype, mode in ((17, 19800), (18, 19900)):
            line = kerberos.hashcat_lines(11, "alice", "CTF.LOCAL", "",
                                          etype, cipher)[0]
            edata = cipher[:-12].hex()
            checksum = cipher[-12:].hex()
            self.assertEqual(
                line,
                f"$krb5asrep${etype}$alice@CTF.LOCAL:{edata}${checksum}")
            self.assertEqual(kerberos.hashcat_modes(11, etype), [mode])

    def test_aes_tgs_rep_split(self):
        cipher = bytes(range(64))
        for etype, mode in ((17, 19600), (18, 19700)):
            line = kerberos.hashcat_lines(13, "alice", "CTF.LOCAL",
                                          "host/server", etype, cipher)[0]
            self.assertTrue(line.startswith(
                f"$krb5tgs${etype}$*alice$CTF.LOCAL$host/server*$"))
            self.assertTrue(line.endswith(
                cipher[:-12].hex() + "$" + cipher[-12:].hex()))
            self.assertEqual(kerberos.hashcat_modes(13, etype), [mode])

    def test_empty_cipher(self):
        self.assertEqual(kerberos.hashcat_lines(11, "alice", "R", "", 23, b""),
                         [])
        self.assertEqual(kerberos.hashcat_modes(11, 1), [])


class TimelineTest(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"time": "2026-01-01 10:00:02", "frame": 9, "user": "alice",
             "realm": "ctf.local", "service": "host/server", "msg_type": 13,
             "src": "10.0.0.2", "error_code": 0},
            {"time": "2026-01-01 10:00:01", "frame": 2, "user": "alice",
             "realm": "CTF.LOCAL", "msg_type": 10, "src": "10.0.0.2",
             "error_code": 24},
            {"time": "2026-01-01 10:00:01", "frame": 1, "user": "bob",
             "realm": "CTF.LOCAL", "msg_type": 11, "src": "10.0.0.3"},
        ]

    def test_sorted_rows(self):
        rows = kerberos.build_timeline(self.events)
        self.assertEqual([row["frame"] for row in rows], [1, 2, 9])
        self.assertEqual([row["status"] for row in rows],
                         ["success", "error", "success"])
        self.assertEqual(rows[1]["msg_type"], "AS-REQ")
        self.assertEqual(rows[1]["realm"], "CTF.LOCAL")
        self.assertEqual(rows[2]["service"], "host/server")
        self.assertEqual(set(rows[0]), {"time", "frame", "user", "realm",
                                        "service", "msg_type", "src",
                                        "status"})

    def test_summary(self):
        summary = kerberos.summarise_timeline(self.events)
        self.assertIn("alice@CTF.LOCAL: 2 (success 1, error 1)", summary)
        self.assertIn("bob@CTF.LOCAL: 1 (success 1, error 0)", summary)


if __name__ == "__main__":
    unittest.main()
