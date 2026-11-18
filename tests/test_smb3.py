"""Unit tests for SMB3 key derivation and transform decryption."""
from __future__ import annotations

import hashlib
import hmac
import struct
import tempfile
import unittest
from pathlib import Path

from fnet import smb3
from fnet.utils.crypto import aes_gcm_encrypt, md4, rc4
from fnet.utils.smb import SMB2_MAGIC
from fnet.utils.wifi import ccm_encrypt

from tests.test_smb import (create_request, create_response, header,
                            nbss, read_request, read_response)

USER = "alice"
DOMAIN = "LAB"
PASSWORD = "Password123"
CHALLENGE = bytes.fromhex("1122334455667788")
SESSION_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def smb2(command: int, *, status: int = 0, flags: int = 0,
         message_id: int = 1, tree_id: int = 0, session_id: int = 1,
         body: bytes = b"") -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s", SMB2_MAGIC, 64, 1, status, command, 1,
        flags, 0, message_id, 0, tree_id, session_id, b"\x00" * 16) + body


def negotiate_request() -> bytes:
    body = struct.pack("<HHHHI16sII", 36, 1, 0x03, 0, 0x40, b"\x00" * 16,
                       0, 0) + struct.pack("<H", 0x0311)
    return smb2(0, message_id=1, body=body)


def negotiate_response() -> bytes:
    body = struct.pack("<HHHH16sII", 65, 0x03, 0x0311, 0, b"\x00" * 16,
                       0x40, 0)
    return smb2(0, flags=0x1, message_id=1, body=body)


def type3_blob(nt_response: bytes, encrypted_key: bytes) -> bytes:
    domain = DOMAIN.encode("utf-16le")
    user = USER.encode("utf-16le")
    workstation = b""
    blob = bytearray(64)
    blob[0:8] = b"NTLMSSP\x00"
    blob[8:12] = (3).to_bytes(4, "little")
    offset = 64
    payload = b""

    def put(length_at: int, offset_at: int, value: bytes) -> None:
        nonlocal offset, payload
        struct.pack_into("<HHI", blob, length_at, len(value), len(value),
                         offset)
        payload += value
        offset += len(value)

    put(28, 32, domain)
    put(36, 40, user)
    put(44, 48, workstation)
    put(20, 24, nt_response)
    put(52, 56, encrypted_key)
    struct.pack_into("<HHI", blob, 12, 0, 0, 0)  # LM response: empty
    struct.pack_into("<I", blob, 60, 0x00088235 | 0x40000000)
    return bytes(blob) + payload


def session_setup_request(blob: bytes) -> bytes:
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(blob), 0)
    return smb2(1, message_id=2, body=body + blob)


def session_setup_response() -> bytes:
    body = struct.pack("<HBBIIHHQ", 9, 0, 0, 0, 0, 64, 0, 0)
    return smb2(1, flags=0x1, message_id=2, session_id=0x41, body=body)


def preauth_hash(messages) -> bytes:
    digest = bytes(64)
    for message in messages:
        raw = bytearray(message)
        raw[48:64] = b"\x00" * 16
        digest = hashlib.sha512(digest + bytes(raw)).digest()
    return digest


def transform(key: bytes, cipher: str, plaintext: bytes,
              session_id: int = 0x41) -> bytes:
    nonce = b"\x01" + b"\x00" * 7 + b"\x11" * 4 + b"\x00" * 4
    header_bytes = bytearray(
        b"\xfdSMB" + b"\x00" * 16 + nonce
        + len(plaintext).to_bytes(4, "little") + b"\x00\x00"
        + (1).to_bytes(2, "little") + session_id.to_bytes(8, "little"))
    aad = bytes(header_bytes[20:52])
    if cipher == "AES-GCM":
        sealed = aes_gcm_encrypt(plaintext, key, nonce[:12], aad, tag_len=16)
        ciphertext, tag = sealed[:-16], sealed[-16:]
    else:
        sealed = ccm_encrypt(key, nonce[:11], aad, plaintext, tag_len=16)
        ciphertext, tag = sealed[:-16], sealed[-16:]
    header_bytes[4:20] = tag
    return bytes(header_bytes) + ciphertext


class FakeTshark:
    """Minimal ``TShark.fields`` stand-in so the test runs without a capture."""

    def __init__(self, rows):
        self.rows = rows

    def fields(self, pcap, fields, display_filter="", **kwargs):
        return self.rows


class Smb3KeyTest(unittest.TestCase):
    def test_nt_hash_vectors(self):
        self.assertEqual(md4("password".encode("utf-16le")).hex(),
                         "8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(smb3.nt_hash_from_password("password").hex(),
                         "8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(
            smb3.nt_hash_from_hex("8846F7EA-EE8F-B117-AD06-BDD830B7586C"),
            bytes.fromhex("8846f7eaee8fb117ad06bdd830b7586c"))
        self.assertIsNone(smb3.nt_hash_from_hex(
            "alice::LAB:1122334455667788:"
            "aabbccddeeff00112233445566778899:01010000"))

    def test_kdf_microsoft_smb311_vector(self):
        session_key = bytes.fromhex("419FDDF34C1E001909D362AE7FB6AF79")
        context = bytes.fromhex(
            "B23F3CBFD69487D9832B79B1594A367C"
            "DD950909B774C3A4C412B4FCEA9EDDDB"
            "A7DB256BA2EA30E977F11F9B11324757"
            "8E0E915C6D2A513B8F2FCA5707DC8770")
        self.assertEqual(
            smb3.kdf(session_key, "SMBC2SCipherKey", context, 16).hex(),
            "a2f5e80e5d59103034f32e52f698e5ec")

    def test_session_key_candidates_recover_exported_key(self):
        nt_hash = md4(PASSWORD.encode("utf-16le"))
        response_key = hmac.new(
            nt_hash, (USER.upper() + DOMAIN).encode("utf-16le"),
            hashlib.md5).digest()
        blob = bytes.fromhex("0101000000000000") + b"\x22" * 8
        proof = hmac.new(response_key, CHALLENGE + blob,
                         hashlib.md5).digest()
        session_base = hmac.new(response_key, proof, hashlib.md5).digest()
        exchange = hmac.new(session_base, b"session key exchange",
                            hashlib.md5).digest()
        encrypted = rc4(exchange, SESSION_KEY)
        auth = {"user": USER, "domain": DOMAIN, "nt_proof": proof,
                "session_key": encrypted}
        candidates = dict(smb3.session_key_candidates(auth, nt_hash))
        self.assertEqual(candidates["ntlmv2+key-exchange"], SESSION_KEY)
        self.assertEqual(candidates["ntlmv2-base"], session_base)

    def test_preauth_candidates_include_every_prefix(self):
        request = negotiate_request()
        response = negotiate_response()
        messages = [(1, "1", "a", _parse(request)),
                    (2, "2", "b", _parse(response))]
        candidates = smb3.preauth_candidates(messages)
        self.assertEqual([frames for _hash, frames in candidates],
                         [["1", "2"], ["1"]])
        self.assertEqual(candidates[0][0], preauth_hash([request, response]))

    def test_transform_roundtrip_gcm_and_ccm(self):
        key = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
        plaintext = header(3, message_id=1) + b"\x09\x00" + b"\x00" * 6
        for cipher in smb3.CIPHERS:
            message = _parse(transform(key, cipher, plaintext))
            decrypted, ok = smb3.decrypt_transform(key, cipher, message)
            self.assertTrue(ok, cipher)
            self.assertEqual(decrypted, plaintext)
            wrong, ok = smb3.decrypt_transform(b"\x00" * 16, cipher, message)
            self.assertFalse(ok, cipher)

    def test_cipher_keys_yields_base_session_key(self):
        """``cipher_keys`` 的第 6 项永远是派生前的会话密钥。"""
        base = SESSION_KEY
        preauth = (bytes.fromhex("ab" * 64), ["7", "9"])
        schemes = list(smb3.cipher_keys([("ntlmv2-base", base)], [preauth]))
        self.assertTrue(schemes)
        for scheme in schemes:
            self.assertEqual(len(scheme), 6, scheme)
            self.assertEqual(scheme[5], base, scheme)
        direct = [scheme for scheme in schemes
                  if scheme[0].endswith(":direct")]
        self.assertTrue(direct)
        for scheme in direct:
            self.assertEqual(scheme[2], base)  # direct: key == base


class Smb3DecryptCaptureTest(unittest.TestCase):
    def _build_capture(self):
        nt_hash = md4(PASSWORD.encode("utf-16le"))
        response_key = hmac.new(
            nt_hash, (USER.upper() + DOMAIN).encode("utf-16le"),
            hashlib.md5).digest()
        nt_blob = bytes.fromhex("0101000000000000") + b"\x22" * 8
        proof = hmac.new(response_key, CHALLENGE + nt_blob,
                         hashlib.md5).digest()
        nt_response = proof + nt_blob
        session_base = hmac.new(response_key, proof, hashlib.md5).digest()
        exchange = hmac.new(session_base, b"session key exchange",
                            hashlib.md5).digest()
        encrypted_key = rc4(exchange, SESSION_KEY)
        blob = type3_blob(nt_response, encrypted_key)

        neg_req = negotiate_request()
        neg_resp = negotiate_response()
        ses_req = session_setup_request(blob)
        ses_resp = session_setup_response()
        preauth = preauth_hash([neg_req, neg_resp, ses_req, ses_resp])
        c2s_key = smb3.kdf(SESSION_KEY, "SMBC2SCipherKey", preauth, 16)
        s2c_key = smb3.kdf(SESSION_KEY, "SMBS2CCipherKey", preauth, 16)

        file_id = bytes(range(16))
        payload = b"flag{smb3_decrypted}"
        client_plain = [
            create_request("docs\\secret.txt", message_id=3),
            read_request(file_id, length=len(payload), message_id=4),
        ]
        server_plain = [
            create_response(file_id, message_id=3),
            read_response(payload, message_id=4),
        ]
        client = [neg_req, ses_req] + [
            transform(c2s_key, "AES-GCM", item) for item in client_plain]
        server = [neg_resp, ses_resp] + [
            transform(s2c_key, "AES-GCM", item) for item in server_plain]

        rows = []
        seq = 0
        for index, payload in enumerate(client):
            rows.append([str(index * 2 + 1), "0", "10.0.0.1", "50000",
                         "10.0.0.2", "445", str(seq),
                         nbss(payload).hex()])
            seq += len(nbss(payload))
        seq = 0
        for index, payload in enumerate(server):
            rows.append([str(index * 2 + 2), "0", "10.0.0.2", "445",
                         "10.0.0.1", "50000", str(seq),
                         nbss(payload).hex()])
            seq += len(nbss(payload))
        return rows

    def test_decrypt_capture_recovers_files_and_flags(self):
        rows = self._build_capture()
        with tempfile.TemporaryDirectory() as tmp:
            result = smb3.decrypt_capture(
                "fake.pcapng", FakeTshark(rows), password=PASSWORD,
                output_dir=tmp)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["decrypted"], 4)
            self.assertEqual(result["flags"], ["flag{smb3_decrypted}"])
            self.assertTrue(result["sessions"])
            session = result["sessions"][0]
            self.assertEqual(session["user"], USER)
            self.assertEqual(session["domain"], DOMAIN)
            self.assertEqual(session["dialect"], "SMB 3.1.1")
            names = {item["name"] for item in result["files"]}
            self.assertIn("smb3_files.txt", names)
            exported = list(Path(tmp).glob("smb3_file_*_secret.txt.bin"))
            self.assertEqual(len(exported), 1)
            self.assertEqual(exported[0].read_bytes(),
                             b"flag{smb3_decrypted}")
            summary = (Path(tmp) / "smb3_files.txt").read_text(encoding="utf-8")
            self.assertIn("secret.txt", summary)

    def test_decrypt_capture_exposes_and_saves_keys(self):
        rows = self._build_capture()
        with tempfile.TemporaryDirectory() as tmp:
            result = smb3.decrypt_capture(
                "fake.pcapng", FakeTshark(rows), password=PASSWORD,
                output_dir=tmp)
            self.assertTrue(result["ok"], result)
            session = result["sessions"][0]
            # SMB 3.1.1: 密文密钥是 KDF 派生的，会话密钥仍是 NTLMv2 base key
            self.assertEqual(session["nt_session_key"], SESSION_KEY.hex())
            self.assertNotEqual(session["session_key"], SESSION_KEY.hex())

            keys = result["keys"]
            self.assertEqual(len(keys), 1, keys)
            record = keys[0]
            self.assertEqual(
                set(record),
                {"stream", "session_id", "cipher", "key_source",
                 "session_key", "cipher_key", "user", "domain", "decrypted"})
            self.assertEqual(record["session_key"], SESSION_KEY.hex())
            self.assertEqual(record["cipher_key"], session["session_key"])
            self.assertEqual(record["cipher"], "AES-GCM")
            self.assertEqual(record["user"], USER)
            self.assertEqual(record["domain"], DOMAIN)
            self.assertEqual(record["stream"], session["stream"])
            self.assertTrue(
                record["key_source"].startswith("ntlmv2+key-exchange"),
                record["key_source"])
            self.assertGreater(record["decrypted"], 0)

            entry = next(item for item in result["files"]
                         if item["name"] == "smb3_keys.txt")
            path = Path(tmp) / "smb3_keys.txt"
            self.assertTrue(path.is_file())
            self.assertEqual(entry["size"], path.stat().st_size)
            self.assertTrue(path.read_text(encoding="utf-8").startswith(
                "# stream\tsession_id\tcipher\tkey_source\tsession_key\t"
                "cipher_key\tuser\tdomain\n"))
            reread = smb3.read_keys_file(path)
            self.assertEqual(len(reread), 1, reread)
            for column in smb3.KEYS_COLUMNS:
                self.assertEqual(reread[0][column], record[column], column)

    def test_read_keys_file_missing_and_garbage(self):
        self.assertEqual(smb3.read_keys_file(
            Path("/nonexistent-job/smb3_keys.txt")), [])
        self.assertEqual(smb3.read_keys_file(None), [])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "smb3_keys.txt"
            path.write_bytes(b"\xff\xfe\x00\x01 not utf-8 at all")
            self.assertEqual(smb3.read_keys_file(path), [])
            path.write_text(
                "# stream\tsession_id\tcipher\tkey_source\tsession_key\t"
                "cipher_key\tuser\tdomain\n"
                "\n"
                "# 注释行\t也跳过\n"
                "这不是表格\n"
                "3\t0x4000\tAES-GCM\t会话密钥:direct\t"
                + SESSION_KEY.hex() + "\t" + SESSION_KEY.hex()
                + "\talice\tCORP\n"
                "7\t0x41\tAES-CCM\n",
                encoding="utf-8")
            rows = smb3.read_keys_file(path)
        self.assertEqual(len(rows), 2, rows)
        self.assertEqual(rows[0]["stream"], "3")
        self.assertEqual(rows[0]["session_key"], SESSION_KEY.hex())
        self.assertEqual(rows[0]["user"], "alice")
        self.assertEqual(rows[0]["domain"], "CORP")
        self.assertEqual(set(rows[0]), set(smb3.KEYS_COLUMNS))
        self.assertEqual(rows[1]["cipher"], "AES-CCM")
        self.assertEqual(rows[1]["session_key"], "")
        self.assertEqual(rows[1]["domain"], "")

    def test_keys_file_text_orders_by_stream(self):
        text = smb3.keys_file_text([
            {"stream": "10", "session_id": "0x2", "cipher": "AES-GCM",
             "key_source": "会话密钥:direct", "session_key": "bb",
             "cipher_key": "cc", "user": "bob", "domain": "LAB"},
            {"stream": "3", "session_id": "0x1", "cipher": "AES-CCM",
             "key_source": "ntlmv2-base:direct", "session_key": "aa",
             "cipher_key": "dd", "user": "alice", "domain": "CORP"},
            "忽略不是字典的行",
        ])
        lines = text.splitlines()
        self.assertEqual(len(lines), 3, lines)
        self.assertTrue(lines[0].startswith("# stream\t"))
        self.assertTrue(lines[1].startswith("3\t0x1\t"))
        self.assertTrue(lines[2].startswith("10\t0x2\t"))
        self.assertEqual(lines[1].split("\t")[6], "alice")

    def test_wrong_password_reports_failure(self):
        rows = self._build_capture()
        with tempfile.TemporaryDirectory() as tmp:
            result = smb3.decrypt_capture(
                "fake.pcapng", FakeTshark(rows), password="wrong",
                output_dir=tmp)
            self.assertFalse(result["ok"])
            self.assertEqual(result["decrypted"], 0)
            self.assertEqual(result["keys"], [])
            self.assertNotIn("smb3_keys.txt",
                             {item["name"] for item in result["files"]})
            self.assertTrue(result["error"])


def _parse(payload: bytes):
    from fnet.utils import smb

    messages = smb.parse_messages(nbss(payload))
    if not messages:
        raise AssertionError("failed to parse synthetic SMB2 message")
    return messages[0]


if __name__ == "__main__":
    unittest.main()
