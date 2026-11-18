"""Unit tests for the SMB2/SMB3 wire decoder (no tshark)."""
from __future__ import annotations

import struct
import unittest

from fnet.utils import smb


def header(command: int, *, status: int = 0, flags: int = 0,
           message_id: int = 1, tree_id: int = 0, session_id: int = 1,
           next_command: int = 0) -> bytes:
    return struct.pack(
        "<4sHHIHHIIQIIQ16s", smb.SMB2_MAGIC, 64, 1, status, command, 1,
        flags, next_command, message_id, 0, tree_id, session_id, b"\x00" * 16)


def nbss(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def tree_connect_request(share: str, message_id: int = 1) -> bytes:
    path = share.encode("utf-16le")
    body = struct.pack("<HHHH", 9, 0, 64 + 8, len(path)) + path
    return header(3, message_id=message_id) + body


def create_request(name: str, message_id: int = 2,
                   options: int = 0) -> bytes:
    raw = name.encode("utf-16le")
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0, 0, 0,
                       0, 0, 64 + 56, len(raw), 0, 0) + raw
    return header(5, message_id=message_id) + body


def create_response(file_id: bytes, message_id: int = 2,
                    attributes: int = 0x20) -> bytes:
    body = struct.pack("<HBBIQQQQQQII16sII", 89, 0, 0, 1,
                       0, 0, 0, 0, 0, 0, attributes, 0,
                       file_id, 0, 0)
    return header(5, flags=0x1, message_id=message_id) + body


def write_request(file_id: bytes, data: bytes, offset: int = 0,
                  message_id: int = 3) -> bytes:
    body = struct.pack("<HHIQ16sIIHHI", 49, 64 + 48, len(data), offset,
                       file_id, 0, 0, 0, 0, 0) + data
    return header(9, message_id=message_id) + body


def read_request(file_id: bytes, offset: int = 0, length: int = 1024,
                 message_id: int = 4) -> bytes:
    body = struct.pack("<HBBIQ16sIIHHI", 49, 0, 0, length, offset, file_id,
                       0, 0, 0, 0, 0)
    return header(8, message_id=message_id) + body


def read_response(data: bytes, message_id: int = 4) -> bytes:
    body = struct.pack("<HBBIII", 17, 64 + 16, 0, len(data), 0, 0) + data
    return header(8, flags=0x1, message_id=message_id) + body


def tree_connect_response(message_id: int = 1, share_flags: int = 0,
                          tree_id: int = 5) -> bytes:
    body = struct.pack("<HBBIII", 16, 1, 0, share_flags, 0, 0x1F01FF)
    return header(3, flags=0x1, message_id=message_id, tree_id=tree_id) + body


def ioctl_response(ctl_code: int, output: bytes, file_id: bytes,
                   message_id: int = 5) -> bytes:
    body = struct.pack("<HH I 16s I I I I I I I I",
                       49, 0, ctl_code, file_id, 0, 0, 0,
                       64 + 56, len(output), 0, 0, 0) + output
    return header(11, flags=0x1, message_id=message_id) + body


class SmbParseTest(unittest.TestCase):
    def test_netbios_framing_with_multiple_messages(self):
        data = nbss(tree_connect_request("\\\\srv\\share"))
        data += nbss(create_request("docs\\flag.txt"))
        messages = smb.parse_messages(data)
        self.assertEqual([m.command_name for m in messages],
                         ["TREE_CONNECT", "CREATE"])
        self.assertEqual(messages[0].share, "\\\\srv\\share")
        self.assertEqual(messages[1].file_name, "docs\\flag.txt")
        self.assertTrue(all(m.offset > 0 for m in messages))

    def test_direct_tcp_without_netbios_header(self):
        payload = create_request("direct.txt")
        messages = smb.parse_messages(payload)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].file_name, "direct.txt")

    def test_read_and_write_payloads(self):
        file_id = b"A" * 16
        messages = smb.parse_messages(
            nbss(write_request(file_id, b"flag{smb_write}", 10)))
        self.assertEqual(messages[0].write_data, b"flag{smb_write}")
        self.assertEqual(messages[0].file_offset, 10)
        self.assertEqual(messages[0].file_id, file_id)

        response = smb.parse_messages(nbss(read_response(b"file body")))[0]
        self.assertEqual(response.read_data, b"file body")
        request = smb.parse_messages(nbss(read_request(file_id, 7)))[0]
        self.assertEqual(request.file_offset, 7)
        self.assertEqual(request.file_id, file_id)

    def test_create_response_file_id(self):
        file_id = bytes(range(16))
        message = smb.parse_messages(nbss(create_response(file_id)))[0]
        self.assertTrue(message.is_response)
        self.assertEqual(message.file_id, file_id)

    def test_compound_messages(self):
        first = tree_connect_response(message_id=1)
        first = first[:20] + struct.pack("<I", len(first)) + first[24:]
        second = read_response(b"compound", message_id=2)
        messages = smb.parse_messages(nbss(first + second))
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[1].read_data, b"compound")

    def test_negotiate_dialects_and_security(self):
        request = header(0, message_id=1) + struct.pack(
            "<HHHHI16sII", 36, 2, 0, 0, 0x40, b"\x00" * 16, 0, 0) + struct.pack(
            "<HH", 0x0311, 0x0302)
        message = smb.parse_messages(nbss(request))[0]
        self.assertEqual(message.dialects, [0x0311, 0x0302])

    def test_session_setup_ntlm_identity(self):
        user = "alice".encode("utf-16le")
        domain = "CORP".encode("utf-16le")
        ws = "KALI".encode("utf-16le")
        blob = bytearray(b"NTLMSSP\x00" + (3).to_bytes(4, "little")
                         + b"\x00" * 52)
        offset = 64
        for (length_at, offset_at), value in zip(
                ((28, 32), (36, 40), (44, 48)), (domain, user, ws)):
            struct.pack_into("<HHI", blob, length_at, len(value), len(value),
                             offset)
            offset += len(value)
        blob = bytes(blob) + domain + user + ws
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24,
                           len(blob), 0) + blob
        message = smb.parse_messages(nbss(header(1, message_id=1) + body))[0]
        self.assertEqual(message.auth_package, "NTLMSSP")
        self.assertEqual(message.user, "alice")
        self.assertEqual(message.domain, "CORP")
        self.assertEqual(message.workstation, "KALI")

    def test_encrypted_transform(self):
        payload = (smb.SMB3_TRANSFORM + b"\x11" * 16 + b"\x22" * 16
                   + (4096).to_bytes(4, "little") + b"\x00\x00"
                   + b"\x01\x00" + (7).to_bytes(8, "little"))
        message = smb.parse_messages(nbss(payload))[0]
        self.assertTrue(message.encrypted)
        self.assertEqual(message.original_size, 4096)
        self.assertEqual(message.session_id, 7)

    def test_transform_header_fields(self):
        payload = (smb.SMB3_TRANSFORM + b"\x11" * 16 + b"\x22" * 16
                   + (4096).to_bytes(4, "little") + b"\x00\x00"
                   + b"\x01\x00" + (7).to_bytes(8, "little") + b"cipher")
        message = smb.parse_messages(nbss(payload))[0]
        self.assertEqual(message.signature, b"\x11" * 16)
        self.assertEqual(message.nonce, b"\x22" * 16)
        self.assertEqual(message.transform_flags, 1)
        self.assertEqual(message.raw, payload)

    def test_ntlm_type3_fields(self):
        nt = b"\xaa" * 16 + b"\xbb" * 32
        blob = bytearray(b"NTLMSSP\x00" + (3).to_bytes(4, "little")
                         + b"\x00" * 52)
        offset = 64
        for (length_at, offset_at), value in zip(
                ((36, 40), (28, 32), (20, 24)),
                (b"a\x00l\x00", b"L\x00", nt)):
            struct.pack_into("<HHI", blob, length_at, len(value), len(value),
                             offset)
            offset += len(value)
        struct.pack_into("<I", blob, 60, 0x00088235)
        message = smb.find_ntlm_type3(bytes(blob) + b"a\x00l\x00L\x00" + nt)
        self.assertEqual(message["user"], "al")
        self.assertEqual(message["domain"], "L")
        self.assertEqual(message["nt"], nt)
        self.assertEqual(message["nt_proof"], nt[:16])
        self.assertEqual(message["flags"], 0x00088235)
        self.assertEqual(smb.find_ntlm_type3(b"nothing"), {})

    def test_compressed_transform(self):
        payload = (smb.SMB3_COMPRESSED + (2048).to_bytes(4, "little")
                   + b"\x01\x00" + b"\x00\x00" + b"\x00" * 8)
        message = smb.parse_messages(nbss(payload))[0]
        self.assertTrue(message.compressed)
        self.assertEqual(message.original_size, 2048)

    def test_dfs_referral_paths(self):
        file_id = b"B" * 16
        text = "\\\\dc01\\share\\dept".encode("utf-16le")
        message = smb.parse_messages(nbss(
            ioctl_response(0x00060194, text, file_id)))[0]
        self.assertEqual(message.ctl_name, "DFS_GET_REFERRALS")
        self.assertIn("\\\\dc01\\share", message.dfs_paths)

    def test_pipe_path_helpers(self):
        self.assertTrue(smb.is_pipe(smb.Smb2Message(
            file_name="\\\\srv\\IPC$\\pipe\\srvsvc")))
        self.assertTrue(smb.is_pipe(smb.Smb2Message(file_name="\\PIPE\\winreg")))
        self.assertFalse(smb.is_pipe(smb.Smb2Message(file_name="docs\\a.txt")))
        self.assertEqual(smb.normalize_pipe("\\\\srv\\IPC$\\pipe\\srvsvc"),
                         "srvsvc")

    def test_garbage_is_ignored(self):
        self.assertEqual(smb.parse_messages(b"\x00\x00\x00\x00garbage"), [])


if __name__ == "__main__":
    unittest.main()