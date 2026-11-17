"""SMB2/SMB3 wire decoder for the SMB special action.

The tshark SMB2 dissector is excellent, but it needs the default ports and it
does not reassemble ``READ`` payloads back into complete files.  This module
parses the NetBIOS session service framing and the SMB2 header itself, so the
handler can:

* follow ``TREE_CONNECT``/``CREATE``/``READ``/``WRITE`` and rebuild file
  contents (including named pipes);
* report DFS referrals, SMB3 encryption/compression transforms, negotiate
  dialects and per-share encryption requirements;
* extract NTLM identities from ``SESSION_SETUP`` even on non-standard ports.

Only the subset needed for forensics is decoded; unknown commands still surface
their name, status and header fields.  Pure functions, no tshark/I/O.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"
SMB3_TRANSFORM = b"\xfdSMB"
SMB3_COMPRESSED = b"\xfcSMB"
NTLMSSP = b"NTLMSSP\x00"

MAX_MESSAGE = 8 * 1024 * 1024

SMB2_COMMANDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
    4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ",
    9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "KEEPALIVE",
    14: "FIND", 15: "NOTIFY", 16: "GETINFO", 17: "SETINFO", 18: "BREAK",
    19: "SERVER_NOTIFY",
}

#: SMB2 header flags worth naming.
SMB2_FLAGS = {
    0x00000001: "SERVER_TO_REDIR", 0x00000002: "ASYNC_COMMAND",
    0x00000004: "RELATED_OPERATIONS", 0x00000008: "SIGNED",
    0x00000010: "DFS_OPERATIONS", 0x00000020: "REPLAY_OPERATION",
}

#: Common FSCTL codes seen in SMB traffic.
FSCTL_NAMES = {
    0x00060194: "DFS_GET_REFERRALS",
    0x000601B0: "DFS_GET_REFERRALS_EX",
    0x0011C017: "PIPE_TRANSCEIVE",
    0x0011400C: "PIPE_PEEK",
    0x001401FC: "QUERY_NETWORK_INTERFACE_INFO",
    0x00140204: "VALIDATE_NEGOTIATE_INFO",
    0x000900C0: "SRV_COPYCHUNK",
    0x000900A4: "SRV_ENUMERATE_SNAPSHOTS",
}

SHAREFLAG_ENCRYPT_DATA = 0x00000800
GLOBAL_CAP_ENCRYPTION = 0x00000040

DIALECTS = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}

DFS_REFERRAL_RE = re.compile(r"\\\\(?:[A-Za-z0-9._$-]+)\\[A-Za-z0-9._$-]+")


@dataclass
class Smb2Message:
    protocol: str = "SMB2"
    command: int = -1
    command_name: str = ""
    status: int = 0
    flags: int = 0
    message_id: int = 0
    session_id: int = 0
    tree_id: int = 0
    credit: int = 0
    offset: int = 0
    frame: str = ""
    body: bytes = b""

    # TREE_CONNECT
    share: str = ""
    share_type: str = ""
    share_flags: int = 0

    # CREATE
    file_name: str = ""
    file_id: bytes = b""
    file_attributes: int = 0
    create_options: int = 0

    # READ / WRITE
    read_data: bytes = b""
    write_data: bytes = b""
    file_offset: int = 0

    # IOCTL / DFS
    ctl_code: int = 0
    ctl_name: str = ""
    ioctl_input: bytes = b""
    ioctl_output: bytes = b""
    dfs_paths: list[str] = field(default_factory=list)

    # SESSION_SETUP
    security_blob: bytes = b""
    user: str = ""
    domain: str = ""
    workstation: str = ""
    auth_package: str = ""

    # NEGOTIATE
    dialects: list[int] = field(default_factory=list)
    dialect: int = 0
    capabilities: int = 0
    security_mode: int = 0

    # SMB3 transforms
    encrypted: bool = False
    compressed: bool = False
    original_size: int = 0

    @property
    def success(self) -> bool:
        return self.status in (0, 0x00000000)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x1)

    @property
    def flag_names(self) -> list[str]:
        return [name for bit, name in SMB2_FLAGS.items() if self.flags & bit]

    @property
    def is_failure(self) -> bool:
        return self.status not in (0, 0x80000000) and bool(self.status)

    def status_text(self) -> str:
        return f"{self.status:#010x}" if self.status else "0"


def command_name(value: int) -> str:
    return SMB2_COMMANDS.get(int(value), f"CMD_{value}")


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 8], "little")


def _utf16(data: bytes) -> str:
    return data.decode("utf-16le", "replace").rstrip("\x00")


def iter_nbss(data: bytes):
    """Yield ``(smb_payload, offset)`` for each NetBIOS session message."""
    offset = 0
    length = len(data)
    while offset < length:
        if offset + 8 <= length and data[offset] == 0 and \
                data[offset + 4:offset + 8][:1] in (b"\xfe", b"\xff", b"\xfd", b"\xfc"):
            size = int.from_bytes(data[offset + 1:offset + 4], "big")
            if 1 <= size <= MAX_MESSAGE and offset + 4 + size <= length:
                yield data[offset + 4:offset + 4 + size], offset + 4
                offset += 4 + size
                continue
        magic = data[offset:offset + 4]
        if magic in (SMB2_MAGIC, SMB1_MAGIC, SMB3_TRANSFORM, SMB3_COMPRESSED):
            # Direct/TCP capture without the NetBIOS header.
            yield data[offset:], offset
            return
        next_offset = data.find(SMB2_MAGIC, offset + 1)
        if next_offset < 0:
            return
        offset = next_offset


def _ntlm_identity(blob: bytes) -> tuple[str, str, str]:
    if len(blob) < 64 or not blob.startswith(NTLMSSP):
        return "", "", ""
    kind = int.from_bytes(blob[8:12], "little")
    if kind != 3:
        return "", "", ""

    def read(length_at: int, offset_at: int) -> bytes:
        length = _u16(blob, length_at)
        offset = _u32(blob, offset_at)
        if not length or offset + length > len(blob):
            return b""
        return blob[offset:offset + length]

    domain = _utf16(read(28, 32))
    user = _utf16(read(36, 40))
    workstation = _utf16(read(44, 48))
    return user, domain, workstation


def _parse_transform(payload: bytes, offset: int) -> Smb2Message:
    # COMPRESSION/ENCRYPTION transform header: proto(4) signature(16)
    # nonce(16) original_size(4) reserved(2) flags(2) session_id(8).
    original_size = _u32(payload, 36)
    session_id = _u64(payload, 44) if len(payload) >= 52 else 0
    return Smb2Message(protocol="SMB3-Transform", command_name="ENCRYPTED",
                       encrypted=True, original_size=original_size,
                       session_id=session_id, offset=offset)


def _parse_compressed(payload: bytes, offset: int) -> Smb2Message:
    return Smb2Message(protocol="SMB3-Compressed", command_name="COMPRESSED",
                       compressed=True, original_size=_u32(payload, 4),
                       offset=offset)


def parse_packet(payload: bytes, offset: int = 0) -> list[Smb2Message]:
    """Parse one NetBIOS session payload (possibly a compound SMB2 chain)."""
    if payload.startswith(SMB3_TRANSFORM):
        return [_parse_transform(payload, offset)]
    if payload.startswith(SMB3_COMPRESSED):
        return [_parse_compressed(payload, offset)]
    if payload.startswith(SMB1_MAGIC):
        command = payload[4] if len(payload) > 4 else 0
        return [Smb2Message(protocol="SMB1", command=command,
                            command_name=f"SMB1_CMD_{command}",
                            status=_u32(payload, 5), offset=offset)]
    if not payload.startswith(SMB2_MAGIC):
        return []

    messages: list[Smb2Message] = []
    base = 0
    while base + 64 <= len(payload):
        header = payload[base:base + 64]
        next_command = _u32(header, 20)
        body_end = base + next_command if next_command else len(payload)
        if body_end <= base or body_end > len(payload):
            body_end = len(payload)
        message = Smb2Message(
            command=_u16(header, 12),
            status=_u32(header, 8),
            flags=_u32(header, 16),
            message_id=_u64(header, 24),
            session_id=_u64(header, 40),
            tree_id=_u32(header, 36),
            credit=_u16(header, 14),
            offset=offset + base,
            body=payload[base + 64:body_end],
        )
        message.command_name = command_name(message.command)
        _parse_body(message)
        messages.append(message)
        if not next_command:
            break
        base += next_command
    return messages


def _parse_body(message: Smb2Message) -> None:
    body = message.body
    command = message.command
    try:
        if command == 0:  # NEGOTIATE
            if message.is_response:
                message.security_mode = _u16(body, 2)
                message.dialect = _u16(body, 4)
                message.capabilities = _u32(body, 24)
            else:
                count = _u16(body, 2)
                message.dialects = [_u16(body, 36 + index * 2)
                                    for index in range(min(count, 64))]
        elif command == 1:  # SESSION_SETUP
            security_offset = _u16(body, 12)
            security_length = _u16(body, 14)
            if security_offset >= 64 and security_length:
                index = security_offset - 64
                message.security_blob = body[index:index + security_length]
                if message.security_blob.startswith(NTLMSSP):
                    message.auth_package = "NTLMSSP"
                    (message.user, message.domain,
                     message.workstation) = _ntlm_identity(message.security_blob)
                elif b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" in message.security_blob:
                    message.auth_package = "Kerberos"
        elif command == 3:  # TREE_CONNECT
            if message.is_response:
                message.share_type = "pipe" if body[2:4] == b"\x02\x00" else "disk"
                message.share_flags = _u32(body, 4)
            else:
                path_offset = _u16(body, 4)
                path_length = _u16(body, 6)
                if path_offset >= 64 and path_length:
                    index = path_offset - 64
                    message.share = _utf16(body[index:index + path_length])
        elif command == 5:  # CREATE
            if message.is_response:
                message.file_id = body[64:80]
                message.file_attributes = _u32(body, 56)
            else:
                message.file_attributes = _u32(body, 28)
                message.create_options = _u32(body, 40)
                name_offset = _u16(body, 44)
                name_length = _u16(body, 46)
                if name_offset >= 64 and name_length:
                    index = name_offset - 64
                    message.file_name = _utf16(body[index:index + name_length])
        elif command == 8:  # READ
            if message.is_response:
                data_offset = body[2] if len(body) > 2 else 0
                data_length = _u32(body, 4)
                if data_offset >= 64 and data_length:
                    index = data_offset - 64
                    message.read_data = body[index:index + data_length]
            else:
                message.file_offset = _u64(body, 8)
                message.file_id = body[16:32]
        elif command == 9:  # WRITE
            if not message.is_response:
                data_offset = _u16(body, 2)
                length = _u32(body, 4)
                message.file_offset = _u64(body, 8)
                message.file_id = body[16:32]
                if data_offset >= 64 and length:
                    index = data_offset - 64
                    message.write_data = body[index:index + length]
            else:
                message.file_offset = _u64(body, 8)
        elif command == 11:  # IOCTL
            message.ctl_code = _u32(body, 4)
            message.ctl_name = FSCTL_NAMES.get(message.ctl_code, "")
            message.file_id = body[8:24]
            if not message.is_response:
                input_offset = _u32(body, 24)
                input_count = _u32(body, 28)
                if input_offset >= 64 and input_count:
                    index = input_offset - 64
                    message.ioctl_input = body[index:index + input_count]
            else:
                output_offset = _u32(body, 36)
                output_count = _u32(body, 40)
                if output_offset >= 64 and output_count:
                    index = output_offset - 64
                    message.ioctl_output = body[index:index + output_count]
                    if message.ctl_code in (0x00060194, 0x000601B0):
                        message.dfs_paths = _dfs_paths(message.ioctl_output)
    except (IndexError, ValueError):
        pass


def _dfs_paths(data: bytes) -> list[str]:
    """Extract ``\\\\server\\share`` referrals from a DFS IOCTL response."""
    paths: list[str] = []
    if not data:
        return paths
    # Referral v3/v4 uses UTF-16LE offsets; a plain UTF-16LE scan catches the
    # share names without depending on the exact referral layout.
    text = data.decode("utf-16le", "ignore")
    for match in DFS_REFERRAL_RE.finditer(text):
        value = match.group(0)
        if value not in paths:
            paths.append(value)
    if not paths:
        decoded = data.decode("utf-8", "ignore")
        for match in DFS_REFERRAL_RE.finditer(decoded):
            value = match.group(0)
            if value not in paths:
                paths.append(value)
    return paths


def parse_messages(data: bytes) -> list[Smb2Message]:
    """Parse every SMB message in one reassembled TCP direction."""
    messages: list[Smb2Message] = []
    for payload, offset in iter_nbss(data):
        messages.extend(parse_packet(payload, offset))
    return messages


def is_pipe(message: Smb2Message, shares: dict[int, str] | None = None) -> bool:
    """True when the create/read/write refers to a named pipe path."""
    name = message.file_name or message.share
    if name.upper().startswith("IPC$") or "\\PIPE\\" in name.upper():
        return True
    return False


def normalize_pipe(name: str) -> str:
    text = (name or "").strip("\\")
    match = re.search(r"(?i)pipe\\(.+)$", text)
    return match.group(1) if match else text


def file_id_key(message: Smb2Message) -> tuple[int, int, bytes]:
    return (message.session_id, message.tree_id, message.file_id)


def decode_status(status: int) -> str:
    common = {
        0x00000000: "STATUS_SUCCESS",
        0xC0000022: "STATUS_ACCESS_DENIED",
        0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
        0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
        0xC00000CC: "STATUS_BAD_NETWORK_NAME",
        0xC0000120: "STATUS_CANCELLED",
        0xC0000205: "STATUS_INSUFF_SERVER_RESOURCES",
        0xC00000AC: "STATUS_PIPE_NOT_AVAILABLE",
    }
    return common.get(status, f"{status:#010x}")