"""SSH (Secure Shell 2) parsing over a reassembled TCP stream.

Wireshark dissects SSH only down to the record layer — everything after the
first ``NEWKEYS`` is encrypted anyway, so the interesting forensics surface
lives *before* keying: the version exchange, the ``KEXINIT`` algorithm
negotiation and the ``userauth`` layer when passwords are sent in the clear
(possible with legacy servers or deliberately in CTF captures).

This module parses the parts of RFC 4251/4252/4253 that matter for incident
work:

* version exchange banners (``SSH-2.0-OpenSSH_9.6``);
* ``SSH_MSG_KEXINIT`` name lists (kex, host key, cipher, MAC, compression);
* ``SSH_MSG_USERAUTH_REQUEST`` — username, service and method, including
  cleartext ``password`` and ``publickey`` blobs;
* ``SSH_MSG_USERAUTH_FAILURE`` / ``SUCCESS`` so failed attempts and brute
  force timelines can be reconstructed per user;
* encryption detection (parsing stops at ``NEWKEYS`` / unparseable framing).

Everything is pure stdlib, tolerant of truncation, and unit testable without
tshark or a capture file.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

#: Well-known SSH message types (RFC 4250).
MSG_NAMES = {
    1: "DISCONNECT",
    2: "IGNORE",
    3: "UNIMPLEMENTED",
    4: "DEBUG",
    5: "SERVICE_REQUEST",
    6: "SERVICE_ACCEPT",
    20: "KEXINIT",
    21: "NEWKEYS",
    50: "USERAUTH_REQUEST",
    51: "USERAUTH_FAILURE",
    52: "USERAUTH_SUCCESS",
    53: "USERAUTH_BANNER",
    80: "GLOBAL_REQUEST",
    81: "REQUEST_SUCCESS",
    82: "REQUEST_FAILURE",
    90: "CHANNEL_OPEN",
    94: "CHANNEL_DATA",
}

#: Cap so a corrupt stream cannot make us loop forever.
MAX_MESSAGES = 20_000
MAX_PACKET = 4 * 1024 * 1024


class SshError(ValueError):
    """Raised when SSH framing cannot be decoded."""


@dataclass
class SshMessage:
    """One parsed SSH element (banner or binary packet)."""

    kind: str                 # banner | packet | encrypted
    name: str = ""
    msg_type: int = -1
    offset: int = 0
    frame: str = ""
    fields: dict = field(default_factory=dict)
    raw: bytes = b""
    encrypted: bool = False

    @property
    def type_name(self) -> str:
        return self.name or MSG_NAMES.get(self.msg_type,
                                          f"MSG_{self.msg_type}")


def _string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise SshError("truncated string header")
    length = struct.unpack_from(">I", data, offset)[0]
    if length > MAX_PACKET or offset + 4 + length > len(data):
        raise SshError("truncated string value")
    return data[offset + 4:offset + 4 + length], offset + 4 + length


def _name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    raw, offset = _string(data, offset)
    text = raw.decode("utf-8", "replace")
    return [name for name in text.split(",") if name], offset


def parse_banner(data: bytes, offset: int = 0) -> tuple[dict, int] | None:
    """Parse one ``SSH-x.y-...`` version exchange at ``offset``.

    Returns ``(fields, end)`` or ``None`` when no banner starts here.
    """
    index = data.find(b"SSH-", offset)
    if index < 0:
        return None
    end = data.find(b"\n", index)
    if end < 0:
        # Banner possibly split across segments: wait for more bytes.
        return None
    line = data[index:end].rstrip(b"\r").decode("utf-8", "replace")
    fields: dict = {"banner": line}
    # ``SSH-<version>-<software>[ <comment>]``
    body = line[4:]
    head, _, comment = body.partition(" ")
    proto, _, software = head.partition("-")
    fields["protocol"] = proto if proto else head
    fields["software"] = software
    fields["comment"] = comment
    return fields, end + 1


def parse_kexinit(payload: bytes) -> dict:
    """Parse the payload of ``SSH_MSG_KEXINIT`` (after the type byte)."""
    result: dict = {}
    offset = 16  # cookie
    keys = ("kex_algorithms", "server_host_key_algorithms",
            "encryption_algorithms_client_to_server",
            "encryption_algorithms_server_to_client",
            "mac_algorithms_client_to_server",
            "mac_algorithms_server_to_client",
            "compression_algorithms_client_to_server",
            "compression_algorithms_server_to_client",
            "languages_client_to_server", "languages_server_to_client")
    for key in keys:
        try:
            names, offset = _name_list(payload, offset)
        except SshError:
            return result
        result[key] = names
    if offset < len(payload):
        result["first_kex_packet_follows"] = bool(payload[offset])
    return result


def parse_userauth_request(payload: bytes) -> dict:
    """Parse ``SSH_MSG_USERAUTH_REQUEST`` payload (after the type byte)."""
    fields: dict = {}
    offset = 0
    try:
        user_raw, offset = _string(payload, offset)
        service_raw, offset = _string(payload, offset)
        method_raw, offset = _string(payload, offset)
        fields["user"] = user_raw.decode("utf-8", "replace")
        fields["service"] = service_raw.decode("utf-8", "replace")
        method = method_raw.decode("utf-8", "replace")
        fields["method"] = method
        if method == "password":
            if offset < len(payload):
                offset += 1  # boolean FALSE
            password, offset = _string(payload, offset)
            fields["password"] = password.decode("utf-8", "replace")
        elif method == "publickey":
            if offset < len(payload):
                fields["has_signature"] = bool(payload[offset])
                offset += 1
            algo, offset = _string(payload, offset)
            fields["algorithm"] = algo.decode("utf-8", "replace")
            blob, offset = _string(payload, offset)
            fields["key_blob"] = blob.hex()
        elif method == "hostbased":
            algo, offset = _string(payload, offset)
            fields["algorithm"] = algo.decode("utf-8", "replace")
    except SshError:
        fields["truncated"] = True
    return fields


def parse_stream(data: bytes, frame_lookup=None) -> list[SshMessage]:
    """Parse a reassembled SSH direction into banners and binary packets.

    Parsing stops at ``NEWKEYS`` or at the first unparseable packet: from
    that point on the stream is encrypted and only sizes leak.
    """
    messages: list[SshMessage] = []
    size = len(data or b"")
    offset = 0
    # Version exchange: one or two banners (client and server live in their
    # own direction), possibly preceded by comment lines.
    while True:
        banner = parse_banner(data, offset)
        if banner is None:
            break
        fields, end = banner
        messages.append(SshMessage(
            kind="banner", name="VERSION", offset=offset,
            frame=frame_lookup(offset) if frame_lookup else "",
            fields=fields, raw=data[offset:end]))
        offset = end
    encrypted = False
    while offset + 5 <= size and len(messages) < MAX_MESSAGES:
        (packet_len,) = struct.unpack_from(">I", data, offset)
        if packet_len < 4 or packet_len > MAX_PACKET or \
                offset + 4 + packet_len > size:
            # Not valid framing: either garbage or the start of encryption.
            encrypted = True
            break
        padding_len = data[offset + 4]
        payload_len = packet_len - 1 - padding_len
        if payload_len < 0 or offset + 4 + packet_len > size:
            encrypted = True
            break
        payload = data[offset + 5:offset + 5 + payload_len]
        msg_type = payload[0] if payload else -1
        frame = frame_lookup(offset) if frame_lookup else ""
        if msg_type == 20:  # KEXINIT
            fields = parse_kexinit(payload[1:])
            messages.append(SshMessage(
                kind="packet", name="KEXINIT", msg_type=20, offset=offset,
                frame=frame, fields=fields,
                raw=data[offset:offset + 4 + packet_len]))
        elif msg_type == 50:  # USERAUTH_REQUEST
            fields = parse_userauth_request(payload[1:])
            messages.append(SshMessage(
                kind="packet", name="USERAUTH_REQUEST", msg_type=50,
                offset=offset, frame=frame, fields=fields,
                raw=data[offset:offset + 4 + packet_len]))
        elif msg_type == 51:  # USERAUTH_FAILURE
            body = payload[1:]
            fields = {}
            try:
                names, pos = _name_list(body, 0)
                fields["methods"] = names
                if pos < len(body):
                    fields["partial_success"] = bool(body[pos])
            except SshError:
                fields["truncated"] = True
            messages.append(SshMessage(
                kind="packet", name="USERAUTH_FAILURE", msg_type=51,
                offset=offset, frame=frame, fields=fields,
                raw=data[offset:offset + 4 + packet_len]))
        elif msg_type == 53:  # USERAUTH_BANNER
            try:
                text, _ = _string(payload[1:], 0)
                fields = {"banner": text.decode("utf-8", "replace")}
            except SshError:
                fields = {"truncated": True}
            messages.append(SshMessage(
                kind="packet", name="USERAUTH_BANNER", msg_type=53,
                offset=offset, frame=frame, fields=fields,
                raw=data[offset:offset + 4 + packet_len]))
        else:
            messages.append(SshMessage(
                kind="packet", name=MSG_NAMES.get(msg_type, ""),
                msg_type=msg_type, offset=offset, frame=frame,
                fields={}, raw=data[offset:offset + 4 + packet_len]))
        if msg_type == 21:  # NEWKEYS: everything after this is encrypted
            encrypted = True
        offset += 4 + packet_len
    if encrypted and offset < size:
        messages.append(SshMessage(
            kind="encrypted", name="ENCRYPTED", offset=offset,
            frame=frame_lookup(offset) if frame_lookup else "",
            fields={"remaining": size - offset}, encrypted=True,
            raw=data[offset:]))
    return messages


def looks_like_ssh(data: bytes) -> bool:
    """True when the buffer starts with an SSH version exchange."""
    head = bytes(data or b"")[:256]
    if not head:
        return False
    if head.startswith(b"SSH-"):
        return parse_banner(head) is not None
    return False


def auth_events(messages: list[SshMessage]) -> list[dict]:
    """Reconstruct the userauth timeline of one direction.

    ``USERAUTH_FAILURE`` carries no username, so failures are attributed to
    the most recent ``USERAUTH_REQUEST`` seen in the same direction.
    """
    events: list[dict] = []
    last_user = ""
    for message in messages:
        if message.kind != "packet":
            continue
        if message.msg_type == 50:
            last_user = message.fields.get("user", "")
            events.append({
                "kind": "request",
                "frame": message.frame,
                "user": last_user,
                "method": message.fields.get("method", ""),
                "password": message.fields.get("password", ""),
                "algorithm": message.fields.get("algorithm", ""),
            })
        elif message.msg_type == 51:
            events.append({
                "kind": "failure",
                "frame": message.frame,
                "user": last_user,
                "methods": message.fields.get("methods", []),
                "partial": message.fields.get("partial_success", False),
            })
        elif message.msg_type == 52:
            events.append({
                "kind": "success",
                "frame": message.frame,
                "user": last_user,
            })
    return events


def failure_counts(events: list[dict]) -> dict[str, int]:
    """Failures per username (unknown users grouped under ``""``)."""
    counts: dict[str, int] = {}
    for event in events:
        if event.get("kind") == "failure":
            user = event.get("user") or ""
            counts[user] = counts.get(user, 0) + 1
    return counts
