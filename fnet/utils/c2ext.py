"""Sliver C2 / meterpreter staging helpers (pure stdlib, offline).

The Cobalt Strike side lives in :mod:`fnet.features.cs`; this module covers the
other two families from the C2 roadmap entry and is a pure byte parser so it
stays unit-testable without tshark or a capture file:

Sliver (BishopFox/sliver)
    * HTTP(S) beacon: procedural URIs whose **file extension** selects the
      message type (``.html/.jsp`` key exchange, ``.php`` session messages,
      ``.js`` long poll, ``.png`` close, ``.woff`` stager, ``.txt`` RSA key
      exchange) plus the ``_=`` nonce query argument;
    * DNS beacon: messages are protobuf ``DNSMessage`` blobs encoded into
      subdomains with a modified Base32 (``ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz``)
      or the bitcoin Base58 alphabet;
    * session payloads use AES-GCM in legacy <=1.4 builds; v1.5/v1.6 use
      ChaCha20-Poly1305 (see :mod:`fnet.utils.sliver_c2`);
    * mTLS implants use ECDSA certificates with a CN-only subject and a
      clientAuth-only EKU — see :func:`sliver_mtls_cert_profile`.

Meterpreter (metasploit)
    * HTTP(S)/passive-x staging: the initial ``GET`` URI hashes to the
      ``INIT_*`` checksum (92 = Windows/native, ``INITM`` was the classic
      literal), stage responses are a 4-byte big-endian length prefix
      followed by the ``metsrv`` stage; poll requests carry a ``RECV`` body;
    * TCP/wire packets: ``XOR key(4) + [session GUID(16) + encrypt
      flags(4)] + length(4) + type(4)`` — everything after the 4-byte key is
      XOR-obfuscated (see ``Rex::Post::Meterpreter::Packet``); legacy builds
      use a 12-byte header without GUID/flags.  Encrypted packets are
      AES-CBC with a leading IV (flag 1 = AES-256, 2 = AES-128).

Meterpreter wire parsing/decryption is implemented in
:mod:`fnet.utils.meterpreter_wire`; the compatibility functions in this module
delegate to it.  Decryption is only attempted when the matching symmetric
session key is supplied (handler parameter), mirroring the Cobalt Strike
handler's fallback of keeping candidate blobs as artifacts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from fnet.utils import meterpreter_wire
from fnet.utils.crypto import aes_gcm_decrypt

# ---------------------------------------------------------------------------
# Meterpreter staging
# ---------------------------------------------------------------------------
URI_CHECKSUM_INITW = 92   # Windows/native initial stage URI
URI_CHECKSUM_INITX64 = 93  # x64 stager (pre-UUID convention)
INITM_MARKER = "INITM"

STAGE_MIN_SIZE = 1024


def checksum8(text: str) -> int:
    return sum(text.encode("latin-1", "ignore")) & 0xFF


def meterpreter_stage_uri(uri: str) -> dict | None:
    """Classify an HTTP request URI as a meterpreter staging request."""
    path = (uri or "").split("?", 1)[0]
    if INITM_MARKER in path.upper():
        return {"checksum": None, "arch": "x86", "reason": "INITM 标记"}
    for offset in (0, 1):
        target = path[offset:] if offset else path
        if not target:
            continue
        value = checksum8(target)
        if value == URI_CHECKSUM_INITW:
            return {"checksum": value, "arch": "x86", "reason": "URI 校验和 92"}
        if value == URI_CHECKSUM_INITX64:
            return {"checksum": value, "arch": "x64", "reason": "URI 校验和 93"}
    return None


@dataclass
class StageBlob:
    """A downloaded meterpreter stage (``metsrv``) plus its strings."""

    stage: bytes
    length_prefixed: bool
    is_pe: bool
    strings: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.stage)


def parse_stage_blob(body: bytes) -> StageBlob | None:
    """Parse an HTTP stage response body (optionally length-prefixed)."""
    if not body or len(body) < 64:
        return None
    stage = body
    length_prefixed = False
    if len(body) >= 4:
        declared = int.from_bytes(body[:4], "big")
        if 0 < declared == len(body) - 4:
            stage = body[4:]
            length_prefixed = True
    if not length_prefixed and body[:2] != b"MZ" and len(body) > 4:
        declared = int.from_bytes(body[:4], "big")
        # Reverse TCP staging always prefixes the stage length; accept it even
        # when trailing data (e.g. retransmit artifacts) was captured.
        if 0 < declared <= len(body) - 4:
            stage = body[4:4 + declared]
            length_prefixed = True
    strings = [match.group().decode("latin-1")
               for match in re.finditer(rb"[\x20-\x7e]{6,}", stage)]
    return StageBlob(stage=stage, length_prefixed=length_prefixed,
                     is_pe=stage[:2] == b"MZ", strings=strings)


# ---------------------------------------------------------------------------
# Meterpreter XOR / encrypted packet layer
# ---------------------------------------------------------------------------
XOR_KEY_SIZE = 4
GUID_SIZE = 16
MODERN_HEADER_SIZE = XOR_KEY_SIZE + GUID_SIZE + 4 + 4 + 4  # 32
LEGACY_HEADER_SIZE = XOR_KEY_SIZE + 4 + 4  # 12

ENC_FLAG_NONE = 0x0
ENC_FLAG_AES256 = 0x1
ENC_FLAG_AES128 = 0x2

#: Packet type word (first TLV of every packet carries the packet type).
PACKET_TYPES = {0: "request", 1: "response", 2: "config",
                10: "plain_request", 11: "plain_response"}

MAX_PACKET_LENGTH = 16 * 1024 * 1024

# Nested TLV ids (Rex::Post::Meterpreter); ids kept in sync with
# fnet/utils/meterpreter.py so both modules print the same vocabulary.
TLV_META_STRING = 1 << 16
TLV_META_UINT = 1 << 17
TLV_META_RAW = 1 << 18
TLV_META_BOOL = 1 << 19
TLV_META_QWORD = 1 << 20
TLV_META_GROUP = 1 << 31
TLV_NAMES = {
    (TLV_META_UINT, 1): "COMMAND_ID",
    (TLV_META_STRING, 2): "REQUEST_ID",
    (TLV_META_GROUP, 3): "EXCEPTION",
    (TLV_META_UINT, 4): "RESULT",
    (TLV_META_STRING, 10): "STRING",
    (TLV_META_UINT, 11): "UINT",
    (TLV_META_BOOL, 12): "BOOL",
    (TLV_META_STRING, 51): "CHANNEL_TYPE",
    (TLV_META_STRING, 460): "MACHINE_ID",
    (TLV_META_RAW, 461): "UUID",
    (TLV_META_RAW, 462): "SESSION_GUID",
    (TLV_META_RAW, 552): "SYM_KEY",
    (TLV_META_RAW, 553): "ENC_SYM_KEY",
}


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(value ^ key[index % len(key)]
                 for index, value in enumerate(data))


def _tlv_name(tlv_type: int) -> str:
    return TLV_NAMES.get((tlv_type & 0xFFFF0000, tlv_type & 0xFFFF),
                         f"0x{tlv_type & 0xFFFFFFFF:08x}")


def _decode_tlv_value(tlv_type: int, value: bytes) -> str:
    if tlv_type & TLV_META_STRING:
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    if tlv_type & TLV_META_UINT:
        return str(int.from_bytes(value[:4], "big")) if value else ""
    if tlv_type & TLV_META_QWORD:
        return str(int.from_bytes(value[:8], "big")) if value else ""
    if tlv_type & TLV_META_BOOL:
        return "true" if value[:1] not in (b"", b"\x00") else "false"
    return value[:64].hex() if value else ""


def _walk_tlvs(data: bytes, start: int) -> list[dict]:
    """Sequential TLV walk (big endian ``NN`` headers, length self-inclusive)."""
    tlvs: list[dict] = []
    offset = start
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        if not 8 <= length <= MAX_PACKET_LENGTH or offset + length > len(data):
            break
        tlv_type = int.from_bytes(data[offset + 4:offset + 8], "big")
        value = data[offset + 8:offset + length]
        tlvs.append({
            "name": _tlv_name(tlv_type),
            "type": tlv_type,
            "value": _decode_tlv_value(tlv_type, value),
            "raw": value,
        })
        offset += length
    return tlvs


@dataclass
class MPacket:
    """One meterpreter wire packet with decoded header and TLV summary."""

    version: str          # "modern" (32B header) or "legacy" (12B header)
    offset: int
    total: int
    xor_key: bytes
    session_guid: bytes
    encrypt_flags: int
    length: int
    packet_type: int
    encrypted: bool
    plaintext: bytes      # nested TLV stream (after decryption when possible)
    tlvs: list[dict] = field(default_factory=list)
    command_id: int | None = None

    @property
    def kind(self) -> str:
        return PACKET_TYPES.get(self.packet_type, "unknown")

    @property
    def command_hex(self) -> str:
        return "-" if self.command_id is None else f"0x{self.command_id:08x}"


def _header_valid(length: int, packet_type: int, flags: int, total: int,
                  available: int, version: str) -> bool:
    if not 8 <= length <= MAX_PACKET_LENGTH or total > available:
        return False
    if version == "modern" and flags not in (
            ENC_FLAG_NONE, ENC_FLAG_AES256, ENC_FLAG_AES128):
        return False
    return packet_type in PACKET_TYPES


def _decode_at(data: bytes, offset: int) -> MPacket | None:
    available = len(data) - offset
    if available >= MODERN_HEADER_SIZE:
        xor_key = data[offset:offset + XOR_KEY_SIZE]
        head = _xor_bytes(data[offset:offset + MODERN_HEADER_SIZE], xor_key)
        length = int.from_bytes(head[24:28], "big")
        packet_type = int.from_bytes(head[28:32], "big")
        flags = int.from_bytes(head[20:24], "big")
        total = length + MODERN_HEADER_SIZE - 8
        if _header_valid(length, packet_type, flags, total, available,
                         "modern"):
            # The 32-byte header already carries length/type; what follows
            # is the nested TLV stream directly (encrypted: IV + ciphertext).
            body = _xor_bytes(data[offset + MODERN_HEADER_SIZE:offset + total],
                              xor_key)
            encrypted = flags != ENC_FLAG_NONE
            plaintext = b"" if encrypted else body
            return MPacket(version="modern", offset=offset, total=total,
                           xor_key=xor_key,
                           session_guid=head[4:20], encrypt_flags=flags,
                           length=length, packet_type=packet_type,
                           encrypted=encrypted, plaintext=plaintext)
    if available >= LEGACY_HEADER_SIZE:
        xor_key = data[offset:offset + XOR_KEY_SIZE]
        head = _xor_bytes(data[offset:offset + LEGACY_HEADER_SIZE], xor_key)
        length = int.from_bytes(head[4:8], "big")
        packet_type = int.from_bytes(head[8:12], "big")
        total = length + XOR_KEY_SIZE
        if _header_valid(length, packet_type, 0, total, available, "legacy"):
            body = _xor_bytes(data[offset + LEGACY_HEADER_SIZE:offset + total],
                              xor_key)
            return MPacket(version="legacy", offset=offset, total=total,
                           xor_key=xor_key, session_guid=b"",
                           encrypt_flags=ENC_FLAG_NONE, length=length,
                           packet_type=packet_type, encrypted=False,
                           plaintext=body)
    return None


def iter_packets(data: bytes, key: bytes | None = None,
                 scan_limit: int = 4096) -> list:
    """兼容入口：解析结果由 :mod:`fnet.utils.meterpreter_wire` 提供。

    新代码应使用 ``meterpreter_wire.iter_packets``；这里保留旧模块的函数名，
    避免历史调用方和单元测试继续依赖本文件中过时的重复解析器。
    """
    return meterpreter_wire.iter_packets(data, key=key, scan_limit=scan_limit)


def decrypt_packet_body(data: bytes, packet: MPacket,
                        key: bytes) -> bytes | None:
    """兼容入口：AES-CBC 解密单个报文体，失败返回 ``None``。"""
    return meterpreter_wire.decrypt_packet_body(data, packet, key)


def looks_like_xor_meterpreter(data: bytes) -> bool:
    """协议识别回调：由严格的新解析器判断是否存在合法 meterpreter 报文。"""
    return meterpreter_wire.looks_like_xor_meterpreter(data)


# ---------------------------------------------------------------------------
# Sliver HTTP(S) beacon
# ---------------------------------------------------------------------------
SLIVER_HTTP_EXTS = {
    ".txt": "RSA 公钥交换（旧版）",
    ".jsp": "会话初始化（旧版）",
    ".html": "会话初始化/密钥交换",
    ".css": "会话初始化",
    ".php": "会话消息（AES-GCM）",
    ".js": "长轮询拉取任务",
    ".png": "关闭会话",
    ".woff": "stager/shellcode 分发",
}

#: Default procedural path/file words from the stock http-c2.json profile.
SLIVER_URI_WORDS = {
    "bootstrap", "bootstrap.min", "jquery.min", "jquery", "route", "app",
    "app.min", "array", "backbone", "script", "email", "login", "signin",
    "api", "samples", "rpc", "index", "admin", "logout", "users", "profile",
    "register", "javascripts", "javascript", "jscript", "js", "umd",
    "assets", "bundle", "bundles", "scripts",
}

SLIVER_NONCE_ARGS = {"_", "nonce"}


def classify_sliver_uri(uri: str) -> dict | None:
    """Score an HTTP URI against the Sliver procedural C2 conventions."""
    path = (uri or "").split("?", 1)[0]
    query = (uri or "").split("?", 1)[1] if "?" in (uri or "") else ""
    lowered = path.lower()
    ext = next((name for name in SLIVER_HTTP_EXTS if lowered.endswith(name)),
               None)
    if ext is None:
        return None
    segments = [seg for seg in lowered.split("/") if seg]
    word_hits = sorted({word for seg in segments
                        for word in SLIVER_URI_WORDS
                        if seg == word or (len(seg) > len(word)
                                           and seg.startswith(word))})
    pairs = [pair for pair in query.split("&") if "=" in pair]
    names = {pair.split("=", 1)[0] for pair in pairs}
    nonce = bool(names & SLIVER_NONCE_ARGS)
    score = len(word_hits) + (1 if nonce else 0)
    # Stager / key-exchange extensions are Sliver-specific on their own.
    if ext in (".woff", ".txt", ".jsp", ".html"):
        score += 1
    return {"ext": ext, "message": SLIVER_HTTP_EXTS[ext], "nonce": nonce,
            "word_hits": word_hits, "query_args": len(pairs), "score": score}


def sliver_aesgcm_decrypt(blob: bytes, key: bytes) -> bytes | None:
    """Decrypt a Sliver session payload (nonce = first 12 bytes, AES-GCM)."""
    if len(blob) < 12 + 16 or len(key) not in (16, 32):
        return None
    plain, tag_ok = aes_gcm_decrypt(blob[12:], key, blob[:12])
    if not tag_ok or not plain:
        return None
    return plain


# ---------------------------------------------------------------------------
# Sliver DNS beacon
# ---------------------------------------------------------------------------
SLIVER_BASE32 = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz"
SLIVER_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

DNS_MESSAGE_TYPES = {
    0: "NOP/FINGERPRINT", 1: "TOTP", 2: "INIT", 3: "POLL", 4: "CLOSE",
    6: "MANIFEST", 7: "DATA_TO_IMPLANT", 8: "DATA_FROM_IMPLANT", 9: "CLEAR",
}


def sliver_base32_decode(text: str) -> bytes | None:
    alphabet = SLIVER_BASE32
    index = {char: position for position, char in enumerate(alphabet)}
    bits = 0
    acc = 0
    out = bytearray()
    for char in text.lower():
        value = index.get(char)
        if value is None:
            return None
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out) if out else None


def sliver_base58_decode(text: str) -> bytes | None:
    index = {char: position for position, char in enumerate(SLIVER_BASE58)}
    if not text:
        return None
    value = 0
    for char in text:
        digit = index.get(char)
        if digit is None:
            return None
        value = value * 58 + digit
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    zeros = 0
    for char in text:
        if char == SLIVER_BASE58[0]:
            zeros += 1
        else:
            break
    return b"\x00" * zeros + raw


def sliver_base32_encode(data: bytes) -> str:
    alphabet = SLIVER_BASE32
    acc = 0
    bits = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(alphabet[(acc >> bits) & 0x1F])
    if bits:
        out.append(alphabet[(acc << (5 - bits)) & 0x1F])
    return "".join(out)


def sliver_base58_encode(data: bytes) -> str:
    value = int.from_bytes(data, "big") if data else 0
    out = []
    while value > 0:
        value, digit = divmod(value, 58)
        out.append(SLIVER_BASE58[digit])
    zeros = 0
    for byte in data:
        if byte:
            break
        zeros += 1
    if zeros:
        out.extend(SLIVER_BASE58[0] * zeros)
    return "".join(reversed(out))


def _varint(data: bytes, pos: int) -> tuple[int, int] | None:
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 42:
            return None
    return None


def parse_protobuf_fields(data: bytes) -> list[dict] | None:
    """Generic protobuf field walk (``(field, wire, value)`` records)."""
    fields = []
    pos = 0
    while pos < len(data):
        head = _varint(data, pos)
        if head is None:
            return None
        key, pos = head
        field_no, wire = key >> 3, key & 7
        if field_no == 0:
            return None
        if wire == 0:
            value = _varint(data, pos)
            if value is None:
                return None
            pos = value[1]
            fields.append({"field": field_no, "wire": wire,
                           "varint": value[0], "bytes": b""})
        elif wire == 2:
            length = _varint(data, pos)
            if length is None or length[1] + length[0] > len(data):
                return None
            start = length[1]
            fields.append({"field": field_no, "wire": wire,
                           "varint": 0, "bytes": data[start:start + length[0]]})
            pos = start + length[0]
        else:
            return None  # fixed64/fixed32/SGROUP/EGROUP unused by DNSMessage
    return fields


def parse_dns_message(data: bytes) -> dict | None:
    """Parse a ``dnspb.DNSMessage`` (Type=1 ID=2 Start=3 Stop=4 Size=5 Data=6)."""
    fields = parse_protobuf_fields(data)
    if not fields:
        return None
    message: dict = {"type": None, "id": None, "start": None, "stop": None,
                     "size": None, "data": b""}
    seen_type = False
    for item in fields:
        if item["field"] == 1 and item["wire"] == 0:
            if item["varint"] > 9:
                return None
            message["type"] = item["varint"]
            seen_type = True
        elif item["field"] == 2 and item["wire"] == 0:
            message["id"] = item["varint"]
        elif item["field"] in (3, 4, 5) and item["wire"] == 0:
            message[{3: "start", 4: "stop", 5: "size"}[item["field"]]] = \
                item["varint"]
        elif item["field"] == 6 and item["wire"] == 2:
            message["data"] = item["bytes"]
    if not seen_type or message["type"] is None:
        return None
    if message["type"] not in DNS_MESSAGE_TYPES:
        return None
    return message


def decode_sliver_dns_subdomain(qname: str,
                                parents: tuple[str, ...] = ()) -> dict | None:
    """Decode a Sliver DNS C2 query name (Base32 first, then Base58).

    Base58 is case sensitive so the original query case is preserved; the
    Base32 decoder lowercases on its own (DNS treats a/A equally and Sliver
    re-cases its labels freely).
    """
    name = (qname or "").rstrip(".").strip()
    if not name:
        return None
    labels = name.split(".")
    parent_labels = 0
    if parents:
        parents = tuple(p.rstrip(".").lower() for p in parents if p)
        lowered = [label.lower() for label in labels]
        for parent in parents:
            count = len(parent.split("."))
            if len(labels) > count and \
                    ".".join(lowered[-count:]) == parent:
                parent_labels = count
                break
    for keep in range(len(labels) - max(parent_labels, 1),
                      max(len(labels) - max(parent_labels, 1) - 3, 0) - 1, -1):
        if keep <= 0:
            break
        subdata = "".join(labels[:keep])
        if len(subdata) < 12:
            continue
        for encoding, decoder in (("base32", sliver_base32_decode),
                                  ("base58", sliver_base58_decode)):
            raw = decoder(subdata)
            if not raw:
                continue
            message = parse_dns_message(raw)
            if message is not None:
                return {"subdata": subdata, "encoding": encoding,
                        "raw": raw, "message": message}
    return None


# ---------------------------------------------------------------------------
# Sliver mTLS certificate heuristics
# ---------------------------------------------------------------------------
OID_COMMON_NAME = b"\x55\x04\x03"
OID_ORG_NAME = b"\x55\x04\x0a"
OID_ORG_UNIT = b"\x55\x04\x0b"
OID_EKU_CLIENT = b"\x2b\x06\x01\x05\x05\x07\x03\x02"    # 1.3.6.1.5.5.7.3.2
OID_EKU_SERVER = b"\x2b\x06\x01\x05\x05\x07\x03\x01"    # 1.3.6.1.5.5.7.3.1
OID_SIG_RSA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01"        # 1.2.840.113549.1.1
OID_SIG_ECDSA = b"\x2a\x86\x48\xce\x3d\x04\x03"          # 1.2.840.10045.4.3


@dataclass
class CertProfile:
    common_name: str = ""
    organization: str = ""
    org_unit: str = ""
    eku_client: bool = False
    eku_server: bool = False
    ecdsa_signature: bool = False
    validity_days: int | None = None
    score: int = 0
    reasons: list[str] = field(default_factory=list)


def _der_children(data: bytes) -> list[bytes]:
    """Children of a DER SEQUENCE/SET (top level only)."""
    out = []
    pos = 0
    while pos + 2 <= len(data):
        first = data[pos]
        pos += 1
        first_len = data[pos]
        pos += 1
        if first_len & 0x80:
            count = first_len & 0x7F
            if count == 0 or pos + count > len(data):
                break
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        else:
            length = first_len
        if pos + length > len(data):
            break
        out.append(data[pos:pos + length])
        pos += length
    return out


def _decode_der_string(value: bytes) -> str:
    if not value:
        return ""
    tag = value[0]
    if tag not in (0x0C, 0x13, 0x14, 0x16, 0x1A):
        return ""
    pos = 1
    length = value[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(value[pos:pos + count], "big")
        pos += count
    return value[pos:pos + length].decode("latin-1", "replace")


def _rdn_common_names(name_seq: bytes) -> tuple[str, str, str]:
    """Return (CN, O, OU) found in one RDNSequence."""
    cn = org = ou = ""
    for rdn in _der_children(name_seq):
        for atv in _der_children(rdn):
            children = _der_children(atv)
            if len(children) != 2:
                continue
            oid, value = children
            if OID_COMMON_NAME in oid:
                cn = _decode_der_string(value)
            elif OID_ORG_NAME in oid:
                org = _decode_der_string(value)
            elif OID_ORG_UNIT in oid:
                ou = _decode_der_string(value)
    return cn, org, ou


def _parse_time(value: str) -> int | None:
    import calendar
    import datetime
    value = value.strip()
    for pattern in ("%y%m%d%H%M%SZ", "%Y%m%d%H%M%SZ"):
        try:
            return calendar.timegm(
                datetime.datetime.strptime(value, pattern).timetuple())
        except ValueError:
            continue
    return None


def sliver_mtls_cert_profile(der: bytes) -> CertProfile:
    """Minimal X.509 walk scoring a certificate for Sliver mTLS traits."""
    profile = CertProfile()
    try:
        top = _der_children(der)
        if not top:
            return profile
        tbs = _der_children(top[0])
        if not tbs:
            return profile
    except Exception:  # noqa: BLE001 - malformed DER must never raise
        return profile
    for item in tbs:
        if item[:1] not in (b"\x30", b"\xa0"):
            continue
        cn, org, ou = _rdn_common_names(item)
        if cn and not profile.common_name:
            profile.common_name = cn
        if org and not profile.organization:
            profile.organization = org
        if ou and not profile.org_unit:
            profile.org_unit = ou
    blob = der
    profile.eku_client = OID_EKU_CLIENT in blob
    profile.eku_server = OID_EKU_SERVER in blob
    profile.ecdsa_signature = OID_SIG_ECDSA in blob and OID_SIG_RSA not in blob[:256]
    # validity: the UTCTime/GeneralizedTime pair inside tbsCertificate
    times = [match.group().decode("latin-1") for match in
             re.finditer(rb"(?:\d{12}|\d{14})Z", tbs[0] if tbs else der)]
    if len(times) >= 2:
        start, end = _parse_time(times[0]), _parse_time(times[1])
        if start and end and end > start:
            profile.validity_days = (end - start) // 86400
    # Scoring: ECDSA + clientAuth-only + CN-only subject + 2-3y validity.
    if profile.ecdsa_signature:
        profile.score += 2
        profile.reasons.append("ECDSA 签名算法")
    if profile.eku_client and not profile.eku_server:
        profile.score += 2
        profile.reasons.append("仅 clientAuth 扩展用途")
    if profile.common_name and not (profile.organization or profile.org_unit):
        profile.score += 1
        profile.reasons.append("主体仅含 CN")
    if profile.validity_days and 700 <= profile.validity_days <= 1200:
        profile.score += 1
        profile.reasons.append(f"有效期 {profile.validity_days} 天")
    return profile


def looks_like_sliver_mtls_cert(der: bytes) -> CertProfile | None:
    profile = sliver_mtls_cert_profile(der)
    return profile if profile.score >= 4 else None
