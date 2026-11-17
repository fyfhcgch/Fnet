"""Port-independent protocol detection from the first TCP payload bytes.

Wireshark only dissects Redis/MongoDB/PostgreSQL/LDAP on their well-known
ports unless a "Decode As" rule is supplied.  CTF captures and real incident
traffic frequently move these services to non-standard ports, so the feature
handlers use the small signature checks in this module to find candidate
streams and then pass ``-d tcp.port==...,<dissector>`` to tshark.

The functions are deliberately conservative: a payload must match the wire
format of the protocol (RESP arrays, MongoDB message headers, PostgreSQL
startup packets, LDAP BER) before a stream is treated as that protocol.  They
are pure functions, which keeps them easy to unit test without tshark.
"""
from __future__ import annotations

import re
from typing import Iterable

#: Default server ports used by the handlers.  A detection on any other port
#: is reported as "non-default port" by the feature handlers.
DEFAULT_PORTS: dict[str, tuple[int, ...]] = {
    "redis": (6379, 6380),
    "mongodb": (27017, 27018, 27019),
    "postgres": (5432, 5433),
    "ldap": (389, 636, 3268, 3269),
    "smb2": (445, 139),
    "http2": (443, 80, 8080, 8443),
}

#: tshark ``-d tcp.port==<port>,<name>`` dissector names.
DECODE_AS: dict[str, str] = {
    "mongodb": "mongo",
    "postgres": "pgsql",
    "ldap": "ldap",
    "smb2": "smb2",
}

REDIS_COMMANDS = frozenset({
    "AUTH", "HELLO", "SELECT", "GET", "SET", "SETEX", "PSETEX", "MSET",
    "MGET", "DEL", "EXISTS", "HGET", "HSET", "HGETALL", "LPUSH", "RPUSH",
    "LRANGE", "SADD", "SMEMBERS", "CONFIG", "INFO", "KEYS", "SCAN", "EVAL",
    "FLUSHALL", "FLUSHDB", "CLIENT", "ACL", "MONITOR", "SUBSCRIBE", "PING",
    "PUBLISH", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "COMMAND",
})

MONGO_OPCODES = frozenset({1, 1000, 2001, 2002, 2004, 2005, 2006, 2007,
                           2012, 2013})

#: PostgreSQL protocol 3.0 startup and the two special startup requests.
POSTGRES_STARTUP_VERSIONS = frozenset({196608, 80877103, 80877102})
POSTGRES_FRONTEND_TYPES = frozenset(b"QPBEDCXSHdcfp")

MAX_MESSAGE = 64 * 1024 * 1024
MAX_INSPECT = 32 * 1024
#: Minimum score accepted by :func:`detect_protocol`; weak guesses are left to
#: the user's explicit "decode as" choice instead of producing false positives.
MIN_CONFIDENCE = 60


def _head(data: bytes) -> bytes:
    return bytes(data or b"")[:MAX_INSPECT]


def _ber_length(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode one BER length header, returning ``(length, header_size)``."""
    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if not 1 <= count <= 4 or offset + 1 + count > len(data):
        return None
    length = int.from_bytes(data[offset + 1:offset + 1 + count], "big")
    return length, 1 + count


def detect_redis(data: bytes) -> bool:
    """True for a RESP command or an inline Redis command."""
    head = _head(data)
    if not head:
        return False
    if b" HTTP/" in head or re.match(
            rb"(?i)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) "
            rb"[^ \r\n]+ HTTP/", head):
        return False
    if head[:1] == b"*":
        match = re.match(rb"\*(\d{1,6})\r\n", head)
        if not match:
            return False
        count = int(match.group(1))
        if not 1 <= count <= 1024:
            return False
        rest = head[match.end():]
        if rest[:1] == b"$":
            return bool(re.match(rb"\$\d{1,9}\r\n", rest))
        # A few clients send inline array elements; accept a command name.
        first = rest.split(b"\r\n", 1)[0].strip().split(b" ", 1)[0]
        return first.upper().decode("latin-1", "replace") in REDIS_COMMANDS
    # Inline protocol: "PING\r\n" / "AUTH password\r\n".
    line = head.split(b"\r\n", 1)[0]
    if not line or line.startswith((b"+", b"-", b":", b"$")):
        return False
    parts = line.split()
    if not parts:
        return False
    try:
        command = parts[0].decode("ascii").upper()
    except UnicodeDecodeError:
        return False
    return command in REDIS_COMMANDS


def detect_mongodb(data: bytes) -> bool:
    """True when the payload starts with a plausible MongoDB wire header."""
    head = _head(data)
    if len(head) < 16:
        return False
    length = int.from_bytes(head[0:4], "little")
    opcode = int.from_bytes(head[12:16], "little")
    if not 16 <= length <= MAX_MESSAGE or opcode not in MONGO_OPCODES:
        return False
    # OP_MSG/OP_QUERY bodies start with flag bits or a collection name; the
    # header alone is already a very strong signal, but reject obviously
    # non-Mongo bodies (e.g. a TLS record with the same length bytes).
    if opcode == 2013 and len(head) >= 20:
        flags = int.from_bytes(head[16:20], "little")
        if flags & ~0x0000FFFF:
            return False
    return True


def detect_postgres(data: bytes) -> bool:
    """True for a PostgreSQL startup packet or frontend message."""
    head = _head(data)
    if len(head) < 5:
        return False
    length = int.from_bytes(head[0:4], "big")
    if 8 <= length <= MAX_MESSAGE and len(head) >= 8:
        version = int.from_bytes(head[4:8], "big")
        if version in POSTGRES_STARTUP_VERSIONS:
            return True
        # Startup packet: length + key/value pairs ending with a NUL.
        if head[8:9] and b"\x00" in head[8:min(length, len(head))]:
            keys = head[8:min(length, len(head))].split(b"\x00")
            if any(key in (b"user", b"database", b"application_name",
                           b"client_encoding") for key in keys):
                return True
    if head[0] in POSTGRES_FRONTEND_TYPES:
        body_length = int.from_bytes(head[1:5], "big")
        if 4 <= body_length <= MAX_MESSAGE:
            return True
    return False


def detect_ldap(data: bytes) -> bool:
    """True for an LDAP BER message (bind/search/result)."""
    head = _head(data)
    if len(head) < 4 or head[0] != 0x30:
        return False
    outer = _ber_length(head, 1)
    if outer is None:
        return False
    length, header = outer
    offset = 1 + header
    if length < 3 or offset + 2 > len(head):
        return False
    if head[offset] != 0x02:  # messageID INTEGER
        return False
    message_id = _ber_length(head, offset + 1)
    if message_id is None:
        return False
    id_length, id_header = message_id
    if id_length < 1 or id_length > 4:
        return False
    op = offset + 1 + id_header + id_length
    if op >= len(head):
        return False
    tag = head[op]
    # BindRequest 0x60, BindResponse 0x61, Unbind 0x42, SearchRequest 0x63,
    # SearchResultEntry 0x64, SearchResultDone 0x65, ExtendedRequest 0x77.
    return 0x60 <= tag <= 0x6F or tag in (0x42,)


def detect_smb2(data: bytes) -> bool:
    """True for SMB1/SMB2/SMB3 headers, including NetBIOS framing."""
    head = _head(data)
    if head[:4] in (b"\xfeSMB", b"\xffSMB", b"\xfdSMB"):
        return True
    # Direct TCP transport (port 445) has no NetBIOS header, but some captures
    # carry the 4 byte session-service header first.
    if len(head) >= 8 and head[0] == 0:
        frame = int.from_bytes(head[1:4], "big")
        if 1 <= frame <= MAX_MESSAGE and head[4:8] in (
                b"\xfeSMB", b"\xffSMB", b"\xfdSMB"):
            return True
    return False


def detect_http2(data: bytes) -> bool:
    """True for the HTTP/2 connection preface or a plausible first frame."""
    head = _head(data)
    if head.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        return True
    if len(head) >= 9 and head[0] == 0x00:
        length = int.from_bytes(head[0:3], "big")
        frame_type = head[3]
        stream_id = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
        if 0 < length <= 16384 and frame_type <= 9 and stream_id:
            return True
    return False


#: Detection order matters: the more specific/structured formats come first.
DETECTORS = (
    ("mongodb", detect_mongodb),
    ("postgres", detect_postgres),
    ("ldap", detect_ldap),
    ("smb2", detect_smb2),
    ("redis", detect_redis),
    ("http2", detect_http2),
)


def detect_protocol(data: bytes) -> str:
    """Return the best protocol guess for a payload, or ``""``."""
    name, confidence = detect_protocol_scored(data)
    return name if confidence >= MIN_CONFIDENCE else ""


def detect_protocol_scored(data: bytes) -> tuple[str, int]:
    """Return ``(protocol, confidence)`` so callers can suppress weak hits."""
    for name, detector in DETECTORS:
        try:
            if detector(data):
                return name, confidence_for(name, data)
        except (ValueError, IndexError):
            continue
    return "", 0


def confidence_for(protocol: str, data: bytes) -> int:
    """Heuristic confidence in the 0-100 range for one detection."""
    head = _head(data)
    if protocol == "smb2":
        return 95 if head[:4] in (b"\xfeSMB", b"\xffSMB", b"\xfdSMB") else 85
    if protocol == "http2":
        return 95 if head.startswith(b"PRI * HTTP/2.0\r\n") else 65
    if protocol == "mongodb":
        return 85
    if protocol == "postgres":
        if len(head) >= 8 and int.from_bytes(head[4:8], "big") in (
                POSTGRES_STARTUP_VERSIONS):
            return 90
        return 70
    if protocol == "ldap":
        return 85
    if protocol == "redis":
        if head[:1] == b"*":
            return 90 if b"$" in head[:64] else 75
        return 65
    return 60


def default_ports(protocol: str) -> tuple[int, ...]:
    return DEFAULT_PORTS.get(str(protocol or "").lower(), ())


def is_default_port(protocol: str, port: int | str) -> bool:
    try:
        value = int(port)
    except (TypeError, ValueError):
        return False
    return value in default_ports(protocol)


def decode_as(protocol: str) -> str:
    return DECODE_AS.get(str(protocol or "").lower(), "")


def _iter_ports(values: Iterable) -> list[int]:
    ports: list[int] = []
    for value in values or ():
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def decode_args(protocol: str, ports: Iterable[int]) -> list[str]:
    """Build tshark ``-d`` arguments for detected non-default ports."""
    dissector = decode_as(protocol)
    if not dissector:
        return []
    args: list[str] = []
    for port in _iter_ports(ports):
        args += ["-d", f"tcp.port=={port},{dissector}"]
    return args


def port_filter(protocol: str, ports: Iterable[int]) -> str:
    """Display filter matching any of ``ports`` (both directions)."""
    clauses = [f"tcp.port == {port}" for port in _iter_ports(ports)]
    return " || ".join(clauses)
