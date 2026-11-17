"""MySQL client/server protocol parsing over reassembled TCP streams.

The tshark MySQL dissector is good at well-formed single queries but hides the
details CTF/forensics work needs: the handshake salt and auth plugin, the
SHA1/SHA256 password scrambles, result-set metadata, ``LOAD DATA LOCAL
INFILE`` uploads and ``LOAD_FILE()`` reads whose result row carries a file's
contents.  This module decodes the wire format directly:

* packet framing (3-byte little-endian length + sequence id);
* ``Protocol::HandshakeV10`` and ``Protocol::HandshakeResponse41``;
* ``OK``, ``ERR`` and ``EOF`` packets, and column definitions;
* text-protocol result sets, including MySQL 8's ``CLIENT_DEPRECATE_EOF``
  mode where the column-definition ``EOF`` is omitted;
* ``mysql_native_password`` / ``caching_sha2_password`` scramble checks;
* ``LOAD DATA LOCAL INFILE`` requests and the client upload packets.

Everything is pure standard library (``hashlib``/``hmac`` only) and tolerant
of truncated captures, so the tests run without tshark.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

#: Hard caps so a corrupt/malicious capture cannot exhaust memory.
MAX_PACKET = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_COLUMNS = 4096
MAX_QUERIES = 200
MAX_QUERY_CHARS = 64 * 1024
MAX_ROWS = 2000
MAX_ROWS_PER_SET = 200
MAX_RESULT_SETS = 64
MAX_LOCAL_INFILES = 32
MAX_LOCAL_INFILE_BYTES = 8 * 1024 * 1024
MAX_USERS = 32

CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_FOUND_ROWS = 0x00000002
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_NO_SCHEMA = 0x00000010
CLIENT_COMPRESS = 0x00000020
CLIENT_ODBC = 0x00000040
CLIENT_LOCAL_FILES = 0x00000080
CLIENT_IGNORE_SPACE = 0x00000100
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_INTERACTIVE = 0x00000400
CLIENT_SSL = 0x00000800
CLIENT_IGNORE_SIGPIPE = 0x00001000
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_RESERVED = 0x00004000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_STATEMENTS = 0x00010000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PS_MULTI_RESULTS = 0x00040000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
CLIENT_SESSION_TRACK = 0x00800000
CLIENT_DEPRECATE_EOF = 0x01000000
CLIENT_OPTIONAL_RESULTSET_METADATA = 0x02000000
CLIENT_ZSTD_COMPRESSION_ALGORITHM = 0x04000000
CLIENT_QUERY_ATTRIBUTES = 0x08000000

#: Status flag marking another result set after the current one.
SERVER_MORE_RESULTS_EXISTS = 0x0008

CAPABILITY_NAMES = {
    CLIENT_LONG_PASSWORD: "CLIENT_LONG_PASSWORD",
    CLIENT_FOUND_ROWS: "CLIENT_FOUND_ROWS",
    CLIENT_LONG_FLAG: "CLIENT_LONG_FLAG",
    CLIENT_CONNECT_WITH_DB: "CLIENT_CONNECT_WITH_DB",
    CLIENT_NO_SCHEMA: "CLIENT_NO_SCHEMA",
    CLIENT_COMPRESS: "CLIENT_COMPRESS",
    CLIENT_ODBC: "CLIENT_ODBC",
    CLIENT_LOCAL_FILES: "CLIENT_LOCAL_FILES",
    CLIENT_IGNORE_SPACE: "CLIENT_IGNORE_SPACE",
    CLIENT_PROTOCOL_41: "CLIENT_PROTOCOL_41",
    CLIENT_INTERACTIVE: "CLIENT_INTERACTIVE",
    CLIENT_SSL: "CLIENT_SSL",
    CLIENT_IGNORE_SIGPIPE: "CLIENT_IGNORE_SIGPIPE",
    CLIENT_TRANSACTIONS: "CLIENT_TRANSACTIONS",
    CLIENT_SECURE_CONNECTION: "CLIENT_SECURE_CONNECTION",
    CLIENT_MULTI_STATEMENTS: "CLIENT_MULTI_STATEMENTS",
    CLIENT_MULTI_RESULTS: "CLIENT_MULTI_RESULTS",
    CLIENT_PS_MULTI_RESULTS: "CLIENT_PS_MULTI_RESULTS",
    CLIENT_PLUGIN_AUTH: "CLIENT_PLUGIN_AUTH",
    CLIENT_CONNECT_ATTRS: "CLIENT_CONNECT_ATTRS",
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS: "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
    CLIENT_SESSION_TRACK: "CLIENT_SESSION_TRACK",
    CLIENT_DEPRECATE_EOF: "CLIENT_DEPRECATE_EOF",
    CLIENT_OPTIONAL_RESULTSET_METADATA: "CLIENT_OPTIONAL_RESULTSET_METADATA",
    CLIENT_ZSTD_COMPRESSION_ALGORITHM: "CLIENT_ZSTD_COMPRESSION_ALGORITHM",
    CLIENT_QUERY_ATTRIBUTES: "CLIENT_QUERY_ATTRIBUTES",
}

COLUMN_TYPES = {
    0: "DECIMAL", 1: "TINY", 2: "SHORT", 3: "LONG", 4: "FLOAT",
    5: "DOUBLE", 6: "NULL", 7: "TIMESTAMP", 8: "LONGLONG", 9: "INT24",
    10: "DATE", 11: "TIME", 12: "DATETIME", 13: "YEAR", 14: "NEWDATE",
    15: "VARCHAR", 16: "BIT", 245: "JSON", 246: "NEWDECIMAL", 247: "ENUM",
    248: "SET", 249: "TINY_BLOB", 250: "MEDIUM_BLOB", 251: "LONG_BLOB",
    252: "BLOB", 253: "VAR_STRING", 254: "STRING", 255: "GEOMETRY",
}

COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_STATISTICS = 0x09
COM_PING = 0x0E
COM_CHANGE_USER = 0x11
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17

COMMAND_NAMES = {
    COM_QUIT: "COM_QUIT", COM_INIT_DB: "COM_INIT_DB", COM_QUERY: "COM_QUERY",
    COM_FIELD_LIST: "COM_FIELD_LIST", COM_STATISTICS: "COM_STATISTICS",
    COM_PING: "COM_PING", COM_CHANGE_USER: "COM_CHANGE_USER",
    COM_STMT_PREPARE: "COM_STMT_PREPARE", COM_STMT_EXECUTE: "COM_STMT_EXECUTE",
}
#: Every client command opcode lives in ``0x01..0x1f``; a packet whose first
#: byte is outside that range is a LOCAL INFILE data chunk, not a command.
COMMAND_CODES = frozenset(range(0x01, 0x20))

LOAD_DATA_LOCAL_RE = re.compile(
    r"^\s*load\s+(?:data|xml)\s+local\s+infile", re.IGNORECASE)
LOAD_FILE_RE = re.compile(r"load_file\s*\(\s*'([^']*)'", re.IGNORECASE)

DEFAULT_AUTH_PLUGIN = "mysql_native_password"


def _decode(value: bytes) -> str:
    """Decode protocol text as UTF-8, falling back to latin-1."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


def _port(value) -> int | str:
    """Return a TCP port as ``int`` when possible, otherwise as text."""
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return str(value or "")


def _capability_names(value: int) -> list[str]:
    """Return the names of the capability bits set in ``value``."""
    return [name for bit, name in sorted(CAPABILITY_NAMES.items())
            if value & bit]


def _read_lenenc(data: bytes, index: int) -> tuple[int | None, int]:
    """Read a length-encoded integer, returning ``(value, next_index)``.

    ``None`` means the 0xFB NULL marker; a truncated or 0xFF prefix also
    yields ``None`` and leaves the index at the end of the prefix.
    """
    if index < 0 or index >= len(data):
        return None, index
    first = data[index]
    if first < 0xFB:
        return first, index + 1
    if first == 0xFB:
        return None, index + 1
    if first == 0xFC:
        end = index + 3
        if end > len(data):
            return None, len(data)
        return int.from_bytes(data[index + 1:end], "little"), end
    if first == 0xFD:
        end = index + 4
        if end > len(data):
            return None, len(data)
        return int.from_bytes(data[index + 1:end], "little"), end
    if first == 0xFE:
        end = index + 9
        if end > len(data):
            return None, len(data)
        return int.from_bytes(data[index + 1:end], "little"), end
    return None, index + 1


def _cstring(data: bytes, index: int,
             limit: int | None = None) -> tuple[bytes, int]:
    """Read a NUL-terminated byte string, tolerating a missing terminator."""
    if index < 0 or index >= len(data):
        return b"", max(0, index)
    stop = len(data) if limit is None else min(limit, len(data))
    end = data.find(b"\x00", index)
    if end < 0 or end > stop:
        return data[index:stop], stop
    return data[index:end], end + 1


def _read_lenenc_str(data: bytes, index: int) -> tuple[str | None, int]:
    """Read a length-encoded string as text (``None`` for SQL NULL)."""
    length, index = _read_lenenc(data, index)
    if length is None:
        return None, index
    if length < 0 or length > len(data) - index:
        return _decode(data[index:]), len(data)
    return _decode(data[index:index + length]), index + length


def iter_packets(data: bytes) -> Iterator[tuple[int, bytes, int]]:
    """Yield ``(sequence_id, payload, offset)`` for each complete packet.

    The header is a 3-byte little-endian payload length plus one sequence
    byte.  Parsing stops at the first truncated header/payload or when the
    :data:`MAX_PACKET` / :data:`MAX_TOTAL` guards are exceeded; a partial
    trailing packet is never emitted.
    """
    raw = bytes(data or b"")
    size = len(raw)
    offset = 0
    total = 0
    while offset < size:
        if offset + 4 > size:
            break
        length = (raw[offset] | (raw[offset + 1] << 8)
                  | (raw[offset + 2] << 16))
        if length > MAX_PACKET or total + length > MAX_TOTAL:
            break
        end = offset + 4 + length
        if end > size:
            break
        yield raw[offset + 3], raw[offset + 4:end], offset
        total += length
        offset = end


def _as_payloads(raw: bytes) -> list[bytes]:
    """Split ``raw`` into payloads, or return it whole when it is unframed."""
    raw = bytes(raw or b"")
    if not raw:
        return []
    packets = list(iter_packets(raw))
    if packets and packets[0][2] == 0:
        consumed = packets[-1][2] + 4 + len(packets[-1][1])
        if consumed == len(raw):
            return [payload for _sequence, payload, _offset in packets]
    return [raw]


@dataclass
class Handshake:
    """Decoded ``Protocol::HandshakeV10`` sent by the server."""

    protocol_version: int = 10
    server_version: str = ""
    connection_id: int = 0
    auth_plugin_data: bytes = b""
    capabilities: int = 0
    charset: int = 0
    status_flags: int = 0
    auth_plugin_name: str = ""

    @classmethod
    def parse(cls, payload: bytes) -> "Handshake | None":
        """Parse a HandshakeV10 payload, or return ``None`` when malformed."""
        data = bytes(payload or b"")
        if len(data) < 1 or data[0] != 10:
            return None
        index = 1
        end = data.find(b"\x00", index)
        if end < 0:
            return None
        server_version = _decode(data[index:end])
        index = end + 1
        if index + 4 + 8 + 1 + 2 + 1 > len(data):
            return None
        connection_id = int.from_bytes(data[index:index + 4], "little")
        index += 4
        part1 = data[index:index + 8]
        index += 8
        index += 1  # 0x00 filler after the first salt part
        capabilities_low = int.from_bytes(data[index:index + 2], "little")
        index += 2
        charset = data[index]
        index += 1
        status_flags = 0
        if index + 2 <= len(data):
            status_flags = int.from_bytes(data[index:index + 2], "little")
            index += 2
        capabilities_high = 0
        if index + 2 <= len(data):
            capabilities_high = int.from_bytes(data[index:index + 2], "little")
            index += 2
        capabilities = (capabilities_high << 16) | capabilities_low
        auth_length = 0
        if index < len(data):
            auth_length = data[index]
            index += 1
        index = min(index + 10, len(data))  # reserved, all zero
        part2 = b""
        if index < len(data):
            # The second salt part is auth_len - 8 bytes, typically the last
            # 12 salt bytes plus a NUL; the length is always at least 13.
            part2_length = max(13, auth_length - 8)
            part2 = data[index:index + part2_length]
            index += len(part2)
        plugin = ""
        if index < len(data):
            end = data.find(b"\x00", index)
            if end < 0:
                end = len(data)
            plugin = _decode(data[index:end])
        salt = (part1 + part2).split(b"\x00", 1)[0][:20]
        return cls(
            protocol_version=10,
            server_version=server_version,
            connection_id=connection_id,
            auth_plugin_data=salt,
            capabilities=capabilities,
            charset=charset,
            status_flags=status_flags,
            auth_plugin_name=plugin,
        )

    def as_dict(self) -> dict:
        """Render the handshake as a plain dictionary."""
        return {
            "protocol_version": self.protocol_version,
            "server_version": self.server_version,
            "connection_id": self.connection_id,
            "auth_plugin_data": self.auth_plugin_data,
            "auth_plugin_name": self.auth_plugin_name,
            "capabilities": self.capabilities,
            "capability_names": _capability_names(self.capabilities),
            "charset": self.charset,
            "status_flags": self.status_flags,
        }


def parse_handshake(payload: bytes) -> dict | None:
    """Parse a server ``HandshakeV10`` payload into a dictionary."""
    handshake = Handshake.parse(payload)
    return handshake.as_dict() if handshake is not None else None


def parse_handshake_response(payload: bytes) -> dict | None:
    """Parse a client ``HandshakeResponse41`` payload into a dictionary.

    The auth response, database and plugin name are only present when the
    matching capability bits are set, so every optional field is guarded.
    """
    data = bytes(payload or b"")
    if len(data) < 32:
        return None
    capabilities = int.from_bytes(data[0:4], "little")
    max_packet = int.from_bytes(data[4:8], "little")
    charset = data[8]
    index = 9 + 23  # charset + 23 reserved bytes
    raw_user, index = _cstring(data, index)
    auth_response = b""
    if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        length, index = _read_lenenc(data, index)
        if length:
            auth_response = data[index:index + length]
            index += len(auth_response)
    elif capabilities & CLIENT_SECURE_CONNECTION:
        if index < len(data):
            length = data[index]
            index += 1
            auth_response = data[index:index + length]
            index += len(auth_response)
    else:
        auth_response, index = _cstring(data, index)
    database = ""
    if capabilities & CLIENT_CONNECT_WITH_DB and index < len(data):
        raw_db, index = _cstring(data, index)
        database = _decode(raw_db)
    plugin = ""
    if capabilities & CLIENT_PLUGIN_AUTH and index < len(data):
        raw_plugin, index = _cstring(data, index)
        plugin = _decode(raw_plugin)
    attributes: dict[str, str] = {}
    if capabilities & CLIENT_CONNECT_ATTRS and index < len(data):
        total, cursor = _read_lenenc(data, index)
        end = min(len(data), cursor + (total or 0))
        while cursor < end:
            key, cursor = _cstring(data, cursor, end)
            if not key or cursor >= end:
                break
            value, cursor = _cstring(data, cursor, end)
            attributes[_decode(key)] = _decode(value)
    return {
        "capabilities": capabilities,
        "capability_names": _capability_names(capabilities),
        "max_packet": max_packet,
        "charset": charset,
        "username": _decode(raw_user),
        "auth_response": auth_response,
        "database": database,
        "auth_plugin_name": plugin,
        "attributes": attributes,
    }


def _is_ok_packet(payload: bytes) -> bool:
    """Return True when a payload looks like an ``OK`` packet."""
    if not payload:
        return False
    if payload[0] == 0x00:
        return len(payload) >= 3
    # With CLIENT_DEPRECATE_EOF the result-set terminator is an OK packet
    # whose header byte is 0xFE; a short 0xFE packet is an old EOF instead.
    return payload[0] == 0xFE and len(payload) >= 7


def _is_eof_packet(payload: bytes) -> bool:
    """Return True when a payload looks like a pre-8.0 ``EOF`` packet."""
    return bool(payload) and payload[0] == 0xFE and len(payload) < 7


def parse_ok(payload: bytes) -> dict | None:
    """Parse an ``OK`` packet, or return ``None`` for any other packet type."""
    data = bytes(payload or b"")
    if not data or data[0] not in (0x00, 0xFE):
        return None
    if data[0] == 0xFE and len(data) < 7:
        return None
    index = 1
    affected, index = _read_lenenc(data, index)
    last_id, index = _read_lenenc(data, index)
    status = 0
    warnings = 0
    if index + 2 <= len(data):
        status = int.from_bytes(data[index:index + 2], "little")
        index += 2
    if index + 2 <= len(data):
        warnings = int.from_bytes(data[index:index + 2], "little")
        index += 2
    return {
        "type": "ok",
        "header": data[0],
        "affected_rows": int(affected or 0),
        "last_insert_id": int(last_id or 0),
        "status_flags": status,
        "warnings": warnings,
        "info": _decode(data[index:]),
    }


def parse_err(payload: bytes) -> dict | None:
    """Parse an ``ERR`` packet, or return ``None`` for any other packet type."""
    data = bytes(payload or b"")
    if len(data) < 3 or data[0] != 0xFF:
        return None
    code = int.from_bytes(data[1:3], "little")
    index = 3
    sqlstate = ""
    if data[3:4] == b"#" and len(data) >= 9:
        sqlstate = _decode(data[4:9])
        index = 9
    return {
        "type": "err",
        "code": code,
        "error_code": code,
        "sqlstate": sqlstate,
        "message": _decode(data[index:]),
    }


def parse_eof(payload: bytes) -> dict | None:
    """Parse a legacy ``EOF`` packet, or return ``None`` for other types."""
    data = bytes(payload or b"")
    if not data or data[0] != 0xFE or len(data) >= 9:
        return None
    warnings = int.from_bytes(data[1:3], "little") if len(data) >= 3 else 0
    status = int.from_bytes(data[3:5], "little") if len(data) >= 5 else 0
    return {
        "type": "eof",
        "warnings": warnings,
        "status_flags": status,
    }


def native_password_scramble(password: str, salt: bytes) -> bytes:
    """Return the MySQL 4.1 native-password scramble for ``password``.

    ``SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))``; an empty
    password produces an empty auth response, as the protocol expects.
    """
    if not password:
        return b""
    nonce = bytes(salt or b"")[:20]
    stage1 = hashlib.sha1(password.encode("utf-8")).digest()
    stage2 = hashlib.sha1(stage1).digest()
    mixed = hashlib.sha1(nonce + stage2).digest()
    return bytes(left ^ right for left, right in zip(stage1, mixed))


def caching_sha2_scramble(password: str, salt: bytes) -> bytes:
    """Return the ``caching_sha2_password`` scramble for ``password``.

    ``SHA256(password) XOR SHA256(SHA256(SHA256(password)) + salt)``.
    """
    if not password:
        return b""
    nonce = bytes(salt or b"")[:20]
    stage1 = hashlib.sha256(password.encode("utf-8")).digest()
    stage2 = hashlib.sha256(stage1).digest()
    mixed = hashlib.sha256(stage2 + nonce).digest()
    return bytes(left ^ right for left, right in zip(stage1, mixed))


def verify_native_password(password: str, salt: bytes,
                           response: bytes) -> bool:
    """Check a captured ``mysql_native_password`` auth response."""
    expected = native_password_scramble(password, salt)
    return hmac.compare_digest(expected, bytes(response or b""))


def verify_caching_sha2(password: str, salt: bytes, response: bytes) -> bool:
    """Check a captured ``caching_sha2_password`` fast-auth response."""
    expected = caching_sha2_scramble(password, salt)
    return hmac.compare_digest(expected, bytes(response or b""))


def parse_column_definition(payload: bytes) -> dict:
    """Parse one ``ColumnDefinition41`` packet into a dictionary."""
    data = bytes(payload or b"")
    index = 0
    fields: dict[str, str] = {}
    for name in ("catalog", "schema", "table", "org_table", "name",
                 "org_name"):
        value, index = _read_lenenc_str(data, index)
        fields[name] = value or ""
    charset = 0
    length = 0
    column_type = 0
    flags = 0
    decimals = 0
    _fixed, index = _read_lenenc(data, index)
    if index + 2 <= len(data):
        charset = int.from_bytes(data[index:index + 2], "little")
        index += 2
    if index + 4 <= len(data):
        length = int.from_bytes(data[index:index + 4], "little")
        index += 4
    if index < len(data):
        column_type = data[index]
        index += 1
    if index + 2 <= len(data):
        flags = int.from_bytes(data[index:index + 2], "little")
        index += 2
    if index < len(data):
        decimals = data[index]
    return {
        **fields,
        "charset": charset,
        "length": length,
        "type": column_type,
        "type_name": COLUMN_TYPES.get(column_type, str(column_type)),
        "flags": flags,
        "decimals": decimals,
        "nullable": not bool(flags & 0x0001),
    }


def decode_text_row(payload: bytes, columns: int) -> list[str | None]:
    """Decode a text-protocol row into ``columns`` values.

    The 0xFB length prefix means SQL NULL and becomes ``None``; a truncated
    tail yields the bytes present so a partial capture stays readable.
    """
    data = bytes(payload or b"")
    values: list[str | None] = []
    index = 0
    for _ in range(max(0, min(int(columns), MAX_COLUMNS))):
        length, index = _read_lenenc(data, index)
        if length is None:
            values.append(None)
            continue
        chunk = data[index:index + length]
        index += len(chunk)
        values.append(_decode(chunk))
    return values


class ResultSet:
    """Server packets that answer one ``COM_QUERY``.

    ``columns`` holds the decoded column definitions, ``rows`` the text rows,
    and ``error``/``ok``/``eof`` the terminating packet (whichever applies).
    ``consumed`` is the number of input payloads used, so a caller walking a
    whole server stream knows where the next response starts.  MySQL 8's
    ``CLIENT_DEPRECATE_EOF`` mode (no EOF after the column definitions) is
    selected with ``deprecate_eof=True``.
    """

    def __init__(self, payloads: Iterable[bytes] | bytes = (),
                 *, deprecate_eof: bool = False,
                 max_rows: int | None = None) -> None:
        self.columns: list[dict] = []
        self.rows: list[list[str | None]] = []
        self.error: dict | None = None
        self.ok: dict | None = None
        self.eof: dict | None = None
        self.local_infile: str | None = None
        self.column_count = 0
        self.status_flags = 0
        self.warnings = 0
        self.consumed = 0
        self.truncated = False
        self._parse(self._payloads(payloads), deprecate_eof,
                    MAX_ROWS if max_rows is None else max(0, int(max_rows)))

    @staticmethod
    def _payloads(payloads: Iterable[bytes] | bytes) -> list[bytes]:
        if payloads is None:
            return []
        if isinstance(payloads, (bytes, bytearray, memoryview)):
            return _as_payloads(bytes(payloads))
        return [bytes(item) for item in payloads if item is not None]

    def _finish(self, packet: dict | None) -> None:
        if not packet:
            return
        self.status_flags = int(packet.get("status_flags") or 0)
        self.warnings = int(packet.get("warnings") or 0)

    def _parse(self, packets: list[bytes], deprecate_eof: bool,
               max_rows: int) -> None:
        if not packets:
            return
        first = packets[0]
        if first[:1] == b"\xff":
            self.error = parse_err(first)
            self.consumed = 1
            return
        if first[:1] == b"\xfb":
            self.local_infile = parse_local_infile_request(first)
            self.consumed = 1
            return
        if _is_ok_packet(first):
            self.ok = parse_ok(first)
            self._finish(self.ok)
            self.consumed = 1
            return
        count, _index = _read_lenenc(first, 0)
        if count is None:
            self.truncated = True
            return
        self.column_count = int(count)
        if self.column_count > MAX_COLUMNS:
            self.truncated = True
            self.consumed = 1
            return
        index = 1
        for _ in range(self.column_count):
            if index >= len(packets):
                self.truncated = True
                break
            self.columns.append(parse_column_definition(packets[index]))
            index += 1
        if not deprecate_eof and index < len(packets) \
                and _is_eof_packet(packets[index]):
            self.eof = parse_eof(packets[index])
            index += 1
        while index < len(packets):
            payload = packets[index]
            if payload[:1] == b"\xff":
                self.error = parse_err(payload)
                index += 1
                break
            if _is_eof_packet(payload):
                self.eof = parse_eof(payload)
                index += 1
                break
            if _is_ok_packet(payload):
                self.ok = parse_ok(payload)
                index += 1
                break
            if payload[:1] == b"\xfb":
                self.local_infile = parse_local_infile_request(payload)
                index += 1
                break
            if len(self.rows) >= max_rows:
                # Keep consuming until the terminator so ``consumed`` stays
                # usable, but stop storing rows.
                self.truncated = True
                index += 1
                continue
            self.rows.append(decode_text_row(payload, self.column_count))
            index += 1
        self._finish(self.eof or self.ok)
        self.consumed = index


def parse_local_infile_request(payload: bytes) -> str | None:
    """Return the filename from a ``0xFB`` LOCAL INFILE request."""
    data = bytes(payload or b"")
    if not data or data[0] != 0xFB:
        return None
    return _decode(data[1:].rstrip(b"\x00"))


def load_data_chunks(payloads: Iterable[bytes] | bytes) -> bytes:
    """Concatenate a client's ``LOAD DATA LOCAL INFILE`` upload packets.

    Each item may be a payload or a framed packet blob (the 3-byte header is
    stripped with :func:`iter_packets`).  The empty packet that terminates the
    upload ends the result.  The returned bytes are capped at
    :data:`MAX_LOCAL_INFILE_BYTES`.
    """
    if isinstance(payloads, (bytes, bytearray, memoryview)):
        items: Iterable[bytes] = _as_payloads(bytes(payloads))
    else:
        items = list(payloads or [])
    chunks: list[bytes] = []
    total = 0
    for item in items:
        for payload in _as_payloads(bytes(item)):
            if not payload:
                return b"".join(chunks)
            chunks.append(payload[:MAX_LOCAL_INFILE_BYTES - total])
            total += len(chunks[-1])
            if total >= MAX_LOCAL_INFILE_BYTES:
                return b"".join(chunks)
    return b"".join(chunks)


def _session_packets(item) -> list[tuple[int, bytes, int]]:
    """Return the decoded packets of one stream-like object."""
    return list(iter_packets(getattr(item, "data", b"") or b""))


def _stream_role(packets: list[tuple[int, bytes, int]]) -> str:
    """Classify a stream as ``server``, ``client`` or unknown."""
    if not packets:
        return ""
    payload = packets[0][1]
    if Handshake.parse(payload) is not None:
        return "server"
    if parse_handshake_response(payload) is not None:
        return "client"
    return ""


def _auth_switch(payload: bytes) -> tuple[str, bytes]:
    """Return ``(plugin, salt)`` from an ``AuthSwitchRequest`` payload."""
    body = payload[1:] if payload[:1] == b"\xFE" else b""
    end = body.find(b"\x00")
    if end < 0:
        return _decode(body), b""
    plugin = _decode(body[:end])
    salt = body[end + 1:].split(b"\x00", 1)[0][:20]
    return plugin, salt


def _add_unique(values: list[str], value: str, limit: int) -> None:
    """Append ``value`` to ``values`` once, respecting a hard cap."""
    text = str(value or "")
    if text and text not in values and len(values) < limit:
        values.append(text)


def _empty_summary() -> dict:
    """Return a summary dictionary with every field present."""
    return {
        "protocol": "mysql",
        "host": "",
        "port": 0,
        "client": "",
        "server_version": "",
        "auth_plugin": "",
        "auth_salt": "",
        "users": [],
        "databases": [],
        "passwords": [],
        "queries": [],
        "result_sets": [],
        "local_infiles": [],
        "load_file_results": [],
        "errors": [],
    }


def _merge_summary(total: dict, part: dict) -> None:
    """Merge one session summary into ``total`` with the caps applied."""
    for key in ("host", "client", "server_version", "auth_plugin",
                "auth_salt"):
        if not total[key] and part[key]:
            total[key] = part[key]
    if not total["port"]:
        total["port"] = part["port"]
    for user in part["users"]:
        _add_unique(total["users"], user, MAX_USERS)
    for database in part["databases"]:
        _add_unique(total["databases"], database, MAX_USERS)
    for password in part["passwords"]:
        _add_unique(total["passwords"], password, MAX_USERS)
    for query in part["queries"]:
        if len(total["queries"]) < MAX_QUERIES:
            total["queries"].append(query)
    for item in part["result_sets"]:
        if len(total["result_sets"]) >= MAX_RESULT_SETS:
            break
        total["result_sets"].append(item)
    for item in part["local_infiles"]:
        if len(total["local_infiles"]) >= MAX_LOCAL_INFILES:
            break
        total["local_infiles"].append(item)
    for item in part["load_file_results"]:
        if len(total["load_file_results"]) >= MAX_QUERIES:
            break
        total["load_file_results"].append(item)
    total["errors"].extend(part["errors"])


def _summarise_session(server, server_packets, client,
                       client_packets) -> dict:
    """Summarise the login, queries and result sets of one session."""
    info = _empty_summary()
    if server is not None:
        info["host"] = str(getattr(server, "src", "") or "")
        info["port"] = _port(getattr(server, "sport", ""))
    if client is not None:
        info["client"] = (f"{getattr(client, 'src', '')}:"
                          f"{getattr(client, 'sport', '')}")
    if not server_packets:
        return info
    handshake = Handshake.parse(server_packets[0][1])
    if handshake is None:
        return info
    info["server_version"] = handshake.server_version
    info["auth_plugin"] = handshake.auth_plugin_name
    info["auth_salt"] = handshake.auth_plugin_data.hex()
    capabilities = handshake.capabilities

    ci = 0
    if client_packets:
        response = parse_handshake_response(client_packets[0][1])
        if response is not None:
            ci = 1
            if response["capabilities"]:
                capabilities = response["capabilities"]
            _add_unique(info["users"], response["username"], MAX_USERS)
            _add_unique(info["databases"], response["database"], MAX_USERS)
            if response["auth_plugin_name"]:
                info["auth_plugin"] = response["auth_plugin_name"]
    deprecate_eof = bool(capabilities & CLIENT_DEPRECATE_EOF)

    # Authentication: OK/ERR ends it; an auth switch or caching_sha2 full-auth
    # request consumes the matching client packet.
    si = 1
    while si < len(server_packets):
        payload = server_packets[si][1]
        if not payload:
            si += 1
            continue
        tag = payload[0]
        if tag == 0xFF:
            error = parse_err(payload)
            if error:
                info["errors"].append(error)
            si += 1
            break
        if tag == 0x00:
            si += 1
            break
        if tag == 0xFE:
            plugin, salt = _auth_switch(payload)
            if plugin:
                info["auth_plugin"] = plugin
            if salt:
                info["auth_salt"] = salt.hex()
            si += 1
            if ci < len(client_packets):
                auth_response = client_packets[ci][1]
                ci += 1
                if plugin == "mysql_clear_password":
                    text = _decode(auth_response.rstrip(b"\x00"))
                    _add_unique(info["passwords"], text, MAX_USERS)
            continue
        if tag == 0x01:
            si += 1
            if len(payload) > 1 and payload[1] == 0x04 \
                    and ci < len(client_packets):
                text = _decode(client_packets[ci][1].rstrip(b"\x00"))
                ci += 1
                _add_unique(info["passwords"], text, MAX_USERS)
            continue
        break

    total_rows = 0
    infile: dict | None = None
    pending_load_file: str | None = None
    while ci < len(client_packets):
        payload = client_packets[ci][1]
        if infile is not None:
            ci += 1
            if not payload:
                infile["size"] = len(infile["data"])
                if si < len(server_packets):
                    error = parse_err(server_packets[si][1])
                    if error:
                        info["errors"].append(error)
                    si += 1
                infile = None
                continue
            remaining = MAX_LOCAL_INFILE_BYTES - len(infile["data"])
            if remaining > 0:
                infile["data"] += payload[:remaining]
            continue
        if not payload:
            ci += 1
            continue
        code = payload[0]
        if code not in COMMAND_CODES:
            ci += 1
            continue
        ci += 1
        sql = ""
        if code in (COM_QUERY, COM_STMT_PREPARE):
            sql = _decode(payload[1:])
            if sql.strip() and len(info["queries"]) < MAX_QUERIES:
                info["queries"].append(sql[:MAX_QUERY_CHARS])
            if code == COM_STMT_PREPARE:
                # COM_STMT_PREPARE_OK is metadata, not a text result set.
                if si < len(server_packets):
                    si += 1
                continue
            match = LOAD_FILE_RE.search(sql)
            pending_load_file = match.group(1) if match else None
        elif code == COM_INIT_DB:
            _add_unique(info["databases"], _decode(payload[1:]), MAX_USERS)
            if si < len(server_packets):
                error = parse_err(server_packets[si][1])
                if error:
                    info["errors"].append(error)
                si += 1
            continue
        elif code == COM_CHANGE_USER:
            raw_user, cursor = _cstring(payload, 1)
            _add_unique(info["users"], _decode(raw_user), MAX_USERS)
            if cursor < len(payload):
                cursor += 1 + payload[cursor]
                raw_db, _cursor = _cstring(payload, cursor)
                _add_unique(info["databases"], _decode(raw_db), MAX_USERS)
            if si < len(server_packets):
                si += 1
            continue

        if si >= len(server_packets):
            continue
        first = server_packets[si][1]
        if first[:1] == b"\xfb":
            filename = parse_local_infile_request(first) or ""
            si += 1
            record = {"filename": filename, "data": b"", "size": 0,
                      "query": sql}
            if len(info["local_infiles"]) < MAX_LOCAL_INFILES:
                info["local_infiles"].append(record)
            infile = record
            continue
        rounds = 0
        while si < len(server_packets) and rounds < 16:
            rounds += 1
            remaining = max(0, MAX_ROWS - total_rows)
            result = ResultSet(
                [item[1] for item in server_packets[si:]],
                deprecate_eof=deprecate_eof,
                max_rows=min(MAX_ROWS_PER_SET, remaining))
            if result.consumed <= 0:
                break
            si += result.consumed
            if result.error is not None:
                info["errors"].append(result.error)
                break
            if result.local_infile is not None:
                record = {"filename": result.local_infile, "data": b"",
                          "size": 0, "query": sql}
                if len(info["local_infiles"]) < MAX_LOCAL_INFILES:
                    info["local_infiles"].append(record)
                infile = record
                break
            if result.columns:
                if len(info["result_sets"]) < MAX_RESULT_SETS:
                    info["result_sets"].append({
                        "columns": [column.get("name", "")
                                    for column in result.columns],
                        "column_definitions": result.columns,
                        "rows": result.rows,
                        "rows_returned": len(result.rows),
                        "truncated": result.truncated,
                    })
                total_rows += len(result.rows)
                if pending_load_file is not None:
                    value = None
                    if result.rows and result.rows[0]:
                        value = result.rows[0][0]
                    info["load_file_results"].append({
                        "query": sql,
                        "filename": pending_load_file,
                        "data": value if isinstance(value, str) else "",
                        "found": value is not None,
                    })
                    pending_load_file = None
            if not (result.status_flags & SERVER_MORE_RESULTS_EXISTS):
                break
        pending_load_file = None
    if infile is not None:
        infile["size"] = len(infile["data"])
    return info


def summarise_stream(streams) -> dict:
    """Summarise MySQL sessions from reassembled stream objects.

    ``streams`` is any iterable of objects exposing ``.src``, ``.sport``,
    ``.dst``, ``.dport`` and ``.data`` (see
    :class:`fnet.utils.stream.StreamData`).  The server direction is found by
    the handshake and paired with the matching client direction, so the parser
    also works on non-standard ports.  The returned dictionary holds the
    host/port, server version, auth plugin, users, databases, queries, result
    sets (limited), LOCAL INFILE uploads, ``LOAD_FILE`` results and errors.
    """
    items = list(streams or [])
    servers: list[tuple[object, list]] = []
    clients: list[tuple[object, list]] = []
    for item in items:
        packets = _session_packets(item)
        role = _stream_role(packets)
        if role == "server":
            servers.append((item, packets))
        elif role == "client":
            clients.append((item, packets))
    summary = _empty_summary()
    if not servers:
        return summary
    used: set[int] = set()
    for server, server_packets in servers:
        client = None
        client_packets: list = []
        for index, (candidate, candidate_packets) in enumerate(clients):
            if index in used:
                continue
            if (str(getattr(candidate, "src", ""))
                    == str(getattr(server, "dst", ""))
                    and str(getattr(candidate, "sport", ""))
                    == str(getattr(server, "dport", ""))
                    and str(getattr(candidate, "dst", ""))
                    == str(getattr(server, "src", ""))
                    and str(getattr(candidate, "dport", ""))
                    == str(getattr(server, "sport", ""))):
                client = candidate
                client_packets = candidate_packets
                used.add(index)
                break
        _merge_summary(summary, _summarise_session(
            server, server_packets, client, client_packets))
    if not summary["auth_plugin"]:
        summary["auth_plugin"] = DEFAULT_AUTH_PLUGIN
    return summary



