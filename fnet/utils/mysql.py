"""Pure-Python MySQL client/server protocol parsing over reassembled streams.

Wireshark's ``mysql`` dissector only works on well-known ports and hides most
of the interesting detail behind field names.  This module parses the MySQL
wire protocol itself so it keeps working on non-standard ports and on captures
where tshark's dissector gives up:

* packet framing: 3-byte little-endian length + 1-byte sequence id;
* server handshake (greeting): protocol/server version, connection id,
  20-byte auth salt (8 + 12 layout), capabilities, charset, status flags and
  the authentication plugin name;
* client handshake response: capabilities, username, auth scramble response,
  default database and plugin name;
* response packets: ``OK`` / ``ERR`` / ``EOF``;
* text result sets: column definitions, ``NULL``-aware row decoding and a
  :class:`ResultSet` consumer that handles both classic ``EOF`` framing and
  MySQL 8 ``CLIENT_DEPRECATE_EOF``;
* ``LOAD DATA LOCAL INFILE``: the server's ``0xFB`` filename request and the
  raw client file chunks that follow it;
* password scrambles: ``mysql_native_password`` (SHA1 based) and
  ``caching_sha2_password`` (SHA256 based), plus verifiers to check a captured
  handshake response against a candidate password.

Everything is a pure function on ``bytes`` with hard caps so a corrupt or
malicious capture cannot exhaust memory.  No helper raises on malformed
input: parsers return ``None`` / partial data instead.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Iterable, Iterator, Protocol, Sequence

#: Hard caps so a corrupt/malicious capture cannot exhaust memory.
MAX_DATA_BYTES = 8 * 1024 * 1024
MAX_QUERIES = 200
MAX_ROWS = 2000

#: Capability flags (client/server handshake capabilities).
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_COMPRESS = 0x00000020
CLIENT_LOCAL_FILES = 0x00000080
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_STATEMENTS = 0x00010000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_ATTRS = 0x00100000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
CLIENT_SESSION_TRACK = 0x00800000
CLIENT_DEPRECATE_EOF = 0x01000000

#: Client command bytes (first byte of a client packet).
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_FIELD_LIST = 0x04
COM_PING = 0x0E

#: Column type codes from the column definition (protocol 41).
COLUMN_TYPES = {
    0: "decimal", 1: "tiny", 2: "short", 3: "long", 4: "float",
    5: "double", 6: "null", 7: "timestamp", 8: "longlong", 9: "int24",
    10: "date", 11: "time", 12: "datetime", 13: "year", 14: "newdate",
    15: "varchar", 16: "bit", 245: "json", 246: "newdecimal", 247: "enum",
    248: "set", 249: "tinyblob", 250: "mediumblob", 251: "longblob",
    252: "blob", 253: "varstring", 254: "string", 255: "geometry",
}

#: First bytes that identify a server response packet shape.
_OK_HEADER = b"\x00"
_ERR_HEADER = b"\xff"
_EOF_HEADER = b"\xfe"
_LOCAL_INFILE_HEADER = b"\xfb"

_COMMAND_BYTES = range(0x00, 0x20)


# ---------------------------------------------------------------------------
# Packet framing
# ---------------------------------------------------------------------------

def iter_packets(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(sequence, payload)`` for each MySQL packet in ``data``.

    The framing is a 3-byte little-endian payload length followed by a 1-byte
    sequence id.  Parsing stops cleanly (no exception) at the first
    truncated or malformed header, so a clipped capture yields the packets
    that did arrive.
    """
    data = bytes(data or b"")
    pos = 0
    total = len(data)
    while pos + 4 <= total:
        length = int.from_bytes(data[pos:pos + 3], "little")
        seq = data[pos + 3]
        if pos + 4 + length > total:
            return  # truncated payload: stop
        yield seq, data[pos + 4:pos + 4 + length]
        pos += 4 + length


# ---------------------------------------------------------------------------
# Length-encoded integers / strings
# ---------------------------------------------------------------------------

def read_lenenc_int(data: bytes, pos: int) -> tuple[int | None, int]:
    """Read a length-encoded integer at ``pos``; ``(None, pos)`` if malformed.

    ``0xFB`` is reported as ``(None, pos + 1)`` (the NULL marker); callers
    that need to distinguish NULL from malformed data should check the byte
    before calling.
    """
    if pos < 0 or pos >= len(data):
        return None, pos
    first = data[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFB:
        return None, pos + 1
    size = {0xFC: 2, 0xFD: 3, 0xFE: 8}.get(first)
    if size is None or pos + 1 + size > len(data):
        return None, pos
    return int.from_bytes(data[pos + 1:pos + 1 + size], "little"), pos + 1 + size


def _read_lenenc_str(data: bytes, pos: int) -> tuple[str | None, int]:
    """Read one length-encoded UTF-8 string; ``None`` when malformed."""
    length, pos = read_lenenc_int(data, pos)
    if length is None or pos + length > len(data):
        return None, pos
    return data[pos:pos + length].decode("utf-8", "replace"), pos + length


# ---------------------------------------------------------------------------
# Handshake packets
# ---------------------------------------------------------------------------

def parse_handshake(payload: bytes) -> dict | None:
    """Parse the server greeting (protocol version 10 handshake packet).

    Returns a dict with ``protocol``, ``server_version``, ``connection_id``,
    ``salt`` (20 bytes, 8 + 12 layout), ``capabilities``, ``charset``,
    ``status`` and ``auth_plugin`` — or ``None`` when the packet is not a
    recognisable v10 greeting (or is truncated in its fixed part).
    """
    payload = bytes(payload or b"")
    if not payload or payload[0] != 10:
        return None
    end = payload.find(b"\x00", 1)
    if end < 0:
        return None
    server_version = payload[1:end].decode("utf-8", "replace")
    pos = end + 1
    # connection id (4) + salt part 1 (8) + filler (1) + caps low (2)
    # + charset (1) + status (2) + caps high (2) = 20 bytes.
    if pos + 20 > len(payload):
        return None
    connection_id = int.from_bytes(payload[pos:pos + 4], "little")
    salt_part1 = payload[pos + 4:pos + 12]
    pos += 13
    capabilities = int.from_bytes(payload[pos:pos + 2], "little")
    pos += 2
    charset = payload[pos]
    pos += 1
    status = int.from_bytes(payload[pos:pos + 2], "little")
    pos += 2
    capabilities |= int.from_bytes(payload[pos:pos + 2], "little") << 16
    pos += 2
    auth_data_len = payload[pos] if pos < len(payload) else 0
    pos += 1
    pos += 10  # reserved (all zero)
    if pos > len(payload):
        return None

    salt = bytes(salt_part1)
    auth_plugin = ""
    if capabilities & (CLIENT_PLUGIN_AUTH | CLIENT_SECURE_CONNECTION):
        part2_len = max(13, auth_data_len - 8) if auth_data_len else 13
        part2 = payload[pos:pos + part2_len]
        if not part2:
            return None
        pos += len(part2)
        salt += part2[:12]
        if pos < len(payload):
            stop = payload.find(b"\x00", pos)
            if stop < 0:
                stop = len(payload)
            auth_plugin = payload[pos:stop].decode("utf-8", "replace")
    else:
        # Pre-4.1 greeting: only the 8-byte salt is present.
        stop = payload.find(b"\x00", pos)
        if stop >= 0 and stop - pos > len(salt):
            salt += payload[pos:stop]

    if len(salt) < 20:
        salt = (salt + b"\x00" * 20)[:20]
    return {
        "protocol": 10,
        "server_version": server_version,
        "connection_id": connection_id,
        "salt": salt[:20],
        "capabilities": capabilities,
        "charset": charset,
        "status": status,
        "auth_plugin": auth_plugin,
    }


def parse_handshake_response(payload: bytes) -> dict | None:
    """Parse the client's handshake response (protocol 41).

    Returns a dict with ``capabilities``, ``max_packet``, ``charset``,
    ``username``, ``auth_response`` (bytes), ``database`` and
    ``auth_plugin`` — or ``None`` when the fixed part or the username is
    malformed.  ``auth_response`` is empty for passwordless logins; the
    plugin-specific fields are omitted from the wire packet by older clients
    and come back as ``""``.
    """
    payload = bytes(payload or b"")
    if len(payload) < 32:
        return None
    capabilities = int.from_bytes(payload[0:4], "little")
    max_packet = int.from_bytes(payload[4:8], "little")
    charset = payload[8]
    pos = 32  # 4 caps + 4 max packet + 1 charset + 23 reserved
    end = payload.find(b"\x00", pos)
    if end < 0:
        return None
    username = payload[pos:end].decode("utf-8", "replace")
    pos = end + 1

    auth_response = b""
    if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
        length, pos = read_lenenc_int(payload, pos)
        if length is None or pos + length > len(payload):
            return None
        auth_response = payload[pos:pos + length]
        pos += length
    elif capabilities & CLIENT_SECURE_CONNECTION:
        if pos >= len(payload):
            return None
        length = payload[pos]
        pos += 1
        if pos + length > len(payload):
            return None
        auth_response = payload[pos:pos + length]
        pos += length
    else:
        end = payload.find(b"\x00", pos)
        if end >= 0:
            auth_response = payload[pos:end]
            pos = end + 1

    database = ""
    if capabilities & CLIENT_CONNECT_WITH_DB and pos < len(payload):
        end = payload.find(b"\x00", pos)
        if end >= 0:
            database = payload[pos:end].decode("utf-8", "replace")
            pos = end + 1

    auth_plugin = ""
    if capabilities & CLIENT_PLUGIN_AUTH and pos < len(payload):
        end = payload.find(b"\x00", pos)
        if end < 0:
            end = len(payload)
        auth_plugin = payload[pos:end].decode("utf-8", "replace")

    return {
        "capabilities": capabilities,
        "max_packet": max_packet,
        "charset": charset,
        "username": username,
        "auth_response": auth_response,
        "database": database,
        "auth_plugin": auth_plugin,
    }


# ---------------------------------------------------------------------------
# Response packets: OK / ERR / EOF
# ---------------------------------------------------------------------------

def parse_ok(payload: bytes) -> dict | None:
    """Parse an ``OK`` packet (``0x00`` header) or ``None``."""
    payload = bytes(payload or b"")
    if not payload or payload[0] != 0x00:
        return None
    pos = 1
    affected_rows, pos = read_lenenc_int(payload, pos)
    last_insert_id, pos = read_lenenc_int(payload, pos)
    affected_rows = affected_rows or 0
    last_insert_id = last_insert_id or 0
    status = 0
    warnings = 0
    if pos + 4 <= len(payload):
        status = int.from_bytes(payload[pos:pos + 2], "little")
        warnings = int.from_bytes(payload[pos + 2:pos + 4], "little")
        pos += 4
    elif pos + 2 <= len(payload):
        status = int.from_bytes(payload[pos:pos + 2], "little")
        pos += 2
    info = payload[pos:].decode("utf-8", "replace")
    return {
        "affected_rows": affected_rows,
        "last_insert_id": last_insert_id,
        "status": status,
        "warnings": warnings,
        "info": info,
    }


def parse_err(payload: bytes) -> dict | None:
    """Parse an ``ERR`` packet (``0xFF`` header) or ``None``."""
    payload = bytes(payload or b"")
    if not payload or payload[0] != 0xFF or len(payload) < 3:
        return None
    code = int.from_bytes(payload[1:3], "little")
    pos = 3
    sql_state = ""
    if len(payload) > pos and payload[pos:pos + 1] == b"#":
        sql_state = payload[pos + 1:pos + 6].decode("ascii", "replace")
        pos += 6
    message = payload[pos:].decode("utf-8", "replace")
    return {"code": code, "sql_state": sql_state, "message": message}


def parse_eof(payload: bytes) -> dict | None:
    """Parse an ``EOF`` packet (``0xFE`` header, <= 5 bytes) or ``None``."""
    payload = bytes(payload or b"")
    if not payload or payload[0] != 0xFE or len(payload) > 5:
        return None
    warnings = 0
    status = 0
    if len(payload) >= 3:
        warnings = int.from_bytes(payload[1:3], "little")
    if len(payload) >= 5:
        status = int.from_bytes(payload[3:5], "little")
    return {"warnings": warnings, "status": status}


def _is_eof(payload: bytes) -> bool:
    """EOF disambiguation: ``0xFE`` and short (a 9-byte lenenc string can
    also start with ``0xFE``, so length is the discriminator)."""
    return payload[:1] == _EOF_HEADER and len(payload) < 9


# ---------------------------------------------------------------------------
# Auth scrambles
# ---------------------------------------------------------------------------

def native_password_scramble(pw: str | bytes, salt: bytes) -> bytes:
    """``mysql_native_password`` scramble.

    ``SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))`` — the 20-byte value sent as
    the client auth response.
    """
    if isinstance(pw, str):
        pw = pw.encode("utf-8")
    stage1 = hashlib.sha1(pw).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(bytes(salt or b"") + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def caching_sha2_scramble(pw: str | bytes, salt: bytes) -> bytes:
    """``caching_sha2_password`` scramble.

    ``SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) + salt)``.
    """
    if isinstance(pw, str):
        pw = pw.encode("utf-8")
    digest1 = hashlib.sha256(pw).digest()
    digest2 = hashlib.sha256(digest1).digest()
    digest3 = hashlib.sha256(digest2 + bytes(salt or b"")).digest()
    return bytes(a ^ b for a, b in zip(digest1, digest3))


def verify_native_password(pw: str | bytes, salt: bytes,
                           response: bytes) -> bool:
    """Check a captured auth response against a candidate password."""
    expected = native_password_scramble(pw, salt)
    return hmac.compare_digest(expected, bytes(response or b""))


def verify_caching_sha2(pw: str | bytes, salt: bytes,
                        response: bytes) -> bool:
    """Check a captured ``caching_sha2_password`` response."""
    expected = caching_sha2_scramble(pw, salt)
    return hmac.compare_digest(expected, bytes(response or b""))


def crack_response(salt: bytes, response: bytes,
                   candidates: Iterable[str | bytes],
                   plugin: str = "mysql_native_password") -> str | bytes | None:
    """Try each candidate password against one captured auth response.

    ``plugin`` selects the scramble ("mysql_native_password" or
    "caching_sha2_password").  Returns the matching password or ``None``.
    """
    verifier = verify_native_password
    if "sha2" in str(plugin or "").lower():
        verifier = verify_caching_sha2
    for candidate in candidates or ():
        if verifier(candidate, salt, response):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Result sets
# ---------------------------------------------------------------------------

def parse_column_definition(payload: bytes) -> dict | None:
    """Parse one column definition (protocol 41) packet payload."""
    payload = bytes(payload or b"")
    pos = 0
    info: dict = {}
    for key in ("catalog", "schema", "table", "org_table", "name", "org_name"):
        value, pos = _read_lenenc_str(payload, pos)
        if value is None:
            return None
        info[key] = value
    fixed_len, pos = read_lenenc_int(payload, pos)
    if fixed_len is None or pos + fixed_len > len(payload):
        return None
    fixed = payload[pos:pos + fixed_len]
    if len(fixed) < 10:
        return None
    info["charset"] = int.from_bytes(fixed[0:2], "little")
    info["column_length"] = int.from_bytes(fixed[2:6], "little")
    info["type"] = fixed[6]
    info["type_name"] = COLUMN_TYPES.get(fixed[6], f"type{fixed[6]}")
    info["flags"] = int.from_bytes(fixed[7:9], "little")
    info["decimals"] = fixed[9]
    return info


def decode_text_row(payload: bytes,
                    columns: Sequence | int | None = None) -> list[str | None]:
    """Decode one text result-set row into ``str`` / ``None`` values.

    ``columns`` may be the column count or a column list; it only bounds how
    many values are decoded.  ``0xFB`` markers decode as ``None`` (NULL).
    Truncated or malformed value framing yields the values decoded so far.
    """
    payload = bytes(payload or b"")
    target: int | None = None
    if isinstance(columns, int):
        target = max(0, columns)
    elif columns:
        target = len(columns)
    values: list[str | None] = []
    pos = 0
    while pos < len(payload):
        if target is not None and len(values) >= target:
            break
        if payload[pos] == 0xFB:
            values.append(None)
            pos += 1
            continue
        length, pos = read_lenenc_int(payload, pos)
        if length is None or pos + length > len(payload):
            break  # malformed / truncated: keep what we have
        values.append(payload[pos:pos + length].decode("utf-8", "replace"))
        pos += length
    return values


def _decode_row_exact(payload: bytes,
                      count: int) -> list[str | None] | None:
    """Decode exactly ``count`` values, or ``None`` if the framing is short
    or leaves leftover bytes (used to tell a row from an OK packet)."""
    values: list[str | None] = []
    pos = 0
    while len(values) < count:
        if pos >= len(payload):
            return None
        if payload[pos] == 0xFB:
            values.append(None)
            pos += 1
            continue
        length, pos = read_lenenc_int(payload, pos)
        if length is None or pos + length > len(payload):
            return None
        values.append(payload[pos:pos + length].decode("utf-8", "replace"))
        pos += length
    if pos != len(payload):
        return None
    return values


class ResultSet:
    """Consume server packet payloads for one command response.

    ``packets`` is an iterable of *payloads* (bytes without the 4-byte packet
    header) for a single command's server response.  Handles the classic
    ``EOF`` framing and MySQL 8 ``CLIENT_DEPRECATE_EOF`` (no EOF after the
    columns, final ``OK`` packet terminates the rows).  Never raises.
    """

    def __init__(self, packets: Iterable[bytes]):
        self.columns: list[dict] = []
        self.column_names: list[str] = []
        self.rows: list[list[str | None]] = []
        self.error: dict | None = None
        self.ok: dict | None = None
        self.column_count = 0
        self.consumed = 0
        self._parse(iter(packets or ()))

    # -- internals ----------------------------------------------------------

    def _next(self, it: Iterator[bytes]) -> bytes | None:
        self.consumed += 1
        try:
            return bytes(next(it) or b"")
        except StopIteration:
            self.consumed -= 1
            return None

    def _parse(self, it: Iterator[bytes]) -> None:
        first = self._next(it)
        if first is None:
            return
        if first[:1] == _ERR_HEADER:
            self.error = parse_err(first)
            return
        if first[:1] == _OK_HEADER:
            self.ok = parse_ok(first)
            return
        self.column_count, _ = read_lenenc_int(first, 0)
        if self.column_count is None:
            self.column_count = 0

        while len(self.columns) < self.column_count:
            packet = self._next(it)
            if packet is None:
                return
            if packet[:1] == _ERR_HEADER:
                self.error = parse_err(packet)
                return
            if _is_eof(packet):
                return  # zero-column EOF should not happen; be safe
            column = parse_column_definition(packet)
            if column is None:
                break
            self.columns.append(column)
            self.column_names.append(column["name"])

        packet = self._next(it)
        if packet is None:
            return
        if _is_eof(packet):
            # Classic framing closes the column-definition section with an
            # EOF packet; the rows follow it.  DEPRECATE_EOF omits this EOF.
            packet = self._next(it)
        while packet is not None:
            if packet[:1] == _ERR_HEADER:
                self.error = parse_err(packet)
                return
            if _is_eof(packet):
                self.ok = parse_eof(packet)
                return
            if packet[:1] == _OK_HEADER and self.column_count > 0:
                # CLIENT_DEPRECATE_EOF: an OK packet terminates the rows.  A
                # row whose first column is empty also starts with 0x00, so
                # prefer an exact row decode when one fits.
                row = _decode_row_exact(packet, self.column_count)
                if row is None:
                    self.ok = parse_ok(packet)
                    return
                if len(self.rows) < MAX_ROWS:
                    self.rows.append(row)
                packet = self._next(it)
                continue
            if len(self.rows) < MAX_ROWS:
                self.rows.append(decode_text_row(packet, self.column_count))
            packet = self._next(it)

    # -- conveniences -------------------------------------------------------

    @property
    def succeeded(self) -> bool:
        """``True`` when the command completed without an error packet."""
        return self.error is None and bool(self.rows or self.ok is not None
                                           or self.columns)


# ---------------------------------------------------------------------------
# LOAD DATA LOCAL INFILE
# ---------------------------------------------------------------------------

def parse_local_infile_request(payload: bytes) -> str | None:
    """Parse the server's ``LOCAL INFILE`` request (``0xFB`` + filename).

    Returns the requested filename, or ``None`` when the payload is not a
    ``0xFB`` request or carries no filename.
    """
    payload = bytes(payload or b"")
    if not payload or payload[0] != 0xFB:
        return None
    name = payload[1:].rstrip(b"\x00")
    if not name:
        return None
    return name.decode("utf-8", "replace")


def load_data_chunks(payloads: Iterable[bytes]) -> bytes:
    """Concatenate the client file bytes of a ``LOCAL INFILE`` upload.

    Accepts an iterable of packet payloads *or* full packets (3-byte length +
    sequence header); framed packets are recognised by a matching header and
    stripped.  An empty payload is the end-of-upload marker and simply
    contributes nothing.  The result is capped at :data:`MAX_DATA_BYTES`.
    """
    chunks: list[bytes] = []
    total = 0
    for item in payloads or ():
        data = bytes(item or b"")
        # Strip the packet header when the item is a framed packet (an empty
        # payload is the end-of-upload marker and contributes nothing).
        if len(data) >= 4:
            declared = int.from_bytes(data[:3], "little")
            if declared == len(data) - 4:
                data = data[4:]
        if not data:
            continue
        chunks.append(data)
        total += len(data)
        if total >= MAX_DATA_BYTES:
            break
    return b"".join(chunks)[:MAX_DATA_BYTES]


# ---------------------------------------------------------------------------
# Stream summarisation
# ---------------------------------------------------------------------------

class StreamLike(Protocol):
    """Duck type of the reassembled streams accepted by the summariser."""

    src: str
    sport: str
    dst: str
    dport: str
    data: bytes


def summarise_stream(streams: Iterable[StreamLike] | StreamLike) -> dict:
    """Summarise MySQL traffic from reassembled TCP streams.

    ``streams`` is an iterable of objects exposing ``.src``, ``.sport``,
    ``.dst``, ``.dport`` and ``.data`` (e.g.
    :class:`fnet.utils.stream.StreamData`); a single such object is accepted
    too.  The server side is detected from a valid handshake greeting in the
    first packets; without one the summary stays empty.

    The returned dict has ``host``/``port`` (the server), ``server_version``,
    ``auth_plugin``, ``users``, ``databases``, ``queries``, ``result_sets``
    (query + columns + rows, errors included), ``local_infiles`` (filename,
    size and uploaded bytes) and ``load_file_results`` (row values of
    ``LOAD_FILE()`` queries).  List sizes are capped (200 queries, 2000 rows,
    8 MiB of file data); malformed input never raises.
    """
    summary = {
        "host": "",
        "port": 0,
        "server_version": "",
        "auth_plugin": "",
        "users": [],
        "databases": [],
        "queries": [],
        "result_sets": [],
        "local_infiles": [],
        "load_file_results": [],
    }
    items = list(streams) if isinstance(streams, (list, tuple)) else \
        ([streams] if streams is not None else [])
    if streams is not None and not isinstance(streams, (list, tuple)) \
            and not hasattr(streams, "data"):
        try:
            items = list(streams)  # a generator/iterator of streams
        except TypeError:
            items = []

    # Direction detection: the server is the stream whose first packet is a
    # valid handshake greeting.
    server = None
    server_packets: list[bytes] = []
    handshake: dict | None = None
    for stream in items:
        try:
            data = bytes(stream.data or b"")
        except Exception:
            continue
        packets = [payload for _, payload in iter_packets(data)]
        if packets and packets[0][:1] == b"\x0a":
            parsed = parse_handshake(packets[0])
            if parsed:
                server = stream
                server_packets = packets
                handshake = parsed
                break
    if server is None:
        return summary

    summary["host"] = str(getattr(server, "src", "") or "")
    try:
        summary["port"] = int(getattr(server, "sport", 0))
    except (TypeError, ValueError):
        summary["port"] = 0
    summary["server_version"] = handshake["server_version"]
    summary["auth_plugin"] = handshake["auth_plugin"]

    client = None
    for stream in items:
        if stream is not server:
            client = stream
            break
    client_packets: list[bytes] = []
    if client is not None:
        try:
            client_packets = [payload for _, payload
                              in iter_packets(bytes(client.data or b""))]
        except Exception:
            client_packets = []

    # Login: the first client packet should be the handshake response.
    si = 1  # server packets consumed so far (the greeting)
    ci = 0
    if client_packets:
        response = parse_handshake_response(client_packets[0])
        ci = 1
        if response:
            if response["username"] and \
                    response["username"] not in summary["users"]:
                summary["users"].append(response["username"])
            if response["database"] and \
                    response["database"] not in summary["databases"]:
                summary["databases"].append(response["database"])

    pending_query = ""
    total_rows = 0

    def add_query(text: str) -> None:
        nonlocal pending_query
        pending_query = text
        if len(summary["queries"]) < MAX_QUERIES:
            summary["queries"].append(text)

    while si < len(server_packets) and ci < len(client_packets):
        current = server_packets[si]
        si += 1

        # LOCAL INFILE request: drain the client's raw file chunks.
        if current[:1] == _LOCAL_INFILE_HEADER:
            filename = parse_local_infile_request(current)
            blob = bytearray()
            while ci < len(client_packets):
                chunk = client_packets[ci]
                ci += 1
                if not chunk:
                    break  # empty packet ends the upload
                if len(blob) >= MAX_DATA_BYTES:
                    continue
                blob.extend(chunk)
            entry = {
                "query": pending_query,
                "filename": filename or "",
                "size": len(blob),
                "data": bytes(blob[:MAX_DATA_BYTES]),
            }
            if len(summary["local_infiles"]) < MAX_QUERIES:
                summary["local_infiles"].append(entry)
            pending_query = ""
            continue

        if current[:1] == _ERR_HEADER:
            if pending_query and len(summary["result_sets"]) < MAX_QUERIES:
                summary["result_sets"].append({
                    "query": pending_query, "columns": [], "rows": [],
                    "error": parse_err(current),
                })
            pending_query = ""
        elif current[:1] == _OK_HEADER or _is_eof(current):
            pending_query = ""
        else:
            # Assume a result set and let ResultSet consume the packets.
            result = ResultSet(server_packets[si - 1:])
            si += max(0, result.consumed - 1)
            remaining_rows = max(0, MAX_ROWS - total_rows)
            rows = result.rows[:remaining_rows] if remaining_rows else []
            total_rows += len(rows)
            if pending_query and len(summary["result_sets"]) < MAX_QUERIES:
                summary["result_sets"].append({
                    "query": pending_query,
                    "columns": result.column_names,
                    "rows": rows,
                    "error": result.error,
                })
                if "LOAD_FILE" in pending_query.upper() and result.rows:
                    values = [cell for row in result.rows for cell in row]
                    if len(summary["load_file_results"]) < MAX_QUERIES:
                        summary["load_file_results"].append({
                            "query": pending_query,
                            "values": values,
                        })
            pending_query = ""

        # Consume the next client command.
        while ci < len(client_packets):
            command = client_packets[ci]
            ci += 1
            if not command:
                continue
            if command[0] not in _COMMAND_BYTES:
                continue  # not a command packet: skip
            if command[0] == COM_QUERY:
                add_query(command[1:].decode("utf-8", "replace"))
            elif command[0] == COM_INIT_DB:
                name = command[1:].rstrip(b"\x00").decode("utf-8", "replace")
                if name and name not in summary["databases"]:
                    summary["databases"].append(name)
            elif command[0] == COM_QUIT:
                ci = len(client_packets)
            break  # each command expects exactly one server response

    # Leftover server responses with no matching command: surface their
    # result sets so truncated captures still show data.
    while si < len(server_packets) and not pending_query:
        current = server_packets[si]
        si += 1
        if current[:1] in (_OK_HEADER, _ERR_HEADER, _EOF_HEADER,
                           _LOCAL_INFILE_HEADER):
            continue
        result = ResultSet(server_packets[si - 1:])
        si += max(0, result.consumed - 1)
        if result.rows and total_rows < MAX_ROWS:
            take = result.rows[:MAX_ROWS - total_rows]
            total_rows += len(take)
            summary["result_sets"].append({
                "query": "", "columns": result.column_names, "rows": take,
                "error": result.error,
            })

    # Truncated captures may end before the server replies: still surface the
    # commands that were sent.
    while ci < len(client_packets):
        command = client_packets[ci]
        ci += 1
        if not command or command[0] not in _COMMAND_BYTES:
            continue
        if command[0] == COM_QUERY:
            text = command[1:].decode("utf-8", "replace")
            if len(summary["queries"]) < MAX_QUERIES and \
                    text not in summary["queries"]:
                summary["queries"].append(text)
        elif command[0] == COM_INIT_DB:
            name = command[1:].rstrip(b"\x00").decode("utf-8", "replace")
            if name and name not in summary["databases"]:
                summary["databases"].append(name)
    return summary


__all__ = [
    "MAX_DATA_BYTES", "MAX_QUERIES", "MAX_ROWS", "COLUMN_TYPES",
    "CLIENT_CONNECT_WITH_DB", "CLIENT_DEPRECATE_EOF", "CLIENT_LOCAL_FILES",
    "CLIENT_PLUGIN_AUTH", "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA",
    "CLIENT_PROTOCOL_41", "CLIENT_SECURE_CONNECTION", "CLIENT_SESSION_TRACK",
    "COM_FIELD_LIST", "COM_INIT_DB", "COM_PING", "COM_QUERY", "COM_QUIT",
    "ResultSet", "iter_packets", "parse_handshake", "parse_handshake_response",
    "parse_ok", "parse_err", "parse_eof", "parse_column_definition",
    "decode_text_row", "parse_local_infile_request", "load_data_chunks",
    "native_password_scramble", "caching_sha2_scramble",
    "verify_native_password", "verify_caching_sha2", "crack_response",
    "summarise_stream", "StreamLike",
]
