"""PostgreSQL frontend/backend protocol parsing over reassembled streams.

tshark dissects the simple-query protocol well, but CTF and incident captures
often exercise the extended query protocol, ``SSLRequest``, ``COPY`` and binary
``Bind`` parameters that the field extractor does not surface.  This module
parses the message framing itself:

* startup packets: protocol version, ``user``/``database`` parameters,
  ``SSLRequest``/``GSSENCRequest``/``CancelRequest``;
* frontend: simple ``Query``; ``Parse``/``Bind``/``Describe``/``Execute``/
  ``Close``/``Sync``; password messages; ``COPY`` data;
* backend: authentication requests (cleartext/MD5/SASL), parameter status,
  row descriptions/data, command tags, errors and ``COPY`` data;
* binary parameter decoding based on the OIDs declared by ``Parse``.

Several message type bytes overlap between the two directions (``E`` is
``Execute`` from the client but ``ErrorResponse`` from the server).  Callers
should therefore pass ``direction="frontend"`` or ``"backend"``; when it is
unknown the parser falls back to a conservative heuristic.

All helpers are pure functions and tolerate truncated streams.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

PROTOCOL_V3 = 196608
SSL_REQUEST = 80877103
CANCEL_REQUEST = 80877102
GSSENC_REQUEST = 80877104

FRONTEND_TYPES = {
    "Q": "Query", "P": "Parse", "B": "Bind", "E": "Execute", "D": "Describe",
    "C": "Close", "S": "Sync", "H": "Flush", "X": "Terminate",
    "F": "FunctionCall", "d": "CopyData", "c": "CopyDone", "f": "CopyFail",
    "p": "PasswordMessage",
}
BACKEND_TYPES = {
    "R": "Authentication", "E": "ErrorResponse", "N": "NoticeResponse",
    "S": "ParameterStatus", "K": "BackendKeyData", "Z": "ReadyForQuery",
    "T": "RowDescription", "D": "DataRow", "C": "CommandComplete",
    "1": "ParseComplete", "2": "BindComplete", "3": "CloseComplete",
    "n": "NoData", "s": "PortalSuspended", "I": "EmptyQueryResponse",
    "G": "CopyInResponse", "H": "CopyOutResponse", "W": "CopyBothResponse",
    "d": "CopyData", "c": "CopyDone", "V": "FunctionCallResponse",
    "t": "ParameterDescription", "A": "NotificationResponse",
}

FRONTEND_ONLY = frozenset("QPBFXp")
BACKEND_ONLY = frozenset("RNKZT123nsIGWVtA")

#: Common type OIDs used to decode binary Bind parameters.
TYPE_NAMES = {
    16: "bool", 17: "bytea", 18: "char", 19: "name", 20: "int8",
    21: "int2", 23: "int4", 25: "text", 26: "oid", 114: "json",
    700: "float4", 701: "float8", 1043: "varchar", 1082: "date",
    1114: "timestamp", 1184: "timestamptz", 1700: "numeric",
    2950: "uuid", 3802: "jsonb",
}

MAX_MESSAGE = 64 * 1024 * 1024


class PgError(ValueError):
    """Raised when PostgreSQL framing cannot be decoded."""


@dataclass
class PgMessage:
    frame: str
    offset: int
    direction: str          # frontend | backend | startup
    type: str
    name: str
    fields: dict = field(default_factory=dict)
    raw: bytes = b""

    @property
    def query(self) -> str:
        return str(self.fields.get("query") or "")


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def cstring(self, index: int) -> tuple[str, int]:
        end = self.data.find(b"\x00", index)
        if end < 0:
            raise PgError("unterminated cstring")
        return self.data[index:end].decode("utf-8", "replace"), end + 1

    def int16(self, index: int) -> tuple[int, int]:
        if index + 2 > len(self.data):
            raise PgError("truncated int16")
        return struct.unpack_from(">h", self.data, index)[0], index + 2

    def int32(self, index: int) -> tuple[int, int]:
        if index + 4 > len(self.data):
            raise PgError("truncated int32")
        return struct.unpack_from(">i", self.data, index)[0], index + 4


def _decode_text(value: bytes) -> str:
    if value is None:
        return ""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


def decode_binary(value: bytes, oid: int | None = None) -> str:
    """Render one binary parameter value as readable text."""
    if value is None:
        return ""
    if oid == 16 and len(value) == 1:
        return "true" if value[0] else "false"
    if oid in (20, 21, 23, 26) and len(value) in (2, 4, 8):
        return str(int.from_bytes(value, "big", signed=True))
    if oid == 700 and len(value) == 4:
        return str(struct.unpack(">f", value)[0])
    if oid == 701 and len(value) == 8:
        return str(struct.unpack(">d", value)[0])
    if oid == 17 and value:
        return "\\x" + value.hex()
    # Unknown OID: try integers first, then UTF-8.
    if len(value) in (2, 4, 8):
        number = int.from_bytes(value, "big", signed=True)
        if abs(number) < 10 ** 15:
            return str(number)
    if all(32 <= byte < 127 or byte in (9, 10, 13) for byte in value):
        return value.decode("utf-8", "replace")
    return "\\x" + value.hex()


def _parse_startup(body: bytes) -> dict:
    if len(body) < 4:
        raise PgError("short startup packet")
    code = struct.unpack_from(">i", body, 0)[0]
    if code == SSL_REQUEST:
        return {"version": code, "kind": "SSLRequest"}
    if code == CANCEL_REQUEST:
        if len(body) >= 12:
            pid, key = struct.unpack_from(">ii", body, 4)
            return {"version": code, "kind": "CancelRequest",
                    "pid": pid, "secret": key}
        return {"version": code, "kind": "CancelRequest"}
    if code == GSSENC_REQUEST:
        return {"version": code, "kind": "GSSENCRequest"}
    params: dict[str, str] = {}
    index = 4
    while index < len(body):
        if body[index] == 0:
            break
        end = body.find(b"\x00", index)
        if end < 0:
            break
        key = body[index:end].decode("utf-8", "replace")
        index = end + 1
        end = body.find(b"\x00", index)
        if end < 0:
            break
        value = body[index:end].decode("utf-8", "replace")
        index = end + 1
        params[key] = value
    return {"version": code, "kind": "StartupMessage", "params": params}


def _parse_parse(reader: _Reader, body: bytes) -> dict:
    statement, index = reader.cstring(0)
    query, index = reader.cstring(index)
    count, index = reader.int16(index)
    oids: list[int] = []
    for _ in range(max(0, count)):
        oid, index = reader.int32(index)
        oids.append(oid)
    return {"statement": statement, "query": query, "param_oids": oids}


def _parse_bind(reader: _Reader, body: bytes, statements: dict) -> dict:
    portal, index = reader.cstring(0)
    statement, index = reader.cstring(index)
    format_count, index = reader.int16(index)
    formats: list[int] = []
    for _ in range(max(0, format_count)):
        fmt, index = reader.int16(index)
        formats.append(fmt)
    param_count, index = reader.int16(index)
    oids = list((statements.get(statement) or {}).get("param_oids") or [])
    params: list[dict] = []
    for position in range(max(0, param_count)):
        length, index = reader.int32(index)
        if length < 0:
            value = b""
            is_null = True
        else:
            if index + length > len(body):
                raise PgError("truncated Bind parameter")
            value = body[index:index + length]
            index += length
            is_null = False
        fmt = formats[position] if position < len(formats) else (
            formats[0] if formats else 0)
        oid = oids[position] if position < len(oids) else None
        rendered = "" if is_null else (
            decode_binary(value, oid) if fmt == 1 else _decode_text(value))
        params.append({"index": position, "oid": oid,
                       "type": TYPE_NAMES.get(oid or 0, ""),
                       "format": "binary" if fmt == 1 else "text",
                       "null": is_null, "value": rendered,
                       "raw_len": len(value)})
    result_count, index = reader.int16(index)
    result_formats: list[int] = []
    for _ in range(max(0, result_count)):
        fmt, index = reader.int16(index)
        result_formats.append(fmt)
    return {"portal": portal, "statement": statement,
            "params": params, "result_formats": result_formats}


def _parse_describe(reader: _Reader, body: bytes) -> dict:
    if not body:
        return {}
    target = chr(body[0])
    name, _ = reader.cstring(1)
    return {"target": target, "name": name}


def _parse_execute(reader: _Reader, body: bytes) -> dict:
    portal, index = reader.cstring(0)
    max_rows, _ = reader.int32(index)
    return {"portal": portal, "max_rows": max_rows}


def _parse_error(reader: _Reader, body: bytes) -> dict:
    fields: dict[str, str] = {}
    index = 0
    while index < len(body) and body[index] != 0:
        code = chr(body[index])
        index += 1
        end = body.find(b"\x00", index)
        if end < 0:
            break
        fields[code] = body[index:end].decode("utf-8", "replace")
        index = end + 1
    return fields


def _parse_auth(reader: _Reader, body: bytes) -> dict:
    if len(body) < 4:
        return {"auth_type": None}
    kind = struct.unpack_from(">i", body, 0)[0]
    info: dict = {"auth_type": kind}
    extra = body[4:]
    if kind == 5 and len(extra) >= 4:
        info["kind"] = "md5"
        info["salt"] = extra[:4].hex()
    elif kind == 3:
        info["kind"] = "cleartext"
    elif kind == 10:
        info["kind"] = "sasl"
        info["mechanisms"] = [item.decode("ascii", "replace")
                              for item in extra.split(b"\x00") if item]
    elif kind in (11, 12):
        info["kind"] = "sasl-continue" if kind == 11 else "sasl-final"
        info["data"] = _decode_text(extra)
    elif kind == 0:
        info["kind"] = "ok"
    return info


def _parse_row_description(reader: _Reader, body: bytes) -> dict:
    count, index = reader.int16(0)
    columns: list[dict] = []
    for _ in range(max(0, count)):
        name, index = reader.cstring(index)
        _table, index = reader.int32(index)
        _attnum, index = reader.int16(index)
        oid, index = reader.int32(index)
        _typlen, index = reader.int16(index)
        _typmod, index = reader.int32(index)
        fmt, index = reader.int16(index)
        columns.append({"name": name, "oid": oid,
                        "type": TYPE_NAMES.get(oid, ""),
                        "format": "binary" if fmt else "text"})
    return {"columns": columns}


def _parse_data_row(reader: _Reader, body: bytes) -> dict:
    count, index = reader.int16(0)
    values: list[str] = []
    for _ in range(max(0, count)):
        length, index = reader.int32(index)
        if length < 0:
            values.append("")
            continue
        if index + length > len(body):
            raise PgError("truncated DataRow")
        values.append(_decode_text(body[index:index + length]))
        index += length
    return {"values": values}


def _parse_parameter_status(reader: _Reader, body: bytes) -> dict:
    name, index = reader.cstring(0)
    value, _ = reader.cstring(index)
    return {name: value}


def _side(kind: str, direction: str) -> str:
    if direction in ("frontend", "backend"):
        return direction
    if kind in FRONTEND_ONLY:
        return "frontend"
    if kind in BACKEND_ONLY:
        return "backend"
    # Overlapping types: default to the frontend interpretation only for
    # lowercase copy messages, otherwise the backend reply is more likely.
    return "backend"


def _parse_message(kind: str, body: bytes, side: str,
                   statements: dict) -> dict:
    reader = _Reader(body)
    if side == "frontend":
        if kind == "Q":
            return {"query": _decode_text(body[:-1] if body.endswith(b"\x00")
                                          else body)}
        if kind == "P":
            return _parse_parse(reader, body)
        if kind == "B":
            return _parse_bind(reader, body, statements)
        if kind == "D":
            return _parse_describe(reader, body)
        if kind == "E":
            return _parse_execute(reader, body)
        if kind == "C":
            return _parse_describe(reader, body)
        if kind == "F":
            return {"body_len": len(body)}
        if kind == "p":
            return {"password": _decode_text(
                body[:-1] if body.endswith(b"\x00") else body)}
        if kind in ("d", "c", "f"):
            return {"data": body, "size": len(body)}
        return {}
    # backend
    if kind == "R":
        return _parse_auth(reader, body)
    if kind in ("E", "N"):
        return _parse_error(reader, body)
    if kind == "S":
        return _parse_parameter_status(reader, body)
    if kind == "Z":
        return {"status": chr(body[0]) if body else ""}
    if kind == "T":
        return _parse_row_description(reader, body)
    if kind == "D":
        return _parse_data_row(reader, body)
    if kind == "C":
        return {"tag": _decode_text(
            body[:-1] if body.endswith(b"\x00") else body)}
    if kind == "t":
        count, _ = reader.int16(0)
        return {"count": count}
    if kind in ("G", "H", "W"):
        return {"format": body[0] if body else 0,
                "columns": list(body[1:])}
    if kind == "K" and len(body) >= 8:
        pid, secret = struct.unpack_from(">ii", body, 0)
        return {"pid": pid, "secret": secret}
    if kind in ("d", "c"):
        return {"data": body, "size": len(body)}
    return {}


def parse_stream(data: bytes, frame_lookup=None, direction: str = "",
                 ) -> list[PgMessage]:
    """Parse one reassembled PostgreSQL direction into messages."""
    messages: list[PgMessage] = []
    statements: dict[str, dict] = {}
    index = 0
    size = len(data or b"")
    first = True
    while index < size:
        if first and data[index:index + 1] == b"\x00":
            if index + 4 > size:
                break
            length = struct.unpack_from(">i", data, index)[0]
            if length < 8 or index + length > size:
                break
            body = data[index + 4:index + length]
            fields = _parse_startup(body)
            frame = frame_lookup(index) if frame_lookup else ""
            messages.append(PgMessage(
                frame=frame, offset=index, direction="startup",
                type="startup", name=str(fields.get("kind", "StartupMessage")),
                fields=fields, raw=data[index:index + length]))
            index += length
            first = False
            continue
        first = False
        if index + 5 > size:
            break
        kind = data[index:index + 1].decode("latin-1")
        length = struct.unpack_from(">i", data, index + 1)[0]
        if length < 4 or index + 1 + length > size:
            break
        body = data[index + 5:index + 1 + length]
        side = _side(kind, direction)
        frame = frame_lookup(index) if frame_lookup else ""
        try:
            fields = _parse_message(kind, body, side, statements)
            if side == "frontend" and kind == "P":
                statements[fields.get("statement", "")] = fields
        except (PgError, struct.error, IndexError):
            fields = {"truncated": True}
        name = (FRONTEND_TYPES.get(kind) if side == "frontend"
                else BACKEND_TYPES.get(kind)) or kind
        messages.append(PgMessage(
            frame=frame, offset=index, direction=side, type=kind,
            name=name, fields=fields, raw=data[index:index + 1 + length]))
        index += 1 + length
    return messages


def queries(messages: list[PgMessage]) -> list[dict]:
    """Return simple and extended queries with their bound parameters."""
    pending: dict[str, dict] = {}
    results: list[dict] = []
    by_portal: dict[str, dict] = {}
    for message in messages:
        if message.type == "P" and message.direction == "frontend":
            pending[message.fields.get("statement", "")] = message.fields
        elif message.type == "B" and message.direction == "frontend":
            statement = message.fields.get("statement", "")
            parsed = pending.get(statement) or {}
            record = {
                "frame": message.frame,
                "statement": statement,
                "portal": message.fields.get("portal", ""),
                "query": parsed.get("query", ""),
                "params": message.fields.get("params") or [],
                "execute_frames": [],
            }
            results.append(record)
            by_portal[record["portal"]] = record
        elif message.type == "Q" and message.direction == "frontend":
            results.append({"frame": message.frame, "statement": "",
                            "portal": "", "query": message.query,
                            "params": [], "execute_frames": []})
        elif message.type == "E" and message.direction == "frontend":
            portal = message.fields.get("portal", "")
            record = by_portal.get(portal)
            if record is not None:
                record["execute_frames"].append(message.frame)
    return results


def auth_events(messages: list[PgMessage]) -> list[dict]:
    """Return authentication requests and cleartext passwords."""
    events: list[dict] = []
    for message in messages:
        if message.type == "R" and message.direction == "backend":
            kind = message.fields.get("kind")
            if kind in ("cleartext", "md5", "sasl", "sasl-continue",
                        "sasl-final"):
                events.append({"frame": message.frame, "request": kind,
                               "fields": message.fields})
        elif message.type == "p" and message.fields.get("password"):
            events.append({"frame": message.frame,
                           "password": message.fields["password"]})
    return events


def copy_data(messages: list[PgMessage]) -> list[dict]:
    """Collect ``COPY`` payloads per direction and detect COPY FROM STDIN."""
    copies: list[dict] = []
    current: dict | None = None
    for message in messages:
        if message.type in ("G", "H", "W") and message.direction == "backend":
            current = {"frame": message.frame,
                       "direction": {"G": "in", "H": "out",
                                     "W": "both"}[message.type],
                       "chunks": [], "bytes": 0}
            copies.append(current)
        elif message.type == "d" and current is not None:
            data = message.fields.get("data") or b""
            current["chunks"].append(data)
            current["bytes"] += len(data)
    for item in copies:
        item["data"] = b"".join(item.pop("chunks"))
    return copies


def startup_info(messages: list[PgMessage]) -> list[dict]:
    return [item.fields for item in messages if item.type == "startup"]
