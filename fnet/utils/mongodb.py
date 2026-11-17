"""MongoDB wire protocol + BSON parsing over reassembled TCP streams.

The tshark MongoDB dissector covers single documents well but hides the
details CTF/forensics work needs: OP_MSG sections, SCRAM authentication
exchanges, GridFS chunk reassembly and documents spread over several packets.
This module decodes the wire format and BSON directly:

* all modern opcodes (OP_MSG, OP_QUERY, OP_REPLY, OP_GET_MORE, OP_INSERT,
  OP_UPDATE, OP_DELETE, OP_KILL_CURSORS);
* OP_MSG flag bits, ``kind 0`` bodies and ``kind 1`` document sequences,
  including the optional CRC-32C trailer;
* SCRAM-SHA-1/SCRAM-SHA-256 ``saslStart``/``saslContinue`` payloads;
* GridFS ``fs.files``/``fs.chunks`` documents reassembled into whole files
  with length/MD5 checks.

It is intentionally dependency free (no ``pymongo``) and pure, so the tests
run without a capture file or tshark.
"""
from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass, field

MAX_MESSAGE = 64 * 1024 * 1024
MAX_DOCUMENT = 16 * 1024 * 1024
MAX_GRIDFS_FILES = 200
MAX_GRIDFS_BYTES = 32 * 1024 * 1024

OPCODES = {
    1: "OP_REPLY",
    2001: "OP_UPDATE",
    2002: "OP_INSERT",
    2004: "OP_QUERY",
    2005: "OP_GET_MORE",
    2006: "OP_DELETE",
    2007: "OP_KILL_CURSORS",
    2012: "OP_COMPRESSED",
    2013: "OP_MSG",
}


class BsonError(ValueError):
    """Raised when a BSON document cannot be decoded."""


@dataclass(frozen=True)
class ObjectId:
    hex: str

    def __str__(self) -> str:
        return self.hex


@dataclass(frozen=True)
class BinaryValue:
    subtype: int
    data: bytes

    def text(self) -> str:
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(self.data).decode("ascii")

    def __str__(self) -> str:
        return self.text()


@dataclass
class MongoMessage:
    frame: str
    offset: int
    request_id: int
    response_to: int
    opcode: int
    name: str
    body: dict = field(default_factory=dict)
    raw: bytes = b""
    truncated: bool = False


def _cstring(data: bytes, index: int) -> tuple[str, int]:
    end = data.find(b"\x00", index)
    if end < 0:
        raise BsonError("unterminated cstring")
    return data[index:end].decode("utf-8", "replace"), end + 1


def _string(data: bytes, index: int) -> tuple[str, int]:
    if index + 4 > len(data):
        raise BsonError("truncated string length")
    length = struct.unpack_from("<i", data, index)[0]
    if length < 1 or index + 4 + length > len(data):
        raise BsonError("bad string length")
    raw = data[index + 4:index + 4 + length - 1]
    return raw.decode("utf-8", "replace"), index + 4 + length


def _value(kind: int, data: bytes, index: int, depth: int):
    if depth > 32:
        raise BsonError("BSON nesting too deep")
    if kind == 0x01:
        return struct.unpack_from("<d", data, index)[0], index + 8
    if kind == 0x02:
        return _string(data, index)
    if kind == 0x03:
        return decode_document(data, index, depth + 1)
    if kind == 0x04:
        doc, end = decode_document(data, index, depth + 1)
        try:
            array = [doc[key] for key in
                     sorted(doc, key=lambda item: int(item))]
        except (TypeError, ValueError):
            array = list(doc.values())
        return array, end
    if kind == 0x05:
        length = struct.unpack_from("<i", data, index)[0]
        subtype = data[index + 4]
        start = index + 5
        if length < 0 or start + length > len(data):
            raise BsonError("truncated binary value")
        return BinaryValue(subtype, data[start:start + length]), start + length
    if kind in (0x06, 0x0A):
        return None, index
    if kind == 0x07:
        return ObjectId(data[index:index + 12].hex()), index + 12
    if kind == 0x08:
        return bool(data[index]), index + 1
    if kind == 0x09:
        return struct.unpack_from("<q", data, index)[0], index + 8
    if kind == 0x0B:
        pattern, index = _cstring(data, index)
        options, index = _cstring(data, index)
        return (pattern, options), index
    if kind == 0x0C:
        _namespace, index = _string(data, index)
        return ObjectId(data[index:index + 12].hex()), index + 12
    if kind in (0x0D, 0x0E):
        return _string(data, index)
    if kind == 0x0F:
        total = struct.unpack_from("<i", data, index)[0]
        end = index + total
        code, cursor = _string(data, index + 4)
        _scope, _cursor = decode_document(data, cursor, depth + 1)
        return code, end
    if kind == 0x10:
        return struct.unpack_from("<i", data, index)[0], index + 4
    if kind == 0x11:
        increment, timestamp = struct.unpack_from("<II", data, index)
        return {"increment": increment, "timestamp": timestamp}, index + 8
    if kind == 0x12:
        return struct.unpack_from("<q", data, index)[0], index + 8
    if kind == 0x13:
        return "0x" + data[index:index + 16].hex(), index + 16
    if kind == 0x7F:
        return "MaxKey", index
    if kind == 0xFF:
        return "MinKey", index
    raise BsonError(f"unsupported BSON type 0x{kind:02x}")


def decode_document(data: bytes, offset: int = 0, depth: int = 0,
                    ) -> tuple[dict, int]:
    """Decode one BSON document, returning ``(document, next_offset)``."""
    if offset + 4 > len(data):
        raise BsonError("truncated BSON header")
    size = struct.unpack_from("<i", data, offset)[0]
    if size < 5 or size > MAX_DOCUMENT or offset + size > len(data):
        raise BsonError("bad BSON document size")
    end = offset + size
    index = offset + 4
    document: dict = {}
    while index < end - 1:
        kind = data[index]
        index += 1
        name, index = _cstring(data, index)
        value, index = _value(kind, data, index, depth)
        document[name] = value
    if index >= end or data[index] != 0:
        raise BsonError("missing BSON terminator")
    return document, end


def _parse_op_msg(body: bytes) -> dict:
    if len(body) < 4:
        raise BsonError("short OP_MSG")
    flags = struct.unpack_from("<I", body, 0)[0]
    payload = body[:-4] if flags & 1 and len(body) >= 8 else body
    index = 4
    sections: list[dict] = []
    while index < len(payload):
        kind = payload[index]
        index += 1
        if kind == 0:
            document, index = decode_document(payload, index)
            sections.append({"kind": 0, "document": document})
        elif kind == 1:
            if index + 4 > len(payload):
                raise BsonError("short OP_MSG sequence")
            size = struct.unpack_from("<i", payload, index)[0]
            end = index + size
            if size < 5 or end > len(payload):
                raise BsonError("bad OP_MSG sequence size")
            identifier, cursor = _cstring(payload, index + 4)
            documents = []
            while cursor < end:
                document, cursor = decode_document(payload, cursor)
                documents.append(document)
            sections.append({"kind": 1, "identifier": identifier,
                             "documents": documents})
            index = end
        else:
            raise BsonError("unknown OP_MSG section kind")
    return {"flags": flags, "sections": sections}


def _parse_op_query(body: bytes) -> dict:
    if len(body) < 4:
        raise BsonError("short OP_QUERY")
    flags = struct.unpack_from("<I", body, 0)[0]
    namespace, index = _cstring(body, 4)
    skip, number = struct.unpack_from("<ii", body, index)
    index += 8
    query, index = decode_document(body, index)
    documents = [query]
    if index < len(body):
        selector, index = decode_document(body, index)
        documents.append(selector)
    return {"flags": flags, "namespace": namespace, "skip": skip,
            "number_to_return": number, "documents": documents}


def _parse_op_reply(body: bytes) -> dict:
    if len(body) < 20:
        raise BsonError("short OP_REPLY")
    flags = struct.unpack_from("<I", body, 0)[0]
    cursor_id = struct.unpack_from("<q", body, 4)[0]
    starting = struct.unpack_from("<i", body, 12)[0]
    number = struct.unpack_from("<i", body, 16)[0]
    index = 20
    documents = []
    while index < len(body):
        document, index = decode_document(body, index)
        documents.append(document)
    return {"flags": flags, "cursor_id": cursor_id, "starting_from": starting,
            "number_returned": number, "documents": documents}


def _parse_op_get_more(body: bytes) -> dict:
    index = 4
    namespace, index = _cstring(body, index)
    number = struct.unpack_from("<i", body, index)[0]
    return {"namespace": namespace, "number_to_return": number}


def _parse_op_kill_cursors(body: bytes) -> dict:
    count = struct.unpack_from("<i", body, 4)[0]
    index = 8
    cursors = []
    for _ in range(max(0, count)):
        cursors.append(struct.unpack_from("<q", body, index)[0])
        index += 8
    return {"cursors": cursors}


def _parse_op_insert(body: bytes) -> dict:
    namespace, index = _cstring(body, 4)
    documents = []
    while index < len(body):
        document, index = decode_document(body, index)
        documents.append(document)
    return {"namespace": namespace, "documents": documents}


def _parse_op_update(body: bytes) -> dict:
    namespace, index = _cstring(body, 4)
    selector, index = decode_document(body, index)
    update, index = decode_document(body, index)
    return {"namespace": namespace, "documents": [selector, update]}


def _parse_op_delete(body: bytes) -> dict:
    namespace, index = _cstring(body, 4)
    selector, _ = decode_document(body, index)
    return {"namespace": namespace, "documents": [selector]}


def _parse_body(opcode: int, body: bytes) -> dict:
    if opcode == 2013:
        return _parse_op_msg(body)
    if opcode == 2004:
        return _parse_op_query(body)
    if opcode == 1:
        return _parse_op_reply(body)
    if opcode == 2005:
        return _parse_op_get_more(body)
    if opcode == 2007:
        return _parse_op_kill_cursors(body)
    if opcode == 2002:
        return _parse_op_insert(body)
    if opcode == 2001:
        return _parse_op_update(body)
    if opcode == 2006:
        return _parse_op_delete(body)
    return {"body_len": len(body)}


def parse_stream(data: bytes, frame_lookup=None) -> list[MongoMessage]:
    """Parse a reassembled MongoDB byte stream into wire messages."""
    messages: list[MongoMessage] = []
    index = 0
    size = len(data or b"")
    while index + 16 <= size:
        length, request_id, response_to, opcode = struct.unpack_from(
            "<iiii", data, index)
        if length < 16 or length > MAX_MESSAGE or index + length > size:
            break
        body = data[index + 16:index + length]
        frame = frame_lookup(index) if frame_lookup else ""
        truncated = False
        try:
            fields = _parse_body(opcode, body)
        except (BsonError, struct.error, IndexError):
            fields = {}
            truncated = True
        messages.append(MongoMessage(
            frame=frame, offset=index, request_id=request_id,
            response_to=response_to, opcode=opcode,
            name=OPCODES.get(opcode, f"OP_{opcode}"), body=fields,
            raw=data[index:index + length], truncated=truncated))
        index += length
    return messages


def namespace(message: MongoMessage) -> str:
    value = message.body.get("namespace") or message.body.get("full_name")
    if value:
        return str(value)
    # OP_MSG commands put the collection in the first command keyword, e.g.
    # ``{"find": "users", "$db": "app"}``.  The kind-1 section identifier
    # (``documents``) is a wire field, not a collection name.
    for section in message.body.get("sections") or []:
        document = section.get("document") or {}
        if document.get("$db"):
            for key, item in document.items():
                if not key.startswith("$") and isinstance(item, str):
                    return f"{document['$db']}.{item}"
    return ""


def documents(message: MongoMessage) -> list[dict]:
    """Return every BSON document carried by one message."""
    result: list[dict] = []
    for section in message.body.get("sections") or []:
        if section.get("kind") == 0 and isinstance(section.get("document"), dict):
            result.append(section["document"])
        for document in section.get("documents") or []:
            if isinstance(document, dict):
                result.append(document)
    for document in message.body.get("documents") or []:
        if isinstance(document, dict):
            result.append(document)
    return result


def collection_name(message: MongoMessage) -> str:
    value = namespace(message)
    return value.split(".", 1)[1] if "." in value else value


def iter_strings(value, depth: int = 0):
    """Yield every scalar rendered as text (used for flag/secret scanning)."""
    if depth > 32:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from iter_strings(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from iter_strings(item, depth + 1)
    elif isinstance(value, BinaryValue):
        yield value.text()
    elif value is not None:
        yield str(value)


def command_of(message: MongoMessage) -> str:
    """Return the first command keyword of an OP_MSG/OP_QUERY document."""
    for document in documents(message):
        for key in document:
            if not key.startswith("$"):
                return key
    return ""


def _payload_text(value) -> str:
    if isinstance(value, BinaryValue):
        return value.data.decode("latin-1", "replace")
    if isinstance(value, bytes):
        return value.decode("latin-1", "replace")
    if value is None:
        return ""
    return str(value)


def _scram_fields(payload: str) -> dict:
    fields: dict[str, str] = {}
    for part in (payload or "").split(","):
        key, separator, value = part.partition("=")
        if separator:
            fields[key] = value
    return fields


def scram_exchanges(messages: list[MongoMessage]) -> list[dict]:
    """Extract SCRAM-SHA-1/256 users, nonces, salts and proofs."""
    events: list[dict] = []
    active = ""
    for message in messages:
        for document in documents(message):
            mechanism = document.get("mechanism")
            text_mechanisms = document.get("saslSupportedMechs")
            if text_mechanisms and not mechanism:
                text = " ".join(str(item) for item in
                                (text_mechanisms if isinstance(
                                    text_mechanisms, list) else [text_mechanisms]))
                if "SCRAM" in text.upper():
                    events.append({"frame": message.frame,
                                   "kind": "mechanisms",
                                   "mechanism": text})
            if mechanism and "SCRAM" in str(mechanism).upper():
                active = str(mechanism)
            if "saslStart" in document or "saslContinue" in document or (
                    "payload" in document and ("conversationId" in document
                                               or "done" in document)):
                mechanism = mechanism or active
                if not mechanism or "SCRAM" not in str(mechanism).upper():
                    continue
                payload = _payload_text(document.get("payload"))
                fields = _scram_fields(payload)
                event = {"frame": message.frame, "kind": "scram",
                         "mechanism": str(mechanism), "payload": payload,
                         "raw_fields": fields}
                if "saslStart" in document:
                    # "n,,n=user,r=nonce"
                    bare = payload[3:] if payload.startswith("n,,") else payload
                    start = _scram_fields(bare)
                    event["user"] = start.get("n", "").replace("=2C", ",")
                    event["client_nonce"] = start.get("r", "")
                elif "p" in fields:
                    event["kind"] = "scram-final"
                    event["proof"] = fields.get("p", "")
                    event["client_nonce"] = fields.get("r", "")
                    event["channel"] = fields.get("c", "")
                elif "s" in fields:
                    event["kind"] = "scram-server"
                    event["salt"] = fields.get("s", "")
                    event["iterations"] = fields.get("i", "")
                    event["server_nonce"] = fields.get("r", "")
                elif "v" in fields:
                    event["kind"] = "scram-verified"
                    event["verifier"] = fields.get("v", "")
                elif "e" in fields:
                    event["kind"] = "scram-error"
                    event["error"] = fields.get("e", "")
                events.append(event)
    return events


def _doc_id(value) -> str:
    return str(value) if value is not None else ""


def gridfs_files(messages: list[MongoMessage]) -> list[dict]:
    """Reassemble ``fs.files``/``fs.chunks`` GridFS documents."""
    files: dict[str, dict] = {}
    chunks: dict[str, dict[int, tuple[bytes, str]]] = {}
    for message in messages:
        name = collection_name(message)
        for document in documents(message):
            if "files_id" in document and "data" in document:
                identifier = _doc_id(document.get("files_id"))
                number = document.get("n", 0)
                data = document.get("data")
                if not isinstance(data, BinaryValue):
                    continue
                chunks.setdefault(identifier, {})[int(number)] = (
                    data.data, message.frame)
            elif "filename" in document and ("chunkSize" in document
                                             or name.endswith(".files")):
                identifier = _doc_id(document.get("_id"))
                files[identifier] = {
                    "id": identifier,
                    "frame": message.frame,
                    "filename": str(document.get("filename") or ""),
                    "length": int(document.get("length") or 0),
                    "chunk_size": int(document.get("chunkSize") or 0),
                    "content_type": str(document.get("contentType")
                                        or document.get("content_type") or ""),
                    "upload_date": document.get("uploadDate"),
                    "md5": str(document.get("md5") or ""),
                }

    result: list[dict] = []
    identifiers = list(dict.fromkeys(list(files) + list(chunks)))
    for identifier in identifiers[:MAX_GRIDFS_FILES]:
        meta = files.get(identifier, {"id": identifier, "frame": "",
                                      "filename": "", "length": 0,
                                      "chunk_size": 0, "content_type": "",
                                      "md5": ""})
        parts = chunks.get(identifier, {})
        ordered = [parts[number][0] for number in sorted(parts)]
        first_frame = meta.get("frame") or (
            parts[min(parts)][1] if parts else "")
        data = b"".join(ordered)[:MAX_GRIDFS_BYTES]
        expected = [number for number in range(len(parts))]
        complete = (all(number in parts for number in expected)
                    and (not meta["length"] or len(data) >= meta["length"]))
        result.append({
            **meta,
            "frame": first_frame,
            "data": data,
            "chunks": len(parts),
            "complete": complete,
            "actual_length": len(data),
            "actual_md5": hashlib.md5(data).hexdigest(),
        })
    return result


def sensitive_tokens(value, depth: int = 0) -> list[str]:
    """Find user/password/token looking keys in a decoded BSON value."""
    tokens: list[str] = []
    if depth > 16:
        return tokens
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in ("user", "username", "login", "account", "password",
                           "passwd", "pwd", "token", "secret", "key") and \
                    not isinstance(item, (dict, list)):
                rendered = _payload_text(item)
                if rendered:
                    tokens.append(f"{key}={rendered}")
            tokens.extend(sensitive_tokens(item, depth + 1))
    elif isinstance(value, (list, tuple)):
        for item in value:
            tokens.extend(sensitive_tokens(item, depth + 1))
    return tokens
