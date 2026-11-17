"""HTTP/2 framing and HPACK decoding for the raw-stream extractor.

Wireshark dissects HTTP/2 only on its default ports and only when the
connection preface is present.  CTF captures frequently hide HTTP/2 on
non-standard ports, split a connection over several TCP segments, or carry it
inside an already-decrypted TLS stream.  This module parses the bytes itself:

* frame headers (DATA/HEADERS/CONTINUATION/SETTINGS/PRIORITY/RST_STREAM/
  PUSH_PROMISE/PING/GOAWAY/WINDOW_UPDATE) with padding and priority fields;
* modern HPACK (RFC 7541): static table, dynamic table with size updates,
  incremental/without/never indexing, integer and Huffman strings;
* per-direction stream state, header/trailer blocks, DATA body reassembly and
  END_STREAM tracking;
* gRPC message framing plus a best-effort Protobuf field walker.

The functions are pure (no tshark, no I/O), so they are unit-testable without a
capture file.  :func:`parse_direction` is fed one reassembled TCP direction at
a time from :mod:`fnet.utils.stream`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from fnet.utils._hpack_data import HUFFMAN_CODES, HUFFMAN_LENGTHS
from fnet.utils._hpack_data import STATIC_TABLE as _STATIC_TABLE_BYTES

#: RFC 7541 Appendix A as ``(name, value)`` text pairs (1-based index).
STATIC_TABLE: list[tuple[str, str]] = [
    (name.decode("utf-8"), value.decode("utf-8"))
    for name, value in _STATIC_TABLE_BYTES
]

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_FRAME = 16_777_215
MAX_HEADER_BLOCK = 4 * 1024 * 1024
MAX_BODY = 8 * 1024 * 1024
MAX_FRAMES = 200_000

FRAME_TYPES = {
    0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
    4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
    8: "WINDOW_UPDATE", 9: "CONTINUATION",
}

FLAGS = {
    "DATA": {0x1: "END_STREAM", 0x8: "PADDED"},
    "HEADERS": {0x1: "END_STREAM", 0x4: "END_HEADERS", 0x8: "PADDED",
                0x20: "PRIORITY"},
    "CONTINUATION": {0x4: "END_HEADERS"},
    "SETTINGS": {0x1: "ACK"},
    "PUSH_PROMISE": {0x4: "END_HEADERS", 0x8: "PADDED"},
    "PING": {0x1: "ACK"},
}

ERROR_CODES = {
    0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR",
    3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED",
    6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR",
    10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY",
    13: "HTTP_1_1_REQUIRED",
}

SETTINGS_NAMES = {
    1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
}

#: Header names whose values are credentials / session material.
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token",
}


# ---------------------------------------------------------------------------
# HPACK
# ---------------------------------------------------------------------------
def _build_huffman_tree() -> dict:
    root: dict = {}
    for symbol, (code, length) in enumerate(zip(HUFFMAN_CODES,
                                                HUFFMAN_LENGTHS)):
        node = root
        for bit in range(length - 1, -1, -1):
            node = node.setdefault((code >> bit) & 1, {})
        node["symbol"] = symbol
    return root


HUFFMAN_ROOT = _build_huffman_tree()


def huffman_decode(data: bytes) -> str:
    """Decode one HPACK Huffman string (RFC 7541 section 5.2)."""
    out = bytearray()
    node = HUFFMAN_ROOT
    bits_seen = 0
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            node = node.get(bit)
            if node is None:
                raise ValueError("invalid Huffman code")
            bits_seen += 1
            if "symbol" in node:
                symbol = node["symbol"]
                if symbol == 256:
                    raise ValueError("EOS symbol in Huffman string")
                out.append(symbol)
                node = HUFFMAN_ROOT
                bits_seen = 0
    # RFC 7541: the remaining bits must be the most significant bits of EOS
    # (all ones) and fewer than 8 bits long.
    if node is not HUFFMAN_ROOT:
        if bits_seen >= 8:
            raise ValueError("invalid Huffman padding")
        probe = node
        while isinstance(probe, dict) and "symbol" not in probe:
            if 0 not in probe or 1 not in probe:
                break
            probe = probe[1]
        if not (isinstance(probe, dict) and probe.get("symbol") == 256):
            raise ValueError("invalid Huffman padding")
    return out.decode("utf-8", "replace")


def decode_integer(data: bytes, offset: int, prefix: int) -> tuple[int, int]:
    """Decode an HPACK integer; returns ``(value, next_offset)``."""
    if offset >= len(data):
        raise ValueError("truncated integer")
    mask = (1 << prefix) - 1
    value = data[offset] & mask
    offset += 1
    if value < mask:
        return value, offset
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated integer")
        byte = data[offset]
        offset += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, offset
        if shift > 63:
            raise ValueError("integer overflow")


def _decode_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data):
        raise ValueError("truncated string")
    huffman = bool(data[offset] & 0x80)
    length, offset = decode_integer(data, offset, 7)
    if length < 0 or offset + length > len(data):
        raise ValueError("truncated string")
    raw = data[offset:offset + length]
    offset += length
    if huffman:
        return huffman_decode(raw), offset
    return raw.decode("utf-8", "replace"), offset


class HpackDecoder:
    """Stateful HPACK decoder (one instance per connection direction)."""

    def __init__(self, max_table_size: int = 4096) -> None:
        self.max_table_size = max(0, int(max_table_size))
        self.dynamic: list[tuple[str, str]] = []
        self.dynamic_size = 0
        self.size_updates: list[int] = []
        self.indexed_hits = 0
        self.literal_count = 0

    # -- dynamic table -------------------------------------------------
    def _size(self) -> int:
        return sum(len(name) + len(value) + 32 for name, value in self.dynamic)

    def _evict(self) -> None:
        while self.dynamic and self._size() > self.max_table_size:
            name, value = self.dynamic.pop()
            self.dynamic_size -= len(name) + len(value) + 32
        self.dynamic_size = self._size()

    def _add(self, name: str, value: str) -> None:
        if len(name) + len(value) + 32 > self.max_table_size:
            return
        self.dynamic.insert(0, (name, value))
        self._evict()

    def _lookup(self, index: int) -> tuple[str, str]:
        if index <= 0:
            raise ValueError(f"invalid header index {index}")
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        position = index - len(STATIC_TABLE) - 1
        if position >= len(self.dynamic):
            raise ValueError(f"header index {index} outside dynamic table")
        return self.dynamic[position]

    # -- decoding ------------------------------------------------------
    def decode(self, data: bytes) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = []
        offset = 0
        length = len(data)
        while offset < length:
            first = data[offset]
            if first & 0x80:  # indexed header field
                index, offset = decode_integer(data, offset, 7)
                headers.append(self._lookup(index))
                self.indexed_hits += 1
                continue
            if first & 0x40:  # literal with incremental indexing
                index, offset = decode_integer(data, offset, 6)
                if index:
                    name = self._lookup(index)[0]
                else:
                    name, offset = _decode_string(data, offset)
                value, offset = _decode_string(data, offset)
                headers.append((name, value))
                self._add(name, value)
                self.literal_count += 1
                continue
            if first & 0x20:  # dynamic table size update
                size, offset = decode_integer(data, offset, 5)
                self.max_table_size = min(size, self.max_table_size)
                self._evict()
                self.size_updates.append(size)
                continue
            # Literal without indexing (0000) / never indexed (0001).
            never = bool(first & 0x10)
            index, offset = decode_integer(data, offset, 4)
            if index:
                name = self._lookup(index)[0]
            else:
                name, offset = _decode_string(data, offset)
            value, offset = _decode_string(data, offset)
            headers.append((name, value))
            self.literal_count += 1
            continue
        return headers


def encode_integer(value: int, prefix: int, mask: int = 0x00) -> bytes:
    """Encode an HPACK integer (used by the sample generator and tests)."""
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes([mask | value])
    out = bytearray([mask | limit])
    value -= limit
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_literal(name: str, value: str, *, indexing: bool = False) -> bytes:
    """Encode a literal header field without Huffman (sample/test helper)."""
    raw_name = name.encode("utf-8")
    raw_value = value.encode("utf-8")
    prefix = 6 if indexing else 4
    first = 0x40 if indexing else 0x00
    out = bytearray(encode_integer(0, prefix, first))
    out += encode_integer(len(raw_name), 7)
    out += raw_name
    out += encode_integer(len(raw_value), 7)
    out += raw_value
    return bytes(out)


# ---------------------------------------------------------------------------
# Frames and streams
# ---------------------------------------------------------------------------
@dataclass
class H2Frame:
    type: int
    flags: int
    stream: int
    payload: bytes
    offset: int = 0
    frame: str = ""

    @property
    def name(self) -> str:
        return FRAME_TYPES.get(self.type, f"TYPE_{self.type}")

    def flag_names(self) -> list[str]:
        table = FLAGS.get(self.name, {})
        return [label for bit, label in table.items() if self.flags & bit]

    def describe(self) -> str:
        flags = ",".join(self.flag_names())
        return f"{self.name} stream={self.stream}" + (f" [{flags}]" if flags else "")


@dataclass
class H2Stream:
    stream: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    trailers: list[tuple[str, str]] = field(default_factory=list)
    body: bytearray = field(default_factory=bytearray)
    frames: list[str] = field(default_factory=list)
    ended: bool = False
    padding: int = 0

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers + self.trailers:
            if key.lower() == lowered:
                return value
        return default

    def headers_dict(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in self.headers:
            out.setdefault(key.lower(), value)
        return out

    @property
    def body_bytes(self) -> bytes:
        return bytes(self.body)

    @property
    def truncated(self) -> bool:
        return len(self.body) >= MAX_BODY


@dataclass
class H2Side:
    """Result of parsing one direction of a connection."""

    streams: dict[int, H2Stream] = field(default_factory=dict)
    settings: list[dict] = field(default_factory=list)
    priorities: dict[int, dict] = field(default_factory=dict)
    resets: dict[int, int] = field(default_factory=dict)
    goaway: dict | None = None
    pings: int = 0
    window_updates: int = 0
    pushes: list[int] = field(default_factory=list)
    frame_count: int = 0
    truncated: bool = False
    decode_errors: int = 0

    def stream(self, number: int) -> H2Stream:
        item = self.streams.get(number)
        if item is None:
            item = H2Stream(stream=number)
            self.streams[number] = item
        return item


def parse_frames(data: bytes, frame_at: Callable[[int], str] | None = None,
                 *, max_frames: int = MAX_FRAMES) -> tuple[list[H2Frame], bool]:
    """Split a byte stream into HTTP/2 frames.

    Returns ``(frames, truncated)``.  A trailing partial frame is dropped and
    reported through ``truncated`` so the caller can warn about packet loss.
    """
    offset = 0
    length = len(data)
    if data.startswith(PREFACE):
        offset = len(PREFACE)
    frames: list[H2Frame] = []
    truncated = False
    while offset + 9 <= length:
        header = data[offset:offset + 9]
        frame_length = int.from_bytes(header[0:3], "big")
        frame_type = header[3]
        flags = header[4]
        stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
        if frame_length > MAX_FRAME:
            truncated = True
            break
        if offset + 9 + frame_length > length:
            truncated = True
            break
        payload = data[offset + 9:offset + 9 + frame_length]
        frame_number = frame_at(offset) if frame_at else ""
        frames.append(H2Frame(frame_type, flags, stream, payload, offset,
                              frame_number))
        offset += 9 + frame_length
        if len(frames) >= max_frames:
            truncated = True
            break
    return frames, truncated


def _strip_padding(payload: bytes, padded: bool) -> tuple[bytes, int]:
    if not padded:
        return payload, 0
    if not payload:
        raise ValueError("padded frame without pad length")
    pad = payload[0]
    if pad + 1 > len(payload):
        raise ValueError("invalid frame padding")
    return payload[1:len(payload) - pad], pad


def parse_direction(data: bytes, frame_at: Callable[[int], str] | None = None,
                    *, max_body: int = MAX_BODY) -> H2Side:
    """Parse one direction (client->server or server->client) of a connection."""
    side = H2Side()
    frames, truncated = parse_frames(data, frame_at)
    side.frame_count = len(frames)
    side.truncated = truncated
    decoder = HpackDecoder()
    pending: dict[int, dict] = {}
    for frame in frames:
        side.stream(frame.stream)
        try:
            _apply_frame(side, frame, decoder, pending, max_body)
        except (ValueError, IndexError, KeyError):
            side.decode_errors += 1
            continue
    # A header block without END_HEADERS is incomplete; expose nothing for it.
    if pending:
        side.truncated = True
    return side


def _apply_frame(side: H2Side, frame: H2Frame, decoder: HpackDecoder,
                 pending: dict[int, dict], max_body: int) -> None:
    name = frame.name
    if name == "SETTINGS":
        if frame.flags & 0x1 or frame.stream:
            return
        entries = []
        for offset in range(0, len(frame.payload) - 5, 6):
            key = int.from_bytes(frame.payload[offset:offset + 2], "big")
            value = int.from_bytes(frame.payload[offset + 2:offset + 6], "big")
            entries.append({"id": key, "name": SETTINGS_NAMES.get(key, str(key)),
                            "value": value})
        side.settings.append({"frame": frame.frame, "entries": entries})
        return
    if name == "PING":
        side.pings += 1
        return
    if name == "GOAWAY":
        if len(frame.payload) >= 8:
            last = int.from_bytes(frame.payload[0:4], "big") & 0x7FFFFFFF
            code = int.from_bytes(frame.payload[4:8], "big")
            debug = frame.payload[8:].decode("utf-8", "replace")
            side.goaway = {"last_stream": last, "code": code,
                           "name": ERROR_CODES.get(code, str(code)),
                           "debug": debug[:400], "frame": frame.frame}
        return
    if name == "WINDOW_UPDATE":
        side.window_updates += 1
        return
    if name == "PRIORITY":
        if len(frame.payload) >= 5:
            dependency = int.from_bytes(frame.payload[0:4], "big")
            side.priorities[frame.stream] = {
                "dependency": dependency & 0x7FFFFFFF,
                "exclusive": bool(dependency & 0x80000000),
                "weight": frame.payload[4] + 1,
            }
        return
    if name == "RST_STREAM":
        if len(frame.payload) >= 4:
            code = int.from_bytes(frame.payload[0:4], "big")
            side.resets[frame.stream] = code
            side.stream(frame.stream).ended = True
        return
    if name in ("HEADERS", "PUSH_PROMISE"):
        stream = side.stream(frame.stream)
        stream.frames.append(frame.frame)
        if name == "PUSH_PROMISE":
            if len(frame.payload) < 4:
                raise ValueError("short push promise")
            promised = int.from_bytes(frame.payload[0:4], "big") & 0x7FFFFFFF
            side.pushes.append(promised)
            payload = frame.payload[4:]
            padding = bool(frame.flags & 0x8)
            payload, _pad = _strip_padding(payload, padding)
            state = pending.setdefault(promised, {"block": bytearray(),
                                                  "trailers": False,
                                                  "end_stream": False})
            state["block"] += payload
            if frame.flags & 0x4:
                block = bytes(state.pop("block"))
                pending.pop(promised, None)
                side.stream(promised).headers.extend(
                    decoder.decode(block[:MAX_HEADER_BLOCK]))
            return
        payload = frame.payload
        if frame.flags & 0x8:
            payload, pad = _strip_padding(payload, True)
            stream.padding += pad
        if frame.flags & 0x20:
            if len(payload) < 5:
                raise ValueError("short priority block")
            dependency = int.from_bytes(payload[0:4], "big")
            side.priorities[frame.stream] = {
                "dependency": dependency & 0x7FFFFFFF,
                "exclusive": bool(dependency & 0x80000000),
                "weight": payload[4] + 1,
            }
            payload = payload[5:]
        state = pending.setdefault(frame.stream, {
            "block": bytearray(), "trailers": bool(stream.headers),
        })
        if state.get("block") is None:
            state["block"] = bytearray()
        state["block"] += payload
        state["end_stream"] = bool(frame.flags & 0x1)
        if frame.flags & 0x4:
            block = bytes(state.pop("block"))
            pending.pop(frame.stream, None)
            headers = decoder.decode(block[:MAX_HEADER_BLOCK])
            if stream.headers:
                stream.trailers.extend(headers)
            else:
                stream.headers.extend(headers)
            if state.get("end_stream"):
                stream.ended = True
        return
    if name == "CONTINUATION":
        state = pending.get(frame.stream)
        if not state or state.get("block") is None:
            raise ValueError("continuation without a pending header block")
        state["block"] += frame.payload
        if frame.flags & 0x4:
            block = bytes(state.pop("block"))
            pending.pop(frame.stream, None)
            stream = side.stream(frame.stream)
            headers = decoder.decode(block[:MAX_HEADER_BLOCK])
            if stream.headers:
                stream.trailers.extend(headers)
            else:
                stream.headers.extend(headers)
            if state.get("end_stream"):
                stream.ended = True
        return
    if name == "DATA":
        stream = side.stream(frame.stream)
        payload, pad = _strip_padding(frame.payload, bool(frame.flags & 0x8))
        stream.padding += pad
        stream.frames.append(frame.frame)
        room = max(0, max_body - len(stream.body))
        stream.body.extend(payload[:room])
        if len(payload) > room:
            side.truncated = True
        if frame.flags & 0x1:
            stream.ended = True


# ---------------------------------------------------------------------------
# gRPC / Protobuf
# ---------------------------------------------------------------------------
def grpc_messages(body: bytes, *, max_messages: int = 1000) -> list[tuple[bool, bytes]]:
    """Split a gRPC DATA body into ``(compressed, payload)`` messages."""
    messages: list[tuple[bool, bytes]] = []
    offset = 0
    while offset + 5 <= len(body) and len(messages) < max_messages:
        compressed = bool(body[offset] & 0x1)
        length = int.from_bytes(body[offset + 1:offset + 5], "big")
        if length < 0 or offset + 5 + length > len(body):
            break
        messages.append((compressed, body[offset + 5:offset + 5 + length]))
        offset += 5 + length
    return messages


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            break
    raise ValueError("truncated varint")


def protobuf_fields(data: bytes, *, depth: int = 0,
                    max_fields: int = 200) -> list[str]:
    """Best-effort Protobuf walker for readable gRPC payload summaries."""
    if depth > 3 or not data:
        return []
    lines: list[str] = []
    offset = 0
    while offset < len(data) and len(lines) < max_fields:
        try:
            key, offset = _read_varint(data, offset)
        except ValueError:
            break
        number, wire = key >> 3, key & 0x7
        if number == 0:
            break
        try:
            if wire == 0:
                value, offset = _read_varint(data, offset)
                lines.append(f"#{number} varint={value}")
            elif wire == 1:
                if offset + 8 > len(data):
                    break
                value = int.from_bytes(data[offset:offset + 8], "little")
                lines.append(f"#{number} fixed64={value}")
                offset += 8
            elif wire == 2:
                length, offset = _read_varint(data, offset)
                if length < 0 or offset + length > len(data):
                    break
                chunk = data[offset:offset + length]
                offset += length
                text = chunk.decode("utf-8", "strict") if _utf8ish(chunk) else ""
                if text and text.isprintable():
                    lines.append(f"#{number} string={text[:200]}")
                elif chunk:
                    nested = protobuf_fields(chunk, depth=depth + 1,
                                             max_fields=max_fields - len(lines))
                    if nested:
                        lines.append(f"#{number} message:")
                        lines.extend("  " + item for item in nested)
                    else:
                        lines.append(f"#{number} bytes={chunk[:32].hex()}"
                                     + ("…" if len(chunk) > 32 else ""))
            elif wire == 5:
                if offset + 4 > len(data):
                    break
                value = int.from_bytes(data[offset:offset + 4], "little")
                lines.append(f"#{number} fixed32={value}")
                offset += 4
            else:
                break
        except ValueError:
            break
    return lines


def _utf8ish(chunk: bytes) -> bool:
    if not chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(32 <= byte < 127 or byte in (9, 10, 13) or byte > 127
               for byte in chunk)


def is_grpc(headers: list[tuple[str, str]]) -> bool:
    for key, value in headers:
        if key.lower() == "content-type" and "grpc" in value.lower():
            return True
    return False


def looks_like_http2(data: bytes, *, min_frames: int = 1) -> bool:
    """Cheap check used before spending time on a full parse."""
    if not data:
        return False
    if data.startswith(PREFACE):
        return True
    frames, _truncated = parse_frames(data)
    return len(frames) >= min_frames and all(
        frame.type <= 9 for frame in frames[:min_frames])