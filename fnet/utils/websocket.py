"""Pure-Python WebSocket frame parsing and message reassembly.

tshark's WebSocket dissector is good at single frames but hides the details of
fragmentation and ``permessage-deflate``.  This module parses raw TCP payloads
so the handler can:

* skip the HTTP Upgrade handshake and resume at the first frame;
* unmask client-to-server frames;
* join continuation frames into one application message;
* inflate ``permessage-deflate`` messages;
* keep control frames (ping/pong/close) separate from data messages.

The parser is intentionally tolerant: incomplete frames stay in the buffer and
are completed by the next TCP payload of the same direction.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass, field

OP_CONTINUATION = 0
OP_TEXT = 1
OP_BINARY = 2
OP_CLOSE = 8
OP_PING = 9
OP_PONG = 10

OPCODES = {
    OP_CONTINUATION: "continuation",
    OP_TEXT: "text",
    OP_BINARY: "binary",
    OP_CLOSE: "close",
    OP_PING: "ping",
    OP_PONG: "pong",
}

CONTROL_OPCODES = frozenset({OP_CLOSE, OP_PING, OP_PONG})
DATA_OPCODES = frozenset({OP_TEXT, OP_BINARY})

MAX_FRAME = 64 * 1024 * 1024
MAX_MESSAGE = 128 * 1024 * 1024


@dataclass
class Frame:
    fin: bool
    opcode: int
    payload: bytes
    masked: bool = False
    rsv1: bool = False
    frame: str = ""

    @property
    def name(self) -> str:
        return OPCODES.get(self.opcode, f"opcode-{self.opcode}")

    @property
    def control(self) -> bool:
        return self.opcode in CONTROL_OPCODES


@dataclass
class Message:
    opcode: int
    payload: bytes
    frames: list[str] = field(default_factory=list)
    compressed: bool = False
    control: bool = False

    @property
    def name(self) -> str:
        return OPCODES.get(self.opcode, f"opcode-{self.opcode}")

    @property
    def binary(self) -> bool:
        return self.opcode == OP_BINARY


def strip_http_handshake(data: bytes) -> tuple[bytes, bool]:
    """Drop an HTTP Upgrade request/response from the front of ``data``."""
    if b"\r\n\r\n" not in data:
        return data, False
    head, _, rest = data.partition(b"\r\n\r\n")
    lowered = head.lower()
    if (b"http/1." in lowered or b"get " in lowered or b"post " in lowered
            or b"sec-websocket" in lowered or b"upgrade: websocket" in lowered):
        return rest, True
    return data, False


def unmask(payload: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(payload)
    return bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))


def _parse_one(buffer: bytearray, frame_hint: str) -> tuple[Frame, int] | None:
    if len(buffer) < 2:
        return None
    first, second = buffer[0], buffer[1]
    fin = bool(first & 0x80)
    rsv1 = bool(first & 0x40)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(buffer) < 4:
            return None
        length = int.from_bytes(buffer[2:4], "big")
        offset = 4
    elif length == 127:
        if len(buffer) < 10:
            return None
        length = int.from_bytes(buffer[2:10], "big")
        offset = 10
    if length > MAX_FRAME:
        # Corrupt stream: skip one byte so the caller can resynchronise.
        del buffer[:1]
        return None
    key = b""
    if masked:
        if len(buffer) < offset + 4:
            return None
        key = bytes(buffer[offset:offset + 4])
        offset += 4
    total = offset + length
    if len(buffer) < total:
        return None
    payload = bytes(buffer[offset:total])
    if masked:
        payload = unmask(payload, key)
    del buffer[:total]
    return Frame(fin=fin, opcode=opcode, payload=payload, masked=masked,
                 rsv1=rsv1, frame=frame_hint), total


class FrameParser:
    """Incremental parser for one direction of one TCP stream."""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.handshake_done = False
        self._frame_hint = ""

    def feed(self, data: bytes, frame: str = "") -> list[Frame]:
        if not data:
            return []
        if not self.buffer and frame:
            self._frame_hint = frame
        if not self.handshake_done:
            stripped, done = strip_http_handshake(data)
            if done:
                self.handshake_done = True
                data = stripped
            else:
                # The handshake may span several segments; wait for CRLFCRLF.
                self.buffer.extend(data)
                if b"\r\n\r\n" not in self.buffer:
                    return []
                stripped, done = strip_http_handshake(bytes(self.buffer))
                if not done:
                    self.handshake_done = True
                    stripped = bytes(self.buffer)
                self.buffer.clear()
                data = stripped
                self.handshake_done = True
        self.buffer.extend(data)
        frames: list[Frame] = []
        while True:
            parsed = _parse_one(self.buffer, self._frame_hint or frame)
            if parsed is None:
                break
            frame_obj, _consumed = parsed
            frames.append(frame_obj)
            # A frame that starts in this chunk gets this chunk's frame
            # number; the next frame may span into the following packet.
            self._frame_hint = frame if self.buffer else ""
        return frames


def parse_frames(data: bytes, frame: str = "") -> list[Frame]:
    parser = FrameParser()
    parser.handshake_done = True
    return parser.feed(data, frame)


def inflate_message(payload: bytes, max_size: int = MAX_MESSAGE) -> bytes:
    """Inflate one ``permessage-deflate`` payload (raw DEFLATE)."""
    if not payload:
        return b""
    # RFC 7692 strips the trailing empty DEFLATE block; put it back.
    data = payload
    if not data.endswith(b"\x00\x00\xff\xff"):
        data += b"\x00\x00\xff\xff"
    try:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        out = decompressor.decompress(data, max_size)
        out += decompressor.flush()
        return out
    except zlib.error:
        return b""


def reassemble(frames: list[Frame], inflate: bool = True) -> list[Message]:
    """Join fragmented data frames, keeping control frames separate."""
    messages: list[Message] = []
    current: Message | None = None

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        if inflate and current.compressed:
            plain = inflate_message(current.payload)
            if plain:
                current.payload = plain
        messages.append(current)
        current = None

    for frame in frames:
        if frame.control:
            # Control frames may be interleaved with a fragmented message and
            # must not terminate it (RFC 6455 §5.4).
            messages.append(Message(opcode=frame.opcode, payload=frame.payload,
                                    frames=[frame.frame], control=True))
            continue
        if frame.opcode in DATA_OPCODES:
            finish()
            current = Message(opcode=frame.opcode, payload=frame.payload,
                              frames=[frame.frame], compressed=frame.rsv1)
        elif frame.opcode == OP_CONTINUATION:
            if current is None:
                # An orphan continuation: keep it as a binary message so no
                # captured bytes are silently dropped.
                current = Message(opcode=OP_BINARY, payload=frame.payload,
                                  frames=[frame.frame])
            else:
                current.payload += frame.payload
                current.frames.append(frame.frame)
        else:
            # Reserved/extension opcode: surface it instead of dropping it.
            finish()
            messages.append(Message(opcode=frame.opcode, payload=frame.payload,
                                    frames=[frame.frame], control=True))
            continue
        if frame.fin:
            finish()
        if current is not None and len(current.payload) > MAX_MESSAGE:
            current.payload = current.payload[:MAX_MESSAGE]
            finish()
    finish()
    return messages


def parse_messages(data: bytes, inflate: bool = True) -> list[Message]:
    return reassemble(parse_frames(data), inflate=inflate)


def looks_like_frame(data: bytes) -> bool:
    """Cheap sanity check used before treating a stream as WebSocket."""
    if len(data) < 2:
        return False
    opcode = data[0] & 0x0F
    return opcode <= 10 and not (data[0] & 0x30)
