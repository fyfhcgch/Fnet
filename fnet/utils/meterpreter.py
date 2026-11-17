"""Meterpreter / metsvc TCP TLV protocol parser (pure stdlib, offline).

Metasploit Meterpreter speaks a length-prefixed TLV protocol over its TCP
channel (the legacy ``metsvc`` service and every ``meterpreter`` payload
before encryption).  The wire format is::

    packet TLV:  length(u32) + type(u32) + value[length - 8]

``length`` counts itself (header included).  The first TLV of each exchange
carries a packet type (``PACKET_TYPE_REQUEST/RESPONSE/PLAIN_*``); its value
contains the nested per-message TLVs:

* ``COMMAND_ID`` (1)          - the staged command number (uint)
* ``REQUEST_ID`` (2)          - correlation GUID (string)
* ``EXCEPTION`` (3)           - error message (complex/string)
* ``RESULT`` (4)              - completion status (uint)
* ``STRING`` (10) / ``UINT`` (12) / ``BOOL`` (13) - command parameters

Meta-type bits live in the upper half word of the type field (see
``Rex::Post::Meterpreter::Packet`` in the metasploit source for the
authoritative table); the low 16 bits select the concrete TLV id.

Everything here is a pure byte parser: no tshark, no third-party packages,
which keeps it unit-testable without a capture file.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- meta types (upper half word of the TLV type) -------------------------
TLV_META_TYPE_NONE = 0
TLV_META_TYPE_STRING = 1 << 16
TLV_META_TYPE_UINT = 1 << 17
TLV_META_TYPE_RAW = 1 << 18
TLV_META_TYPE_BOOL = 1 << 19
TLV_META_TYPE_QWORD = 1 << 20
TLV_META_TYPE_COMPRESSED = 1 << 29
TLV_META_TYPE_COMPLEX = 1 << 30
TLV_META_TYPE_GROUP = 1 << 31

META_MASK = 0xFFFF0000
ID_MASK = 0x0000FFFF

# --- packet types (TLV ids 0/1/10/11 with meta type NONE) ------------------
PACKET_TYPES = {
    0: "request",
    1: "response",
    10: "plain_request",
    11: "plain_response",
}

# --- well-known TLV ids (metasploit core/standard api) ---------------------
TLV_NAMES = {
    (TLV_META_TYPE_UINT, 1): "COMMAND_ID",
    (TLV_META_TYPE_STRING, 2): "REQUEST_ID",
    (TLV_META_TYPE_COMPLEX, 3): "EXCEPTION",
    (TLV_META_TYPE_UINT, 4): "RESULT",
    (TLV_META_TYPE_STRING, 10): "STRING",
    (TLV_META_TYPE_RAW, 11): "RAW",
    (TLV_META_TYPE_UINT, 12): "UINT",
    (TLV_META_TYPE_BOOL, 13): "BOOL",
    (TLV_META_TYPE_UINT, 14): "LENGTH",
    (TLV_META_TYPE_RAW, 15): "MEMORY",
}

#: Maximum sane TLV length so garbage cannot make us allocate wildly.
MAX_TLV_LENGTH = 16 * 1024 * 1024
HEADER_LEN = 8


@dataclass
class Tlv:
    """One raw TLV element from the byte stream."""

    type: int
    value: bytes
    length: int
    offset: int
    endianness: str

    @property
    def meta(self) -> int:
        return self.type & META_MASK

    @property
    def tlv_id(self) -> int:
        return self.type & ID_MASK

    @property
    def name(self) -> str:
        return TLV_NAMES.get((self.meta, self.tlv_id),
                             f"0x{self.type & 0xFFFFFFFF:08x}")


@dataclass
class MeterpreterPacket:
    """One parsed packet TLV plus its decoded nested fields."""

    kind: str
    type: int
    frame: str
    offset: int
    length: int
    command_id: int | None = None
    request_id: str = ""
    strings: list[str] = field(default_factory=list)
    uints: list[int] = field(default_factory=list)
    bools: list[bool] = field(default_factory=list)
    exception: str = ""
    result: int | None = None
    unknown: list[str] = field(default_factory=list)

    @property
    def command_hex(self) -> str:
        return "-" if self.command_id is None else \
            f"0x{self.command_id:08x}"


@dataclass
class ParseResult:
    """Result of parsing one direction of a TCP stream."""

    packets: list[MeterpreterPacket] = field(default_factory=list)
    extra_tlvs: list[Tlv] = field(default_factory=list)
    #: bytes not consumed by a clean TLV walk (0 when the stream parses fully)
    leftover: int = 0
    endianness: str = "big"


def _tlv_name(tlv_type: int) -> str:
    return TLV_NAMES.get((tlv_type & META_MASK, tlv_type & ID_MASK),
                         f"0x{tlv_type & 0xFFFFFFFF:08x}")


def _decode_value(tlv: Tlv) -> str:
    """Human readable value for non-container TLVs."""
    if tlv.meta in (TLV_META_TYPE_STRING, TLV_META_TYPE_COMPLEX):
        return tlv.value.rstrip(b"\x00").decode("utf-8", "replace")
    if tlv.meta == TLV_META_TYPE_UINT:
        return str(int.from_bytes(tlv.value[:4], tlv.endianness))
    if tlv.meta == TLV_META_TYPE_BOOL:
        return "true" if tlv.value[:1] not in (b"", b"\x00") else "false"
    if tlv.meta == TLV_META_TYPE_QWORD:
        return str(int.from_bytes(tlv.value[:8], tlv.endianness))
    return tlv.value[:64].hex() if tlv.value else ""


def _walk_tlvs(data: bytes, start: int, endianness: str) -> tuple[
        list[Tlv], int]:
    """Parse sequential TLVs; stop at the first malformed header."""
    tlvs: list[Tlv] = []
    offset = start
    order = "big" if endianness == "big" else "little"
    while offset + HEADER_LEN <= len(data):
        length = int.from_bytes(data[offset:offset + 4], order)
        if not HEADER_LEN <= length <= MAX_TLV_LENGTH \
                or offset + length > len(data):
            break
        tlv_type = int.from_bytes(data[offset + 4:offset + 8], order)
        value = data[offset + HEADER_LEN:offset + length]
        tlvs.append(Tlv(type=tlv_type, value=value, length=length,
                        offset=offset, endianness=order))
        offset += length
    return tlvs, offset


def _build_packet(container: Tlv, frame: str) -> MeterpreterPacket | None:
    nested, _ = _walk_tlvs(container.value, 0, container.endianness)
    kind = PACKET_TYPES.get(container.type & ID_MASK)
    if kind is None or not nested:
        return None
    packet = MeterpreterPacket(kind=kind, type=container.type,
                               frame=frame, offset=container.offset,
                               length=container.length)
    order = container.endianness
    for tlv in nested:
        if (tlv.meta, tlv.tlv_id) == (TLV_META_TYPE_UINT, 1) \
                and len(tlv.value) >= 4:
            packet.command_id = int.from_bytes(tlv.value[:4], order)
        elif tlv.name == "REQUEST_ID":
            packet.request_id = _decode_value(tlv)
        elif tlv.name == "STRING":
            packet.strings.append(_decode_value(tlv))
        elif tlv.name == "UINT":
            packet.uints.append(int.from_bytes(tlv.value[:4], order))
        elif tlv.name == "BOOL":
            packet.bools.append(tlv.value[:1] not in (b"", b"\x00"))
        elif tlv.name == "EXCEPTION":
            packet.exception = _decode_value(tlv)
        elif tlv.name == "RESULT" and len(tlv.value) >= 4:
            packet.result = int.from_bytes(tlv.value[:4], order)
        else:
            packet.unknown.append(
                f"{_tlv_name(tlv.type)}={_decode_value(tlv)}")
    return packet


def _parse_once(data: bytes, endianness: str, frame_at=None) -> ParseResult:
    result = ParseResult(endianness=endianness)
    tlvs, consumed = _walk_tlvs(data, 0, endianness)
    result.leftover = len(data) - consumed
    for tlv in tlvs:
        frame = frame_at(tlv.offset) if frame_at else ""
        if PACKET_TYPES.get(tlv.type & ID_MASK):
            packet = _build_packet(tlv, frame)
            if packet is not None:
                result.packets.append(packet)
                continue
        result.extra_tlvs.append(tlv)
    return result


def parse(data: bytes, frame_at=None) -> ParseResult:
    """Parse one reassembled TCP direction.

    Meterpreter TLVs are network byte order (big endian, ``pack("NN")`` in
    the Ruby side and ``htonl`` in metsvc).  Some builds/tools emit little
    endian headers, so the parser tries big endian first and falls back when
    the stream does not walk cleanly.
    """
    big = _parse_once(data, "big", frame_at)
    if big.packets and big.leftover == 0:
        return big
    little = _parse_once(data, "little", frame_at)
    best = max((big, little),
               key=lambda item: (len(item.packets), -item.leftover))
    return best


def looks_like_meterpreter(data: bytes) -> bool:
    """Detection callback for :func:`fnet.features.common.protocol_streams`."""
    if not data or len(data) < HEADER_LEN + HEADER_LEN + 4:
        return False
    return bool(parse(data).packets)


def summary_line(packet: MeterpreterPacket) -> str:
    """One human readable line for reports and timelines."""
    parts = [f"命令 {packet.command_hex}"]
    if packet.request_id:
        parts.append(f"请求 {packet.request_id[:24]}")
    if packet.exception:
        parts.append(f"异常 {packet.exception[:80]}")
    if packet.strings:
        parts.append("字符串 " + " | ".join(
            value.replace("\n", " ")[:80] for value in packet.strings[:4]))
    if packet.uints:
        parts.append("UINT " + ",".join(str(value) for value in packet.uints[:4]))
    if packet.bools:
        parts.append("BOOL " + ",".join(
            "true" if flag else "false" for flag in packet.bools[:4]))
    if packet.unknown:
        parts.append("其它 " + "; ".join(packet.unknown[:3]))
    return f"{packet.kind} " + " ".join(parts)
