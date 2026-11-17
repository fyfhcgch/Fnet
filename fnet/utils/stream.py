"""TCP stream reassembly for the raw protocol parsers.

Wireshark's protocol dissectors handle most of this for well-known ports, but
the Redis/MongoDB/PostgreSQL extractors also parse ``tcp.payload`` directly so
they keep working on non-standard ports and on captures where a command spans
several packets.  This module turns per-packet rows into one ordered byte
stream per ``(tcp.stream, direction)`` pair:

* packets are ordered by TCP sequence number, not capture order;
* retransmissions and overlapping segments are kept once;
* sequence gaps are counted so the caller can warn about truncated data;
* every byte keeps the frame number that carried it, so findings can still
  point at a frame in Wireshark.

The functions are pure and do not import tshark, which keeps them easy to unit
test without a capture file.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field

from fnet.utils.pcap import hex_to_bytes

#: Hard caps so a corrupt/malicious capture cannot exhaust memory.
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
SEQ_MOD = 0x1_0000_0000
SEQ_HALF = 0x8000_0000

#: tshark fields expected by :func:`reassemble_rows`, in order.
STREAM_FIELDS = ["frame.number", "tcp.stream", "ip.src", "tcp.srcport",
                 "ip.dst", "tcp.dstport", "tcp.seq", "tcp.payload"]


@dataclass
class StreamData:
    """One reassembled direction of a TCP stream."""

    stream: str
    src: str
    sport: str
    dst: str
    dport: str
    data: bytes = b""
    #: ``(start, end, frame)`` spans into :attr:`data`.
    segments: list[tuple[int, int, str]] = field(default_factory=list)
    gaps: int = 0
    retransmits: int = 0
    truncated: bool = False

    def frame_at(self, offset: int) -> str:
        """Return the frame that carried ``offset`` (best effort)."""
        if not self.segments:
            return ""
        starts = [item[0] for item in self.segments]
        index = bisect_right(starts, max(0, int(offset))) - 1
        if index < 0:
            index = 0
        start, end, frame = self.segments[index]
        # Offsets inside a gap belong to the next captured segment.
        if offset >= end and index + 1 < len(self.segments):
            return self.segments[index + 1][2]
        return frame or self.segments[index][2]

    def spans(self):
        """Yield ``(start, end, frame)`` triples."""
        yield from self.segments

    @property
    def direction(self) -> str:
        return f"{self.src}:{self.sport} -> {self.dst}:{self.dport}"


@dataclass
class _Segment:
    frame: str
    seq: int | None
    order: int
    data: bytes


def _parse_seq(value: str) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text) % SEQ_MOD
    except ValueError:
        return None


def _assemble(segments: list[_Segment], limit: int) -> tuple[
        bytes, list[tuple[int, int, str]], int, int, bool]:
    if not segments:
        return b"", [], 0, 0, False

    if any(segment.seq is None for segment in segments):
        # No usable sequence numbers: keep capture order and concatenate.
        buffer = bytearray()
        spans: list[tuple[int, int, str]] = []
        truncated = False
        for segment in sorted(segments, key=lambda item: item.order):
            if len(buffer) >= limit:
                truncated = True
                break
            payload = segment.data[:limit - len(buffer)]
            start = len(buffer)
            buffer.extend(payload)
            spans.append((start, len(buffer), segment.frame))
        return bytes(buffer), spans, 0, 0, truncated

    base = segments[0].seq or 0
    rel: list[tuple[int, _Segment]] = []
    for segment in segments:
        delta = ((segment.seq or 0) - base) % SEQ_MOD
        if delta >= SEQ_HALF:
            delta -= SEQ_MOD
        rel.append((delta, segment))
    rel.sort(key=lambda item: (item[0], item[1].order))
    origin = rel[0][0]

    buffer = bytearray()
    spans: list[tuple[int, int, str]] = []
    gaps = 0
    retransmits = 0
    truncated = False
    expected = origin
    for offset, segment in rel:
        if offset + len(segment.data) <= expected:
            retransmits += 1
            continue
        if offset > expected:
            gaps += 1
        skip = max(0, expected - offset)
        payload = segment.data[skip:]
        if len(buffer) + len(payload) > limit:
            payload = payload[:limit - len(buffer)]
            truncated = True
        if not payload:
            expected = max(expected, offset + len(segment.data))
            continue
        start = len(buffer)
        buffer.extend(payload)
        spans.append((start, len(buffer), segment.frame))
        expected = offset + len(segment.data)
        if truncated:
            break
    return bytes(buffer), spans, gaps, retransmits, truncated


def reassemble_rows(rows, *, max_stream_bytes: int = MAX_STREAM_BYTES,
                    max_total_bytes: int = MAX_TOTAL_BYTES,
                    ) -> list[StreamData]:
    """Reassemble tshark field rows into per-direction byte streams.

    Each row must contain, in order::

        frame.number, tcp.stream, ip.src, tcp.srcport,
        ip.dst, tcp.dstport, tcp.seq, tcp.payload
    """
    groups: dict[tuple[str, str, str, str, str], list[_Segment]] = {}
    order = 0
    for row in rows or []:
        values = list(row or []) + [""] * 8
        (frame, stream, src, sport, dst, dport, seq, raw) = values[:8]
        data = hex_to_bytes(raw)
        if not stream or not data:
            continue
        key = (stream, src, sport, dst, dport)
        groups.setdefault(key, []).append(_Segment(
            frame=frame, seq=_parse_seq(seq), order=order, data=data))
        order += 1

    streams: list[StreamData] = []
    remaining = max(0, int(max_total_bytes))
    for key, segments in groups.items():
        if remaining <= 0:
            break
        stream, src, sport, dst, dport = key
        data, spans, gaps, retransmits, truncated = _assemble(
            segments, min(max_stream_bytes, remaining))
        remaining -= len(data)
        streams.append(StreamData(
            stream=stream, src=src, sport=sport, dst=dst, dport=dport,
            data=data, segments=spans, gaps=gaps,
            retransmits=retransmits, truncated=truncated))
    streams.sort(key=lambda item: (int(item.stream)
                                   if item.stream.isdigit() else 10 ** 9,
                                   item.sport))
    return streams


def stream_rows(ctx, display_filter: str, *, limit: int = 40_000,
                extra: list[str] | None = None):
    """Fetch and reassemble the TCP payload rows for a display filter."""
    from fnet.features.common import tshark_rows

    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "ip.src", "tcp.srcport",
              "ip.dst", "tcp.dstport", "tcp.seq", "tcp.payload"],
        display_filter, limit=limit, extra=extra)
    return reassemble_rows(rows)


def frame_lookup(stream: StreamData):
    """Return ``offset -> frame`` helper matching :meth:`StreamData.frame_at`."""
    return stream.frame_at
