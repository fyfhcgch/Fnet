"""Deep flag scan across reassembled streams, files and prior findings.

The classic ``text_scan.keyword_scan`` handler works packet by packet: a flag
split over two TCP segments, hidden in Base64 inside a reassembled HTTP body,
or written to an exported file is easy to miss.  This handler is deliberately
checkbox-less and runs *after* the extractors::

    python3 -m fnet -C capture.pcap --features \\
        checkBox_30,protocols.credentials,text_scan.deep

Every hit keeps its source (stream/file/finding), frame and a confidence level
so a flag from a random binary string does not outrank one from decrypted
traffic.  Placeholder flags (``flag{test}``, ``flag{example}`` ...) are
suppressed by default; pass ``flag_allow_placeholders=1`` to keep them.
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from pathlib import Path

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.pcap import file_magic_bytes, hex_to_bytes, payload_text, printable_ratio
from fnet.utils.stream import reassemble_rows

PLACEHOLDERS = {
    "test", "tests", "example", "sample", "demo", "placeholder", "xxx",
    "flag", "ctf", "todo", "dummy", "fake", "notreal", "not_a_flag",
}
CONFIDENCE_ORDER = {"高": 3, "中": 2, "低": 1}
B64_CHUNK_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_CHUNK_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}){8,}\b")
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_TOTAL_STREAM_BYTES = 128 * 1024 * 1024


def is_placeholder(flag: str) -> bool:
    """True for obvious documentation/test flags that should not be reported."""
    match = re.search(r"\{(.*)\}", flag or "")
    if not match:
        return False
    value = match.group(1).strip().lower()
    if value in PLACEHOLDERS:
        return True
    if set(value) <= set("xX*.-_ "):
        return True
    return False


def decoded_views(data: bytes, *, limit: int = 400_000) -> list[tuple[str, str]]:
    """Readable views of a binary blob: raw, strings, Base64, hex, URL."""
    views: list[tuple[str, str]] = []
    if not data:
        return views
    raw = payload_text(data[:limit])
    views.append(("raw", raw))
    if len(data) <= limit:
        strings = " ".join(match.group().decode("latin-1")
                           for match in ASCII_RE.finditer(data))
        if strings and strings != raw:
            views.append(("strings", strings))
    text = raw
    stripped = re.sub(r"\s+", "", text)
    for match in B64_CHUNK_RE.finditer(stripped):
        candidate = match.group(0) + "=" * (-len(match.group(0)) % 4)
        try:
            blob = base64.b64decode(candidate, validate=False)
        except (binascii.Error, ValueError):
            continue
        if blob and blob != data and printable_ratio(blob) >= 0.6:
            views.append(("base64", payload_text(blob)))
    for match in HEX_CHUNK_RE.finditer(text):
        blob = hex_to_bytes(match.group(0))
        if blob and printable_ratio(blob) >= 0.6:
            views.append(("hex", payload_text(blob)))
    unquoted = urllib.parse.unquote(text)
    if unquoted != text:
        views.append(("url", unquoted))
    return views


class FlagCollector:
    """De-duplicate flags while keeping the strongest source/confidence."""

    def __init__(self, allow_placeholders: bool = False) -> None:
        self.allow_placeholders = allow_placeholders
        self.items: dict[str, dict] = {}

    def add(self, flag: str, *, source: str, confidence: str,
            frame: str = "", detail: str = "") -> bool:
        if not flag or (not self.allow_placeholders and is_placeholder(flag)):
            return False
        current = self.items.get(flag)
        record = {
            "flag": flag, "source": source, "confidence": confidence,
            "frame": frame, "detail": detail,
        }
        if current is None:
            self.items[flag] = record
            return True
        if CONFIDENCE_ORDER.get(confidence, 0) > CONFIDENCE_ORDER.get(
                current["confidence"], 0):
            current.update(record)
            return True
        if frame and frame not in current.get("frame", ""):
            current["frame"] = ",".join(
                part for part in (current.get("frame"), frame) if part)
        return False

    def sorted(self) -> list[dict]:
        return sorted(self.items.values(), key=lambda item: (
            -CONFIDENCE_ORDER.get(item["confidence"], 0), item["source"],
            item["flag"]))


def _scan_text(collector: FlagCollector, text: str, *, source: str,
               frame: str = "", confidence: str = "高",
               deep: bool = True) -> None:
    for flag in codec.find_flags(text):
        collector.add(flag, source=source, confidence=confidence,
                      frame=frame, detail=source)
    if not deep:
        return
    # Chained encodings (Base64 -> URL -> hex) that survive one transform.
    for candidate in codec.decode_chain(text, rounds=2):
        if candidate and candidate != text:
            for flag in codec.find_flags(candidate):
                collector.add(flag, source=source + "/解码链",
                              confidence="中", frame=frame,
                              detail=source + " 解码后")


def _tcp_streams(ctx: FeatureContext):
    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "ip.src", "tcp.srcport",
              "ip.dst", "tcp.dstport", "tcp.seq", "tcp.payload"],
        "", limit=200_000)
    return reassemble_rows(rows, max_stream_bytes=MAX_STREAM_BYTES,
                           max_total_bytes=MAX_TOTAL_STREAM_BYTES)


def _udp_streams(ctx: FeatureContext) -> list[tuple[str, bytes, str]]:
    rows = tshark_rows(
        ctx, ["frame.number", "udp.stream", "ip.src", "udp.srcport",
              "ip.dst", "udp.dstport", "udp.payload"], "", limit=200_000)
    groups: dict[tuple[str, str, str, str, str], list[tuple[int, bytes]]] = {}
    for row in rows:
        row += [""] * (7 - len(row))
        frame, stream, src, sport, dst, dport, raw = row
        data = hex_to_bytes(raw)
        if not data:
            continue
        try:
            number = int(frame)
        except ValueError:
            number = 0
        groups.setdefault((stream, src, sport, dst, dport), []).append(
            (number, data))
    output = []
    for (stream, src, sport, dst, dport), chunks in groups.items():
        chunks.sort()
        data = b"".join(chunk for _number, chunk in chunks)[:MAX_STREAM_BYTES]
        output.append((f"udp {stream} {src}:{sport}->{dst}:{dport}", data,
                       str(chunks[0][0]) if chunks else ""))
    return output


def _scan_files(ctx: FeatureContext, collector: FlagCollector) -> int:
    base = Path(ctx.output_dir or ".")
    if not base.is_dir():
        return 0
    scanned = 0
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            continue
        if path.suffix in (".html", ".csv", ".json"):
            # Reports repeat the same findings; scanning them adds no value.
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        scanned += 1
        magic = file_magic_bytes(data[:32])
        views = decoded_views(data)
        for label, text in views:
            _scan_text(collector, text, source=f"文件 {path.name} ({magic})",
                       confidence="高" if label == "raw" else "中")
    return scanned


def _scan_findings(ctx: FeatureContext, collector: FlagCollector) -> None:
    for item in list(ctx.findings):
        summary = str(item.get("summary") or "")
        detail = str(item.get("detail") or "")
        if item.get("kind") == "flag":
            collector.add(summary, source="已有发现", confidence="高",
                          frame=str(item.get("frame") or ""),
                          detail=detail)
            continue
        for text in (summary, detail):
            _scan_text(collector, text, source=f"发现/{item.get('kind')}",
                       frame=str(item.get("frame") or ""), confidence="中")


def deep_scan(ctx: FeatureContext) -> None:
    allow = str(ctx.params.get("flag_allow_placeholders") or "0").lower() in (
        "1", "true", "yes", "on")
    collector = FlagCollector(allow)

    _scan_findings(ctx, collector)

    streams = _tcp_streams(ctx)
    ctx.report(f"深度扫描: 重组 TCP 流 {len(streams)} 条", "info")
    for index, stream in enumerate(streams):
        if index % 20 == 0:
            ctx.check_cancel()
        label = (f"TCP 流 {stream.stream} "
                 f"{stream.src}:{stream.sport}->{stream.dst}:{stream.dport}")
        if stream.gaps:
            label += f" (丢包 {stream.gaps})"
        for kind, text in decoded_views(stream.data):
            confidence = "高" if kind == "raw" else "中"
            _scan_text(collector, text, source=f"{label}/{kind}",
                       frame=stream.frame_at(0) if stream.spans else "",
                       confidence=confidence)

    udp = _udp_streams(ctx)
    ctx.report(f"深度扫描: UDP 会话 {len(udp)} 条", "info")
    for label, data, frame in udp:
        for kind, text in decoded_views(data):
            _scan_text(collector, text, source=f"{label}/{kind}",
                       frame=frame, confidence="中")

    files = _scan_files(ctx, collector)
    ctx.report(f"深度扫描: 已导出文件 {files} 个", "info")

    found = collector.sorted()
    if not found:
        ctx.report("深度 flag 扫描完成，未发现新的 flag", "warn")
        ctx.set_progress(100)
        return
    ctx.report(f"===== 深度 flag 扫描结果（{len(found)} 个）=====", "good")
    lines = ["flag\t置信度\t来源\t帧"]
    for item in found:
        ctx.report(f"[{item['confidence']}] {item['flag']}  ← {item['source']}",
                   "good" if item["confidence"] == "高" else "info")
        ctx.add_finding(
            "flag", item["flag"], frame=item["frame"], level="good",
            detail=f"来源: {clean_cell(item['source'], 220)}\n"
                   f"置信度: {item['confidence']}",
            extra={"confidence": item["confidence"],
                   "source": item["source"]})
        lines.append("\t".join([item["flag"], item["confidence"],
                                item["source"], item["frame"]]))
    ctx.write_output("flags_deep.txt", "\n".join(lines) + "\n")
    ctx.set_progress(100)
