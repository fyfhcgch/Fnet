"""Covert-channel reassembly helpers (DNS labels, ICMP payloads).

Pure standard library: these helpers decode and stitch chunks that DNS or
ICMP tunnels split across packets.  Nothing here raises on malformed input;
callers get best-effort results instead.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "Chunk", "decode_chunk", "byte_profile", "decode_assembled",
    "parse_sequence", "reassemble", "group_sessions",
    "analyse_dns", "analyse_icmp", "find_flags", "find_flags_loose",
    "canonical_flag", "length_channel", "write_decoded", "timeline",
]

#: Upper bound for everything :func:`write_decoded` writes in one call.
MAX_TOTAL_BYTES = 16 * 1024 * 1024

#: Per-file guard so one huge chunk cannot exhaust the budget silently.
MAX_FILE_BYTES = 8 * 1024 * 1024

FLAG_PREFIXES = (
    "flag", "ctf", "nssctf", "ctfshow", "picoctf", "dasctf", "moectf",
    "hgame", "flagx", "n1ctf", "idf", "begin", "sctf", "iscc", "buuctf",
    "qwb", "de1ctf", "hfctf", "antctf", "starctf",
)

_FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + "|".join(FLAG_PREFIXES) + r")"
    r"\{[^{}\r\n]{1,300}\}", re.IGNORECASE)
#: 宽松版：不要求前缀前是边界。解码后的可信文本（如 /etc/shadow 片段里
#: ``...UcFLAG{...}`` 这种粘在哈希字段中的 flag）用它可以兜底命中。
_FLAG_LOOSE_RE = re.compile(
    r"(?:" + "|".join(FLAG_PREFIXES) + r")\{[^{}\r\n]{1,300}\}", re.IGNORECASE)
_PREFIXES = set(FLAG_PREFIXES)

_B64_STD = re.compile(r"[A-Za-z0-9+/]+")
_B64_URL = re.compile(r"[A-Za-z0-9_-]+")
_B32 = re.compile(r"[A-Za-z2-7]+=*")
_HEX = re.compile(r"[0-9A-Fa-f]+")

_SEQ_PREFIX = r"(?:seq|chunk|part|packet|pkt|frag|seg|idx|id|p|n|c|f|x)"
_RE_SEQ_OF = re.compile(r"^0*(\d{1,6})[-_/ ]?(?:of|/)[-_/ ]?0*(\d{1,6})$", re.I)
_RE_SEQ_PREFIX = re.compile(r"^" + _SEQ_PREFIX + r"[-_ ]?0*(\d{1,6})$", re.I)
_RE_PREFIX_OF = re.compile(
    r"^" + _SEQ_PREFIX + r"[-_ ]?0*(\d{1,6})[-_ ]?of[-_ ]?0*(\d{1,6})$", re.I)
_RE_PURE = re.compile(r"^0*(\d{1,6})$")
_RE_LETTER = re.compile(r"^[A-Za-z]$")


@dataclass
class Chunk:
    """One decoded piece of a tunnel message."""

    index: int | None = None
    total: int | None = None
    data: bytes = b""
    encoding: str = ""
    label: str = ""
    frame: str = ""
    time: float = 0.0
    session: str = ""

    def size(self) -> int:
        return len(self.data)


# -- text helpers ------------------------------------------------------
def _text_of(data: bytes) -> str:
    """Best-effort text decoding that never raises."""
    for encoding in ("utf-8", "gbk", "big5", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def _plausible(data: bytes) -> bool:
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # latin-1 always succeeds, but non-ASCII bytes are not evidence of
        # readable data: count only the ASCII subset unless a flag appears.
        text = data.decode("latin-1")
        good = sum(32 <= ord(ch) < 127 or ch in "\t\r\n" for ch in text)
    else:
        good = sum(ch.isprintable() or ch in "\t\r\n" for ch in text)
    if good / max(len(text), 1) >= 0.90:
        return True
    return bool(_FLAG_RE.search(text))


def _hex_bytes(value: str) -> bytes:
    cleaned = re.sub(r"(?i)0x|[\s:,.-]", "", value or "")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    if not cleaned or not _HEX.fullmatch(cleaned):
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _field(chunk: Any, name: str, default: Any = None) -> Any:
    if isinstance(chunk, dict):
        return chunk.get(name, default)
    return getattr(chunk, name, default)


# -- decoding ----------------------------------------------------------
def decode_chunk(label: str) -> list[tuple[str, bytes]]:
    """Decode one tunnel label and return ``(encoding, bytes)`` candidates.

    Tries base64 (standard plus urlsafe ``-_``), base32 (case-insensitive),
    hex and URL percent-decoding.  Only printable or flag-like results are
    kept and identical byte strings are deduplicated.
    """
    label = (label or "").strip()
    if not label:
        return []
    core = re.sub(r"\s+", "", label)
    results: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add(encoding: str, raw: bytes | None) -> None:
        if not raw or raw in seen or len(raw) > MAX_TOTAL_BYTES:
            return
        if not _plausible(raw):
            return
        seen.add(raw)
        results.append((encoding, raw))

    # base64 / base64url (padding restored)
    body = core.rstrip("=")
    if len(body) >= 4 and _B64_STD.fullmatch(body):
        padded = body + "=" * (-len(body) % 4)
        try:
            add("base64", base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            pass
    if len(body) >= 4 and _B64_URL.fullmatch(body):
        padded = body.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            add("base64url", base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            pass

    # base32, case-insensitive
    if _B32.fullmatch(core) and len(core.rstrip("=")) >= 8:
        upper = core.upper()
        upper += "=" * (-len(upper.rstrip("=")) % 8)
        try:
            add("base32", base64.b32decode(upper))
        except (binascii.Error, ValueError):
            pass

    # hex, even length only
    if len(core) >= 8 and len(core) % 2 == 0 and _HEX.fullmatch(core):
        add("hex", _hex_bytes(core))

    # URL percent-encoding
    if "%" in label:
        try:
            add("url", urllib.parse.unquote_to_bytes(label))
        except (UnicodeDecodeError, ValueError):
            pass

    return results


def byte_profile(data: bytes) -> dict:
    """Describe a byte blob: length, printable ratio, entropy and alignment.

    Pure helper used to mark reassembled tunnel payloads that decode fine
    but carry unreadable, evenly distributed bytes — the signature of an
    encrypted carrier rather than text.
    """
    data = bytes(data or b"")
    n = len(data)
    printable = (sum(32 <= b < 127 or b in (9, 10, 13) for b in data) / n
                 if n else 0.0)
    entropy = (-sum((count / n) * math.log2(count / n)
                    for count in Counter(data).values()) if n else 0.0)
    return {
        "length": n,
        "printable_ratio": round(printable, 4),
        "entropy": round(entropy, 4),
        "aligned_16": n > 0 and n % 16 == 0,
    }


def _looks_encrypted(data: bytes) -> bool:
    """Heuristic: unreadable and evenly distributed bytes == ciphertext.

    均匀随机的 256 值字节的期望可打印率约为 98/256 ≈ 0.38，所以只看
    ``printable < 0.3`` 会漏掉真实样本；这里联合判定：可打印率 < 0.5 且
    熵 ≥ 7.5（接近满熵 8.0）且长度足够，才判为加密载荷。
    """
    profile = byte_profile(data)
    return (profile["length"] >= 32
            and profile["printable_ratio"] < 0.5
            and profile["entropy"] >= 7.5)


def _decode_raw(label: str) -> list[tuple[str, bytes]]:
    """Whole-payload candidate decodings without the readability filter.

    Same encoding family as :func:`decode_chunk` (base64 / base64url /
    base32 / hex / URL percent) but keeps unreadable results so callers can
    tell an encrypted carrier apart from a failed decode.
    """
    label = (label or "").strip()
    if not label:
        return []
    core = re.sub(r"\s+", "", label)
    results: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()

    def add(encoding: str, raw: bytes | None) -> None:
        if not raw or raw in seen or len(raw) > MAX_TOTAL_BYTES:
            return
        seen.add(raw)
        results.append((encoding, raw))

    body = core.rstrip("=")
    if len(body) >= 4 and _B64_STD.fullmatch(body):
        padded = body + "=" * (-len(body) % 4)
        try:
            add("base64", base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            pass
    if len(body) >= 4 and _B64_URL.fullmatch(body):
        padded = body.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            add("base64url", base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            pass
    if _B32.fullmatch(core) and len(core.rstrip("=")) >= 8:
        upper = core.upper()
        upper += "=" * (-len(upper.rstrip("=")) % 8)
        try:
            add("base32", base64.b32decode(upper))
        except (binascii.Error, ValueError):
            pass
    if len(core) >= 8 and len(core) % 2 == 0 and _HEX.fullmatch(core):
        add("hex", _hex_bytes(core))
    if "%" in label:
        try:
            add("url", urllib.parse.unquote_to_bytes(label))
        except (UnicodeDecodeError, ValueError):
            pass
    return results


def decode_assembled(text: str) -> dict:
    """Decode a fully reassembled tunnel text in one piece.

    ICMP/DNS tunnels often split one large base64 payload across packets;
    per-chunk decoding then fails on every fragment and only raw bytes
    survive reassembly.  This second pass over the joined text:

    1. adopts a decoding that carries a flag or is readable;
    2. marks a base64 result that decodes fine but is unreadable and evenly
       distributed as ``encrypted`` (with entropy / printable ratio in
       ``cipher``) instead of discarding it.

    Returns ``{"data", "encoding", "text", "flags", "encrypted", "cipher"}``;
    ``data`` is empty when no candidate decoding exists.
    """
    result: dict = {"data": b"", "encoding": "", "text": "", "flags": [],
                    "encrypted": False, "cipher": None}
    for encoding, raw in _decode_raw(text or ""):
        found = find_flags(raw)
        if found:
            result.update(data=raw, encoding=encoding, text=_text_of(raw),
                          flags=found)
            return result
        if _plausible(raw):
            result.update(data=raw, encoding=encoding, text=_text_of(raw))
            return result
        # 加密判定只看 base64 家族：hex/url 解出的“均匀不可读字节”通常是
        # 误匹配（任何短文本都能 hex 解码），base64 整段命中才有代表性。
        if encoding in ("base64", "base64url") and _looks_encrypted(raw):
            cipher = dict(byte_profile(raw), encoding=encoding)
            result.update(data=raw, encoding=encoding, encrypted=True,
                          cipher=cipher)
            return result
    return result


#: 长度隐蔽信道的 ASCII 可打印区间（空格 ``0x20`` 到 ``~``）。
LENGTH_MIN = 32
LENGTH_MAX = 126
#: 至少多少个包才认为长度序列可能承载文本。
LENGTH_MIN_PACKETS = 8
#: 可打印长度占比阈值（低于此值说明长度里混入了非文本值）。
LENGTH_MIN_RATIO = 0.9
#: 长度序列至少要有的不同取值数（正常 ping 的定长载荷只有 1 种）。
LENGTH_MIN_DISTINCT = 6
#: 解码文本的可读性下限：低于此值不认为解出了消息，避免把随机字节当文本。
LENGTH_MIN_QUALITY = 0.9
#: 解码文本的最小长度。
LENGTH_MIN_TEXT = 8


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(32 <= ord(ch) < 127 or ch in "\t\r\n" for ch in text)
    return good / len(text)


def _length_variants(numbers: list[int]) -> list[tuple[str, list[int]]]:
    """长度序列的候选读法：可打印过滤、原始字节、去连续重复。

    不同隧道实现会把长度写成 ASCII、原始字节，或因重传出现连续重复；
    这里给出有界候选，由 :func:`length_channel` 统一打分选择，避免针对
    单个样本写死一种读法。
    """
    out: list[tuple[str, list[int]]] = []
    if not numbers:
        return out
    printable = [v for v in numbers if LENGTH_MIN <= v <= LENGTH_MAX]
    if printable and len(printable) / len(numbers) >= LENGTH_MIN_RATIO:
        out.append(("printable", printable))
    if all(0 <= v <= 255 for v in numbers):
        out.append(("raw", list(numbers)))
    dedup: list[int] = []
    for value in numbers:
        if not dedup or dedup[-1] != value:
            dedup.append(value)
    if dedup and dedup != numbers:
        if all(LENGTH_MIN <= v <= LENGTH_MAX for v in dedup):
            out.append(("dedup", dedup))
        if all(0 <= v <= 255 for v in dedup):
            out.append(("dedup_raw", dedup))
    return out


def length_channel(values: Iterable[int]) -> dict:
    """Detect an ASCII-in-length covert channel (payload length == ord(char)).

    有些隐蔽信道不把数据放进载荷，而是让每个包的**长度**承载一个字符。
    纯函数：把长度序列映射为字符，剥离 base64/base32/hex/URL 等编码并
    扫描 flag；同时尝试正序/逆序、可打印过滤/原始字节/去重等常见读法，
    按“是否带 flag、解码文本可读性”打分，选最可信的一种。

    正常 ping（定长载荷）因不同取值太少直接排除；随机长度且解码不出
    可读文本的流量也不会被误报。

    返回 ``{"channel", "values", "text", "printable_ratio", "decodings",
    "decoded_text", "flags", "order", "variant"}``。
    """
    result: dict = {"channel": False, "values": [], "text": "",
                    "printable_ratio": 0.0, "decodings": [], "decoded_text": "",
                    "flags": [], "order": "forward", "variant": ""}
    numbers: list[int] = []
    for value in values or []:
        try:
            numbers.append(int(value))
        except (TypeError, ValueError):
            continue
    result["values"] = numbers
    if len(numbers) < LENGTH_MIN_PACKETS:
        return result

    def peel(sequence: str) -> tuple[str, list[dict], list[str]]:
        """剥离编码层，返回 (最佳文本, 各层结果, flags)。"""
        layers: list[dict] = []
        best = ""
        found: list[str] = find_flags(sequence) or find_flags_loose(sequence)
        if found:
            best = sequence
        decoded = decode_assembled(sequence)
        if decoded.get("text") or decoded.get("flags"):
            decoded_text = decoded.get("text") or ""
            decoded_flags = (list(decoded.get("flags") or [])
                             or find_flags_loose(decoded_text))
            layers.append({"encoding": decoded.get("encoding") or "text",
                           "text": decoded_text,
                           "flags": decoded_flags})
            if decoded_flags or not found:
                best = decoded_text or sequence
                found = decoded_flags or found
        return best, layers, found

    best: tuple | None = None
    for variant, sequence in _length_variants(numbers):
        distinct = len({v for v in sequence if LENGTH_MIN <= v <= LENGTH_MAX})
        if distinct < LENGTH_MIN_DISTINCT:
            continue
        for order, ordered in (("forward", sequence),
                               ("reversed", list(reversed(sequence)))):
            text = "".join(chr(v) for v in ordered)
            decoded_text, layers, flags = peel(text)
            quality = _printable_ratio(decoded_text)
            if not flags and (quality < LENGTH_MIN_QUALITY
                              or len(decoded_text) < LENGTH_MIN_TEXT):
                continue
            score = ((1000 if flags else 0) + quality * 100
                     + min(len(decoded_text), 400) / 10)
            if best is None or score > best[0]:
                best = (score, variant, order, text, decoded_text, layers,
                        flags, sequence)
    if best is None:
        return result

    _, variant, order, text, decoded_text, layers, flags, sequence = best
    result.update(
        channel=True, text=text, decodings=layers, decoded_text=decoded_text,
        flags=flags, order=order, variant=variant,
        printable_ratio=round(
            sum(LENGTH_MIN <= v <= LENGTH_MAX for v in sequence)
            / max(len(sequence), 1), 4))
    return result


def parse_sequence(label: str) -> tuple[int | None, int | None]:
    """Parse a sequence number (and optional total) from a label/chunk name.

    Supports ``0007``, ``7``, ``c007``, ``seq7``, ``7of20``, ``p7`` and
    single letters ``a``..``z`` / ``A``..``Z`` as base26 (``a``=0).
    """
    value = re.sub(r"[\s._-]+", "", (label or "").strip())
    if not value:
        return (None, None)

    match = _RE_SEQ_OF.match(value)
    if match:
        return (int(match.group(1)), int(match.group(2)))
    match = _RE_PREFIX_OF.match(value)
    if match:
        return (int(match.group(1)), int(match.group(2)))
    match = _RE_PURE.match(value)
    if match:
        return (int(match.group(1)), None)
    match = _RE_SEQ_PREFIX.match(value)
    if match:
        return (int(match.group(1)), None)
    if _RE_LETTER.match(value):
        return (ord(value.lower()) - ord("a"), None)
    return (None, None)


# -- reassembly --------------------------------------------------------
def reassemble(chunks: Iterable[Chunk]) -> dict:
    """Stitch chunks into one message, reporting gaps and duplicates.

    ``result["index_mode"]`` explains how the indices were treated:

    - ``"fragmented"``: real chunk indices, deduplicated with gap detection;
    - ``"echo_id"``: every indexed chunk shares one index (ICMP echo tunnels
      keep ``seq`` constant as a session identifier, e.g. ``seq == 0``), so
      the index carries no fragmentation information and all chunks are
      stitched in arrival (frame) order without de-duplication;
    - ``"none"``: chunks had no index at all.
    """
    items = [c for c in (chunks or []) if c is not None]
    indexed = [c for c in items if _field(c, "index") is not None]
    unindexed = [c for c in items if _field(c, "index") is None]

    totals = [int(_field(c, "total")) for c in items
              if _field(c, "total") is not None]
    total = max(totals) if totals else None

    ordered: list[Any] = []
    seen: dict[int, Any] = {}
    duplicate_indices: set[int] = set()
    # 非分片隧道判定：已索引分片多于一个、全部共享同一 index 且没有声明
    # total（例如 124 个 echo request 的 seq 全为 "0"）。此时按 index 去重
    # 会把第一个分片之外的全部载荷误判为重复而丢弃，因此回退为按到达顺序
    # （即帧序）拼接全部未去重的分片，missing 置空、complete 仅看是否有载荷。
    echo_id_mode = bool(
        indexed and len(indexed) > 1 and not totals
        and len({int(_field(c, "index")) for c in indexed}) == 1)
    if echo_id_mode:
        ordered = list(indexed) + list(unindexed)
    else:
        for chunk in sorted(indexed, key=lambda c: (_field(c, "index"),
                                                    _field(c, "time", 0.0))):
            index = int(_field(chunk, "index"))
            if index in seen:
                duplicate_indices.add(index)
                continue
            seen[index] = chunk
            ordered.append(chunk)
        ordered.extend(unindexed)

    indices = sorted(seen)
    missing: list[int] = []
    if indices and not echo_id_mode:
        start = 0 if indices[0] == 0 else 1
        end = max(indices)
        if total is not None:
            end = max(end, total)
        missing = [i for i in range(start, end + 1) if i not in seen]

    data = b"".join(_field(c, "data", b"") or b"" for c in ordered)
    encodings: list[str] = []
    for chunk in ordered:
        encoding = _field(chunk, "encoding", "") or ""
        if encoding and encoding not in encodings:
            encodings.append(encoding)

    return {
        "data": data,
        "ordered": ordered,
        "missing": missing,
        "duplicates": sorted(duplicate_indices),
        "encodings": encodings,
        "text": _text_of(data),
        "complete": bool(ordered) and (echo_id_mode or not missing),
        "index_mode": "echo_id" if echo_id_mode else (
            "fragmented" if seen else "none"),
    }


# -- session grouping --------------------------------------------------
def _parent_domain(name: str) -> str:
    labels = [p for p in (name or "").strip(".").lower().split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def group_sessions(entries: Iterable[Sequence[Any]]) -> dict[str, list]:
    """Group ``(name, qname)`` DNS entries by parent domain.

    Entries with three or more items are treated as ICMP tuples
    ``(src, dst, id, ...)`` and grouped by ``src|dst|id``.
    """
    groups: dict[str, list] = {}
    for entry in entries or []:
        try:
            items = tuple(entry)
        except TypeError:
            continue
        if not items:
            continue
        if len(items) == 2:
            qname = str(items[1] or "")
            if not qname:
                continue
            key = _parent_domain(qname)
        else:
            key = f"{items[0]}|{items[1]}|{items[2]}"
        groups.setdefault(key, []).append(entry)
    return groups


def _refine(data: bytes, flags: list[str],
            encrypted: bool = False) -> tuple[bytes, str, list[str]]:
    """Decode an assembled blob once more when it does not carry a flag.

    ``encrypted=True`` means the blob is ciphertext of a covert channel;
    keep it byte-for-byte and never pretend it is readable text.
    """
    if encrypted or flags:
        return data, "" if encrypted else _text_of(data), flags
    text = _text_of(data)
    for _, decoded in (decode_chunk(text[:1_048_576]) if text else []):
        found = find_flags(decoded)
        if found:
            return decoded, _text_of(decoded), found
    return data, text, flags


# -- DNS ---------------------------------------------------------------
def analyse_dns(rows: Iterable[Sequence[Any]]) -> dict:
    """Decode a DNS tunnel from ``[frame, qname, time]`` tshark rows."""
    chunks_by_domain: dict[str, list[Chunk]] = {}
    session_entries: list[tuple[str, str]] = []
    long_labels = 0
    suspicious = 0
    total_rows = 0

    for row in rows or []:
        try:
            items = list(row)
        except TypeError:
            continue
        if len(items) < 2:
            continue
        total_rows += 1
        frame = str(items[0] or "")
        qname = str(items[1] or "").strip().strip(".")
        time = _as_float(items[2]) if len(items) > 2 else 0.0
        if not qname:
            continue
        parent = _parent_domain(qname)
        labels = [p for p in qname.split(".") if p]
        chain = labels[:-2] if len(labels) > 2 else []
        if not chain:
            continue

        session_entries.append((chain[0], qname))
        lengths = [len(p) for p in chain]
        long_labels += sum(1 for length in lengths if length >= 16)

        index, total = parse_sequence(chain[0])
        payload = chain[1:] if index is not None else chain
        joined = "".join(payload)

        candidates = decode_chunk(joined) if joined else []
        data = b""
        encoding = ""
        if candidates:
            encoding, data = candidates[0]
        elif len(payload) > 1:
            parts: list[bytes] = []
            for label in payload:
                decoded = decode_chunk(label)
                if decoded:
                    encoding = encoding or decoded[0][0]
                    parts.append(decoded[0][1])
            if parts:
                data = b"".join(parts)
        if not data and joined and len(joined) >= 8 and _plausible(
                joined.encode("latin-1", "replace")):
            data = joined.encode("latin-1", "replace")
            encoding = "raw"

        decoded_ok = bool(candidates) or encoding not in ("", "raw")
        if decoded_ok or max(lengths) >= 24:
            suspicious += 1
        if not data:
            continue

        chunks_by_domain.setdefault(parent, []).append(
            Chunk(index=index, total=total, data=data, encoding=encoding,
                  label=joined, frame=frame, time=time, session=parent))

    sessions = group_sessions(session_entries)
    decoded: list[dict] = []
    all_flags: list[str] = []
    for domain, chunks in chunks_by_domain.items():
        result = reassemble(chunks)
        flags = find_flags(result["text"])
        data, text, flags = _refine(result["data"], flags)
        for flag in flags:
            if flag not in all_flags:
                all_flags.append(flag)
        decoded.append({
            "session": domain,
            "data": data,
            "text": text,
            "flags": flags,
            "complete": result["complete"],
            "missing": result["missing"],
            "duplicates": result["duplicates"],
            "encodings": result["encodings"],
            "chunks": len(result["ordered"]),
        })

    return {
        "decoded": decoded,
        "sessions": sessions,
        "long_labels": long_labels,
        "suspicious": suspicious,
        "flags": all_flags,
        "rows": total_rows,
    }


# -- ICMP --------------------------------------------------------------
def _icmp_ident(text: str) -> tuple[int | None, int | None, str]:
    """Split an optional ``<seq>:payload`` prefix used by some ICMP tunnels."""
    match = re.match(r"^([A-Za-z0-9]{1,8})[:|](.+)$", text or "", re.S)
    if not match:
        return (None, None, text or "")
    index, total = parse_sequence(match.group(1))
    if index is None:
        return (None, None, text or "")
    return (index, total, match.group(2))


def analyse_icmp(rows: Iterable[Sequence[Any]]) -> dict:
    """Decode ICMP echo payloads given ``[frame, src, dst, type, seq, data]``."""
    groups: dict[str, list[tuple[Chunk, str]]] = {}
    total_rows = 0

    for row in rows or []:
        try:
            items = list(row)
        except TypeError:
            continue
        if len(items) < 3:
            continue
        total_rows += 1
        frame = str(items[0] or "")
        src = str(items[1] or "")
        dst = str(items[2] or "")
        icmp_type = str(items[3] or "") if len(items) > 3 else ""
        seq = str(items[4] or "") if len(items) > 4 else ""
        raw_hex = str(items[5] or "") if len(items) > 5 else ""
        raw = _hex_bytes(raw_hex)
        if not raw:
            continue
        text = _text_of(raw)
        index, total = parse_sequence(seq)
        embedded_index, embedded_total, payload_text = _icmp_ident(text)
        if index is None and embedded_index is not None:
            index, total = embedded_index, embedded_total
            raw = payload_text.encode("latin-1", "replace")
            text = payload_text

        data = raw
        encoding = "raw"
        if len(text) >= 4 and _plausible(text.encode("latin-1", "replace")):
            candidates = decode_chunk(text)
            if candidates:
                encoding, data = candidates[0]

        # ICMP rows carry no timestamp; frame order is a stable stand-in.
        time = _as_float(items[6]) if len(items) > 6 else _as_float(frame)
        key = f"{src}>{dst}"
        if index is None and seq:
            # A non-numeric seq behaves like an echo identifier, not a chunk
            # number, so keep such conversations apart.
            key += f"#{seq}"
        groups.setdefault(key, []).append((
            Chunk(index=index, total=total, data=data, encoding=encoding,
                  label=text[:120], frame=frame, time=time, session=key),
            icmp_type,
        ))

    decoded: list[dict] = []
    all_flags: list[str] = []
    for key, pairs in groups.items():
        # Prefer echo requests when replies duplicate the same payload.
        requests = [pair for pair in pairs if pair[1] == "8"]
        chosen = requests or pairs
        chunks = [chunk for chunk, _ in chosen]
        result = reassemble(chunks)
        flags = find_flags(result["text"])
        data = result["data"]
        text = result["text"]
        encrypted = False
        cipher = None
        # 双保险：reassemble() 已把“全部 index 相同”的会话按未索引处理
        # （见其 echo_id 分支的注释），这里对整段重组文本再做一次候选解码
        # （base64/base64url/hex/URL）：可读或带 flag 则采用；解出均匀
        # 不可读字节则标记 encrypted，密文字节原样保留、不强行当文本。
        second = decode_assembled(result["text"])
        if second.get("encrypted"):
            data, text, flags = _refine(second["data"], [], encrypted=True)
            encrypted = True
            cipher = second["cipher"]
        elif second.get("data"):
            data = second["data"]
            text = second["text"]
            flags = second["flags"] or flags
            data, text, flags = _refine(data, flags)
        else:
            data, text, flags = _refine(data, flags)
        for flag in flags:
            if flag not in all_flags:
                all_flags.append(flag)
        frames = [str(_field(c, "frame", "") or "")
                  for c in result["ordered"]]
        frames = [frame for frame in frames if frame]
        decoded.append({
            "session": key,
            "data": data,
            "text": text,
            #: 重组后的原始文本（加密载荷的 text 会被清空，预览仍需要它）。
            "raw_text": (result["text"] or "")[:8000],
            "flags": flags,
            "complete": result["complete"],
            "missing": result["missing"],
            "duplicates": result["duplicates"],
            "encodings": result["encodings"],
            "chunks": len(result["ordered"]),
            "index_mode": result.get("index_mode", ""),
            "packets": len(result["ordered"]),
            "payload_bytes": sum(len(_field(c, "data", b"") or b"")
                                 for c in result["ordered"]),
            "frame_range": (f"{frames[0]}-{frames[-1]}" if len(frames) > 1
                            else (frames[0] if frames else "")),
            "encrypted": encrypted,
            "cipher": cipher,
        })

    return {
        "decoded": decoded,
        "sessions": groups,
        "flags": all_flags,
        "rows": total_rows,
        "text": "\n".join(entry["text"] for entry in decoded),
    }


# -- flags / output ----------------------------------------------------
def find_flags(data: bytes | str) -> list[str]:
    """Return conservative ``flag{...}``/``ctf{...}`` style strings."""
    if isinstance(data, (bytes, bytearray)):
        text = _text_of(bytes(data))
    else:
        text = str(data or "")
    if not text:
        return []

    found: list[str] = []
    try:
        from fnet.utils.codec import find_flags as codec_find_flags
    except Exception:  # pragma: no cover - codec is part of the package
        codec_find_flags = None
    if codec_find_flags is not None:
        try:
            for value in codec_find_flags(text):
                prefix = value.split("{", 1)[0].lower()
                if prefix in _PREFIXES and value not in found:
                    found.append(value)
        except Exception:  # pragma: no cover - defensive
            pass

    for match in _FLAG_RE.finditer(text):
        value = match.group(0)
        if value not in found:
            found.append(value)
    return found


def find_flags_loose(data: bytes | str) -> list[str]:
    """Like :func:`find_flags` but tolerates a flag embedded inside a token.

    解码后的可信文本里，flag 常粘在别的字段中（``/etc/shadow`` 的哈希
    ``...UcFLAG{...}``、路径 ``/tmp/flag{...}`` 等），保守正则的边界断言
    会漏掉；仅在“已经确认可读/已解码”的文本上使用这个宽松版本。
    """
    text = (_text_of(bytes(data)) if isinstance(data, (bytes, bytearray))
            else str(data or ""))
    if not text:
        return []
    found: list[str] = []
    for match in _FLAG_LOOSE_RE.finditer(text):
        value = match.group(0)
        if value not in found:
            found.append(value)
    return found


#: CTF 平台最常用的小写前缀；只规范化这一个前缀的大小写变体。
_CANONICAL_PREFIX = "flag"


def canonical_flag(value: str) -> str:
    """Normalize a matched flag to the conventional lowercase ``flag{}`` form.

    解码文本里的 flag 可能粘在哈希/字段中并带出大写前缀（如
    ``...UcFLAG{...}``）。平台通常要求 ``flag{...}``，这里只把 ``flag``
    前缀的大小写统一成小写，其余前缀（``CTF{}`` / ``NSSCTF{}`` 等）保持
    原样，避免破坏题目自身约定。原文仍保留在 finding 的 ``extra.raw_flag``。
    """
    text = str(value or "").strip()
    match = re.match(r"^([A-Za-z]+)(\{.*\})$", text, re.S)
    if not match:
        return text
    prefix, rest = match.group(1), match.group(2)
    if prefix.lower() == _CANONICAL_PREFIX:
        return _CANONICAL_PREFIX + rest
    return text


def _sanitise_session(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._")
    return safe[:80] or "session"


def _entry_data(entry: Any) -> bytes:
    data = _field(entry, "data", b"")
    if isinstance(data, str):
        return data.encode("utf-8", "replace")
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    text = _field(entry, "text", "")
    return str(text or "").encode("utf-8", "replace")


def write_decoded(entries: Iterable[Any], outdir: str | Path,
                  prefix: str = "tunnel") -> list[dict]:
    """Write decoded sessions as ``<prefix>_<session>.bin`` and hash them."""
    written: list[dict] = []
    budget = MAX_TOTAL_BYTES
    try:
        directory = Path(outdir)
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return written

    for number, entry in enumerate(entries or [], 1):
        try:
            data = _entry_data(entry)
            if not data or len(data) > MAX_FILE_BYTES or len(data) > budget:
                continue
            session = _field(entry, "session", "")
            if not session:
                session = _field(entry, "name", "") or f"entry{number}"
            stem = f"{_sanitise_session(prefix)}_{_sanitise_session(session)}"
            path = directory / f"{stem}.bin"
            suffix = 2
            while path.exists():
                path = directory / f"{stem}_{suffix}.bin"
                suffix += 1
            path.write_bytes(data)
            budget -= len(data)
            written.append({
                "name": path.name,
                "path": str(path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        except (OSError, TypeError, ValueError):
            continue
    return written


def timeline(chunks: Iterable[Chunk], buckets: int = 20) -> list[dict]:
    """Bucket chunks over time, reporting counts and bytes per bucket."""
    items = [c for c in (chunks or []) if c is not None]
    if not items:
        return []
    try:
        count = max(1, min(int(buckets), 1000))
    except (TypeError, ValueError):
        count = 20

    times = [_as_float(_field(c, "time", 0.0)) for c in items]
    start = min(times)
    end = max(times)
    span = end - start

    if span <= 0:
        frame_ids = [str(_field(c, "frame", "")) for c in items]
        return [{
            "start": start,
            "end": end,
            "time": start,
            "frames": len(items),
            "frame_ids": frame_ids,
            "bytes": sum(len(_field(c, "data", b"") or b"") for c in items),
            "min": start,
            "max": end,
        }]

    result = [{
        "start": start + span * i / count,
        "end": start + span * (i + 1) / count,
        "time": start + span * i / count,
        "frames": 0,
        "frame_ids": [],
        "bytes": 0,
        "min": None,
        "max": None,
    } for i in range(count)]

    for chunk, moment in zip(items, times):
        offset = int((moment - start) / span * count)
        bucket = result[min(max(offset, 0), count - 1)]
        bucket["frames"] += 1
        bucket["bytes"] += len(_field(chunk, "data", b"") or b"")
        frame = str(_field(chunk, "frame", ""))
        if frame:
            bucket["frame_ids"].append(frame)
        bucket["min"] = moment if bucket["min"] is None else min(bucket["min"], moment)
        bucket["max"] = moment if bucket["max"] is None else max(bucket["max"], moment)
    return result
