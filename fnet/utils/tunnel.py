"""Covert-channel reassembly helpers (DNS labels, ICMP payloads).

Pure standard library: these helpers decode and stitch chunks that DNS or
ICMP tunnels split across packets.  Nothing here raises on malformed input;
callers get best-effort results instead.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "Chunk", "decode_chunk", "parse_sequence", "reassemble", "group_sessions",
    "analyse_dns", "analyse_icmp", "find_flags", "write_decoded", "timeline",
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
    """Stitch chunks into one message, reporting gaps and duplicates."""
    items = [c for c in (chunks or []) if c is not None]
    indexed = [c for c in items if _field(c, "index") is not None]
    unindexed = [c for c in items if _field(c, "index") is None]

    ordered: list[Any] = []
    seen: dict[int, Any] = {}
    duplicate_indices: set[int] = set()
    if indexed:
        for chunk in sorted(indexed, key=lambda c: (_field(c, "index"),
                                                   _field(c, "time", 0.0))):
            index = int(_field(chunk, "index"))
            if index in seen:
                duplicate_indices.add(index)
                continue
            seen[index] = chunk
            ordered.append(chunk)
    ordered.extend(unindexed)

    totals = [int(_field(c, "total")) for c in items
              if _field(c, "total") is not None]
    total = max(totals) if totals else None

    indices = sorted(seen)
    missing: list[int] = []
    if indices:
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
        "complete": bool(ordered) and not missing,
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


def _refine(data: bytes, flags: list[str]) -> tuple[bytes, str, list[str]]:
    """Decode an assembled blob once more when it does not carry a flag."""
    text = _text_of(data)
    if flags:
        return data, text, flags
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
        data, text, flags = _refine(result["data"], flags)
        for flag in flags:
            if flag not in all_flags:
                all_flags.append(flag)
        decoded.append({
            "session": key,
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
