"""PCAP helper utilities built on top of tshark."""
from __future__ import annotations

import re
from pathlib import Path

HEX_CLEAN = re.compile(r"[^0-9a-fA-F]")


def hex_to_bytes(value: str) -> bytes:
    value = HEX_CLEAN.sub("", value or "")
    if len(value) % 2:
        value = value[:-1]
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def to_text(data: bytes) -> str:
    for encoding in ("utf-8", "gbk", "big5", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace")


def payload_text(value: str | bytes) -> str:
    if isinstance(value, (bytes, bytearray)):
        return to_text(bytes(value))
    return to_text(hex_to_bytes(value))


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(32 <= b < 127 or b in (9, 10, 13) or b > 127 for b in data)
    return good / len(data)


def follow_stream(tshark: str, pcap: str | Path, index: int, mode: str = "ascii") -> str:
    """Return ``tshark -z follow,tcp,ascii,N`` output for one stream."""
    from fnet.tools.runner import run

    code, out = run([tshark, "-r", str(pcap), "-q", "-z",
                     f"follow,tcp,{mode},{index}"])
    return out if code == 0 else ""


def conversations(tshark: str, pcap: str | Path, proto: str = "tcp") -> str:
    from fnet.tools.runner import run

    code, out = run([tshark, "-r", str(pcap), "-q", "-z", f"conv,{proto}"])
    return out if code == 0 else ""


def file_magic(path: Path) -> str:
    try:
        head = path.read_bytes()[:16]
    except OSError:
        return "unknown"
    return file_magic_bytes(head)


def file_magic_bytes(head: bytes) -> str:
    """Classify a file from its first bytes (shared by export handlers)."""
    signatures = {
        b"\x89PNG\r\n\x1a\n": "PNG image",
        b"\xff\xd8\xff": "JPEG image",
        b"GIF8": "GIF image",
        b"PK\x03\x04": "ZIP archive",
        b"%PDF": "PDF document",
        b"\x7fELF": "ELF executable",
        b"MZ": "PE executable",
        b"\x1f\x8b": "gzip data",
        b"BZh": "bzip2 data",
        b"7z\xbc\xaf\x27\x1c": "7z archive",
        b"Rar!\x1a\x07": "RAR archive",
        b"\x00\x00\x01\x00": "ICO image",
        b"ID3": "MP3 audio",
        b"\x00\x00\x00\x18ftyp": "MP4 video",
    }
    head = bytes(head or b"")[:16]
    for magic, name in signatures.items():
        if head.startswith(magic):
            return name
    ratio = printable_ratio(head)
    return "text" if ratio > 0.9 else "binary"
