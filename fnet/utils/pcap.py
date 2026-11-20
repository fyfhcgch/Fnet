"""PCAP helper utilities built on top of tshark."""
from __future__ import annotations

import re
from pathlib import Path

from fnet.logger import logger

HEX_CLEAN = re.compile(r"[^0-9a-fA-F]")
#: ``0x`` 前缀可以出现在每个逗号分隔的多值片段前（tshark 的
#: ``0x1301,0xc02f``），因此逐个片段剥离而不是只剥整体前缀。
HEX_PREFIX = re.compile(r"(?i)^0x")
HEX_SEPARATORS = re.compile(r"[:,;\-\s]")


def hex_to_bytes(value: str) -> bytes:
    """Decode a hex string, tolerating the separators tshark emits.

    ``0x``/``0X`` prefixes and ``:``/``-``/``,``/whitespace separators are
    removed before decoding, so ``"0x41"``, ``"41"``, ``"4:1"`` and ``"41 "``
    all yield ``b"A"``; per-value prefixes such as ``"0x1301,0xc02f"`` work
    too.  Anything that cannot be decoded — an odd number of hex digits, a
    non-hex character, or a bare ``"0x"`` — returns ``b""`` instead of
    silently dropping a nibble, which used to turn ``"0x41"`` into
    ``b"\\x04"``.
    """
    tokens = [HEX_PREFIX.sub("", part)
              for part in HEX_SEPARATORS.split(str(value or "").strip())]
    text = "".join(tokens)
    if not text:
        return b""
    if HEX_CLEAN.search(text):
        logger.debug("hex_to_bytes: 含非十六进制字符，已忽略该值")
        return b""
    if len(text) % 2:
        logger.debug(f"hex_to_bytes: 十六进制长度为奇数（{len(text)}），已忽略该值")
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        logger.debug("hex_to_bytes: 无法解码，已忽略该值")
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
    """Fraction of bytes that look like real text (ASCII + tab/newline/CR).

    Bytes above 127 are deliberately *not* counted: counting them made
    random ciphertext look ~75% printable and defeated the noise filters of
    the decryption handlers.

    实际计算委托给 ``fnet.utils.accel``：有关键字扫描的编码变换热点做了
    可选 CUDA/JIT 加速；加速不可用或关闭时回退到本模块的纯 Python 实现，
    结果逐位一致（延迟导入避免循环依赖）。
    """
    if not data:
        return 0.0
    from fnet.utils import accel
    return accel.printable_ratio(data)


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
