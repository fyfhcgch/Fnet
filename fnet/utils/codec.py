"""Small text/crypto helpers used by the UI and by feature handlers."""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import string
import urllib.parse

PRINTABLE = set(string.printable)


# -- simple codecs -----------------------------------------------------
def b64decode_text(value: str) -> str:
    value = re.sub(r"\s+", "", value)
    value += "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError):
        return value
    return _best_effort(raw)


def b32decode_text(value: str) -> str:
    value = re.sub(r"\s+", "", value).upper()
    value += "=" * (-len(value) % 8)
    try:
        raw = base64.b32decode(value)
    except (binascii.Error, ValueError):
        return value
    return _best_effort(raw)


def hexdecode_text(value: str) -> str:
    value = re.sub(r"(?i)0x|[\s:,]", "", value)
    if len(value) % 2:
        value = value[:-1]
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return value
    return _best_effort(raw)


def urldecode_text(value: str) -> str:
    return urllib.parse.unquote(value)


def gbk_text(value: str) -> str:
    """Decode latin-1 mojibake back to GBK when possible."""
    try:
        return value.encode("latin-1", "ignore").decode("gbk", "ignore")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value


def rot13(value: str) -> str:
    return codecs.encode(value, "rot13")


def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def single_byte_xor_candidates(data: bytes, limit: int = 5) -> list[tuple[int, bytes]]:
    """Rank single-byte XOR keys by printable ratio (classic CTF helper)."""
    scored = []
    for key in range(256):
        out = bytes(b ^ key for b in data)
        score = sum(chr(b) in PRINTABLE for b in out) / max(len(out), 1)
        scored.append((score, key, out))
    scored.sort(reverse=True)
    return [(key, out) for _, key, out in scored[:limit]]


def _best_effort(raw: bytes) -> str:
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch in PRINTABLE or ch.isprintable() for ch in text)
        if printable / max(len(text), 1) > 0.85:
            return text
    return raw.decode("latin-1", "replace")


# -- CTF oriented helpers ---------------------------------------------
HEX_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[\s:,-]?){6,}\b")
FLAG_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,20}\{[^{}\r\n]{1,120}\}")
FLAG_RE_LONG = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,20}\{[^{}\r\n]{1,400}\}")


#: Flag prefixes that CTF platforms use; used to trim junk that the
#: webshell echo prepends (``X@Yflag{...}`` -> ``flag{...}``).
FLAG_PREFIXES = ("ctfshow", "begin", "picoctf", "nssctf", "dasctf", "moectf",
                 "flagx", "hgame", "n1ctf", "flag", "idf", "ctf")


def find_flags(text: str) -> list[str]:
    found: list[str] = []
    for match in FLAG_RE.finditer(text or ""):
        value = match.group(0)
        lowered = value.lower()
        for prefix in FLAG_PREFIXES:
            index = lowered.find(prefix + "{")
            if index <= 0:
                continue
            head = value[:index]
            # Junk echo prefixes are short and uppercase/non-alphanumeric
            # (``X@Yflag{...}``, ``[S]flag{...}``); real flag names before a
            # known prefix are longer words (``notaflag{...}``).
            if before_ok(head):
                value = value[index:]
                break
        if value not in found:
            found.append(value)
    return found


def before_ok(head: str) -> bool:
    if not head:
        return False
    if len(head) <= 2 and (head.isupper() or not any(c.isalnum() for c in head)):
        return True
    return False


def decode_chain(value: str, rounds: int = 3) -> list[str]:
    """Try a few common transformations and return readable candidates."""
    seen: list[str] = []
    frontier = [value]
    for _ in range(rounds):
        nxt: list[str] = []
        for item in frontier:
            for func in (b64decode_text, b32decode_text, hexdecode_text,
                         urldecode_text):
                try:
                    out = func(item)
                except Exception:
                    continue
                if out and out != item and out not in seen:
                    seen.append(out)
                    nxt.append(out)
        frontier = nxt
        if not frontier:
            break
    return seen


def extract_hex_strings(text: str, minimum: int = 8) -> list[str]:
    out = []
    for match in HEX_RE.finditer(text):
        cleaned = re.sub(r"(?i)[\s:,-]|0x", "", match.group())
        if len(cleaned) >= minimum and len(cleaned) % 2 == 0:
            out.append(cleaned)
    return out


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(value: str) -> bytes:
    return bytes.fromhex(re.sub(r"(?i)[\s:,-]|0x", "", value))
