"""Small text/crypto helpers used by the UI and by feature handlers."""
from __future__ import annotations

import base64
import binascii
import codecs
import math
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


#: Flag prefixes that CTF platforms use. Two jobs:
#:
#: 1. trim junk that a webshell echo prepends (``X@Yflag{...}`` -> ``flag{...}``);
#: 2. decide tier 1 of the flag policy below — a match whose name is (or ends
#:    with) one of these is a real flag, everything else is only a candidate.
#:
#: ``FLAG_PREFIX_FAMILIES`` holds prefixes matched as a *family* (``bsides*``
#: -> ``bsidessf``/``bsidescf``).  Extend these tuples instead of adding a
#: second, parallel list of known competitions.
FLAG_PREFIXES = (
    "ctfshow", "picoctf", "nssctf", "dasctf", "moectf", "newstar", "dest0g3",
    "glacier", "hgame", "n1ctf", "vnctf", "utctf", "suctf", "buu", "buuctf",
    "xman", "iscc", "nss", "flagx", "begin", "flag", "idf", "ctf",
)
FLAG_PREFIX_FAMILIES = ("bsides",)

#: Words that mark a flag *name* even when another word precedes them
#: (``notaflag{...}``, ``sensorsflag{...}``).  Compared after leet
#: normalisation, so ``fl4g{sql}`` and ``fl4g`` style names still count.
_FLAG_NAME_SUFFIXES = ("flag", "ctf")

#: ``identifier{...}`` matches whose *body* contains any of these characters
#: are source code, not flags (``else{$R.="/";}``, ``bx{width: 90%;}``).
FLAG_CODE_CHARS = frozenset(";<>=$()")

#: CSS/PHP/JS keywords: the strongest signal that a body is source code.
FLAG_CODE_KEYWORDS = (
    "width", "height", "margin", "padding", "display", "font", "color",
    "background", "array_map", "strtolower", "function", "else", "return",
    "var ", "document", "style",
)

#: A CSS declaration body (``width: 40px``, ``color:#fff``) is code even
#: without a trailing semicolon.
FLAG_CSS_DECL_RE = re.compile(
    r"^\s*-{0,2}[a-z][a-z-]*\s*:\s*[^;{}]+;?\s*$", re.IGNORECASE)

#: Classification tiers returned by :func:`classify_flag`.
FLAG_TIER_FLAG = "flag"          # tier 1: accept as a flag finding
FLAG_TIER_CANDIDATE = "candidate"  # everything else: recall-only candidate
FLAG_TIER_CODE = "code"          # tier 2: source-code junk, dropped
FLAG_TIER_CIPHERTEXT = "ciphertext"  # tier 3: binary/ciphertext junk, dropped

_LEET = str.maketrans({"4": "a", "1": "l", "0": "o", "3": "e", "5": "s",
                       "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})

_PRINTABLE_BYTES = bytes(
    1 if (32 <= value < 127 or value in (9, 10, 13)) else 0
    for value in range(256))


def _leet_normalise(name: str) -> str:
    """Lowercase a flag name and undo common leetspeak (``fl4g`` -> ``flag``)."""
    return name.lower().translate(_LEET)


def _printable_ratio(data: bytes) -> float:
    """Local copy of ``fnet.utils.pcap.printable_ratio`` (no import cycle)."""
    if not data:
        return 0.0
    return data.translate(_PRINTABLE_BYTES).count(1) / len(data)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total)
                for count in counts.values())


def _looks_like_ciphertext(body: str) -> bool:
    """Tier 3: binary/encrypted blob smuggled inside ``name{...}``.

    Rejects bodies with a low printable ratio (``YU{×B­ÌÍ½ërg·JÌ¢Ox…}``) and
    high-entropy latin-1 mojibake.  Genuine UTF-8 text (``flag{中文}``) is
    kept: it does not round-trip through latin-1, so it is not mojibake.
    """
    if not body:
        return False
    data = body.encode("utf-8", "replace")
    text_ratio = sum(1 for ch in body if ch.isprintable()) / len(body)
    if max(text_ratio, _printable_ratio(data)) < 0.85:
        return True
    try:
        mojibake = body.encode("latin-1")
    except UnicodeEncodeError:
        return False  # real non-latin1 text (e.g. CJK), not ciphertext
    non_ascii = sum(1 for byte in mojibake if byte > 126)
    return bool(non_ascii) and _shannon_entropy(mojibake) > 3.5


def _looks_like_code(body: str) -> bool:
    """Tier 2: the body is a source-code/CSS fragment, not a flag."""
    if not body:
        return False
    if any(char in FLAG_CODE_CHARS for char in body):
        return True
    if body.rstrip().endswith(";"):
        return True
    lowered = body.lower()
    if any(keyword in lowered for keyword in FLAG_CODE_KEYWORDS):
        return True
    return bool(FLAG_CSS_DECL_RE.match(body))


def _trim_echo_prefix(value: str) -> str:
    """Strip a short junk echo prefix in front of a known flag prefix."""
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
            return value[index:]
    return value


def _is_known_flag_name(name: str) -> bool:
    """Tier 1: is ``name`` a competition prefix (or a name carrying one)?"""
    raw = (name or "").lower()
    if not raw:
        return False
    # Compare the literal spelling first (``dest0g3`` contains digits), then
    # the leetspeak-folded form (``fl4g`` -> ``flag``).
    for candidate in (raw, _leet_normalise(raw)):
        if candidate in FLAG_PREFIXES:
            return True
        if any(candidate.startswith(family)
               for family in FLAG_PREFIX_FAMILIES):
            return True
        if any(candidate.endswith(suffix) for suffix in _FLAG_NAME_SUFFIXES):
            return True
    return False


def classify_flag(value: str) -> str:
    """Return the policy tier for one ``name{body}`` match.

    Tiers are checked from most to least specific:

    * :data:`FLAG_TIER_FLAG` — a known competition prefix (``flag``, ``ctf``,
      ``nssctf`` …) in an otherwise textual body;
    * :data:`FLAG_TIER_CIPHERTEXT` — binary/ciphertext body (tier 3);
    * :data:`FLAG_TIER_CODE` — source code / CSS body (tier 2);
    * :data:`FLAG_TIER_CANDIDATE` — unknown name, plausible text body: kept
      only as a candidate (see :func:`find_flag_candidates`).
    """
    value = value or ""
    if "{" not in value:
        return FLAG_TIER_CANDIDATE
    name, _, body = value.partition("{")
    if body.endswith("}"):
        body = body[:-1]
    if _looks_like_ciphertext(body):
        return FLAG_TIER_CIPHERTEXT
    if _is_known_flag_name(name):
        # Real flags may legitimately contain ``=``/``()`` (base64 padding,
        # ``flag{a(b)}``); a known prefix wins over the code heuristic.
        return FLAG_TIER_FLAG
    if _looks_like_code(body):
        return FLAG_TIER_CODE
    return FLAG_TIER_CANDIDATE


def _iter_matches(text: str):
    for match in FLAG_RE.finditer(text or ""):
        yield _trim_echo_prefix(match.group(0))


def find_flags(text: str) -> list[str]:
    """Return only the flags that pass tier 1 of the flag policy.

    ``identifier{...}`` is far too broad for real traffic (CSS rules, PHP
    snippets and TLS ciphertext all match it), so unknown names are demoted
    to candidates — use :func:`find_flag_candidates` when recall matters.
    """
    found: list[str] = []
    for value in _iter_matches(text):
        if classify_flag(value) != FLAG_TIER_FLAG:
            continue
        if value not in found:
            found.append(value)
    return found


def find_flag_candidates(text: str) -> list[str]:
    """Return plausible but unproven flags (recall only).

    Source-code and ciphertext bodies are still dropped; this is only the
    "unknown name, readable body" bucket that :func:`find_flags` no longer
    promotes to a finding.
    """
    found: list[str] = []
    for value in _iter_matches(text):
        if classify_flag(value) != FLAG_TIER_CANDIDATE:
            continue
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
