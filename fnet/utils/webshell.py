"""Webshell family rules and payload forensics helpers.

The traffic handlers used to hard-code one AES guess per family.  Real
engagements see several encoders per family, so the logic lives here as a
maintainable rule table:

* Godzilla ``AES_BASE64`` / ``AES_RAW`` / ``XOR_BASE64`` and the older
  ``PHP_XOR_BASE64`` payloads;
* Behinder 3.x (XOR + Base64) and Behinder 4.x (AES-CBC, IV prefixed);
* AntSword, Tianxie and China Chopper (菜刀).

Also contains two pure parsers used when a decrypted payload turns out to be a
Java ``.class`` file: a constant-pool reader that recovers the class name,
super class, interfaces and embedded strings, and a small command/output
restorer shared with the response scanner.
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass, field

from fnet.utils.crypto import aes_cbc_decrypt, aes_ecb_decrypt

JAVA_MAGIC = b"\xca\xfe\xba\xbe"
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"


@dataclass(frozen=True)
class WebshellRule:
    family: str
    variant: str
    encoding: str = "base64"      # base64 / raw / xor_base64
    key_spec: str = "md5"         # md5 / md5_16 / sha256_16 / raw / md5_hex_16
    cipher: str = "aes-cbc"       # aes-cbc / aes-ecb / xor / none
    iv: str = "prefix"            # prefix / key / zero / none
    content_types: tuple[str, ...] = ()
    path_markers: tuple[str, ...] = ()
    user_agents: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    sample: str = ""


#: Order matters: the most specific variants come first.
RULES: tuple[WebshellRule, ...] = (
    WebshellRule(
        "godzilla", "AES_BASE64", encoding="base64", key_spec="md5",
        cipher="aes-cbc", iv="prefix",
        path_markers=(".php", ".jsp", ".jspx", ".asp", ".aspx"),
        markers=("godzilla", "pass=", "key="),
        sample="Base64(IV||AES-CBC(MD5(pass)))"),
    WebshellRule(
        "godzilla", "AES_RAW", encoding="raw", key_spec="md5",
        cipher="aes-cbc", iv="prefix",
        content_types=("application/octet-stream", "application/x-www-form-urlencoded"),
        markers=("godzilla",),
        sample="IV||AES-CBC(MD5(pass))"),
    WebshellRule(
        "godzilla", "XOR_BASE64", encoding="xor_base64", key_spec="raw",
        cipher="xor", iv="none",
        markers=("godzilla",), sample="Base64(XOR(pass, payload))"),
    WebshellRule(
        "behinder4", "AES_BASE64", encoding="base64", key_spec="md5_16",
        cipher="aes-cbc", iv="prefix",
        content_types=("application/octet-stream",),
        markers=("behinder", "冰蝎"),
        sample="Base64(IV||AES-CBC(MD5(pass)[:16]))"),
    WebshellRule(
        "behinder4", "AES_RAW", encoding="raw", key_spec="md5_16",
        cipher="aes-cbc", iv="prefix",
        content_types=("application/octet-stream",),
        markers=("behinder", "冰蝎"),
        sample="IV||AES-CBC(MD5(pass)[:16])"),
    WebshellRule(
        "behinder", "XOR_BASE64", encoding="base64", key_spec="md5_16",
        cipher="xor", iv="none",
        content_types=("application/x-www-form-urlencoded",),
        markers=("behinder", "冰蝎"),
        sample="Base64(XOR(payload))"),
    WebshellRule(
        "antsword", "AES_BASE64", encoding="base64", key_spec="md5_16",
        cipher="aes-cbc", iv="prefix",
        content_types=("application/x-www-form-urlencoded",),
        markers=("antsword", "蚁剑"),
        sample="Base64(IV||AES-CBC(MD5(pass)[:16]))"),
    WebshellRule(
        "tianxie", "AES_BASE64", encoding="base64", key_spec="md5",
        cipher="aes-cbc", iv="prefix",
        markers=("tianxie", "天蝎"),
        sample="Base64(IV||AES-CBC(MD5(pass)))"),
    WebshellRule(
        "caidao", "CHOPPER", encoding="none", cipher="none", iv="none",
        markers=("->|", "|<-", "chopper", "菜刀"),
        sample="->|Base64(payload)|<-"),
)

FAMILIES = {rule.family for rule in RULES}
RULE_TABLE = {
    family: [rule for rule in RULES if rule.family == family]
    for family in FAMILIES
}


def rules_for(family: str = "auto", *, user_agent: str = "",
              content_type: str = "", path: str = "",
              body: bytes = b"") -> list[WebshellRule]:
    """Return candidate rules, most likely first.

    ``family="auto"`` scores by user agent, content type, path and payload
    markers.  An explicit family still returns the whole family so every
    encoder is attempted.
    """
    if family != "auto" and family in RULE_TABLE:
        return list(RULE_TABLE[family])
    ua = (user_agent or "").lower()
    ctype = (content_type or "").lower()
    lower_path = (path or "").lower()
    text = (body or b"")[:4096].lower()
    scored: list[tuple[int, WebshellRule]] = []
    for rule in RULES:
        score = 0
        if any(marker in ua for marker in rule.user_agents):
            score += 4
        if any(marker in ctype for marker in rule.content_types):
            score += 3
        if any(marker in lower_path for marker in rule.path_markers):
            score += 1
        if any(marker.encode() in text for marker in rule.markers):
            score += 4
        if "octet-stream" in ctype and rule.encoding == "raw":
            score += 2
        scored.append((score, rule))
    scored.sort(key=lambda item: -item[0])
    return [rule for score, rule in scored if score > 0] or list(RULES)


def derive_keys(password: str, rule: WebshellRule) -> list[tuple[str, bytes]]:
    """Candidate AES/XOR keys for one rule."""
    if not password:
        return []
    raw = password.encode("utf-8", "replace")
    digest = hashlib.md5(raw).digest()
    candidates: list[tuple[str, bytes]] = []
    if rule.key_spec == "md5":
        candidates += [("md5(pass)", digest),
                       ("md5(md5(pass))", hashlib.md5(digest).digest())]
    elif rule.key_spec == "md5_16":
        candidates += [("md5(pass)[:16]", digest[:16]),
                       ("md5(pass) hex[:16]", hashlib.md5(raw).hexdigest()[:16].encode())]
    elif rule.key_spec == "sha256_16":
        candidates += [("sha256(pass)[:16]", hashlib.sha256(raw).digest()[:16])]
    elif rule.key_spec == "md5_hex_16":
        candidates += [("md5(pass) hex[:16]", hashlib.md5(raw).hexdigest()[:16].encode())]
    elif rule.key_spec == "raw":
        candidates += [("raw password", raw)]
    # Always keep the generic variants as a safety net.
    candidates += [
        ("md5(pass)[:16]", digest[:16]),
        ("md5(pass)", digest),
        ("sha256(pass)[:16]", hashlib.sha256(raw).digest()[:16]),
    ]
    seen: set[bytes] = set()
    unique: list[tuple[str, bytes]] = []
    for label, key in candidates:
        if len(key) in (16, 24, 32) and key not in seen:
            seen.add(key)
            unique.append((label, key))
    return unique


def _b64(value: bytes) -> bytes:
    cleaned = re.sub(rb"\s+", b"", value or b"")
    if not cleaned:
        return b""
    cleaned += b"=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception:  # noqa: BLE001
        return b""


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return b""
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def decrypt_candidates(data: bytes, keys: list[tuple[str, bytes]],
                       rule: WebshellRule) -> list[tuple[str, str, bytes]]:
    """Try one rule against a payload.

    Returns ``(key_label, variant, plaintext)`` triples; the caller scores the
    plaintext because only it knows the surrounding capture context.
    """
    if not data:
        return []
    blobs: list[tuple[str, bytes]] = []
    if rule.encoding == "base64":
        decoded = _b64(data)
        if decoded:
            blobs.append(("base64", decoded))
    elif rule.encoding == "xor_base64":
        decoded = _b64(data)
        if decoded:
            blobs.append(("base64", decoded))
        blobs.append(("raw", data))
    else:
        blobs.append(("raw", data))

    output: list[tuple[str, str, bytes]] = []
    for payload_label, blob in blobs:
        if rule.cipher == "xor":
            for key_label, key in keys:
                output.append((key_label, f"XOR/{payload_label}", _xor(blob, key)))
                output.append((key_label, f"XOR/base64/{payload_label}",
                               _b64(_xor(blob, key))))
            continue
        if rule.cipher == "none":
            if rule.encoding == "base64":
                output.append(("-", "base64", blob))
            continue
        for key_label, key in keys:
            if rule.cipher == "aes-cbc":
                if rule.iv == "prefix" and len(blob) >= 32 and len(blob) % 16 == 0:
                    output.append((key_label, f"CBC(IV=前16字节)/{payload_label}",
                                   aes_cbc_decrypt(blob[16:], key, blob[:16])))
                if len(blob) % 16 == 0:
                    output.append((key_label, f"CBC(IV=0)/{payload_label}",
                                   aes_cbc_decrypt(blob, key, b"\x00" * 16)))
            elif rule.cipher == "aes-ecb" and len(blob) % 16 == 0:
                output.append((key_label, f"ECB/{payload_label}",
                               aes_ecb_decrypt(blob, key)))
    return output


# ---------------------------------------------------------------------------
# Java class (memory shell) forensics
# ---------------------------------------------------------------------------
CONSTANT_TAGS = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
                 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}

FILTER_BASES = ("javax.servlet.Filter", "jakarta.servlet.Filter")
SERVLET_BASES = ("javax.servlet.http.HttpServlet", "jakarta.servlet.http.HttpServlet",
                 "javax.servlet.GenericServlet", "jakarta.servlet.GenericServlet")
LISTENER_MARKERS = ("ServletRequestListener", "ServletContextListener",
                    "HttpSessionListener", "ServletContextAttributeListener")
REGISTRATION_MARKERS = (
    "addFilter", "addServlet", "addListener", "FilterDef", "FilterMap",
    "StandardContext", "ServletContext", "ApplicationContext", "Pipeline",
    "addValve", "Wrapper", "FilterChain", "getFilterChain", "invoke",
)


def _u1(data: bytes, offset: int) -> int:
    return data[offset] if offset < len(data) else 0


def _u2(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0] if offset + 2 <= len(data) else 0


def _u4(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0] if offset + 4 <= len(data) else 0


def parse_java_class(data: bytes) -> dict | None:
    """Recover names/strings from a Java ``.class`` constant pool."""
    if not data or not data.startswith(JAVA_MAGIC) or len(data) < 10:
        return None
    count = _u2(data, 8)
    if count < 1:
        return None
    pool: list[tuple[int, object]] = [(0, "")]
    utf8: dict[int, str] = {}
    class_refs: dict[int, int] = {}
    index = 10
    position = 1
    while position < count and index + 1 <= len(data):
        tag = _u1(data, index)
        index += 1
        if tag == 1:
            length = _u2(data, index)
            index += 2
            raw = data[index:index + length]
            index += length
            try:
                text = raw.decode("utf-8", "replace")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", "replace")
            utf8[position] = text
            pool.append((tag, text))
        elif tag in (7, 8, 16, 19, 20):
            value = _u2(data, index)
            index += 2
            if tag == 7:
                class_refs[position] = value
            pool.append((tag, value))
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            index += 4
            pool.append((tag, b""))
        elif tag in (5, 6):
            index += 8
            pool.append((tag, b""))
            position += 1
        elif tag == 15:
            index += 3
            pool.append((tag, b""))
        else:
            return None
        position += 1
    if index + 8 > len(data):
        return None
    this_class = _u2(data, index + 2)
    super_class = _u2(data, index + 4)
    interface_count = _u2(data, index + 6)
    cursor = index + 8
    interfaces: list[str] = []
    for _ in range(interface_count):
        ref = _u2(data, cursor)
        cursor += 2
        interfaces.append(_class_name(ref, class_refs, utf8))

    class_name = _class_name(this_class, class_refs, utf8)
    super_name = _class_name(super_class, class_refs, utf8)
    strings = list(dict.fromkeys(utf8.values()))
    joined = "\n".join(strings)

    kind = "unknown"
    if super_name in FILTER_BASES or any(
            name in interfaces for name in FILTER_BASES):
        kind = "Filter"
    elif super_name in SERVLET_BASES:
        kind = "Servlet"
    elif any(marker in joined for marker in LISTENER_MARKERS):
        kind = "Listener"
    elif "Filter" in class_name or "Filter" in super_name:
        kind = "Filter(推断)"
    elif "Servlet" in class_name or "Servlet" in super_name:
        kind = "Servlet(推断)"

    markers = [marker for marker in REGISTRATION_MARKERS if marker in joined]
    urls = sorted(set(re.findall(r"/(?:[A-Za-z0-9_.*~-]+/?)+", joined)))
    return {
        "class_name": class_name,
        "super_class": super_name,
        "interfaces": [name for name in interfaces if name],
        "kind": kind,
        "registration_markers": markers,
        "url_patterns": urls,
        "strings": strings,
    }


def _class_name(ref: int, class_refs: dict[int, int],
                utf8: dict[int, str]) -> str:
    name_index = class_refs.get(ref, 0)
    return utf8.get(name_index, "").replace("/", ".")


def analyze_java_class(data: bytes) -> dict | None:
    """Parse a decrypted Java class and add a human readable summary."""
    info = parse_java_class(data)
    if info is None:
        return None
    interesting = [text for text in info["strings"]
                   if any(marker in text for marker in REGISTRATION_MARKERS)
                   or "shell" in text.lower() or "cmd" in text.lower()
                   or "exec" in text.lower() or "godzilla" in text.lower()
                   or "behinder" in text.lower()]
    info["interesting_strings"] = interesting[:60]
    info["summary"] = (
        f"Java 内存马候选: {info['kind']} {info['class_name'] or '(未知类名)'}"
        f" 继承 {info['super_class'] or '-'}"
        + (f"，接口 {', '.join(info['interfaces'][:4])}" if info["interfaces"] else "")
        + (f"，注册特征 {', '.join(info['registration_markers'][:6])}"
           if info["registration_markers"] else ""))
    return info


# ---------------------------------------------------------------------------
# Command / output restoration
# ---------------------------------------------------------------------------
COMMAND_RE = re.compile(
    r"(?i)\b(?:cmd|command|exec|shell|run)\s*[=:]\s*['\"]?"
    r"([^\r\n'\";]{1,200})")
KNOWN_COMMANDS = re.compile(
    r"(?i)^\s*(?:whoami|id|uname(?:\s+-a)?|pwd|ls(?:\s+-[a-z]+)?|"
    r"cat\s+\S+|type\s+\S+|dir(?:\s+\S+)?|ipconfig|ifconfig|net\s+\S+|"
    r"tasklist|ps(?:\s+-ef)?|find\s+\S+|grep\s+\S+|echo\s+\S+|"
    r"upload\s+\S+|download\s+\S+|curl\s+\S+|wget\s+\S+|"
    r"systeminfo|hostname)\b")
FILE_OP_RE = re.compile(
    r"(?i)\b(upload|download|file_get_contents|file_put_contents|fopen|"
    r"fwrite|fread|unlink|rename|copy|move|mkdir|readfile)\b")
FLAG_RE = re.compile(
    r"(?i)\b(?:flag|ctf|key|pass(?:word)?)\{[^}\r\n]{1,200}\}")


def restore_output(text: str) -> dict:
    """Structure a decrypted webshell request/response.

    Returns ``commands`` (command strings), ``output`` (remaining text),
    ``files`` (file paths mentioned), ``flags`` and ``operations``.
    """
    text = text or ""
    commands: list[str] = []
    for match in COMMAND_RE.finditer(text):
        value = match.group(1).strip()
        if value:
            commands.append(value)
    for line in text.splitlines():
        stripped = line.strip()
        if KNOWN_COMMANDS.match(stripped) and stripped not in commands:
            commands.append(stripped[:200])
    operations: list[str] = []
    lowered = text.lower()
    for name in ("upload", "download", "write", "read", "delete", "rename",
                 "list", "exec"):
        if name in lowered:
            operations.append(name)
    files = sorted(set(re.findall(
        r"(?<![\w/])(?:[A-Za-z]:\\[^\s\"']+|/(?:[\w.-]+/)*[\w.-]+)", text)))
    flags = list(dict.fromkeys(FLAG_RE.findall(text)))
    output_lines = [line for line in text.splitlines()
                    if line.strip() and not KNOWN_COMMANDS.match(line.strip())]
    return {
        "commands": commands[:40],
        "operations": operations,
        "files": files[:60],
        "flags": flags[:40],
        "output": "\n".join(output_lines[:200]),
        "length": len(text),
    }


def summarize_rule(rule: WebshellRule) -> str:
    return f"{rule.family}/{rule.variant}: {rule.sample}"
