"""Webshell and Apache Shiro ``rememberMe`` decryption.

Supported families: Godzilla (哥斯拉), Behinder (冰蝎), AntSword (蚁剑),
Caidao/China Chopper (菜刀) and Tianxie (天蝎).  The implementations are
signature/heuristic based because every family ships several payload
encoders; the report always states which variant succeeded.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils import webshell as shell_rules
from fnet.paths import ASSETS_DIR
from fnet.utils.crypto import (
    aes_cbc_decrypt, aes_ecb_decrypt, aes_gcm_decrypt, looks_printable,
)
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio

JAVA_MAGIC = b"\xac\xed\x00\x05"
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}){8,}\b")
PHP_MARKERS = (b"<?php", b"<?=", b"eval(", b"assert(", b"system(", b"cmd")
JAVA_MARKERS = (b"java/", b"java.lang", b"javax.", b"class ", b"sun.")
COMMON_MARKERS = (b"cmd", b"whoami", b"id", b"flag", b"key", b"pass", b"<?",
                  b"{\"", b"success", b"result")
#: Java servlet-container classes that show up in decrypted Godzilla /
#: Behinder memory shells (filter/listener/servlet registered at runtime).
MEMORY_SHELL_MARKERS = (
    b"requestcontextlistener", b"standardcontext", b"filterchain",
    b"filterdef", b"servletcontext", b"org.apache.catalina",
    b"javax.servlet", b"jakarta.servlet", b"listener", b"valve",
    b"pipeline", b"addfilter", b"addservlet", b"behind", b"godzilla",
    b"memoryshell", "内存马".encode("utf-8"),
)
#: Markers that are specific enough to stand on their own; the rest are
#: generic Java words and need corroboration.
STRONG_MEMORY_MARKERS = {
    "requestcontextlistener", "standardcontext", "filterdef", "addfilter",
    "addservlet", "org.apache.catalina", "javax.servlet", "jakarta.servlet",
    "behind", "godzilla", "memoryshell", "内存马",
}


def _b64(value: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", urllib.parse.unquote(value or ""))
    if len(cleaned) < 8:
        return None
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception:  # noqa: BLE001
        return None


def _key_candidates(password: str) -> list[tuple[str, bytes]]:
    if not password:
        return []
    raw = password.encode("utf-8", "replace")
    digest = hashlib.md5(raw).digest()
    digest_hex = hashlib.md5(raw).hexdigest().encode()
    out = [
        ("md5(pass)[:16]", digest[:16]),
        ("md5(pass)", digest),
        ("md5(pass) hex[:16]", digest_hex[:16]),
        ("md5(pass) HEX[:16]", digest_hex.upper()[:16]),
        ("md5(md5(pass))", hashlib.md5(digest).digest()),
        ("sha256(pass)[:16]", hashlib.sha256(raw).digest()[:16]),
        ("raw password padded", (raw + b"\x00" * 32)[:32]),
    ]
    if len(urllib.parse.unquote(password)) in (16, 24, 32):
        out.append(("raw 16/24/32", urllib.parse.unquote(password).encode()))
    return [(label, key) for label, key in out if len(key) in (16, 24, 32)]


def _try_aes(data: bytes, key: bytes) -> list[tuple[str, bytes]]:
    results = []
    if len(data) >= 32 and len(data) % 16 == 0:
        results.append(("CBC(IV=前16字节)", aes_cbc_decrypt(data[16:], key, data[:16])))
        results.append(("CBC(IV=key[:16])", aes_cbc_decrypt(data, key, key[:16])))
    if len(data) % 16 == 0:
        results.append(("ECB", aes_ecb_decrypt(data, key)))
        results.append(("CBC(IV=0)", aes_cbc_decrypt(data, key, b"\x00" * 16)))
    # Shiro's GCM cipher stores the 128 bit IV in front of ciphertext+tag.
    if len(data) >= 32:
        plain, _valid = aes_gcm_decrypt(data[16:], key, data[:16],
                                        check_tag=False)
        results.append(("GCM(IV=前16字节)", plain))
        plain, _valid = aes_gcm_decrypt(data[16:], key, key[:16], check_tag=False)
        results.append(("GCM(IV=key[:16])", plain))
    return results


def _score(data: bytes) -> int:
    """Rank decrypted candidates.

    High bytes alone are *not* a good signal: decrypting with the wrong key
    produces plenty of them.  Count real ASCII text and valid UTF-8 instead,
    then reward protocol markers and Java serialization.
    """
    if not data:
        return -1
    if data.startswith(JAVA_MAGIC):
        return 100
    ascii_text = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    score = int(ascii_text / len(data) * 50)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and sum(ch.isprintable() for ch in text) / len(text) > 0.9:
        score = max(score, 50)
    lowered = data.lower()
    for marker in PHP_MARKERS + JAVA_MARKERS + COMMON_MARKERS:
        if marker in lowered:
            score += 12
    if any(marker in lowered for marker in MEMORY_SHELL_MARKERS):
        score += 18
    return score


def memory_shell_markers(data: bytes) -> list[str]:
    """Return the memory-shell markers present in a decrypted payload."""
    lowered = (data or b"").lower()
    return [marker.decode("utf-8", "replace") for marker in MEMORY_SHELL_MARKERS
            if marker in lowered]


def _decrypt_any(data: bytes, keys: list[tuple[str, bytes]],
                 label: str = "") -> tuple[str, bytes, str] | None:
    best: tuple[int, str, bytes, str] | None = None
    for key_label, key in keys:
        for mode, plain in _try_aes(data, key):
            value = _score(plain)
            if value > (best[0] if best else 0):
                best = (value, key_label, plain, mode)
    if best and best[0] >= 20:
        return best[1], best[2], best[3]
    return None


def java_strings(data: bytes, minimum: int = 4) -> list[str]:
    """Extract length-prefixed and printable strings from Java serialization."""
    strings: list[str] = []
    index = 0
    while index + 2 <= len(data):
        length = int.from_bytes(data[index:index + 2], "big")
        if 2 <= length <= 512 and index + 2 + length <= len(data):
            chunk = data[index + 2:index + 2 + length]
            try:
                text = chunk.decode("utf-8")
                if text.isprintable() and len(text) >= minimum:
                    strings.append(text)
                    index += 2 + length
                    continue
            except UnicodeDecodeError:
                pass
        index += 1
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        strings.append(match.group().decode("latin-1"))
    return list(dict.fromkeys(strings))


def load_shiro_keys(manual: str = "") -> list[tuple[str, bytes]]:
    keys: list[tuple[str, bytes]] = []
    if manual:
        raw = _b64(manual) or manual.encode("utf-8", "replace")
        if len(raw) in (16, 24, 32):
            keys.append(("手动密钥", raw))
    key_file = ASSETS_DIR / "shiro_keys.txt"
    if key_file.exists():
        for line in key_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw = _b64(line)
            if raw and len(raw) in (16, 24, 32):
                keys.append((line, raw))
    # De-duplicate but remember the textual key.
    seen: set[bytes] = set()
    unique = []
    for label, key in keys:
        if key not in seen:
            seen.add(key)
            unique.append((label, key))
    return unique


def _decrypt_shiro(blob: bytes, keys: list[tuple[str, bytes]]) -> tuple[str, bytes, str] | None:
    """Try keys cheaply on the first block before decrypting everything."""
    for label, key in keys:
        variants = []
        if len(blob) >= 32 and len(blob) % 16 == 0:
            variants.append(("CBC(IV=前16字节)", blob[16:], blob[:16]))
            variants.append(("CBC(IV=key[:16])", blob, key[:16]))
        if len(blob) % 16 == 0:
            variants.append(("ECB", blob, None))
        for mode, data, iv in variants:
            if len(data) < 16:
                continue
            # Cheap test on first block.
            if iv is not None:
                first = aes_cbc_decrypt(data[:16], key, iv)
            else:
                first = aes_ecb_decrypt(data[:16], key)
            if not (first.startswith(JAVA_MAGIC[:4])
                    or looks_printable(first, 0.8)):
                continue
            plain = (aes_cbc_decrypt(data, key, iv) if iv is not None
                     else aes_ecb_decrypt(data))
            if _score(plain) >= 20 or first.startswith(JAVA_MAGIC[:4]):
                return label, plain, mode
        if len(blob) >= 32:
            for mode, gcm_iv in (("GCM(IV=前16字节)", blob[:16]),
                                 ("GCM(IV=key[:16])", key[:16])):
                plain, valid = aes_gcm_decrypt(blob[16:], key, gcm_iv)
                if not plain:
                    continue
                # A matching GCM tag is proof of the key; without it require
                # a clearly readable plaintext.
                if valid or _score(plain) >= 40:
                    suffix = "" if valid else " (tag 未校验)"
                    return label, plain, mode + suffix
    return None


def shiro(ctx: FeatureContext) -> None:
    manual = str(ctx.params.get("shiro_key") or "")
    mode = str(ctx.params.get("shiro_mode") or "auto")
    keys = load_shiro_keys(manual if mode == "diy" else "")
    if mode == "diy" and not keys:
        ctx.report("手动模式需要有效的 Shiro 密钥（Base64 或 16/24/32 字节）", "error")
        return
    if mode != "diy" and not keys:
        ctx.report("没有可用的 Shiro 密钥，请检查 fnet/assets/shiro_keys.txt", "error")
        return
    if mode != "diy":
        ctx.report(f"自动模式：已加载 {len(keys)} 个候选密钥", "info")

    remember = str(ctx.params.get("shiro_remember") or "rememberMe")
    display_filter = f'http.cookie contains "{remember}"'
    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "http.request.uri",
              "http.cookie", "http.host"], display_filter, limit=20_000)
    if not rows:
        ctx.report(f"没有发现包含 {remember} Cookie 的 HTTP 请求", "warn")
        return

    found: dict[str, str] = {}
    decoded_count = 0
    for index, row in enumerate(rows):
        if index % 20 == 0:
            ctx.set_progress(int(index / len(rows) * 95))
            ctx.check_cancel()
        row += [""] * (5 - len(row))
        frame, stream, uri, cookie, host = row
        value = ""
        for part in cookie.split(";"):
            name, _, raw = part.strip().partition("=")
            if name == remember:
                value = raw
                break
        if not value:
            continue
        blob = _b64(value)
        if not blob:
            ctx.report(f"帧 {frame} Cookie 不是有效 Base64", "warn")
            continue
        result = _decrypt_shiro(blob, keys)
        if result is None:
            ctx.report(f"帧 {frame} 未能解密（尝试了 {len(keys)} 个密钥）", "warn")
            continue
        key_label, plain, variant = result
        decoded_count += 1
        found[key_label] = variant
        ctx.report(f"===== 帧 {frame} 解密成功 =====", "good")
        ctx.report(f"Host: {host}  URI: {uri}", "info")
        ctx.report(f"密钥: {key_label}  模式: {variant}", "good")
        ctx.report(f"明文长度: {len(plain)} 字节  是否 Java 序列化: "
                   f"{'是' if plain.startswith(JAVA_MAGIC) else '否'}", "info")
        if plain.startswith(JAVA_MAGIC):
            strings = java_strings(plain)
            if strings:
                ctx.report("Java 序列化中的字符串:", "good")
                for text in strings[:80]:
                    ctx.report("  " + clean_cell(text, 240), "good")
            suffix = ".ser"
        else:
            text = payload_text(plain)
            for line in text.splitlines()[:60]:
                if line.strip():
                    ctx.report("  " + clean_cell(line, 240), "info")
            suffix = ".bin"
        ctx.write_output(f"shiro_{frame}_{stream}{suffix}", plain)
        ctx.add_finding("webshell", f"Shiro 解密 {uri or host}",
                        frame=frame, level="good",
                        detail=f"密钥 {key_label} · 模式 {variant} · {suffix}\n"
                               + payload_text(plain)[:800])
        for flag in codec.find_flags(payload_text(plain)):
            ctx.report(f"发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag, frame=frame,
                            detail=f"Shiro 解密结果（{key_label}）", level="good")

    if found:
        ctx.report("===== 命中的 Shiro 密钥 =====", "good")
        for key, variant in found.items():
            ctx.report(f"{key}  ({variant})", "good")
        ctx.report("提示：若解出的序列化数据包含上传的 webshell，请把该密钥填入 "
                   "Webshell 解密设置后运行 Webshell 解密。", "info")
    else:
        ctx.report("没有成功解密的 Shiro 流量", "warn")
    ctx.set_progress(100)


CMD_MARKERS = (b"$_post", b"$_get", b"$_request", b"$_server", b"base64_decode",
               b"assert(", b"eval(", b"system(", b"passthru", b"shell_exec",
               b"array_map", b"create_function", b"gzinflate", b"proc_open",
               b"popen(", b"stream_get_contents", b"ini_set", b"set_time_limit",
               b"magic_quotes", b"curl_exec", b"file_get_contents", b"die()")


def _plain_payload(blob: bytes) -> bool:
    """True when the blob already is a readable (base64/plain) webshell body."""
    if not looks_printable(blob, 0.7):
        return False
    lowered = blob.lower()
    score = sum(1 for marker in CMD_MARKERS if marker in lowered)
    return score >= 2 or (PHP_MARKERS[0] in lowered and score >= 1)


def _scan_responses(ctx: FeatureContext) -> int:
    """Report response bodies (command output) and any flag they contain."""
    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "http.response_in", "http.file_data",
              "http.content_type"], "http.response", limit=100_000)
    if not rows:
        return 0
    found = 0
    for index, row in enumerate(rows):
        if index % 200 == 0:
            ctx.check_cancel()
        row += [""] * (5 - len(row))
        frame, stream, _parent, raw, ctype = row
        if not raw:
            continue
        data = hex_to_bytes(raw)
        if not data or printable_ratio(data) < 0.6:
            continue
        text = payload_text(data)
        lowered = data.lower()
        score = sum(1 for marker in CMD_MARKERS if marker in lowered)
        flags = codec.find_flags(text)
        command_output = (score >= 1 or "X@Y" in text or "[S]" in text)
        if not command_output and not flags:
            continue
        found += 1
        ctx.report(f"===== 帧 {frame} 响应数据 =====", "good")
        ctx.report(f"Content-Type: {ctype or '-'}  长度: {len(data)} 字节", "info")
        for line in text.splitlines()[:60]:
            if line.strip():
                ctx.report("  " + clean_cell(line, 240), "info")
        ctx.write_output(f"webshell_response_{frame}.txt", data)
        _report_restored_output(ctx, frame, "", text, "响应明文扫描")
        for flag in flags:
            ctx.report(f"发现 flag: {flag}", "good")
    return found


def _extract_blobs(text: str) -> list[bytes]:
    blobs: list[bytes] = []
    for match in B64_RE.finditer(text or ""):
        raw = _b64(match.group(0))
        if raw and len(raw) >= 16:
            blobs.append(raw)
    for match in HEX_RE.finditer(text or ""):
        raw = hex_to_bytes(match.group(0))
        if raw:
            blobs.append(raw)
    return blobs


def _printable_text(data: bytes) -> str:
    text = payload_text(data)
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:80])


def _decrypt_webshell(ctx: FeatureContext, data: bytes, password: str,
                      family: str) -> tuple[str, bytes, str] | None:
    """Try every rule of ``family`` and keep the most readable plaintext."""
    if not password:
        return None
    best: tuple[int, str, bytes, str] | None = None
    for rule in shell_rules.rules_for(family):
        keys = shell_rules.derive_keys(password, rule)
        if not keys:
            continue
        for key_label, variant, plain in shell_rules.decrypt_candidates(
                data, keys, rule):
            if not plain:
                continue
            value = _score(plain)
            label = f"{key_label} · {rule.family}/{rule.variant} · {variant}"
            if value > (best[0] if best else 0):
                best = (value, label, plain, rule.variant)
    if best and best[0] >= 20:
        return best[1], best[2], best[3]
    return None


def _report_memory_shell(ctx: FeatureContext, frame: str, uri: str,
                         plain: bytes, family: str) -> None:
    """Flag Java servlet-container / memory-shell signatures in plaintext.

    Generic words such as ``listener`` or ``pipeline`` appear in ordinary Java
    stack traces, so a single weak marker is not enough: require either one
    strong servlet-container marker or two weak ones before raising a finding.
    """
    markers = memory_shell_markers(plain)
    strong = sum(1 for marker in markers if marker in STRONG_MEMORY_MARKERS)
    weak = len(markers) - strong
    if strong < 1 and weak < 2:
        return
    ctx.report(f"检测到 {family} 内存马特征（强度 {strong} 强 / {weak} 弱）: "
               f"{', '.join(markers[:8])}", "warn")
    ctx.add_finding(
        "webshell", f"{family} 内存马特征 {uri}", frame=frame, level="warn",
        detail="命中标记: " + ", ".join(markers)
               + f"\n强度: 强 {strong} / 弱 {weak}"
               + "\n" + _printable_text(plain)[:600],
        extra={"strength_strong": strong, "strength_weak": weak,
               "markers": markers[:20]})


def _report_java_class(ctx: FeatureContext, frame: str, uri: str,
                       data: bytes) -> bool:
    """Describe a decrypted Java class file (memory shell forensics)."""
    info = shell_rules.analyze_java_class(data)
    if info is None:
        return False
    ctx.report("===== Java class 内存马取证 =====", "warn")
    ctx.report(info["summary"], "warn")
    ctx.report(f"类名: {info['class_name'] or '-'}  父类: "
               f"{info['super_class'] or '-'}  类型: {info['kind']}", "info")
    if info["interfaces"]:
        ctx.report("接口: " + ", ".join(info["interfaces"][:10]), "info")
    if info["registration_markers"]:
        ctx.report("注册/调用特征: " + ", ".join(
            info["registration_markers"][:12]), "info")
    if info["url_patterns"]:
        ctx.report("URL 模式: " + ", ".join(info["url_patterns"][:12]), "info")
    if info["interesting_strings"]:
        for text in info["interesting_strings"][:40]:
            ctx.report("  " + clean_cell(text, 200), "info")
    ctx.write_output(f"webshell_memory_{frame}.class", data)
    ctx.write_output(f"webshell_memory_{frame}.txt",
                     info["summary"] + "\n\n" + "\n".join(
                         info["interesting_strings"]))
    ctx.add_finding(
        "webshell", f"Java 内存马 {info['kind']} {info['class_name'] or '-'}",
        frame=frame, level="warn",
        detail=info["summary"] + "\n"
               + "\n".join("  " + text for text in info["interesting_strings"][:30])
               + "\n来源 URI: " + (uri or "-"),
        extra={"family": "memory-shell", "class": info["class_name"],
               "kind": info["kind"]})
    return True


def _load_responses(ctx: FeatureContext) -> dict[str, list[tuple[int, bytes, str]]]:
    """Index HTTP response bodies by TCP stream for request/response pairing."""
    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "http.file_data",
              "http.content_type"], "http.response", limit=200_000)
    responses: dict[str, list[tuple[int, bytes, str]]] = {}
    for row in rows:
        row += [""] * (4 - len(row))
        frame, stream, raw, ctype = row
        data = hex_to_bytes(raw)
        if not frame or not data:
            continue
        try:
            number = int(frame)
        except ValueError:
            continue
        responses.setdefault(stream, []).append((number, data, ctype))
    return responses


def _decrypt_response(data: bytes, password: str,
                      family: str) -> tuple[str, bytes, str] | None:
    """Try the request's family rules on the response body."""
    if not password:
        return None
    best: tuple[int, str, bytes, str] | None = None
    for rule in shell_rules.rules_for(family):
        keys = shell_rules.derive_keys(password, rule)
        for key_label, variant, plain in shell_rules.decrypt_candidates(
                data, keys, rule):
            if not plain:
                continue
            value = _score(plain)
            label = f"{key_label} · {rule.family}/{rule.variant} · {variant}"
            if value > (best[0] if best else 0):
                best = (value, label, plain, rule.variant)
    if best and best[0] >= 20:
        return best[1], best[2], best[3]
    return None


def _report_restored_output(ctx: FeatureContext, frame: str, uri: str,
                            text: str, source: str,
                            *, level: str = "good") -> None:
    """Structure commands/output/files/flags from a decrypted payload."""
    info = shell_rules.restore_output(text)
    if info["commands"]:
        ctx.report("命令: " + " | ".join(
            clean_cell(item, 160) for item in info["commands"][:8]), "good")
    if info["operations"]:
        ctx.report("操作: " + ", ".join(info["operations"]), "info")
    if info["files"]:
        ctx.report("文件: " + ", ".join(
            clean_cell(item, 120) for item in info["files"][:10]), "info")
    if info["output"]:
        for line in info["output"].splitlines()[:40]:
            ctx.report("  " + clean_cell(line, 240), "info")
    ctx.add_finding(
        "webshell", f"命令输出 {uri or '-'}", frame=frame, level=level,
        detail=(f"来源: {source}\n命令: {', '.join(info['commands'][:10]) or '-'}\n"
                f"操作: {', '.join(info['operations']) or '-'}\n"
                + info["output"][:700]),
        extra={"commands": info["commands"][:10],
               "operations": info["operations"],
               "files": info["files"][:20]})
    for flag in info["flags"]:
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=frame,
                        detail=f"命令输出（{source}）", level="good")


def _pair_responses(ctx: FeatureContext, responses, used: set[int],
                    request_frame: str, stream: str, uri: str,
                    password: str, family: str) -> int:
    """Decrypt and structure the response that belongs to a shell request."""
    try:
        number = int(request_frame)
    except (TypeError, ValueError):
        return 0
    hits = 0
    for frame_number, data, ctype in responses.get(stream, []):
        if frame_number <= number or frame_number in used:
            continue
        if len(data) > 2 * 1024 * 1024:
            continue
        result = _decrypt_response(data, password, family)
        text = ""
        label = ""
        if result is not None:
            label, plain, variant = result
            text = payload_text(plain)
            suffix = ".ser" if plain.startswith(JAVA_SERIAL_MAGIC) else ".txt"
            ctx.write_output(f"webshell_response_{frame_number}{suffix}", plain)
            if plain.startswith(shell_rules.JAVA_MAGIC):
                _report_java_class(ctx, str(frame_number), uri, plain)
        elif printable_ratio(data) >= 0.65:
            text = payload_text(data)
            lowered = data.lower()
            if not (sum(1 for marker in CMD_MARKERS if marker in lowered) >= 1
                    or codec.find_flags(text)):
                continue
            label = f"明文响应 ({ctype or '-'})"
            ctx.write_output(f"webshell_response_{frame_number}.txt", data)
        if not text.strip():
            continue
        used.add(frame_number)
        hits += 1
        ctx.report(f"===== 帧 {frame_number} 响应解密 ({label}) =====", "good")
        _report_restored_output(ctx, str(frame_number), uri, text,
                                f"响应 · {label}")
    return hits


def _handle_caidao(ctx: FeatureContext, text: str) -> int:
    count = 0
    for match in re.finditer(r"->\|(.*?)\|<-", text or "", re.S):
        raw = _b64(match.group(1))
        if not raw:
            continue
        count += 1
        decoded = payload_text(raw)
        ctx.report("===== 菜刀数据块 =====", "good")
        for line in decoded.splitlines()[:40]:
            if line.strip():
                ctx.report("  " + clean_cell(line, 240), "info")
        ctx.write_output(f"caidao_{count}.txt", decoded)
    if not count:
        # China Chopper also sends plain base64 in POST parameters.
        for blob in _extract_blobs(text)[:20]:
            decoded = payload_text(blob)
            if any(marker.decode("latin-1") in decoded for marker in PHP_MARKERS):
                count += 1
                ctx.report("===== 菜刀候选载荷 =====", "good")
                for line in decoded.splitlines()[:40]:
                    if line.strip():
                        ctx.report("  " + clean_cell(line, 240), "info")
                ctx.write_output(f"caidao_{count}.txt", decoded)
    return count


def decrypt(ctx: FeatureContext) -> None:
    family = str(ctx.params.get("webshell_mode") or "auto")
    password = str(ctx.params.get("webshell_password") or "")
    display_filter = str(ctx.params.get("webshell_filter") or "").strip()
    if family == "off":
        ctx.report("Webshell 解密已关闭", "info")
        return
    if family in ("godzilla", "behinder", "behinder4", "antsword",
                  "tianxie") and not password:
        ctx.report("请在 Webshell 设置中填写连接密码/密钥", "error")
        return
    ctx.report(f"Webshell 规则库: {len(shell_rules.RULES)} 条 / "
               f"{len(shell_rules.FAMILIES)} 个家族 "
               f"({', '.join(sorted(shell_rules.FAMILIES))})", "info")

    fields = ["frame.number", "tcp.stream", "http.request.method",
              "http.request.uri", "http.file_data", "urlencoded-form.value",
              "http.cookie", "http.content_type", "http.user_agent"]
    if display_filter:
        rows = tshark_rows(ctx, fields, display_filter, limit=200_000)
    else:
        rows = tshark_rows(ctx, fields, "http.request", limit=200_000)
    if not rows:
        ctx.report("没有发现 HTTP 请求", "warn")
        return
    responses = _load_responses(ctx)
    used_responses: set[int] = set()
    response_hits = 0

    total = 0
    hits = 0
    for index, row in enumerate(rows):
        if index % 100 == 0:
            ctx.set_progress(int(index / len(rows) * 95))
            ctx.check_cancel()
        row += [""] * (len(fields) - len(row))
        frame, stream, method, uri = row[0], row[1], row[2], row[3]
        content_type, user_agent = row[7], row[8]
        text = "\n".join(row[4:7])
        if not text.strip():
            continue
        total += 1
        if family == "auto" and re.search(
                r"(?i)behinder|godzilla|antsword", user_agent or ""):
            ctx.report(f"帧 {frame} 客户端特征: {clean_cell(user_agent, 160)}",
                       "warn")
        if family == "auto" and "octet-stream" in (content_type or "").lower() \
                and method.upper() == "POST":
            ctx.report(f"帧 {frame} POST 二进制正文（可能是冰蝎 4.x 变体）",
                       "info")
        if family == "caidao":
            hits += _handle_caidao(ctx, text)
            continue
        blobs = _extract_blobs(text)
        for blob in blobs:
            if len(blob) < 16:
                continue
            if blob.startswith(shell_rules.JAVA_MAGIC):
                hits += 1
                ctx.report(f"===== 帧 {frame} 上传 Java class =====", "warn")
                _report_java_class(ctx, frame, uri, blob)
                continue
            if family == "auto" and _plain_payload(blob):
                hits += 1
                decoded = _printable_text(blob)
                plain_hit = any(marker.decode("latin-1").lower()
                                in decoded.lower() for marker in CMD_MARKERS)
                if not plain_hit:
                    continue
                ctx.report(f"===== 帧 {frame} 明文/Base64 载荷 =====", "good")
                ctx.report(f"URI: {uri}  方向: 请求", "info")
                for line in decoded.splitlines()[:50]:
                    ctx.report("  " + clean_cell(line, 240), "info")
                ctx.write_output(f"webshell_{frame}_plain.txt", blob)
                ctx.add_finding("webshell", f"Webshell 明文载荷 {uri}",
                                frame=frame, level="warn",
                                detail=decoded[:800])
                _report_memory_shell(ctx, frame, uri, blob, "明文")
                _report_restored_output(ctx, frame, uri, decoded, "明文请求",
                                        level="warn")
                response_hits += _pair_responses(
                    ctx, responses, used_responses, frame, stream, uri,
                    password, family)
                for flag in codec.find_flags(decoded):
                    ctx.report(f"发现 flag: {flag}", "good")
                    ctx.add_finding("flag", flag, frame=frame,
                                    detail="Webshell 明文载荷", level="good")
                continue
            if family == "auto":
                families = ("godzilla", "behinder", "behinder4", "antsword",
                            "tianxie")
            else:
                families = (family,)
            for name in families:
                result = _decrypt_webshell(ctx, blob, password, name)
                if result is None:
                    continue
                key_label, plain, variant = result
                if _score(plain) < 20:
                    continue
                hits += 1
                ctx.report(f"===== 帧 {frame} {name} 解密成功 ({variant}) =====", "good")
                ctx.report(f"URI: {uri}  密钥: {key_label}", "info")
                decoded = _printable_text(plain)
                for line in decoded.splitlines()[:50]:
                    ctx.report("  " + clean_cell(line, 240), "info")
                if plain.startswith(shell_rules.JAVA_MAGIC):
                    _report_java_class(ctx, frame, uri, plain)
                    suffix = ".class"
                else:
                    suffix = ".ser" if plain.startswith(JAVA_MAGIC) else ".txt"
                    _report_restored_output(ctx, frame, uri, decoded,
                                            f"{name} 请求")
                ctx.write_output(f"webshell_{frame}_{name}{suffix}", plain)
                ctx.add_finding("webshell", f"{name} 解密 {uri}",
                                frame=frame, level="good",
                                detail=f"密钥 {key_label} · {variant}\n"
                                       + _printable_text(plain)[:800])
                if name.startswith("godzilla") or name.startswith("behinder"):
                    _report_memory_shell(ctx, frame, uri, plain, name)
                response_hits += _pair_responses(
                    ctx, responses, used_responses, frame, stream, uri,
                    password, name)
                for flag in codec.find_flags(payload_text(plain)):
                    ctx.report(f"发现 flag: {flag}", "good")
                    ctx.add_finding("flag", flag, frame=frame,
                                    detail=f"{name} 解密结果", level="good")
                break
    scanned = _scan_responses(ctx)
    ctx.report(f"扫描 {total} 个请求，成功解密 {hits} 处，请求/响应配对还原 "
               f"{response_hits} 处，响应明文 {scanned} 处",
               "good" if (hits or scanned or response_hits) else "warn")
    ctx.set_progress(100)
