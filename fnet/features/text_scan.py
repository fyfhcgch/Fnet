"""Keyword / flag scanning across all payloads of a capture."""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse

from fnet.features.common import tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio

FIELDS = [
    "frame.number",
    "_ws.col.protocol",
    "_ws.col.info",
    "tcp.payload",
    "udp.payload",
    "data.data",
    "http.file_data",
    "http.request.uri",
    "http.request.full_uri",
    "http.cookie",
    "http.authorization",
    "http.user_agent",
]

HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
BYTE_DECIMAL_RE = re.compile(r"^(?:\d{1,3}[ ,])+\d{1,3}$")


def _extra_keywords(params: dict) -> list[str]:
    raw = params.get("keywords") or params.get("regex") or ""
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x).strip()]
    return [part.strip() for part in re.split(r"[;\n]", str(raw)) if part.strip()]


def _decoded_views(data: bytes) -> list[tuple[str, str]]:
    """Cheap transforms that reveal encoded flags."""
    views: list[tuple[str, str]] = []
    text = payload_text(data)
    views.append(("raw", text))
    stripped = re.sub(r"\s+", "", text)
    if 8 <= len(stripped) <= 400_000:
        candidate = stripped + "=" * (-len(stripped) % 4)
        try:
            decoded = base64.b64decode(candidate, validate=False)
            if decoded and decoded != data and printable_ratio(decoded) > 0.65:
                views.append(("base64", payload_text(decoded)))
        except (binascii.Error, ValueError):
            pass
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            views.append(("url", unquoted))
    return views


RE_META = set("\\^$.|?*+()[]{}")

def _compile(pattern: str) -> re.Pattern:
    """Compile one keyword.

    Short plain keywords (``SEC``, ``CTF``, ``flag``) get word boundaries so
    they do not match inside unrelated words such as ``content_section``;
    the built-in rule list is very noisy otherwise.  Patterns that use any
    regular-expression syntax are left untouched.
    """
    literal = not (set(pattern) & RE_META)
    if literal and len(pattern) <= 8 and pattern.isascii():
        try:
            return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(pattern)}(?![A-Za-z0-9_])",
                              re.IGNORECASE)
        except re.error:
            pass
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(pattern), re.IGNORECASE)


def keyword_scan(ctx: FeatureContext) -> None:
    params = ctx.params
    patterns: list[str] = []
    if params.get("auto_regex", True):
        patterns.extend(ctx.config.regmatch())
    patterns.extend(_extra_keywords(params))

    # De-duplicate while preserving order.
    patterns = list(dict.fromkeys(p for p in patterns if p))

    compiled: list[tuple[str, re.Pattern]] = []
    for pattern in patterns:
        compiled.append((pattern, _compile(pattern)))

    ctx.report(f"关键字检测：{len(compiled)} 条规则", "info")
    if params.get("decode", True):
        ctx.report("已启用 Base64/URL 解码辅助扫描", "debug")

    display_filter = ""
    if params.get("post_only"):
        display_filter = "http.request.method == POST"
        ctx.report("仅扫描 POST 请求", "info")

    rows = tshark_rows(ctx, FIELDS, display_filter, limit=200_000)
    if not rows:
        ctx.report("没有可分析的报文", "warn")
        return

    max_hits = int(params.get("max_hits") or 500)
    hits = 0
    flags: list[str] = []
    seen_flags: set[str] = set()
    seen_hits: set[tuple[str, str]] = set()

    for index, row in enumerate(rows):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(rows), 1) * 90))
            ctx.check_cancel()
        row += [""] * (len(FIELDS) - len(row))
        frame, proto, info = row[0], row[1], row[2]
        payloads = [row[3], row[4], row[5], row[6]]
        meta = "\n".join(row[7:12])

        haystacks: list[tuple[str, str]] = []
        if meta:
            haystacks.append(("redis", meta))
        for raw in payloads:
            data = hex_to_bytes(raw)
            if not data:
                continue
            for label, view in _decoded_views(data):
                haystacks.append((label, view))

        for label, haystack in haystacks:
            if not haystack:
                continue
            for pattern, rx in compiled:
                for match in rx.finditer(haystack):
                    hits += 1
                    start = max(0, match.start() - 50)
                    end = min(len(haystack), match.end() + 70)
                    snippet = haystack[start:end].replace("\r", " ").replace("\n", " ")
                    ctx.report(
                        f"[{proto}] 帧 {frame} ({label}) 命中 {pattern!r}: …{snippet}…",
                        "good")
                    if (frame, pattern) not in seen_hits:
                        seen_hits.add((frame, pattern))
                        ctx.add_finding(
                            "other", f"命中 {pattern}", frame=frame, level="good",
                            detail=f"[{proto}] ({label}) …{snippet}…")
                    if hits >= max_hits:
                        ctx.report("命中数量达到上限，停止扫描", "warn")
                        ctx.set_progress(100)
                        return
            for flag in codec.find_flags(haystack):
                if flag not in seen_flags:
                    seen_flags.add(flag)
                    flags.append(flag)
                    ctx.report(f"[{proto}] 帧 {frame} 发现 flag: {flag}", "good")
                    ctx.add_finding("flag", flag, frame=frame, level="good",
                                    detail=f"[{proto}] {label}")

    ctx.set_progress(100)
    if flags:
        ctx.report("===== 汇总 flag =====", "good")
        for flag in flags:
            ctx.report(flag, "good")
    ctx.report(f"关键字检测完成，共 {hits} 处命中", "info" if hits else "warn")


def deep(ctx: FeatureContext) -> None:
    """Run the stream/file aware deep flag scan (``text_scan.deep``)."""
    from fnet.features.flag_deep import deep_scan

    deep_scan(ctx)
