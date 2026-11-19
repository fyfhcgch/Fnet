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


def _flag_like_pattern(pattern: str) -> bool:
    """Keep flag/encoded-flag rules when scanning text logs.

    The built-in ``regmatch`` list is tuned for packet payloads and contains
    short words such as ``KEY``/``PASS``; every Ceph line contains "Key:", so
    using the full list on logs would bury real hits under noise.
    """
    lowered = str(pattern or "").lower()
    return ("{" in pattern or "flag" in lowered
            or lowered.startswith(("zmxh", "tvp", "mzw", "ctf", "begin",
                                   "q0nur", "q1rg")))


def _log_keyword_scan(ctx: FeatureContext, compiled: list[tuple[str, re.Pattern]],
                      params: dict, max_hits: int) -> None:
    """Match keywords against parsed log records (no tshark required)."""
    from fnet.utils import logfile

    log = logfile.parse_path(ctx.pcap)
    if not log.records:
        ctx.report("日志中没有可扫描的记录", "warn")
        return
    ctx.report(f"日志关键字扫描：{log.format_name}，{len(log.records)} 条记录",
               "info")
    hits = 0
    seen: set[tuple[int, str]] = set()
    flags: list[str] = []
    seen_flags: set[str] = set()
    decode = bool(params.get("decode", True))
    for record in log.records:
        ctx.check_cancel()
        haystacks = [("raw", record.raw)]
        if decode:
            unquoted = urllib.parse.unquote(record.raw)
            if unquoted != record.raw:
                haystacks.append(("url", unquoted))
        for label, haystack in haystacks:
            for pattern, rx in compiled:
                match = rx.search(haystack)
                if not match:
                    continue
                hits += 1
                start = max(0, match.start() - 50)
                end = min(len(haystack), match.end() + 70)
                snippet = haystack[start:end].replace("\r", " ").replace(
                    "\n", " ")
                ctx.report(f"行 {record.line} ({label}) 命中 {pattern!r}: "
                           f"…{snippet}…", "good")
                key = (record.line, pattern)
                if key not in seen:
                    seen.add(key)
                    is_flag = bool(codec.find_flags(haystack)) or \
                        _flag_like_pattern(pattern)
                    ctx.add_finding(
                        "flag" if is_flag else "log",
                        f"{'发现 flag' if is_flag else '日志关键字命中'}：{pattern}",
                        level="good" if is_flag else "info",
                        detail=f"第 {record.line} 行 ({label}) …{snippet}…",
                        extra={"line": record.line, "log_time": record.time})
                if hits >= max_hits:
                    ctx.report("命中数量达到上限，停止扫描", "warn")
                    break
            for flag in codec.find_flags(haystack):
                if flag in seen_flags:
                    continue
                seen_flags.add(flag)
                flags.append(flag)
                ctx.report(f"行 {record.line} 发现 flag: {flag}", "good")
                ctx.add_finding("flag", flag, level="good",
                                detail=f"第 {record.line} 行 {label}",
                                extra={"line": record.line})
            if hits >= max_hits:
                break
        if hits >= max_hits:
            break
    ctx.set_progress(100)
    if flags:
        ctx.report("===== 汇总 flag =====", "good")
        for flag in flags:
            ctx.report(flag, "good")
    ctx.report(f"关键字检测完成，共 {hits} 处命中",
               "info" if hits else "warn")


def keyword_scan(ctx: FeatureContext) -> None:
    params = ctx.params
    from fnet.utils import logfile

    is_log = (getattr(ctx, "input_kind", "pcap") == "log"
              or logfile.is_log_input(ctx.pcap))
    auto_patterns = list(ctx.config.regmatch()) if params.get("auto_regex", True) else []
    if is_log:
        kept = [pattern for pattern in auto_patterns
                if _flag_like_pattern(pattern)]
        if len(kept) != len(auto_patterns):
            ctx.report(
                f"日志模式：跳过 {len(auto_patterns) - len(kept)} 条面向报文的"
                "宽泛规则，仅保留 flag/编码类与自定义关键字", "info")
        auto_patterns = kept
    patterns: list[str] = auto_patterns
    patterns.extend(_extra_keywords(params))

    # De-duplicate while preserving order.
    patterns = list(dict.fromkeys(p for p in patterns if p))

    compiled: list[tuple[str, re.Pattern]] = []
    for pattern in patterns:
        compiled.append((pattern, _compile(pattern)))

    ctx.report(f"关键字检测：{len(compiled)} 条规则", "info")
    max_hits = int(params.get("max_hits") or 500)
    if is_log:
        _log_keyword_scan(ctx, compiled, params, max_hits)
        return
    if params.get("decode", True):
        ctx.report("已启用 Base64/URL 解码辅助扫描", "debug")

    display_filter = ""
    if params.get("post_only"):
        display_filter = "http.request.method == POST"
        ctx.report("仅扫描 POST 请求", "info")

    from fnet.tools.runner import count_frames

    total_frames = count_frames(
        ctx.pcap, ctx.tshark.path if ctx.tshark is not None else "")
    chunk = max(2_000, min(int(params.get("chunk_frames") or 20_000), 100_000))
    if total_frames > chunk:
        # Scan bounded frame ranges so a 1 GB capture never materialises all
        # payloads at once (the old single tshark call needed gigabytes of RSS).
        ranges = [(start, min(start + chunk - 1, total_frames))
                  for start in range(1, total_frames + 1, chunk)]
        ctx.report(f"分块扫描：{len(ranges)} 个区间，每区间 {chunk} 帧", "debug")
    else:
        ranges = [None]

    hits = 0
    flags: list[str] = []
    seen_flags: set[str] = set()
    seen_hits: set[tuple[str, str]] = set()
    processed = 0
    stopped = False

    def scan_rows(rows) -> bool:
        """Process one batch; returns False once the hit limit is reached."""
        nonlocal processed, hits, stopped
        for index, row in enumerate(rows):
            if index % 200 == 0:
                done = processed + index
                if total_frames:
                    ctx.set_progress(min(90, int(done / total_frames * 90)))
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
                            stopped = True
                            return False
                for flag in codec.find_flags(haystack):
                    if flag not in seen_flags:
                        seen_flags.add(flag)
                        flags.append(flag)
                        ctx.report(f"[{proto}] 帧 {frame} 发现 flag: {flag}", "good")
                        ctx.add_finding("flag", flag, frame=frame, level="good",
                                        detail=f"[{proto}] {label}")
        processed += len(rows)
        return True

    for bounds in ranges:
        if stopped:
            break
        if bounds is None:
            rows = tshark_rows(ctx, FIELDS, display_filter, limit=200_000)
        else:
            start, end = bounds
            bound = f"frame >= {start} && frame <= {end}"
            combined = f"({display_filter}) && {bound}" if display_filter else bound
            rows = tshark_rows(ctx, FIELDS, combined, limit=200_000)
        if not rows:
            continue
        if not scan_rows(rows):
            break

    if not processed and not hits and not flags:
        ctx.report("没有可分析的报文", "warn")
        return

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
