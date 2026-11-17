"""SQL blind-injection reconstruction.

The analyst pastes the regular expression used by the injection payload and a
marker that identifies a *true* response.  Requests are paired with their
responses (via ``http.response_in``) automatically, and the handler also
supports time-based detection and a binary-search mode.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.pcap import hex_to_bytes, payload_text

DEFAULT_SQL_REGEX = r"fl4g\),(\d+),1\)\)=(\d+)"
REQ_FIELDS = ["frame.number", "tcp.stream", "http.request.method",
              "http.request.full_uri", "http.request.uri",
              "http.response_in", "http.cookie"]
RESP_FIELDS = ["frame.number", "tcp.stream", "http.response.code",
               "http.file_data", "frame.time_delta_displayed"]
TRUE_WORDS = re.compile(r"\b(true|yes|成功|正确|success)\b", re.IGNORECASE)
FALSE_WORDS = re.compile(r"\b(false|no|失败|错误|fail)\b", re.IGNORECASE)


def _pairs(ctx: FeatureContext) -> list[dict]:
    reqs = tshark_rows(ctx, REQ_FIELDS, "http.request", limit=200_000)
    resps = tshark_rows(ctx, RESP_FIELDS, "http.response", limit=200_000)
    if not reqs:
        ctx.report("没有发现 HTTP 请求，无法进行盲注还原", "warn")
        return []
    by_frame: dict[str, dict] = {}
    by_stream: dict[str, list[dict]] = defaultdict(list)
    for raw in resps:
        row = raw + [""] * (len(RESP_FIELDS) - len(raw))
        item = dict(zip(RESP_FIELDS, row))
        by_frame[item["frame.number"]] = item
        by_stream[item["tcp.stream"]].append(item)
    for items in by_stream.values():
        items.sort(key=lambda x: int(x["frame.number"] or 0))

    out = []
    for raw in reqs:
        row = raw + [""] * (len(REQ_FIELDS) - len(raw))
        req = dict(zip(REQ_FIELDS, row))
        resp = by_frame.get(req["http.response_in"])
        if resp is None:
            stream = req["tcp.stream"]
            frame = int(req["frame.number"] or 0)
            for candidate in by_stream.get(stream, []):
                if int(candidate["frame.number"] or 0) > frame:
                    resp = candidate
                    break
        req["response"] = resp
        out.append(req)
    return out


def _body(resp: dict | None) -> str:
    if not resp or not resp.get("http.file_data"):
        return ""
    return payload_text(hex_to_bytes(resp["http.file_data"]))


def _detect_success(pairs: list[dict], success_text: str, compare: str,
                    threshold: float) -> tuple[list[bool], str]:
    """Return one boolean per request plus a human readable strategy."""
    bodies = [_body(p.get("response")) for p in pairs]
    if success_text:
        needle = success_text
        if compare == "not_contains":
            flags = [needle not in body for body in bodies]
            return flags, f"响应体不包含 {needle!r}"
        flags = [needle in body for body in bodies]
        if any(flags):
            return flags, f"响应体包含 {needle!r}"
        try:
            rx = re.compile(needle, re.IGNORECASE)
            flags = [bool(rx.search(body)) for body in bodies]
            if any(flags):
                return flags, f"响应体匹配正则 {needle!r}"
        except re.error:
            pass
        ctx_text = f"成功条件 {needle!r} 未命中任何响应，改用启发式"
    else:
        ctx_text = "未提供成功条件，使用响应差异启发式"

    # Time based: a delayed response is the "true" branch.
    deltas = []
    for pair in pairs:
        resp = pair.get("response")
        try:
            deltas.append(float(resp["frame.time_delta_displayed"]) if resp else 0.0)
        except (TypeError, ValueError):
            deltas.append(0.0)
    if deltas and max(deltas) > threshold and (max(deltas) - min(deltas)) > threshold:
        return [d > threshold for d in deltas], f"响应延迟 > {threshold}s（时间盲注）"

    # Body length/contents: group by signature and treat the minority as true.
    signatures = []
    for body in bodies:
        text = re.sub(r"\s+", " ", body)[:400]
        signatures.append(text)
    counter = Counter(signatures)
    if len(counter) == 2:
        ranked = counter.most_common()
        false_sig, true_sig = ranked[0][0], ranked[1][0]
        flags = [sig == true_sig for sig in signatures]
        if 0 < sum(flags) < len(flags):
            return flags, (f"两种响应模板，少数派视为真（真 {counter[true_sig]} 次 / "
                           f"假 {counter[false_sig]} 次）")
    if len(counter) > 1:
        # choose the least frequent template as true
        true_sig = counter.most_common()[-1][0]
        flags = [sig == true_sig for sig in signatures]
        return flags, "多种响应模板，频率最低者视为真（请核对）"
    # Last resort: HTTP status 2xx/3xx and non-empty body.
    flags = [bool(p.get("response") and p["response"]["http.response.code"][:1] in "23")
             for p in pairs]
    return flags, ctx_text


def _int_or_char(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    if value.isdigit():
        return int(value)
    if len(value) == 1:
        return ord(value)
    return None


def _reconstruct(ctx: FeatureContext, pairs: list[dict], pattern: str,
                 flags: list[bool], strategy: str, mode: str,
                 reverse_index: bool, is_char: bool) -> None:
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        ctx.report(f"SQL 正则无效: {exc}", "error")
        return

    ctx.report(f"请求 {len(pairs)} 条，成功 {sum(flags)} 条", "info")
    ctx.report(f"成功判定策略: {strategy}", "info")

    values: dict[int, list[str]] = defaultdict(list)
    raw_hits: list[str] = []
    for order, (pair, success) in enumerate(zip(pairs, flags)):
        text = pair["http.request.full_uri"] or pair["http.request.uri"]
        if pair["http.cookie"]:
            text += " " + pair["http.cookie"]
        match = rx.search(text or "")
        if not match:
            continue
        groups = [g for g in match.groups() if g is not None]
        if not groups:
            continue
        raw_hits.append(match.group(0))
        if len(groups) >= 2:
            index = _int_or_char(groups[0])
            value = _int_or_char(groups[1])
        else:
            index = order + 1
            value = _int_or_char(groups[0])
        if index is None or value is None:
            continue
        if reverse_index:
            index = -index
        if success:
            values[index].append(chr(value) if not is_char and 0 <= value <= 0x10FFFF
                                 else (groups[1] if len(groups) > 1 else groups[0]))

    if raw_hits:
        ctx.report("命中 payload 示例:", "debug")
        for hit in list(dict.fromkeys(raw_hits))[:30]:
            ctx.report("  " + clean_cell(hit, 250), "debug")

    if mode == "binary":
        _binary_reconstruct(ctx, pairs, rx, flags, reverse_index)
        return

    if not values:
        ctx.report("正则未从请求中提取到位置/值，请检查 SQL 正则", "warn")
        return

    ctx.report("===== 盲注还原结果 =====", "good")
    chars = []
    for index in sorted(values, key=lambda value: (value < 0, abs(value))):
        candidates = Counter(values[index])
        char = candidates.most_common(1)[0][0]
        chars.append(char)
        detail = ", ".join(f"{repr(c)}x{n}" for c, n in candidates.most_common(6))
        ctx.report(f"位置 {abs(index)}: {char!r}  ({detail})", "info")
    result = "".join(chars)
    ctx.report(f"还原字符串: {result}", "good")
    ctx.add_finding("sql", f"盲注还原（{mode}）", detail=result, level="good")
    if result:
        ctx.write_output(f"sql_blind_{mode}.txt", result)
    flags_found = codec.find_flags(result)
    for flag in flags_found:
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, detail=f"来自 SQL {mode} 盲注还原", level="good")


def _binary_reconstruct(ctx: FeatureContext, pairs: list[dict], rx: re.Pattern,
                        flags: list[bool], reverse_index: bool) -> None:
    """Binary search: ``substr(...,pos,1) > value`` returns true/false."""
    bounds: dict[int, list[int]] = defaultdict(lambda: [32, 127])
    observed = 0
    for pair, success in zip(pairs, flags):
        text = pair["http.request.full_uri"] or pair["http.request.uri"]
        match = rx.search(text or "")
        if not match:
            continue
        groups = [g for g in match.groups() if g is not None]
        numbers = [_int_or_char(g) for g in groups[-2:]]
        numbers = [n for n in numbers if n is not None]
        if len(numbers) < 2:
            continue
        index, value = numbers[0], numbers[1]
        if reverse_index:
            index = -index
        payload = match.group(0)
        low, high = bounds[index]
        observed += 1
        if re.search(rf">\s*{value}\b", payload) or ">" in payload:
            if success:
                low = max(low, value + 1)
            else:
                high = min(high, value)
        elif re.search(rf"<\s*{value}\b", payload) or "<" in payload:
            if success:
                high = min(high, value - 1)
            else:
                low = max(low, value)
        else:
            # equality from a binary search midpoint
            if success:
                low = high = value
        bounds[index] = [low, high]

    if not observed:
        ctx.report("没有可解析的二分比较，请确认正则包含位置与比较值", "warn")
        return
    ctx.report("===== 二分盲注推断 =====", "good")
    result = []
    for index in sorted(bounds, key=lambda value: (value < 0, abs(value))):
        low, high = bounds[index]
        char = chr(low) if low == high else chr((low + high) // 2)
        result.append(char)
        ctx.report(f"位置 {abs(index)}: 区间 [{low},{high}] -> {char!r}", "info")
    text = "".join(result)
    ctx.report(f"推断字符串: {text}", "good")
    ctx.add_finding("sql", "二分盲注推断", detail=text, level="good")
    for flag in codec.find_flags(text):
        ctx.add_finding("flag", flag, detail="来自二分盲注推断", level="good")
    if text:
        ctx.write_output("sql_binary.txt", text)


def blind(ctx: FeatureContext) -> None:
    params = ctx.params
    pairs = _pairs(ctx)
    if not pairs:
        return
    success_text = str(params.get("sql_success") or "")
    compare = str(params.get("sql_compare") or "contains")
    threshold = float(params.get("sql_time_threshold") or 1.0)
    flags, strategy = _detect_success(pairs, success_text, compare, threshold)
    pattern = str(params.get("sql_regex") or DEFAULT_SQL_REGEX)
    _reconstruct(ctx, pairs, pattern, flags, strategy, "blind",
                 bool(params.get("sql_reverse")),
                 bool(params.get("sql_char")))


def binary(ctx: FeatureContext) -> None:
    params = ctx.params
    pairs = _pairs(ctx)
    if not pairs:
        return
    success_text = str(params.get("sql_success") or "")
    compare = str(params.get("sql_compare") or "contains")
    threshold = float(params.get("sql_time_threshold") or 1.0)
    flags, strategy = _detect_success(pairs, success_text, compare, threshold)
    pattern = str(params.get("sql_regex") or r"(\d+)[^>]*>\s*(\d+)")
    _reconstruct(ctx, pairs, pattern, flags, strategy, "binary",
                 bool(params.get("sql_reverse")),
                 bool(params.get("sql_char")))


def log_analysis(ctx: FeatureContext) -> None:
    """Parse a saved blind-injection log (one line per request)."""
    params = ctx.params
    text = str(params.get("sql_log_text") or "")
    path = params.get("sql_log") or ""
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            ctx.report(f"无法读取日志 {path}: {exc}", "error")
            return
    if not text:
        ctx.report("请在设置中提供盲注日志文件路径或日志内容", "warn")
        return
    pattern = str(params.get("sql_regex") or r"(\d+)\D+(\d+)")
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        ctx.report(f"正则无效: {exc}", "error")
        return

    values: dict[int, list[str]] = defaultdict(list)
    lines = text.splitlines()
    for line in lines:
        lowered = line.lower()
        true_line = bool(TRUE_WORDS.search(line)) or "成功" in line
        false_line = bool(FALSE_WORDS.search(line)) or "失败" in line
        match = rx.search(line)
        if not match:
            continue
        groups = [g for g in match.groups() if g is not None]
        if len(groups) < 2:
            continue
        index, value = _int_or_char(groups[0]), _int_or_char(groups[1])
        if index is None or value is None:
            continue
        if true_line and not false_line:
            values[index].append(chr(value) if 0 <= value <= 0x10FFFF else str(value))

    if not values:
        # No explicit markers: assume the format "index value" is the payload.
        ctx.report("日志中没有 true/false 标记，尝试按出现顺序提取", "warn")
        matches = rx.findall(text)
        for order, groups in enumerate(matches):
            if isinstance(groups, tuple) and len(groups) >= 2:
                value = _int_or_char(groups[1])
                if value is not None:
                    values[order + 1].append(chr(value) if 0 <= value <= 0x10FFFF else "")
    if not values:
        ctx.report("未能从日志提取数据", "warn")
        return
    result = "".join(Counter(values[i]).most_common(1)[0][0] for i in sorted(values))
    ctx.report(f"日志还原字符串: {result}", "good")
    ctx.add_finding("sql", "盲注日志还原", detail=result, level="good")
    for flag in codec.find_flags(result):
        ctx.add_finding("flag", flag, detail="来自 SQL 盲注日志", level="good")
    ctx.write_output("sql_log_result.txt", result)
