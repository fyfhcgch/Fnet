"""Generic flow / protocol summaries extracted with tshark display filters."""
from __future__ import annotations

import ipaddress
from collections import Counter
from pathlib import Path

import re

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils.pcap import conversations, hex_to_bytes, payload_text, printable_ratio

MAX_ROWS = 300


def _is_public_ip(value: str) -> bool:
    """Simple RFC1918/public test for IOC hints (mirrors features.logs)."""
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback
                or address.is_link_local or address.is_multicast
                or address.is_reserved)


def _rows(ctx: FeatureContext, fields: list[str], display_filter: str,
          limit: int = 100_000) -> list[list[str]]:
    return tshark_rows(ctx, fields, display_filter, limit=limit)


def _dump(ctx: FeatureContext, title: str, fields: list[str],
          display_filter: str, limit: int = MAX_ROWS) -> list[list[str]]:
    rows = _rows(ctx, fields, display_filter)
    table(ctx, title, fields, rows, limit=limit)
    return rows


def _payload_rows(ctx: FeatureContext, title: str, display_filter: str,
                  fields: list[str], max_lines: int = 800) -> None:
    rows = _rows(ctx, ["frame.number"] + fields, display_filter)
    if not rows:
        ctx.report(f"{title}: 没有匹配的流量", "warn")
        return
    ctx.report(f"===== {title} ({len(rows)} 条) =====", "good")
    count = 0
    for row in rows:
        row += [""] * (len(fields) + 1 - len(row))
        frame = row[0]
        for raw in row[1:]:
            if not raw:
                continue
            data = hex_to_bytes(raw)
            if not data or printable_ratio(data) < 0.55:
                continue
            text = payload_text(data).replace("\r", "")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                ctx.report(f"[{frame}] {line}", "info")
                count += 1
                if count > max_lines:
                    ctx.report("输出行数达到上限", "warn")
                    return
        ctx.check_cancel()


def _printable_text(value: str) -> bool:
    if len(value) < 4:
        return False
    good = sum(32 <= ord(ch) < 127 or ch in "\t\r\n" for ch in value)
    return good / len(value) > 0.85


def _decode_label(label: str) -> list[tuple[str, str]]:
    """Try the encodings DNS tunnels commonly use on the left-most label."""
    from fnet.utils import codec

    results: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(method: str, value: str) -> None:
        value = value.strip()
        if value and value != label and value not in seen and _printable_text(value):
            seen.add(value)
            results.append((method, value))

    raw = label.replace("-", "+").replace("_", "/")
    if len(raw) >= 8:
        add("base64", codec.b64decode_text(raw.rstrip("=")))
    if re.fullmatch(r"[0-9a-fA-F]{8,}", label) and len(label) % 2 == 0:
        add("hex", codec.hexdecode_text(label))
    if re.fullmatch(r"[A-Z2-7]{8,}=*", label.upper()):
        text = codec.b32decode_text(label)
        if re.search(r"[a-z\s{}]", text):
            add("base32", text)
    if "%" in label:
        add("url", codec.urldecode_text(label))
    return results


def dns(ctx: FeatureContext) -> None:
    from fnet.utils import codec, tunnel

    rows = _dump(ctx, "DNS 查询", ["frame.number", "dns.qry.name",
                                   "dns.qry.type", "dns.a", "dns.aaaa",
                                   "dns.flags.rcode"], "dns")
    names = [r[1] for r in rows if len(r) > 1 and r[1]]
    long_names = [name for name in names if len(name) > 40]
    if long_names:
        ctx.report("疑似 DNS 隐蔽隧道（长域名）:", "warn")
        for name in list(dict.fromkeys(long_names))[:50]:
            ctx.report("  " + name, "warn")
            ctx.add_finding("dns", name, detail="长域名，疑似 DNS 隐蔽隧道",
                            level="warn")
    # DNS tunneling often encodes data in the left-most label.
    labels: Counter = Counter()
    decoded: list[tuple[str, str, str]] = []
    seen_decoded: set[str] = set()
    for name in names:
        label = name.split(".")[0]
        labels[label] += 1
        if len(label) < 8:
            continue
        for method, value in _decode_label(label):
            key = f"{method}:{value}"
            if key in seen_decoded:
                continue
            seen_decoded.add(key)
            decoded.append((label, method, value))
    suspicious = [(label, count) for label, count in labels.items()
                  if len(label) >= 24 and count > 1]
    if suspicious:
        ctx.report("重复的长标签（可能是隧道数据）:", "warn")
        for label, count in suspicious[:30]:
            ctx.report(f"  {label} x{count}", "warn")
    long_labels = [label for label in labels if len(label) >= 16]
    if long_labels or decoded:
        ctx.report("===== 长标签解码结果 =====", "good")
        for label, method, value in decoded[:80]:
            ctx.report(f"  [{method}] {label} -> {clean_cell(value, 200)}", "good")
            ctx.add_finding("dns", f"[{method}] {clean_cell(value, 120)}",
                            detail=f"标签: {label}", level="good")
            for flag in codec.find_flags(value):
                ctx.report(f"  发现 flag: {flag}", "good")
                ctx.add_finding("flag", flag, detail=f"DNS 标签 {label} {method} 解码",
                                level="good")
        if not decoded:
            ctx.report("  长标签未解出可读内容，仅记录原始数据", "info")
    types = Counter(r[2] for r in rows if len(r) > 2 and r[2])
    if types:
        ctx.report("查询类型: " + ", ".join(f"{k}={v}" for k, v in types.most_common()), "info")
    _dns_tunnel(ctx)


def _dns_tunnel(ctx: FeatureContext) -> None:
    """Ordered chunk reassembly, timeline and decoded output for DNS tunnels."""
    from fnet.utils import tunnel

    rows = _rows(ctx, ["frame.number", "dns.qry.name", "frame.time_epoch",
                       "dns.flags.response"], "dns", limit=200_000)
    if not rows:
        return
    seen_flags: set[str] = set()
    # 长度/时序隐蔽信道与载荷内容无关，先单独检查（载荷可能是随机填充）。
    _report_dns_channels(ctx, rows, seen_flags)
    result = tunnel.analyse_dns(rows)
    decoded = result.get("decoded") or []
    if not decoded:
        return
    ctx.report("===== DNS 隧道分块重组 =====", "good")
    chunks = []
    for row in rows:
        row += [""] * (4 - len(row))
        qname = row[1]
        if not qname:
            continue
        chunks.append({
            "frame": row[0],
            "time": _epoch(row[2]) or float(row[0] or 0),
            "data": qname.encode("utf-8", "replace"),
        })
    timeline = tunnel.timeline(chunks, buckets=20)
    peak = max((item["bytes"] for item in timeline), default=0)
    if timeline:
        ctx.report(
            f"隧道时间线: {len(timeline)} 个区间，峰值 {peak} 字节/区间",
            "info")
        for item in timeline:
            if not item["bytes"]:
                continue
            ctx.report(
                f"  {item['start']:.3f}-{item['end']:.3f}s "
                f"{item['frames']} 条 / {item['bytes']} 字节",
                "debug")
    for entry in decoded:
        text = clean_cell(entry.get("text") or "", 400)
        state = "完整" if entry.get("complete") else \
            f"缺块 {len(entry.get('missing') or [])}"
        ctx.report(f"域 {entry.get('session')}: {entry.get('chunks')} 块，{state}",
                   "good")
        if text:
            ctx.report("  " + text, "good")
            ctx.add_finding("dns", f"DNS 隧道重组 {entry.get('session')}",
                            detail=text, level="good",
                            extra={"complete": bool(entry.get("complete")),
                                   "chunks": entry.get("chunks")})
        for flag in entry.get("flags") or []:
            canonical = tunnel.canonical_flag(flag)
            if canonical in seen_flags:
                continue
            seen_flags.add(canonical)
            ctx.report(f"  发现 flag: {canonical}", "good")
            extra = {"raw_flag": flag} if flag != canonical else None
            ctx.add_finding("flag", flag,
                            detail=f"DNS 隧道 {entry.get('session')}",
                            level="good", extra=extra)
    for item in tunnel.write_decoded(decoded, ctx.output_dir or ".",
                                     "dns_tunnel"):
        ctx.report(f"隧道数据已保存: {item['path']} ({item['size']} 字节)",
                   "info")
    for flag in result.get("flags") or []:
        canonical = tunnel.canonical_flag(flag)
        if canonical in seen_flags:
            continue
        seen_flags.add(canonical)
        extra = {"raw_flag": flag} if flag != canonical else None
        ctx.add_finding("flag", flag, detail="DNS 隧道重组", level="good",
                        extra=extra)


def icmp(ctx: FeatureContext) -> None:
    _payload_rows(ctx, "ICMP 载荷", "icmp", ["data.data", "icmp.type"])
    rows = _rows(ctx, ["frame.number", "ip.src", "ip.dst", "icmp.type",
                       "icmp.seq", "data.len"], "icmp")
    if rows:
        sizes = [int(r[5]) for r in rows if len(r) > 5 and r[5].isdigit()]
        if sizes:
            ctx.report(f"ICMP 数量 {len(rows)}，载荷长度范围 {min(sizes)}..{max(sizes)}", "info")
        if len(set(sizes)) > 5 and len(sizes) > 20:
            ctx.report("载荷长度变化较大，可能存在 ICMP 隧道", "warn")
    _icmp_tunnel(ctx)


def _icmp_bin_name(session: str) -> str:
    """载荷落盘文件名，命名与 tunnel.write_decoded/_sanitise_session 一致。"""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(session or "")).strip("._")[:80]
    return f"icmp_tunnel_{safe or 'session'}.bin"


def _session_time_span(result: dict, session: str) -> tuple[float, float]:
    """从 analyse_icmp 的会话分组取首/末帧的 epoch 时间戳。"""
    pairs = (result.get("sessions") or {}).get(session) or []
    times = [float(getattr(chunk, "time", 0.0) or 0.0) for chunk, _ in pairs]
    times = [value for value in times if value > 0]
    if not times:
        return (0.0, 0.0)
    return (min(times), max(times))


def _report_payload_analysis(ctx: FeatureContext, session: str, bin_name: str,
                             first_frame: str, analysis: dict,
                             seen_flags: set[str], preview: str = "",
                             channel_hit: bool = False) -> bool:
    """把 payload_bin 的分层分析结果写成一条高信息密度 finding。

    返回是否解密成功；flag 以 kind=flag 单独 emit（全局去重）。
    """
    prof = analysis.get("profile") or {}
    layers = analysis.get("layers") or []
    decrypt = analysis.get("decrypt") or {}
    content = analysis.get("content") or {}
    alignment = "16 字节对齐" if prof.get("aligned_16") else "未按 16 字节对齐"
    magic_text = f"，magic {prof.get('magic')}" if prof.get("magic") else ""
    picture = (f"熵 {prof.get('entropy') or 0}，"
               f"可打印率 {prof.get('printable_ratio') or 0}，"
               f"{alignment}{magic_text}")
    if layers:
        pieces = []
        for item in layers:
            pieces.append(f"{item.get('encoding')}({item.get('out_bytes')}B)")
        layers_text = "→".join(pieces)
    else:
        layers_text = "无"
    extra = {"bin": bin_name, "session": session,
             "artifact": bin_name,
             "payload_preview": (preview or "")[:1200],
             "entropy": prof.get("entropy") or 0,
             "layers": [item.get("encoding") for item in layers]}

    if decrypt.get("hit"):
        plain = bytes(decrypt.get("plaintext") or b"")
        flags = list(content.get("flags") or [])
        stem = bin_name[:-4] if bin_name.endswith(".bin") else bin_name
        out_name = f"{stem}_decoded{content.get('suggested_ext') or '.txt'}"
        ctx.write_output(out_name, plain)
        preview = clean_cell(plain.decode("utf-8", "replace"), 400)
        detail = (f"{bin_name} 载荷分层分析：画像（{picture}）；"
                  f"编码层 {layers_text}；解密成功："
                  f"cipher={decrypt.get('cipher')} digest={decrypt.get('digest')}"
                  f"（口令已脱敏），配方 `{decrypt.get('recipe')}`；"
                  f"明文预览：{preview}；"
                  f"内容：flag={'、'.join(flags) if flags else '无'}；"
                  f"明文已保存: {out_name}")
        ctx.report(f"ICMP 隧道载荷自动解密成功: {bin_name} "
                   f"({decrypt.get('cipher')} / {decrypt.get('digest')}, 口令已脱敏)",
                   "good")
        if content.get("text"):
            ctx.report("  " + clean_cell(str(content["text"]), 160), "good")
        ctx.add_finding("protocol", f"ICMP 隧道载荷分析 {bin_name}",
                        detail=detail, frame=first_frame, level="good",
                        extra=dict(extra, decrypted=True,
                                   cipher=decrypt.get("cipher") or "",
                                   digest=decrypt.get("digest") or "",
                                   output=out_name, flags=flags))
        for flag in flags:
            if flag in seen_flags:
                continue
            seen_flags.add(flag)
            ctx.report(f"  发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag,
                            detail=f"ICMP 隧道载荷解密 {bin_name}",
                            level="good")
        return True

    attempts = int(decrypt.get("attempts") or 0)
    example = str(decrypt.get("example_command") or "")
    skipped = str(decrypt.get("skipped") or "")
    if skipped:
        fail_text = f"未进入解密尝试（{skipped}）"
    else:
        fail_text = (f"已尝试 {attempts} 种配方"
                     "（常见口令 × AES-128/256 cbc/ctr/ecb × md5/sha256，EVP 派生）")
    detail = (f"{bin_name} 载荷分层分析：画像（{picture}）；"
              f"编码层 {layers_text}；"
              f"载荷预览（前 240 字）：{clean_cell(preview, 240) or '无'}；"
              f"自动解密失败：{fail_text}；"
              f"命令示例：`{example}`（<口令> 请替换为真实口令，"
              "-a -A 仅当载荷为 Base64 文本时适用）；"
              "也可在结果详情里点「破解」填入口令重试，或用 WebUI/CLI 参数 "
              "password/cipher/digest 配合「OpenSSL加密文件分析」"
              "（openssl_file）重跑")
    if channel_hit:
        # 同一方向的长度隐蔽信道已经解出 flag：这里的密文很可能是幌子，
        # 直接告诉用户不用再纠结解密。
        detail += ("；注意：同一方向的「ICMP 长度/时序隐蔽信道」已解出 flag，"
                   "本密文可能只是干扰项，优先看信道结果")
    ctx.report(f"会话 {session} 载荷自动解密未命中，"
               "已生成 openssl 命令示例与参数指引", "warn")
    ctx.add_finding("protocol", f"ICMP 隧道载荷分析 {bin_name}",
                    detail=detail, frame=first_frame, level="warn",
                    extra=dict(extra, decrypted=False, attempts=attempts,
                               example=example))
    return False


def _report_exfil_alert(ctx: FeatureContext, exfil: list[dict],
                        channel_sessions: set[str] | None = None) -> None:
    """汇总加密外传告警（一次），公网 IOC 并入 detail，指向载荷分析结论。"""
    if not exfil:
        return
    public = sorted({item["dst"] for item in exfil if item["public"]})
    if public:
        ctx.report("隧道目标 " + ", ".join(public)
                   + " 为公网地址，已并入加密外传告警", "warn")
    lines = []
    for item in exfil:
        line = (f"{item['session']} → {item['dst']}"
                + ("（公网地址）" if item["public"] else "")
                + f"，密文 {item['bytes']} 字节，熵 {item['entropy']}")
        line += "，已自动解密成功" if item["decrypted"] else "，未自动解密"
        lines.append(line)
    detail = ("内网主机经 ICMP 隧道外传加密载荷：" + "；".join(lines)
              + "。每个方向的画像/编码剥离/解密尝试与命令指引"
                "见对应「ICMP 隧道载荷分析」finding")
    hinted = sorted((channel_sessions or set())
                    & {item["session"] for item in exfil})
    if hinted:
        detail += ("。注意：方向 " + "、".join(hinted)
                   + " 的「ICMP 长度/时序隐蔽信道」已解出 flag，"
                     "该方向的密文大概率是干扰项，结论以信道结果为准")
    ctx.add_finding(
        "protocol", "ICMP 隧道载荷为加密数据（疑似隐蔽外传）",
        detail=detail,
        frame=exfil[0]["first_frame"], level="warn",
        extra={"targets": [item["dst"] for item in exfil],
               "public": public,
               "sessions": [item["session"] for item in exfil]})


#: 隐蔽信道的读法标签（展示用）。
_CHANNEL_VARIANT_LABELS = {
    "printable": "可打印取值",
    "raw": "原始字节",
    "dedup": "去重后可打印取值",
    "dedup_raw": "去重后原始字节",
    "b64-index": "取值作 Base64 索引",
    "b64-index-dedup": "去重后取值作 Base64 索引",
    "b64-index-1": "取值-1 作 Base64 索引",
    "b64-index-1-dedup": "去重后取值-1 作 Base64 索引",
}
#: 时序二值化读法的单位标签。
_TIMING_UNITS = {"ms": "毫秒", "cs": "厘秒", "ds": "分秒"}
#: 隐蔽信道最多分析多少个方向/流，避免大抓包拖慢分析。
MAX_CHANNEL_GROUPS = 40
#: 每个方向最多取多少个样本。
MAX_CHANNEL_SAMPLES = 4000


def _epoch(value) -> float:
    """把 tshark 的 epoch 字段转成正浮点，非法值返回 0。"""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if number >= 0 else 0.0


def _has_epoch(value) -> bool:
    """字段非空且可解析为数值（epoch 0 也是合法时间戳）。"""
    text = str(value or "").strip()
    if not text:
        return False
    try:
        float(text)
    except (TypeError, ValueError):
        return False
    return True


def _safe_stem(prefix: str, name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(name or "")).strip("._")[:80]
    return f"{prefix}_{safe or 'session'}"


def _channel_variant_label(variant: str) -> str:
    """把检测器的 variant 标识翻成可读文案。"""
    text = str(variant or "")
    if text.startswith("bits/"):
        parts = text.split("/")
        polarity = parts[1] if len(parts) > 1 else ""
        order = "MSB" if len(parts) > 2 and parts[2] == "msb" else "LSB"
        offset = parts[3].lstrip("+") if len(parts) > 3 else "0"
        return f"间隔二值化（{polarity}，{order}，位偏移 {offset}）"
    if "/" in text:
        base, unit = text.rsplit("/", 1)
        return (f"{_CHANNEL_VARIANT_LABELS.get(base, base)}"
                f"（{_TIMING_UNITS.get(unit, unit)}）")
    return _CHANNEL_VARIANT_LABELS.get(text, text or "可打印取值")


def _top_groups(buckets: dict) -> dict:
    """样本最多的前 N 组（大抓包里只深挖最可疑的方向/流）。"""
    if len(buckets) <= MAX_CHANNEL_GROUPS:
        return buckets

    def weight(item):
        bucket = item[1]
        return max(len(bucket.get("request") or []),
                   len(bucket.get("reply") or []))

    return dict(sorted(buckets.items(), key=weight, reverse=True)
                [:MAX_CHANNEL_GROUPS])


def _detect_side(bucket: dict, detector) -> tuple[str, list, dict]:
    """请求方向优先，失败回退应答；返回 (方向, 样本, 检测结果)。"""
    for side in ("request", "reply"):
        values = bucket.get(side) or []
        if len(values) < 2:
            continue
        result = detector(values)
        if result.get("channel"):
            return side, values, result
    return "", [], {}


def _emit_channel(ctx: FeatureContext, *, protocol: str, session: str,
                  kind: str, kind_label: str, encoding: str, channel: dict,
                  samples: int, sample_label: str, first_frame: str,
                  seen_flags: set[str], out_name: str,
                  extra_note: str = "") -> bool:
    """把一次信道检测结果写成日志 + 结构化 finding（flag 单独 emit）。"""
    from fnet.utils import tunnel

    decoded = str(channel.get("decoded_text") or "")
    raw_flags = [str(flag) for flag in (channel.get("flags") or [])]
    flags = list(dict.fromkeys(tunnel.canonical_flag(flag)
                               for flag in raw_flags))
    if not decoded and not flags:
        return False
    raw_text = str(channel.get("text") or "")
    layers = channel.get("decodings") or []
    layer_text = "、".join(str(item.get("encoding") or "")
                           for item in layers) or "无"
    variant = _channel_variant_label(str(channel.get("variant") or ""))
    order = "（逆序）" if channel.get("order") == "reversed" else ""
    ctx.write_output(out_name,
                     (decoded or raw_text).encode("utf-8", "replace"))
    detail = (f"{protocol} 方向 {session}，{samples} 个{sample_label}"
              f"按「{variant}」读法映射为字符{order}（可打印占比 "
              f"{float(channel.get('printable_ratio') or 0):.2f}），"
              f"得到文本 {clean_cell(raw_text, 120)}；"
              f"编码层 {layer_text}；"
              f"解码文本预览：{clean_cell(decoded, 400)}；"
              f"flag：{'、'.join(flags) if flags else '无'}；"
              f"解码结果已保存: {out_name}{extra_note}")
    summary = f"{protocol} {kind_label}隐蔽信道 {session}"
    ctx.report(f"{summary}: {samples} 个{sample_label}按「{variant}」映射，"
               f"编码层 {layer_text}"
               + (f"，发现 flag {flags[0]}" if flags else ""),
               "good" if flags else "warn")
    ctx.add_finding("protocol", summary, detail=detail, frame=first_frame,
                    level="good" if flags else "warn",
                    extra={"session": session, "protocol": protocol,
                           "kind": kind, "samples": samples,
                           "encoding": encoding,
                           "order": channel.get("order") or "forward",
                           "variant": channel.get("variant") or "",
                           "layers": layer_text,
                           "decoded": clean_cell(decoded, 1200),
                           "output": out_name,
                           "flags": "、".join(flags)})
    for flag in flags:
        if flag in seen_flags:
            continue
        seen_flags.add(flag)
        ctx.report(f"  发现 flag: {flag}", "good")
        raw_flag = next((item for item in raw_flags
                         if tunnel.canonical_flag(item) == flag), flag)
        extra = {"raw_flag": raw_flag} if raw_flag != flag else None
        ctx.add_finding("flag", flag, frame=first_frame, detail=summary,
                        level="good", extra=extra)
    return bool(flags)


def _report_length_channel(ctx: FeatureContext, rows: list[list[str]],
                           seen_flags: set[str]) -> set[str]:
    """ICMP 载荷长度隐蔽信道：每个包的长度承载一个字符。

    载荷内容可能只是随机填充，消息藏在长度序列里。这里按方向分别收集
    type=8（请求）和 type=0（应答）的长度，优先用请求；请求缺失或被
    裁剪时回退到应答，再交给 :func:`fnet.utils.tunnel.length_channel`
    做多读法打分。

    返回解出 flag 的方向集合，供后续载荷分析提示“flag 在长度通道里”。
    """
    from fnet.utils import tunnel

    buckets: dict[str, dict] = {}
    for row in rows:
        row = list(row) + [""] * (7 - len(row))
        icmp_type = str(row[3] or "")
        if icmp_type not in ("8", "0"):
            continue
        raw = hex_to_bytes(row[5])
        if not raw:
            continue
        key = f"{row[1]}>{row[2]}"
        side = "request" if icmp_type == "8" else "reply"
        bucket = buckets.setdefault(
            key, {"request": [], "reply": [], "frame": str(row[0] or "")})
        if len(bucket[side]) < MAX_CHANNEL_SAMPLES:
            bucket[side].append(len(raw))

    hit_sessions: set[str] = set()
    for session, bucket in _top_groups(buckets).items():
        ctx.check_cancel()
        side, lengths, channel = _detect_side(bucket, tunnel.length_channel)
        if not channel.get("channel"):
            continue
        stem = _icmp_bin_name(session)
        if stem.endswith(".bin"):
            stem = stem[:-4]
        side_text = "请求" if side == "request" else "应答"
        if _emit_channel(
                ctx, protocol="ICMP", session=session, kind="length",
                kind_label="载荷长度", encoding="length-ascii",
                channel=channel, samples=len(lengths),
                sample_label=f"{side_text}包的长度",
                first_frame=bucket.get("frame", ""), seen_flags=seen_flags,
                out_name=f"{stem}_length.txt"):
            hit_sessions.add(session)
    return hit_sessions


def _report_timing_channel(ctx: FeatureContext, rows: list[list[str]],
                           seen_flags: set[str]) -> set[str]:
    """ICMP 包间隔时序隐蔽信道：间隔长短承载字符/比特。"""
    from fnet.utils import tunnel

    buckets: dict[str, dict] = {}
    for row in rows:
        row = list(row) + [""] * (7 - len(row))
        if str(row[3] or "") not in ("8", "0"):
            continue
        if not _has_epoch(row[6]):
            continue
        when = _epoch(row[6])
        key = f"{row[1]}>{row[2]}"
        side = "request" if str(row[3]) == "8" else "reply"
        bucket = buckets.setdefault(
            key, {"request": [], "reply": [], "frame": str(row[0] or "")})
        if len(bucket[side]) < MAX_CHANNEL_SAMPLES:
            bucket[side].append(when)

    hit_sessions: set[str] = set()
    for session, bucket in _top_groups(buckets).items():
        ctx.check_cancel()
        side, times, channel = _detect_side(bucket, tunnel.timing_channel)
        if not channel.get("channel"):
            continue
        stem = _icmp_bin_name(session)
        if stem.endswith(".bin"):
            stem = stem[:-4]
        side_text = "请求" if side == "request" else "应答"
        if _emit_channel(
                ctx, protocol="ICMP", session=session, kind="timing",
                kind_label="包间隔时序", encoding="timing-interval",
                channel=channel, samples=len(times),
                sample_label=f"{side_text}包间隔",
                first_frame=bucket.get("frame", ""), seen_flags=seen_flags,
                out_name=f"{stem}_timing.txt"):
            hit_sessions.add(session)
    return hit_sessions


def _report_dns_channels(ctx: FeatureContext, rows: list[list[str]],
                         seen_flags: set[str]) -> set[str]:
    """DNS 隐蔽信道：查询名标签长度 / 查询名总长度 / 查询间隔时序。

    行格式 ``[frame, qname, epoch, response]``；只分析查询（响应里的
    qname 与查询重复），按父域分组，避免把不同隧道的序列混在一起。
    """
    from fnet.utils import tunnel

    buckets: dict[str, dict] = {}
    for row in rows:
        row = list(row) + [""] * (4 - len(row))
        qname = str(row[1] or "").strip(".")
        if not qname:
            continue
        if str(row[3] or "").strip() in ("1", "True", "true"):
            continue
        labels = [part for part in qname.split(".") if part]
        if not labels:
            continue
        parent = ".".join(labels[-2:]) if len(labels) > 2 else qname
        bucket = buckets.setdefault(parent, {"label": [], "qname": [],
                                             "times": [],
                                             "frame": str(row[0] or "")})
        if len(bucket["label"]) < MAX_CHANNEL_SAMPLES:
            bucket["label"].append(len(labels[0]))
            bucket["qname"].append(len(qname))
        if _has_epoch(row[2]) and len(bucket["times"]) < MAX_CHANNEL_SAMPLES:
            when = _epoch(row[2])
            bucket["times"].append(when)

    hit_sessions: set[str] = set()
    for session, bucket in _top_groups(buckets).items():
        ctx.check_cancel()
        for series, label in (("label", "查询名首标签长度"),
                              ("qname", "查询名总长度")):
            channel = tunnel.length_channel(bucket.get(series) or [])
            if not channel.get("channel"):
                continue
            if _emit_channel(
                    ctx, protocol="DNS", session=session, kind="length",
                    kind_label=label, encoding="length-ascii",
                    channel=channel, samples=len(bucket.get(series) or []),
                    sample_label=label,
                    first_frame=bucket.get("frame", ""),
                    seen_flags=seen_flags,
                    out_name=f"{_safe_stem('dns_tunnel', session)}_length.txt"):
                hit_sessions.add(session)
            break
        channel = tunnel.timing_channel(bucket.get("times") or [])
        if channel.get("channel"):
            if _emit_channel(
                    ctx, protocol="DNS", session=session, kind="timing",
                    kind_label="查询间隔时序", encoding="timing-interval",
                    channel=channel, samples=len(bucket.get("times") or []),
                    sample_label="查询间隔",
                    first_frame=bucket.get("frame", ""),
                    seen_flags=seen_flags,
                    out_name=f"{_safe_stem('dns_tunnel', session)}_timing.txt"):
                hit_sessions.add(session)
    return hit_sessions


def _report_flow_channels(ctx: FeatureContext, protocol: str,
                          display_filter: str,
                          seen_flags: set[str]) -> set[str]:
    """TCP/UDP 流级隐蔽信道：载荷长度与包间隔（按五元组方向分组）。"""
    from fnet.utils import tunnel

    rows = _rows(ctx, ["frame.number", "ip.src", "ip.dst",
                       f"{display_filter}.srcport",
                       f"{display_filter}.dstport", "data.len",
                       "frame.time_epoch"],
                 display_filter, limit=200_000)
    buckets: dict[str, dict] = {}
    for row in rows:
        row = list(row) + [""] * (7 - len(row))
        size = str(row[5] or "")
        if not size.isdigit() or int(size) <= 0:
            continue
        key = f"{row[1]}:{row[3]}>{row[2]}:{row[4]}"
        bucket = buckets.setdefault(
            key, {"request": [], "times": [], "frame": str(row[0] or "")})
        if len(bucket["request"]) < MAX_CHANNEL_SAMPLES:
            bucket["request"].append(int(size))
        if _has_epoch(row[6]) and len(bucket["times"]) < MAX_CHANNEL_SAMPLES:
            when = _epoch(row[6])
            bucket["times"].append(when)

    hit_sessions: set[str] = set()
    for session, bucket in _top_groups(buckets).items():
        ctx.check_cancel()
        channel = tunnel.length_channel(bucket.get("request") or [])
        if channel.get("channel"):
            if _emit_channel(
                    ctx, protocol=protocol, session=session, kind="length",
                    kind_label="载荷长度", encoding="length-ascii",
                    channel=channel, samples=len(bucket.get("request") or []),
                    sample_label="载荷长度",
                    first_frame=bucket.get("frame", ""),
                    seen_flags=seen_flags,
                    out_name=f"{_safe_stem(protocol.lower() + '_flow', session)}"
                             "_length.txt"):
                hit_sessions.add(session)
        channel = tunnel.timing_channel(bucket.get("times") or [])
        if channel.get("channel"):
            if _emit_channel(
                    ctx, protocol=protocol, session=session, kind="timing",
                    kind_label="包间隔时序", encoding="timing-interval",
                    channel=channel, samples=len(bucket.get("times") or []),
                    sample_label="包间隔",
                    first_frame=bucket.get("frame", ""),
                    seen_flags=seen_flags,
                    out_name=f"{_safe_stem(protocol.lower() + '_flow', session)}"
                             "_timing.txt"):
                hit_sessions.add(session)
    return hit_sessions


def _icmp_tunnel(ctx: FeatureContext) -> None:
    """Reassemble chunked ICMP echo tunnels and export the decoded data."""
    from fnet.utils import payload_bin, tunnel

    rows = _rows(ctx, ["frame.number", "ip.src", "ip.dst", "icmp.type",
                       "icmp.seq", "data.data", "frame.time_epoch"],
                 "icmp", limit=200_000)
    if not rows:
        return
    result = tunnel.analyse_icmp(rows)
    decoded = result.get("decoded") or []
    if not decoded:
        return
    ctx.report("===== ICMP 隧道分块重组 =====", "good")
    chunks = []
    for row in rows:
        row += [""] * (7 - len(row))
        raw = hex_to_bytes(row[5])
        if not raw:
            continue
        chunks.append({
            "frame": row[0],
            "time": float(row[6]) if (row[6] or "").replace(".", "", 1).isdigit()
            else float(row[0] or 0),
            "data": raw,
        })
    timeline = tunnel.timeline(chunks, buckets=20)
    if timeline:
        peak = max((item["bytes"] for item in timeline), default=0)
        ctx.report(f"隧道时间线: {len(timeline)} 个区间，峰值 {peak} 字节/区间",
                   "info")
    seen_flags: set[str] = set()
    # 长度/时序隐蔽信道与载荷内容无关，先单独检查（载荷可能全是随机密文）。
    channel_sessions = _report_length_channel(ctx, rows, seen_flags)
    channel_sessions |= _report_timing_channel(ctx, rows, seen_flags)
    # 从抓包正文挖 password=/Basic 头里的候选口令，供载荷自动解密追加尝试。
    mined: list[str] = []
    try:
        with open(ctx.pcap, "rb") as handle:
            mined = payload_bin.mine_passwords(
                handle.read(payload_bin.MAX_MINE_BYTES))
    except OSError:
        mined = []
    exfil: list[dict] = []
    for entry in decoded:
        session = str(entry.get("session") or "")
        encrypted = bool(entry.get("encrypted"))
        text = clean_cell(entry.get("text") or "", 400)
        bin_name = _icmp_bin_name(session)
        payload_preview = str(entry.get("raw_text") or "")[:1200]
        state = "完整" if entry.get("complete") else \
            f"缺块 {len(entry.get('missing') or [])}"
        ctx.report(f"会话 {session}: {entry.get('chunks')} 块，{state}",
                   "good")
        if text:
            ctx.report("  " + text, "good")
            ctx.add_finding("icmp", f"ICMP 隧道重组 {session}",
                            detail=text, level="good",
                            extra={"complete": bool(entry.get("complete")),
                                   "chunks": entry.get("chunks")})
        # 每个隧道 session 一条结构化 finding（kind protocol）。
        encodings = "+".join(entry.get("encodings") or []) or "raw"
        frame_range = str(entry.get("frame_range") or "")
        first_frame = frame_range.split("-")[0] if frame_range else ""
        packets = entry.get("packets") or entry.get("chunks") or 0
        t0, t1 = _session_time_span(result, session)
        uniform = ("高熵密文，标准 base64 解码后非文本" if encrypted
                   else "载荷未见加密特征")
        detail = (f"方向 {session}，包数 {packets}，"
                  f"载荷总长 {entry.get('payload_bytes') or 0} 字节，"
                  f"编码 {encodings}，加密 {'是' if encrypted else '否'}，"
                  f"帧范围 {frame_range or '未知'}，"
                  f"首帧时间戳 {t0:.3f}，末帧时间戳 {t1:.3f}（epoch 秒），"
                  f"{uniform}")
        if session in channel_sessions:
            detail += ("；该方向的「ICMP 长度/时序隐蔽信道」已解出 flag，"
                       "载荷密文很可能只是干扰项")
        ctx.add_finding("protocol", f"ICMP 隧道 {session}",
                        detail=detail,
                        frame=first_frame,
                        level="warn" if encrypted else "info",
                        extra={"session": session,
                               "packets": packets,
                               "payload_bytes": entry.get("payload_bytes") or 0,
                               "encodings": encodings,
                               "encrypted": encrypted,
                               "artifact": bin_name,
                               "payload_preview": payload_preview,
                               "frames": frame_range,
                               "first_epoch": f"{t0:.3f}",
                               "last_epoch": f"{t1:.3f}",
                               "complete": bool(entry.get("complete"))})
        if encrypted:
            # 加密外传：交给 payload_bin 做分层分析（画像/编码剥离/解密尝试）。
            ctx.report(
                f"会话 {session} 的隧道载荷为加密数据（疑似隐蔽外传），"
                "开始载荷分层分析", "warn")
            data = entry.get("data") or b""
            analysis = payload_bin.analyse_payload(
                data, name=bin_name, password_candidates=mined)
            decrypted = _report_payload_analysis(
                ctx, session, bin_name, first_frame, analysis, seen_flags,
                preview=payload_preview,
                channel_hit=session in channel_sessions)
            dst = session.split(">")[-1].split("#")[0] if ">" in session else ""
            cipher = entry.get("cipher") or {}
            exfil.append({"session": session, "dst": dst,
                          "public": _is_public_ip(dst),
                          "bytes": cipher.get("length") or len(data),
                          "entropy": cipher.get("entropy") or 0,
                          "bin": bin_name, "decrypted": decrypted,
                          "first_frame": first_frame})
        for flag in entry.get("flags") or []:
            ctx.report(f"  发现 flag: {flag}", "good")
            if flag not in seen_flags:
                seen_flags.add(flag)
                ctx.add_finding("flag", flag,
                                detail=f"ICMP 隧道 {session}",
                                level="good")
    for item in tunnel.write_decoded(decoded, ctx.output_dir or ".",
                                     "icmp_tunnel"):
        ctx.report(f"隧道数据已保存: {item['path']} ({item['size']} 字节)",
                   "info")
    _report_exfil_alert(ctx, exfil, channel_sessions)


def telnet(ctx: FeatureContext) -> None:
    _payload_rows(ctx, "Telnet 会话", "telnet", ["tcp.payload"])


def ftp(ctx: FeatureContext) -> None:
    rows = _dump(ctx, "FTP 命令", ["frame.number", "ftp.request.command",
                                   "ftp.request.arg", "ftp.response.code",
                                   "ftp.response.arg", "tcp.stream"], "ftp")
    pending_user: dict[str, str] = {}
    for row in rows:
        stream = row[5] if len(row) > 5 else ""
        if len(row) > 2 and row[1].upper() in ("USER", "PASS", "ACCT"):
            ctx.report(f"FTP 凭据: {row[1]} {row[2]}", "good")
            command = row[1].upper()
            account = row[2] if command == "USER" else pending_user.get(stream, "")
            secret = row[2] if command in ("PASS", "ACCT") else ""
            ctx.add_finding("credential", f"FTP {row[1]} {row[2]}",
                            frame=row[0], level="good",
                            extra={"protocol": "ftp", "account": account,
                                   "secret": secret, "stream": stream})
            if command == "USER":
                pending_user[stream] = row[2]
            elif command in ("PASS", "ACCT") and account:
                ctx.add_finding("credential",
                                f"FTP 登录 {account}:{row[2]}",
                                frame=row[0], level="good",
                                detail=f"stream {stream}",
                                extra={"protocol": "ftp", "account": account,
                                       "secret": row[2], "stream": stream})
        if len(row) > 1 and row[1].upper() in ("RETR", "STOR", "APPE"):
            ctx.report(f"FTP 文件传输: {row[1]} {row[2] if len(row) > 2 else ''}", "warn")
            ctx.add_finding("file", f"FTP {row[1]} {row[2] if len(row) > 2 else ''}",
                            frame=row[0], level="warn")
    _payload_rows(ctx, "FTP 数据通道", "ftp-data", ["data.data"])


def mysql(ctx: FeatureContext) -> None:
    _dump(ctx, "MySQL 查询", ["frame.number", "mysql.query", "mysql.user",
                              "mysql.schema", "mysql.packet_length"], "mysql")
    _payload_rows(ctx, "MySQL 原始载荷", "mysql", ["tcp.payload"], max_lines=300)
    rows = _rows(ctx, ["mysql.user", "mysql.schema"], "mysql")
    users = {r[0] for r in rows if r and r[0]}
    if users:
        ctx.report("MySQL 用户: " + ", ".join(sorted(users)), "good")
        for user in sorted(users):
            ctx.add_finding("credential", f"MySQL 用户 {user}", level="good",
                            extra={"protocol": "mysql", "account": user})
    _mysql_sessions(ctx)


def _mysql_sessions(ctx: FeatureContext) -> None:
    """Reassemble MySQL streams so queries/results also work off port 3306."""
    from fnet.utils import mysql as mysql_mod
    from fnet.utils.stream import stream_rows

    streams = stream_rows(ctx, "mysql or tcp.port == 3306", limit=80_000)
    if not streams:
        return
    summary = mysql_mod.summarise_stream(streams)
    if not summary.get("host"):
        return
    host = summary.get("host") or ""
    port = summary.get("port") or ""
    ctx.report(f"===== MySQL 会话 {host}:{port} =====", "good")
    version = summary.get("server_version") or ""
    plugin = summary.get("auth_plugin") or ""
    if version or plugin:
        ctx.report(f"服务端版本: {version or '?'}，认证插件: {plugin or '?'}",
                   "info")
    for user in summary.get("users") or []:
        ctx.report(f"登录用户: {user}", "good")
        ctx.add_finding("credential", f"MySQL 登录用户 {user} @ {host}:{port}",
                        level="good",
                        extra={"protocol": "mysql", "account": user,
                               "host": host, "port": port})
    if summary.get("databases"):
        ctx.report("数据库: " + ", ".join(summary["databases"]), "info")
    queries = summary.get("queries") or []
    if queries:
        ctx.report(f"SQL 语句 {len(queries)} 条", "info")
        for query in queries[:100]:
            ctx.report("  " + clean_cell(query, 300), "info")
        ctx.write_output("mysql_queries.txt", "\n".join(queries))
    result_sets = summary.get("result_sets") or []
    if result_sets:
        lines: list[str] = []
        for result in result_sets[:50]:
            lines.append(f"-- {result.get('query') or '(no query)'}")
            columns = result.get("columns") or []
            if columns:
                lines.append(" | ".join(columns))
            for row in (result.get("rows") or [])[:200]:
                lines.append(" | ".join("" if cell is None else str(cell)
                                        for cell in row))
            if result.get("error"):
                lines.append("错误: " + str(result["error"]))
        ctx.write_output("mysql_results.txt", "\n".join(lines))
        ctx.report(f"结果集 {len(result_sets)} 个，已写入 mysql_results.txt",
                   "info")
    for entry in summary.get("local_infiles") or []:
        name = Path(entry.get("filename") or "local_infile.bin").name
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_"
                       for ch in name)[:80] or "local_infile.bin"
        if entry.get("data"):
            ctx.write_output(f"mysql_local_infile_{safe}", entry["data"])
            ctx.report(f"LOAD DATA LOCAL INFILE 内容已保存: {name} "
                       f"({entry.get('size')} 字节)", "good")
            ctx.add_finding("file", f"MySQL LOCAL INFILE 上传 {name}",
                            level="warn")
    for entry in summary.get("load_file_results") or []:
        values = [str(value) for value in entry.get("values") or []
                  if value not in (None, "")]
        if not values:
            continue
        text = "\n".join(values)
        ctx.report(f"LOAD_FILE 结果 ({clean_cell(str(entry.get('query')), 120)}): "
                   + clean_cell(text, 300), "good")
        ctx.add_finding("file", "MySQL LOAD_FILE 读取文件",
                        detail=clean_cell(text, 400), level="warn",
                        extra={"protocol": "mysql",
                               "query": entry.get("query") or ""})
    for error in summary.get("errors") or []:
        ctx.report("MySQL 错误: " + clean_cell(str(error), 200), "warn")


def smtp(ctx: FeatureContext) -> None:
    _dump(ctx, "SMTP 命令", ["frame.number", "smtp.req.command",
                             "smtp.req.parameter", "smtp.response.code",
                             "smtp.response.parameter"], "smtp")
    _payload_rows(ctx, "SMTP 正文", "smtp", ["data.data"])
    rows = _rows(ctx, ["smtp.req.parameter"], "smtp.req.command == \"MAIL\"")
    for row in rows:
        if row[0]:
            ctx.report(f"发件人: {row[0]}", "info")
    _mail_sessions(ctx)


def _mail_sessions(ctx: FeatureContext) -> None:
    """Parse SMTP/IMAP/POP3 transcripts and carve their attachments."""
    from pathlib import Path as _Path

    from fnet.utils import mail as mail_mod
    from fnet.utils.stream import stream_rows

    streams = stream_rows(
        ctx, "smtp or imap or pop or tcp.port == 25 or tcp.port == 465 "
             "or tcp.port == 587 or tcp.port == 143 or tcp.port == 993 "
             "or tcp.port == 110 or tcp.port == 995", limit=80_000)
    if not streams:
        return
    found = False
    for stream in streams:
        data = getattr(stream, "data", b"") or b""
        if not data:
            continue
        summary = mail_mod.mail_summary("", data)
        protocol = summary.get("protocol") or ""
        if protocol not in ("smtp", "imap", "pop3"):
            continue
        interesting = any(summary.get(key) for key in (
            "credentials", "messages", "mail_from", "mailboxes", "uids"))
        if not interesting:
            continue
        found = True
        where = f"{stream.src}:{stream.sport} -> {stream.dst}:{stream.dport}"
        ctx.report(f"===== {protocol.upper()} 会话 {where} =====", "good")
        for item in summary.get("credentials") or []:
            user = item.get("username") or ""
            secret = item.get("password") or ""
            ctx.report(f"凭据 [{item.get('mechanism') or protocol}] "
                       f"{user}:{secret}", "good")
            ctx.add_finding("credential", f"{protocol.upper()} 登录 {user}:{secret}",
                            level="good",
                            extra={"protocol": protocol, "account": user,
                                   "secret": secret, "stream": stream.stream})
        for sender in summary.get("mail_from") or []:
            ctx.report(f"发件人: {sender}", "info")
            ctx.add_finding("mail", f"{protocol.upper()} 发件人 {sender}",
                            level="info", extra={"protocol": protocol})
        for recipient in summary.get("rcpt_to") or []:
            ctx.report(f"收件人: {recipient}", "info")
        for mailbox in summary.get("mailboxes") or []:
            ctx.report(f"邮箱: {mailbox}", "info")
        for entry in summary.get("messages") or []:
            headers = entry.get("summary") or {}
            subject = headers.get("Subject") or ""
            sender = headers.get("From") or ""
            ctx.report(f"邮件: {clean_cell(subject, 120) or '(无主题)'} "
                       f"来自 {clean_cell(sender, 80)}", "info")
            ctx.add_finding("mail", clean_cell(subject, 160) or "(无主题)",
                            detail=clean_cell(sender, 200), level="info",
                            extra={"protocol": protocol,
                                   "mailbox": entry.get("mailbox") or "",
                                   "size": entry.get("size") or 0})
            message = entry.get("message")
            try:
                attachments = mail_mod.attachment_entries(message)
            except Exception:  # noqa: BLE001 - malformed MIME is not fatal
                attachments = []
            for attachment in attachments:
                raw = attachment.get("data") or b""
                name = _Path(attachment.get("filename")
                             or "attachment.bin").name
                safe = "".join(ch if ch.isalnum() or ch in "._-" else "_"
                               for ch in name)[:80] or "attachment.bin"
                if raw:
                    ctx.write_output(
                        f"mail_{stream.stream}_{protocol}_{safe}", raw)
                ctx.report(f"附件: {name} ({attachment.get('size')} 字节, "
                           f"MD5 {attachment.get('md5')})", "good")
                ctx.add_finding("file",
                                f"{protocol.upper()} 附件 {name}",
                                detail=f"MD5 {attachment.get('md5')}",
                                level="warn",
                                extra={"protocol": protocol,
                                       "filename": name,
                                       "size": attachment.get("size") or 0,
                                       "md5": attachment.get("md5") or ""})
    if not found:
        ctx.report("邮件流会话中没有识别出命令、凭据或附件", "info")


def bluetooth(ctx: FeatureContext) -> None:
    _dump(ctx, "Bluetooth HCI", ["frame.number", "bthci_cmd.opcode",
                                 "bthci_cmd.ogf", "bthci_evt.code",
                                 "bthci_acl.chandle", "btatt.opcode",
                                 "btatt.value"],
          "bthci_cmd or bthci_acl or bthci_evt")
    # bthci_acl.data is unreliable across tshark builds; btatt.value carries
    # the ATT payload on LE links.  Unknown fields are dropped silently by
    # the runner, so this stays compatible with older versions.
    _payload_rows(ctx, "Bluetooth 数据", "bthci_acl or btatt",
                  ["bthci_acl.data", "btatt.value"],
                  max_lines=300)


def udp(ctx: FeatureContext) -> None:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark", "error")
        return
    ctx.report("===== UDP 会话 =====", "good")
    for line in conversations(ctx.tshark.path, ctx.pcap, "udp").splitlines():
        if line.strip():
            ctx.report(line, "info")
    _payload_rows(ctx, "UDP 载荷", "udp", ["udp.payload"], max_lines=400)
    # 流级隐蔽信道：载荷长度或包间隔承载数据（与载荷内容无关）。
    _report_flow_channels(ctx, "UDP", "udp", set())


def tcp(ctx: FeatureContext) -> None:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark", "error")
        return
    ctx.report("===== TCP 会话 =====", "good")
    for line in conversations(ctx.tshark.path, ctx.pcap, "tcp").splitlines():
        if line.strip():
            ctx.report(line, "info")
    _payload_rows(ctx, "TCP 载荷", "tcp", ["tcp.payload"], max_lines=500)
    # 流级隐蔽信道：载荷长度或包间隔承载数据（与载荷内容无关）。
    _report_flow_channels(ctx, "TCP", "tcp", set())


def gtp(ctx: FeatureContext) -> None:
    rows = _dump(ctx, "GTP 消息", ["frame.number", "ip.src", "ip.dst",
                                   "gtp.version", "gtp.message", "gtp.teid",
                                   "gtp.ext_teid"], "gtp")
    teids = Counter(r[5] for r in rows if len(r) > 5 and r[5])
    if teids:
        ctx.report("TEID 统计: " + ", ".join(f"{k}({v})" for k, v in teids.most_common(20)),
                   "info")
        if len(teids) > 1:
            ctx.report("检测到多个 TEID，检查是否有 TEID 混用/错误", "warn")


def http_login(ctx: FeatureContext) -> None:
    from fnet.features import http as http_feature

    ctx.report("专项功能：识别 HTTP 登录成功的账号密码", "good")
    http_feature.extract(ctx)
