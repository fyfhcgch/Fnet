"""Industrial control protocol summaries (Modbus, S7, MQTT, IEC104, ...)."""
from __future__ import annotations

import re
import struct
from collections import Counter

from fnet.features.common import table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.pcap import hex_to_bytes, payload_text

#: Modbus 标准读/写功能码（不含诊断类），用于异常功能码判定。
MODBUS_CODE_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}
MODBUS_NORMAL_CODES = frozenset(MODBUS_CODE_NAMES)
MODBUS_WRITE_CODES = frozenset({6, 16})
MODBUS_MAX_WRITE_FINDINGS = 20
MODBUS_MAX_STEGO_SEGMENTS = 5
MODBUS_STEGO_LABELS = {"big": "大端", "little": "小端", "low8": "低字节"}

#: 疑似 flag 形态（比 codec.find_flags 更严格，用于候选段可读性打分）。
MODBUS_FLAG_SHAPE_RE = re.compile(r"(?i)[a-z0-9_]{0,8}(?:flag|ctf|key|token)\{")


def _flag_shape(text: str) -> bool:
    return bool(MODBUS_FLAG_SHAPE_RE.search(text))

#: 扩展分析字段：在既有表格之外补取 Unit ID / 寄存器值 / 端口方向等信息。
MODBUS_EXT_FIELDS = ["frame.number", "mbtcp.unit_id", "modbus.func_code",
                     "modbus.reference_num", "modbus.regval_uint16",
                     "modbus.exception_code", "tcp.srcport", "tcp.dstport",
                     "tcp.stream"]


def _summary(ctx: FeatureContext, title: str, display_filter: str,
             fields: list[str], limit: int = 300) -> list[list[str]]:
    rows = tshark_rows(ctx, fields, display_filter, limit=50_000)
    table(ctx, title, fields, rows, limit=limit)
    return rows


def _cell(row: list[str], index: int) -> str:
    return row[index] if index < len(row) else ""


def _int_or(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------
# Modbus 寄存器隐蔽通道检测（纯函数，便于单测）
# --------------------------------------------------------------------------
def _encoding_bytes(values: list[int], encoding: str) -> bytes:
    """把 16 位寄存器值序列按指定编码拼成字节流。"""
    if encoding == "little":
        return b"".join(struct.pack("<H", v & 0xFFFF) for v in values)
    if encoding == "low8":
        return bytes(v & 0xFF for v in values)
    return b"".join(struct.pack(">H", v & 0xFFFF) for v in values)


def _decode_registers(values: list[int], encoding: str) -> str:
    """解码为文本；不可打印字节显示为 ``·``。"""
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "·"
                   for b in _encoding_bytes(values, encoding))


def _ascii_runs(values: list[int], encoding: str, min_len: int,
                ratio: float = 0.8) -> list[tuple[int, int]]:
    """返回 ``[起始下标, 结束下标]``（闭区间）的可打印连续段。

    段内按帧序连续取值：整体可打印率不得低于 ``ratio``；完全无打印字节的
    值会切断当前段（避免把无关寄存器并进同一个段）。段长须 ``>= min_len``。
    """
    runs: list[tuple[int, int]] = []
    cur: list[int] = []
    for idx in range(len(values)):
        window_ok = any(0x20 <= b <= 0x7E
                        for b in _encoding_bytes([values[idx]], encoding))
        if not window_ok:
            if len(cur) >= min_len:
                runs.append((cur[0], cur[-1]))
            cur = []
            continue
        if cur:
            data = _encoding_bytes([values[i] for i in cur + [idx]], encoding)
            printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
            if printable / len(data) < ratio:
                if len(cur) >= min_len:
                    runs.append((cur[0], cur[-1]))
                cur = [idx]
            else:
                cur.append(idx)
        else:
            cur.append(idx)
    if len(cur) >= min_len:
        runs.append((cur[0], cur[-1]))
    return runs


def modbus_register_stego(entries: list[tuple], *,
                          max_segments: int = MODBUS_MAX_STEGO_SEGMENTS,
                          min_regs: int = 4,
                          min_low8: int = 6) -> list[dict]:
    """检测寄存器值序列中的 ASCII 隐写段。

    ``entries`` 是按帧序排列的 ``(frame, ref, value)`` 序列。检测规则：

    * 连续 >= ``min_regs`` 个 16 位值按大端或小端拼接，可打印率 >= 80%；
    * 连续 >= ``min_low8`` 个值的低 8 位可打印（单字节 ASCII 流）；
    * 同一段两种字节序都命中时只保留可读性更高的一个（优先含 flag 形态、
      可打印率高者），被 16 位段覆盖的低字节流视为冗余。

    返回最多 ``max_segments`` 个段（按出现顺序），每段含帧号范围、寄存器
    范围、字节序、可打印率与解码文本。
    """
    values = [int(v) & 0xFFFF for (_, _, v) in entries]
    if not values:
        return []
    frames = [f for (f, _, _) in entries]
    refs = [r for (_, r, _) in entries]
    candidates: list[dict] = []
    for encoding, min_len in (("big", min_regs), ("little", min_regs),
                              ("low8", min_low8)):
        for start, end in _ascii_runs(values, encoding, min_len):
            window = values[start:end + 1]
            data = _encoding_bytes(window, encoding)
            printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
            # 解码文本去掉尾部不可打印填充（如 NUL），避免报告里出现 "·"。
            text = _decode_registers(window, encoding)
            while text and not (0x20 <= ord(text[-1]) <= 0x7E):
                text = text[:-1]
            candidates.append({
                "start": start,
                "end": end,
                "encoding": encoding,
                "ratio": printable / len(data) if data else 0.0,
                "text": text,
            })
    # 去重：同一下标段只保留可读性更高的候选。
    priority = {"big": 2, "little": 1, "low8": 0}
    best: dict[tuple[int, int], dict] = {}
    for cand in candidates:
        key = (cand["start"], cand["end"])
        old = best.get(key)
        score = (_flag_shape(cand["text"]), cand["ratio"],
                 priority[cand["encoding"]])
        if old is None or score > (_flag_shape(old["text"]),
                                   old["ratio"],
                                   priority[old["encoding"]]):
            best[key] = cand
    # 低字节流若被某个 16 位段完全覆盖，信息重复，丢弃。
    endian_spans = [(c["start"], c["end"]) for c in best.values()
                    if c["encoding"] != "low8"]
    segments: list[dict] = []
    for cand in best.values():
        if cand["encoding"] == "low8" and any(
                s <= cand["start"] and cand["end"] <= e
                for s, e in endian_spans):
            continue
        seg = dict(cand)
        span_frames = frames[seg["start"]:seg["end"] + 1]
        span_refs = refs[seg["start"]:seg["end"] + 1]
        seg["frame"] = span_frames[0]
        seg["frame_end"] = span_frames[-1]
        seg["ref"] = min(span_refs)
        seg["ref_end"] = max(span_refs)
        seg["count"] = seg["end"] - seg["start"] + 1
        segments.append(seg)
    segments.sort(key=lambda seg: _int_or(seg["frame"], 0) or 0)
    return segments[:max_segments]


# --------------------------------------------------------------------------
# Modbus handler
# --------------------------------------------------------------------------
def _parse_modbus_rows(rows: list[list[str]]) -> list[dict]:
    parsed = []
    for row in rows:
        values = []
        for token in (_cell(row, 4) or "").split(","):
            value = _int_or(token.strip())
            if value is not None:
                values.append(value & 0xFFFF)
        parsed.append({
            "frame": _cell(row, 0),
            "unit": _cell(row, 1),
            "code": _int_or(_cell(row, 2)),
            "ref": _int_or(_cell(row, 3)),
            "values": values,
            "is_request": True,
        })
    return parsed


def _assign_directions(parsed: list[dict], rows: list[list[str]]) -> None:
    """按 TCP 流判定请求/响应：每条流第一帧的目的端口视为服务端端口。"""
    server_ports: dict[str, int] = {}
    for row, item in zip(rows, parsed):
        dport = _int_or(_cell(row, 7), 0) or 0
        stream = _cell(row, 8)
        if dport and stream not in server_ports:
            server_ports[stream] = dport
    for row, item in zip(rows, parsed):
        sport = _int_or(_cell(row, 6), 0) or 0
        dport = _int_or(_cell(row, 7), 0) or 0
        server = server_ports.get(_cell(row, 8), 502)
        item["is_request"] = bool(dport == server and sport != server)
    if not any(item["is_request"] for item in parsed):
        # 端口信息缺失（或方向判定失败）时全部按请求处理，保证检测可用。
        for item in parsed:
            item["is_request"] = True


def _frame_range(first: str, last: str) -> str:
    return first if first == last else f"{first}-{last}"


def _modbus_stego_findings(ctx: FeatureContext, segments: list[dict]) -> None:
    for seg in segments[:MODBUS_MAX_STEGO_SEGMENTS]:
        label = MODBUS_STEGO_LABELS[seg["encoding"]]
        source = seg.get("source") or "寄存器"
        frame_range = _frame_range(seg["frame"], seg["frame_end"])
        ref_range = _frame_range(str(seg["ref"]), str(seg["ref_end"]))
        flags = codec.find_flags(seg["text"])
        mark = "（疑似 flag）" if flags else ""
        detail = (f"帧 {frame_range} {source} 寄存器 {ref_range} 连续 "
                  f"{seg['count']} 个值按{label}拼接，可打印率 "
                  f"{seg['ratio']:.0%}\n解码文本: {seg['text']}{mark}")
        ctx.report(f"疑似 Modbus 寄存器隐写: 帧 {frame_range} {source} "
                   f"寄存器 {ref_range} ({label}) 解码: {seg['text']}{mark}",
                   "good")
        ctx.add_finding("protocol", "疑似 Modbus 寄存器隐写",
                        frame=seg["frame"], detail=detail, level="good")
        for flag in flags:
            ctx.add_finding("flag", f"Modbus 寄存器隐写 flag: {flag}",
                            frame=seg["frame"],
                            detail=f"来源: {source} 寄存器 {ref_range}"
                                   f"（{label}）\n解码文本: {seg['text']}",
                            level="good")


def _modbus_findings(ctx: FeatureContext, rows: list[list[str]]) -> None:
    parsed = _parse_modbus_rows(rows)
    _assign_directions(parsed, rows)
    requests = [p for p in parsed if p["is_request"]]
    responses = [p for p in parsed if not p["is_request"]]

    units = sorted({p["unit"] for p in parsed if p["unit"]})
    stream_ids = {_cell(row, 8) for row in rows}
    if any(stream_ids):
        stream_count = len([s for s in stream_ids if s])
    else:
        stream_count = len({(_cell(row, 6), _cell(row, 7)) for row in rows
                            if _cell(row, 6) or _cell(row, 7)})
    codes = Counter(p["code"] for p in parsed if p["code"] is not None)
    distribution = "、".join(
        f"{count}×{MODBUS_CODE_NAMES.get(code & 0x7F, f'功能码 {code}')}({code})"
        for code, count in codes.most_common())
    details = [f"功能码分布: {distribution or '无'}"]
    if units:
        details.append("Unit ID: " + ", ".join(units))
    details.append(f"TCP 流数: {stream_count}")
    summary = (f"Modbus 流量概览: {len(parsed)} 帧 "
               f"(请求 {len(requests)} / 响应 {len(responses)})")
    ctx.report(summary, "good")
    for line in details:
        ctx.report("  " + line, "info")
    ctx.add_finding("protocol", summary, detail="\n".join(details),
                    level="info")

    # 写操作统计：按引用寄存器聚合。
    writes = [p for p in requests
              if p["code"] in MODBUS_WRITE_CODES and p["values"]]
    by_ref: dict[int, dict] = {}
    for item in writes:
        for offset in range(len(item["values"])):
            ref = (item["ref"] or 0) + offset
            stat = by_ref.setdefault(ref, {"count": 0, "first": item["frame"],
                                           "last": item["frame"]})
            stat["count"] += 1
            stat["last"] = item["frame"]
    if writes:
        top = sorted(by_ref.items(),
                     key=lambda kv: (-kv[1]["count"], _int_or(kv[0], 0) or 0))
        lines = [f"寄存器 {ref}: {stat['count']} 次 "
                 f"(帧 {_frame_range(str(stat['first']), str(stat['last']))})"
                 for ref, stat in top[:15]]
        ctx.report(f"写操作统计: 共 {len(writes)} 次写请求，"
                   f"覆盖 {len(by_ref)} 个寄存器", "info")
        for line in lines:
            ctx.report("  " + line, "info")
        ctx.add_finding(
            "protocol",
            f"Modbus 写操作统计: {len(writes)} 次写 / {len(by_ref)} 个寄存器",
            frame=writes[0]["frame"], detail="\n".join(lines), level="info")
        # 逐条写操作 finding（最多 20 条）。
        for item in writes[:MODBUS_MAX_WRITE_FINDINGS]:
            if item["code"] == 6:
                value = item["values"][0]
                text = (f"帧 {item['frame']} 写寄存器 {item['ref']} = "
                        f"{value} (0x{value:04X})")
            else:
                text = (f"帧 {item['frame']} 写寄存器 "
                        f"{item['ref']}-{(item['ref'] or 0) + len(item['values']) - 1}"
                        f" 共 {len(item['values'])} 个值")
            ctx.add_finding("protocol", f"Modbus 写操作: {text}",
                            frame=item["frame"], level="info")

    # 异常功能码（非标准读写码；异常响应按低位真实功能码判定）。
    anomalies = {code: count for code, count in codes.items()
                 if (code & 0x7F) not in MODBUS_NORMAL_CODES}
    if anomalies:
        first = next((p["frame"] for p in parsed
                      if p["code"] in anomalies), "")
        detail = "、".join(f"{count}×功能码 {code}"
                          for code, count in sorted(anomalies.items()))
        ctx.report(f"发现异常功能码（非标准读写码）: {detail}", "warn")
        ctx.add_finding("protocol", "Modbus 异常功能码", frame=first,
                        detail=detail, level="warn")

    # 寄存器隐蔽通道：写请求与 FC4 读响应分别检测，共享 5 段上限。
    write_entries: list[tuple] = []
    read_entries: list[tuple] = []
    for item in parsed:
        if not item["values"]:
            continue
        base = item["ref"] or 0
        if item["is_request"] and item["code"] in MODBUS_WRITE_CODES:
            write_entries.extend((item["frame"], base + offset, value)
                                 for offset, value in enumerate(item["values"]))
        elif not item["is_request"] and item["code"] == 4:
            read_entries.extend((item["frame"], base + offset, value)
                                for offset, value in enumerate(item["values"]))
    segments: list[dict] = []
    for source, entries in (("写寄存器", write_entries),
                            ("FC4 读寄存器", read_entries)):
        if len(entries) < 4:
            continue
        for seg in modbus_register_stego(entries):
            seg["source"] = source
            segments.append(seg)
    segments.sort(key=lambda seg: _int_or(seg["frame"], 0) or 0)
    _modbus_stego_findings(ctx, segments)


def modbus(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "modbus.func_code",
              "modbus.reference_num", "modbus.word_cnt", "modbus.exception_code"]
    rows = _summary(ctx, "Modbus", "modbus", fields)
    codes = Counter(r[3] for r in rows if len(r) > 3 and r[3])
    if codes:
        ctx.report("功能码统计: " + ", ".join(f"{k}={v}" for k, v in codes.most_common()),
                   "info")
        dangerous = {"5": "写单线圈", "6": "写单寄存器", "15": "写多线圈", "16": "写多寄存器"}
        for code, label in dangerous.items():
            if code.zfill(2) in codes or code in codes:
                ctx.report(f"包含写操作: 功能码 {code} ({label})", "warn")
    exceptions = [r for r in rows if len(r) > 6 and r[6]]
    if exceptions:
        ctx.report(f"发现 {len(exceptions)} 个 Modbus 异常响应", "warn")
        for row in exceptions[:20]:
            ctx.report("  " + " | ".join(row[:7]), "warn")
    if not rows:
        return
    ext_rows = tshark_rows(ctx, MODBUS_EXT_FIELDS, "modbus", limit=50_000)
    _modbus_findings(ctx, ext_rows or rows)


def s7comm(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "s7comm.header.rosctr",
              "s7comm.param.func", "s7comm.resp.data", "s7comm.item.db",
              "s7comm.item.addr"]
    rows = _summary(ctx, "S7comm", "s7comm", fields)
    funcs = Counter(r[4] for r in rows if len(r) > 4 and r[4])
    if funcs:
        ctx.report("功能统计: " + ", ".join(f"{k}={v}" for k, v in funcs.most_common()),
                   "info")
    writes = [r for r in rows if len(r) > 4 and r[4] in ("5", "6", "0x05", "0x06")]
    if writes:
        ctx.report(f"发现 {len(writes)} 个写请求（功能码 5/6）", "warn")
    if rows:
        detail = ("功能统计: " +
                  (", ".join(f"{k}={v}" for k, v in funcs.most_common())
                   if funcs else "无"))
        if writes:
            detail += f"\n写请求: {len(writes)} 条"
        ctx.add_finding("protocol", f"S7comm 流量概览: {len(rows)} 帧",
                        detail=detail, level="info")


def mqtt(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "mqtt.msgtype", "mqtt.topic",
              "mqtt.msg", "mqtt.conack.flags"]
    rows = _summary(ctx, "MQTT", "mqtt", fields)
    topics = Counter(r[4] for r in rows if len(r) > 4 and r[4])
    if topics:
        ctx.report("主题统计:", "info")
        for topic, count in topics.most_common(50):
            ctx.report(f"  {topic} ({count})", "info")
    messages = [r for r in rows if len(r) > 5 and r[5]]
    if messages:
        ctx.report("消息内容示例:", "good")
        for row in messages[:50]:
            ctx.report(f"  [{row[4]}] {row[5]}", "info")
    if not rows:
        return
    detail = ("主题统计: " +
              (", ".join(f"{t} ({c})" for t, c in topics.most_common(10))
               if topics else "无") +
              f"\n含内容消息: {len(messages)} 条")
    ctx.add_finding("protocol", f"MQTT 流量概览: {len(rows)} 帧",
                    detail=detail, level="info")
    # 消息文本（含 Hex 形态）里的 flag 顺手记录，方便 "0 findings" 判空。
    emitted = 0
    seen: set[str] = set()
    for row in rows:
        if emitted >= 10:
            break
        if len(row) < 6 or not row[5]:
            continue
        candidates = [row[5]]
        data = hex_to_bytes(row[5])
        if data:
            candidates.append(payload_text(data))
        for candidate in candidates:
            for flag in codec.find_flags(candidate):
                if flag in seen:
                    continue
                seen.add(flag)
                ctx.add_finding("flag", f"MQTT 消息 flag: {flag}",
                                frame=row[0],
                                detail=f"主题 {row[4]} 消息: {candidate[:200]}",
                                level="good")
                emitted += 1


def iecd(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "iec60870_asdu.typeid",
              "iec60870_asdu.co", "iec60870_asdu.addr",
              "iec60870_asdu.pn", "iec60870_asdu.ioa"]
    rows = _summary(ctx, "IEC 60870-5-104", "iec60870_asdu", fields)
    types = Counter(r[3] for r in rows if len(r) > 3 and r[3])
    if types:
        ctx.report("类型标识统计: " + ", ".join(f"{k}={v}" for k, v in types.most_common()),
                   "info")
    control = [r for r in rows if len(r) > 3 and r[3] in
               ("45", "46", "47", "48", "49", "50", "51", "58", "59", "60", "61", "62", "63", "64")]
    if control:
        ctx.report(f"发现 {len(control)} 个控制方向报文（C_SC/C_DC 等）", "warn")
    if rows:
        ctx.add_finding(
            "protocol", f"IEC 60870-5-104 流量概览: {len(rows)} 帧",
            detail="类型标识统计: " +
                   (", ".join(f"{k}={v}" for k, v in types.most_common())
                    or "无"),
            level="info")


def mms(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "mms.confirmedServiceRequest",
              "mms.service", "mms.domainId", "mms.itemId"]
    rows = _summary(ctx, "MMS", "mms", fields)
    services = Counter(r[3] or r[4] for r in rows if len(r) > 4 and (r[3] or r[4]))
    if services:
        ctx.report("服务统计: " + ", ".join(f"{k}={v}" for k, v in services.most_common()),
                   "info")
    if rows:
        ctx.add_finding(
            "protocol", f"MMS 流量概览: {len(rows)} 帧",
            detail="服务统计: " +
                   (", ".join(f"{k}={v}" for k, v in services.most_common())
                    or "无"),
            level="info")


def omron(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "_ws.col.protocol",
              "_ws.col.info"]
    rows = tshark_rows(ctx, fields, "omron", limit=50_000)
    if not rows:
        rows = tshark_rows(ctx, fields,
                           'ip.addr && (_ws.col.protocol contains "FINS" || '
                           '_ws.col.protocol contains "OMRON")', limit=50_000)
    table(ctx, "OMRON FINS", fields, rows, limit=300)
    if rows:
        protos = Counter((r[3] if len(r) > 3 else "") or "未知" for r in rows)
        ctx.add_finding("protocol", f"OMRON FINS 流量概览: {len(rows)} 帧",
                        detail="协议分布: " + ", ".join(
                            f"{k}={v}" for k, v in protos.most_common(5)),
                        level="info")


def goose(ctx: FeatureContext) -> None:
    fields = ["frame.number", "eth.src", "goose.appid", "goose.gocbRef",
              "goose.stNum", "goose.t", "goose.goosePdu"]
    rows = _summary(ctx, "GOOSE", "goose", fields)
    appids = Counter(r[2] for r in rows if len(r) > 2 and r[2])
    if appids:
        ctx.report("APPID 统计: " + ", ".join(f"{k}={v}" for k, v in appids.most_common()),
                   "info")
    refs = {r[3] for r in rows if len(r) > 3 and r[3]}
    if refs:
        ctx.report("gocbRef: " + ", ".join(sorted(refs)[:20]), "info")
    if rows:
        detail = ("APPID 统计: " +
                  (", ".join(f"{k}={v}" for k, v in appids.most_common())
                   or "无"))
        if refs:
            detail += "\ngocbRef: " + ", ".join(sorted(refs)[:20])
        ctx.add_finding("protocol", f"GOOSE 报文概览: {len(rows)} 帧",
                        detail=detail, level="info")


def summary(ctx: FeatureContext) -> None:
    """Fallback entry point used by MMS/IEC/GOOSE check boxes in the registry."""
    mms(ctx)
    iecd(ctx)
    goose(ctx)
