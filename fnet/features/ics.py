"""Industrial control protocol summaries (Modbus, S7, MQTT, IEC104, ...)."""
from __future__ import annotations

from collections import Counter

from fnet.features.common import table, tshark_rows
from fnet.features.registry import FeatureContext


def _summary(ctx: FeatureContext, title: str, display_filter: str,
             fields: list[str], limit: int = 300) -> list[list[str]]:
    rows = tshark_rows(ctx, fields, display_filter, limit=50_000)
    table(ctx, title, fields, rows, limit=limit)
    return rows


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


def iecd(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "iec60870_asdu.typeid",
              "iec60870_asdu.co", "iec60870_asdu.addr",
              "iec60870_asdu.pn", "iec60870_asdu.ioa"]
    rows = _summary(ctx, "IEC 60870-5-104", "iec60870_asdu or iec60870_apci", fields)
    types = Counter(r[3] for r in rows if len(r) > 3 and r[3])
    if types:
        ctx.report("类型标识统计: " + ", ".join(f"{k}={v}" for k, v in types.most_common()),
                   "info")
    control = [r for r in rows if len(r) > 3 and r[3] in
               ("45", "46", "47", "48", "49", "50", "51", "58", "59", "60", "61", "62", "63", "64")]
    if control:
        ctx.report(f"发现 {len(control)} 个控制方向报文（C_SC/C_DC 等）", "warn")


def mms(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "mms.confirmedServiceRequest",
              "mms.service", "mms.domainId", "mms.itemId"]
    rows = _summary(ctx, "MMS", "mms", fields)
    services = Counter(r[3] or r[4] for r in rows if len(r) > 4 and (r[3] or r[4]))
    if services:
        ctx.report("服务统计: " + ", ".join(f"{k}={v}" for k, v in services.most_common()),
                   "info")


def omron(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "_ws.col.protocol",
              "_ws.col.info"]
    rows = tshark_rows(ctx, fields, "fins or omron", limit=50_000)
    if not rows:
        rows = tshark_rows(ctx, fields,
                           'ip.addr && (_ws.col.protocol contains "FINS" || '
                           '_ws.col.protocol contains "OMRON")', limit=50_000)
    table(ctx, "OMRON FINS", fields, rows, limit=300)


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


def summary(ctx: FeatureContext) -> None:
    """Fallback entry point used by MMS/IEC/GOOSE check boxes in the registry."""
    mms(ctx)
    iecd(ctx)
    goose(ctx)
