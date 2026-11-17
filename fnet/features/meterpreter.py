"""Meterpreter / metsvc session analysis (checkBox_55).

Metasploit Meterpreter exchanges a length-prefixed TLV protocol over its TCP
channel.  The handler reassembles TCP streams that look like Meterpreter TLV
chains (any port - reverse handlers rarely listen on fixed ports; the legacy
``metsvc`` service uses 31337) and uses the pure parser in
:mod:`fnet.utils.meterpreter` to:

* count Meterpreter sessions and per-direction message packets;
* build a command timeline (packet type + COMMAND_ID + parameters);
* surface string parameters, exceptions and unknown TLV types as hex.

Everything is offline: no metasploit installation and no decryption is
involved, so unencrypted Meterpreter captures parse directly.
"""
from __future__ import annotations

import csv
import io

from fnet.features.common import protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import meterpreter as meterpreter_util

MAX_TIMELINE_ROWS = 400


def analyze(ctx: FeatureContext) -> None:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark，请先安装 Wireshark/tshark", "error")
        return

    def matcher(data: bytes) -> bool:
        return meterpreter_util.looks_like_meterpreter(data)

    streams = protocol_streams(ctx, matcher=matcher)
    if not streams:
        ctx.report("没有发现 Meterpreter TLV 流量", "warn")
        ctx.report("提示：Meterpreter/metsvc 会话为 length+type 的 TLV 链，"
                   "metsvc 默认端口 31337，反向连接端口不定；"
                   "已加密或非 Meterpreter 流量无法识别", "info")
        ctx.set_progress(100)
        return

    groups: dict[str, list] = {}
    for stream in streams:
        groups.setdefault(stream.stream, []).append(stream)

    sessions = 0
    packets_total = 0
    rows: list[list[str]] = []
    strings_total = 0
    for index, group in enumerate(groups.values()):
        ctx.check_cancel()
        ctx.set_progress(int(index / max(len(groups), 1) * 90))
        group_packets = []
        for stream in group:
            if stream.gaps:
                ctx.report(f"Meterpreter 流 {stream.stream} 存在 "
                           f"{stream.gaps} 处序列空洞", "warn")
            parsed = meterpreter_util.parse(stream.data, stream.frame_at)
            for packet in parsed.packets:
                group_packets.append((stream, packet))
        if not group_packets:
            continue
        sessions += 1
        first = group_packets[0][0]
        ctx.report(f"===== Meterpreter 会话 {first.stream} "
                   f"({len(group_packets)} 个 TLV 包) =====", "good")
        for stream, packet in group_packets:
            packets_total += 1
            strings_total += len(packet.strings)
            line = meterpreter_util.summary_line(packet)
            ctx.report(f"帧 {packet.frame or '-'} [{stream.direction}] {line}",
                       "info")
            rows.append([packet.frame or "-", first.stream,
                         stream.direction, packet.kind,
                         packet.command_hex,
                         " | ".join(packet.strings)[:200],
                         packet.exception[:120],
                         "; ".join(packet.unknown)[:160]])
            ctx.add_finding(
                "protocol", f"Meterpreter {packet.kind} "
                f"{meterpreter_util.summary_line(packet)}"[:200],
                frame=packet.frame,
                detail=f"流 {first.stream} {stream.direction}",
                extra={"protocol": "meterpreter", "stream": first.stream,
                       "command_id": packet.command_hex,
                       "request_id": packet.request_id})

    if not sessions:
        ctx.report("TCP 流中未解析出完整的 Meterpreter TLV 包", "warn")
        ctx.set_progress(100)
        return

    ctx.report(f"共识别 {sessions} 个 Meterpreter 会话、{packets_total} 个 "
               f"TLV 包、{strings_total} 个字符串参数", "good")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["帧", "流", "方向", "包类型", "命令ID", "字符串参数",
                     "异常", "其它TLV(hex)"])
    for row in rows[:MAX_TIMELINE_ROWS]:
        writer.writerow(row)
    ctx.write_output("meterpreter_timeline.csv", buffer.getvalue())
    ctx.report(f"命令时间线已写入 meterpreter_timeline.csv "
               f"（{min(len(rows), MAX_TIMELINE_ROWS)}/{len(rows)} 行）", "info")
    ctx.set_progress(100)
