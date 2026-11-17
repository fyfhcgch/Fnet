"""Miscellaneous CTF helpers: EV3, SCSI, IP ID covert channel."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio


def ev3(ctx: FeatureContext) -> None:
    fields = ["frame.number", "bthci_acl.data", "btatt.value",
              "btl2cap.payload", "data.data"]
    rows = tshark_rows(ctx, fields, "bthci_acl or btatt or btl2cap or btbrl2cap",
                       limit=50_000)
    if not rows:
        ctx.report("没有发现蓝牙/EV3 数据", "warn")
        return
    ctx.report(f"===== EV3 / 蓝牙数据 ({len(rows)} 条) =====", "good")
    texts: list[str] = []
    for index, row in enumerate(rows):
        if index % 200 == 0:
            ctx.check_cancel()
        row += [""] * (len(fields) - len(row))
        for raw in row[1:]:
            data = hex_to_bytes(raw)
            if not data:
                continue
            for match in re.finditer(rb"[\x20-\x7e]{3,}", data):
                text = match.group().decode("latin-1")
                if text not in texts:
                    texts.append(text)
    if texts:
        ctx.report("可打印字符串:", "good")
        for text in texts[:200]:
            ctx.report("  " + clean_cell(text, 240), "info")
        ctx.write_output("ev3_strings.txt", "\n".join(texts))
    else:
        ctx.report("未发现可打印字符串，已输出原始载荷摘要", "warn")
        table(ctx, "EV3 原始载荷", fields, rows, limit=100)


def scsi(ctx: FeatureContext) -> None:
    fields = ["frame.number", "scsi.lun", "scsi.cdb", "scsi.sbc_lba",
              "scsi.sbc.num_blocks", "scsi.sbc.ctrl", "scsi.data"]
    rows = tshark_rows(ctx, fields, "scsi", limit=50_000)
    if not rows:
        ctx.report("没有发现 SCSI 流量（需要 USB Mass Storage / iSCSI 抓包）", "warn")
        return
    table(ctx, "SCSI 命令", fields[:-1], [r[:-1] for r in rows], limit=300)
    total = 0
    for row in rows:
        row += [""] * (len(fields) - len(row))
        raw = row[6]
        if not raw:
            continue
        data = hex_to_bytes(raw)
        if not data:
            continue
        total += len(data)
        ctx.write_output(f"scsi_{row[0]}.bin", data)
        if printable_ratio(data) > 0.8:
            text = payload_text(data)
            for line in text.splitlines()[:20]:
                if line.strip():
                    ctx.report(f"[{row[0]}] {clean_cell(line, 240)}", "info")
    ctx.report(f"提取 SCSI 数据 {total} 字节", "good")


def ipid(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "ip.id", "ip.len",
              "ip.proto"]
    rows = tshark_rows(ctx, fields, "ip", limit=200_000)
    if not rows:
        ctx.report("没有发现 IP 流量", "warn")
        return
    flows: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
    for row in rows:
        row += [""] * (6 - len(row))
        try:
            frame = int(row[0])
            ipid = int(row[3], 0)
        except ValueError:
            continue
        flows[(row[1], row[2])].append((frame, ipid, int(row[4] or 0)))

    ctx.report(f"共 {len(flows)} 个 IP 流", "info")
    for (src, dst), packets in sorted(flows.items(), key=lambda kv: -len(kv[1]))[:10]:
        packets.sort()
        ids = [p[1] for p in packets]
        deltas = [b - a for a, b in zip(ids, ids[1:])]
        delta_counts = Counter(deltas)
        ctx.report(f"===== {src} -> {dst} ({len(packets)} 包) =====", "good")
        ctx.report(f"IP ID 范围 {min(ids)}..{max(ids)}，最常见的差值: "
                   + ", ".join(f"{d}({c})" for d, c in delta_counts.most_common(5)),
                   "info")
        if ids and all(value == ids[0] for value in ids):
            ctx.report("IP ID 恒定：可能存在 IP ID 隐蔽信道或空闲扫描", "warn")
        elif deltas and delta_counts.most_common(1)[0][0] == 1:
            ctx.report("IP ID 顺序递增（正常行为）", "debug")
        elif len(delta_counts) > 10:
            ctx.report("IP ID 变化异常，可能存在隐蔽信道", "warn")
        # Low byte as an ASCII covert channel.
        low_bytes = bytes(value & 0xFF for value in ids[:2000])
        printable = sum(32 <= b < 127 for b in low_bytes) / max(len(low_bytes), 1)
        if printable > 0.8:
            text = payload_text(low_bytes)
            ctx.report("低字节呈现可打印特征，提取为文本:", "warn")
            for line in text.splitlines()[:30]:
                if line.strip():
                    ctx.report("  " + clean_cell(line, 240), "warn")
            ctx.write_output(f"ipid_{src}_{dst}.txt", text)
