"""ARP analysis: IP/MAC conflicts, gratuitous ARP and spoofing indicators."""
from __future__ import annotations

from collections import Counter, defaultdict

from fnet.features.common import table, tshark_rows
from fnet.features.registry import FeatureContext

FIELDS = ["frame.number", "arp.opcode", "arp.src.hw_mac",
          "arp.src.proto_ipv4", "arp.dst.hw_mac", "arp.dst.proto_ipv4"]


def analyze(ctx: FeatureContext) -> None:
    rows = tshark_rows(ctx, FIELDS, "arp", limit=100_000)
    if not rows:
        ctx.report("没有发现 ARP 流量", "warn")
        return
    table(ctx, "ARP 报文", FIELDS, rows, limit=200)

    opcodes = Counter()
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    gratuitous = []
    for row in rows:
        row += [""] * (len(FIELDS) - len(row))
        frame, opcode, src_mac, src_ip, dst_mac, dst_ip = row
        opcodes[opcode] += 1
        if src_ip and src_mac:
            ip_to_macs[src_ip].add(src_mac.lower())
            mac_to_ips[src_mac.lower()].add(src_ip)
        if src_ip and dst_ip and src_ip == dst_ip:
            gratuitous.append(row)
    ctx.report("操作码统计: " + ", ".join(f"{k}={v}" for k, v in opcodes.most_common()),
               "info")

    spoofed = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    if spoofed:
        ctx.report("===== 同一 IP 对应多个 MAC（疑似 ARP 欺骗） =====", "warn")
        for ip, macs in list(spoofed.items())[:50]:
            ctx.report(f"{ip}: {', '.join(sorted(macs))}", "warn")
    multi = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if multi:
        ctx.report("===== 同一 MAC 声明多个 IP（可能是网关/扫描器） =====", "warn")
        for mac, ips in list(multi.items())[:50]:
            ctx.report(f"{mac}: {', '.join(sorted(ips)[:20])}", "warn")
    if gratuitous:
        ctx.report(f"===== 免费 ARP {len(gratuitous)} 条 =====", "warn")
        for row in gratuitous[:30]:
            ctx.report(" | ".join(row), "warn")
    if not spoofed and not multi:
        ctx.report("未发现明显的 ARP 冲突", "good")
    ctx.set_progress(100)
