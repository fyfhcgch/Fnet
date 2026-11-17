"""Generic flow / protocol summaries extracted with tshark display filters."""
from __future__ import annotations

from collections import Counter

import re

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils.pcap import conversations, hex_to_bytes, payload_text, printable_ratio

MAX_ROWS = 300


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
    from fnet.utils import codec

    rows = _dump(ctx, "DNS 查询", ["frame.number", "dns.qry.name",
                                   "dns.qry.type", "dns.a", "dns.aaaa",
                                   "dns.flags.rcode"], "dns")
    names = [r[1] for r in rows if len(r) > 1 and r[1]]
    long_names = [name for name in names if len(name) > 40]
    if long_names:
        ctx.report("疑似 DNS 隐蔽隧道（长域名）:", "warn")
        for name in dict.fromkeys(long_names)[:50]:
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


def smtp(ctx: FeatureContext) -> None:
    _dump(ctx, "SMTP 命令", ["frame.number", "smtp.req.command",
                             "smtp.req.parameter", "smtp.response.code",
                             "smtp.response.parameter"], "smtp")
    _payload_rows(ctx, "SMTP 正文", "smtp", ["data.data"])
    rows = _rows(ctx, ["smtp.req.parameter"], "smtp.req.command == \"MAIL\"")
    for row in rows:
        if row[0]:
            ctx.report(f"发件人: {row[0]}", "info")


def bluetooth(ctx: FeatureContext) -> None:
    _dump(ctx, "Bluetooth HCI", ["frame.number", "bthci_cmd.opcode",
                                 "bthci_cmd.ogf", "bthci_evt.code",
                                 "bthci_acl.protocol", "bthci_acl.data"],
          "bthci_cmd or bthci_acl or bthci_evt")
    _payload_rows(ctx, "Bluetooth 数据", "bthci_acl", ["bthci_acl.data"],
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


def tcp(ctx: FeatureContext) -> None:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark", "error")
        return
    ctx.report("===== TCP 会话 =====", "good")
    for line in conversations(ctx.tshark.path, ctx.pcap, "tcp").splitlines():
        if line.strip():
            ctx.report(line, "info")
    _payload_rows(ctx, "TCP 载荷", "tcp", ["tcp.payload"], max_lines=500)


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
