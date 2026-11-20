"""Non-job actions exposed by the WebUI menus.

Each function is synchronous and returns a ``dict`` with at least ``ok`` and
``text``; the HTTP layer serialises the dict.  Long external commands accept
a cancellation event.
"""
from __future__ import annotations

import base64
import gzip
import ipaddress
import os
import re
import subprocess
import threading
import zlib
from collections import Counter
from pathlib import Path

from fnet.logger import logger
from fnet.paths import CACHE_DIR
from fnet.tools.runner import ToolBox, run
from fnet.utils import codec, logfile
from fnet.utils.pcap import conversations


def _result(ok: bool, text: str, **extra) -> dict:
    data = {"ok": ok, "text": text}
    data.update(extra)
    return data


def _safe_outdir(name: str) -> Path:
    path = CACHE_DIR / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def _tshark(toolbox: ToolBox, cancel=None):
    tshark = toolbox.tshark()
    if tshark is None:
        return None, _result(False, "未找到 tshark，请先安装 Wireshark/tshark")
    return tshark, None


# ---------------------------------------------------------------------------
# File menu
# ---------------------------------------------------------------------------
def export_all_objects(pcap: str, toolbox: ToolBox,
                       cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox)
    if error:
        return error
    outdir = _safe_outdir("objects")
    lines = []
    total = 0
    for protocol in ("http", "smb", "ftp", "tftp", "imf", "dicom"):
        target = outdir / protocol
        code, out = tshark.export_objects(pcap, protocol, target, cancel=cancel)
        files = [p for p in target.rglob("*") if p.is_file()]
        total += len(files)
        status = "OK" if code == 0 else f"跳过({code})"
        lines.append(f"{protocol:6s} {status:12s} {len(files):4d} 个文件 -> {target}")
        if code != 0 and out.strip():
            lines.append("  " + out.strip().splitlines()[-1][:200])
    return _result(True, "\n".join(lines), output_dir=str(outdir), count=total)


def carve_files(pcap: str, toolbox: ToolBox,
                cancel: threading.Event | None = None) -> dict:
    outdir = _safe_outdir("carved")
    if toolbox.path("foremost"):
        code, out = toolbox.run_tool("foremost", ["-i", pcap, "-o", str(outdir)],
                                     cancel=cancel)
        if code == 0:
            return _result(True, out or f"文件已分离到 {outdir}",
                           output_dir=str(outdir))
    if toolbox.path("binwalk"):
        code, out = toolbox.run_tool("binwalk", ["-e", "--directory", str(outdir), pcap],
                                     cancel=cancel)
        if code == 0:
            return _result(True, out or f"文件已分离到 {outdir}",
                           output_dir=str(outdir))
    # Always available fallback: tshark object export.
    logger.warn("未找到 foremost/binwalk，改用 tshark 导出对象")
    data = export_all_objects(pcap, toolbox, cancel)
    data["text"] = "未找到 foremost/binwalk，已使用 tshark 导出对象\n" + data["text"]
    return data


def repair_pcap(pcap: str, toolbox: ToolBox,
                cancel: threading.Event | None = None) -> dict:
    if not toolbox.path("pcapfix"):
        return _result(False, "未找到 pcapfix（Debian/Ubuntu: apt install pcapfix）")
    outdir = _safe_outdir("repaired")
    outfile = outdir / (Path(pcap).stem + "_fixed.pcap")
    code, out = toolbox.run_tool("pcapfix", ["-o", str(outfile), pcap],
                                 cancel=cancel)
    if code == 0 and outfile.exists():
        return _result(True, out or f"修复完成: {outfile}", output=str(outfile))
    return _result(False, out or f"pcapfix 退出码 {code}")


def etl_to_pcapng(source: str, toolbox: ToolBox,
                  cancel: threading.Event | None = None) -> dict:
    if not toolbox.path("etl2pcapng"):
        return _result(False, "未找到 etl2pcapng（https://github.com/nettrace/etl2pcapng）")
    outdir = _safe_outdir("converted")
    outfile = outdir / (Path(source).stem + ".pcapng")
    code, out = toolbox.run_tool("etl2pcapng", [source, str(outfile)],
                                 cancel=cancel)
    if code == 0 and outfile.exists():
        return _result(True, out or f"转换完成: {outfile}", output=str(outfile))
    return _result(False, out or f"etl2pcapng 退出码 {code}")


# ---------------------------------------------------------------------------
# Packet navigation (log frame links)
# ---------------------------------------------------------------------------
FRAME_FIELDS = ["frame.number", "frame.time_relative", "frame.len",
                "_ws.col.protocol", "_ws.col.info"]
MAX_PACKET_DETAIL = 60_000


def clamp_frame(value) -> int | None:
    """Accept ``frame``/``i`` style text, reject anything unsafe."""
    try:
        frame = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return frame if 1 <= frame <= 1_000_000_000 else None


def clamp_context(value, default: int = 2, maximum: int = 20) -> int:
    try:
        context = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(0, min(context, maximum))


def frame_range(frame: int, context: int = 2) -> tuple[int, int]:
    return max(1, frame - context), frame + context


def _frame_rows(tshark, pcap: str, lo: int, hi: int, cancel=None) -> list[dict]:
    rows = tshark.fields(
        pcap, FRAME_FIELDS,
        f"frame.number >= {lo} && frame.number <= {hi}", cancel=cancel)
    items = []
    for row in rows:
        row += [""] * (len(FRAME_FIELDS) - len(row))
        items.append({
            "frame": row[0],
            "time": row[1],
            "length": row[2],
            "protocol": row[3],
            "info": row[4],
        })
    return items


def frame_detail(pcap: str, frame, toolbox: ToolBox, context=2,
                 cancel: threading.Event | None = None) -> dict:
    """One packet plus its surrounding frames, used by the log frame links."""
    number = clamp_frame(frame)
    if number is None:
        return _result(False, "帧号无效")
    context = clamp_context(context)
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    lo, hi = frame_range(number, context)
    neighbors = _frame_rows(tshark, pcap, lo, hi, cancel)
    packet = next((item for item in neighbors
                   if item["frame"] == str(number)), None)
    if packet is None:
        return _result(False, f"抓包中没有帧 {number}")
    code, detail = run(
        [tshark.path, "-r", pcap, "-Y", f"frame.number == {number}", "-V"],
        timeout=120, echo=False, cancel=cancel)
    detail = detail.strip()
    if code != 0 and not detail:
        detail = f"tshark 退出码 {code}"
    if len(detail) > MAX_PACKET_DETAIL:
        detail = detail[:MAX_PACKET_DETAIL] + "\n… （解码输出过长，已截断）"
    return _result(
        True, f"帧 {number}: {packet['protocol']} {packet['info']}",
        packet=packet, neighbors=neighbors, detail=detail,
        range=[lo, hi], frame=number,
        tools={"wireshark": bool(toolbox.path("wireshark"))})


def extract_frames(pcap: str, frame, toolbox: ToolBox, output: str | Path,
                   context=2, cancel: threading.Event | None = None) -> dict:
    """Write a small pcapng clip around ``frame`` for external inspection."""
    number = clamp_frame(frame)
    if number is None:
        return _result(False, "帧号无效")
    context = clamp_context(context)
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    lo, hi = frame_range(number, context)
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    code, text = run(
        [tshark.path, "-r", str(pcap),
         "-Y", f"frame.number >= {lo} && frame.number <= {hi}",
         "-w", str(target)], timeout=120, echo=False, cancel=cancel)
    if code != 0 or not target.is_file() or target.stat().st_size == 0:
        return _result(False, text.strip() or f"tshark 导出片段失败（退出码 {code}）")
    return _result(True, f"已导出帧 {lo}-{hi} 到 {target.name}",
                   path=str(target), range=[lo, hi],
                   size=target.stat().st_size)


def open_wireshark(pcap: str, frame, toolbox: ToolBox) -> dict:
    """Launch the desktop Wireshark filtered to one frame (local WebUI only)."""
    number = clamp_frame(frame)
    if number is None:
        return _result(False, "帧号无效")
    if not Path(pcap).is_file():
        return _result(False, f"抓包文件不存在: {pcap}")
    path = toolbox.path("wireshark")
    if not path:
        return _result(False, "未找到 Wireshark，请在设置中指定路径或安装 wireshark")
    try:
        subprocess.Popen(
            [path, "-r", str(pcap), "-Y", f"frame.number == {number}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix")
    except OSError as exc:
        return _result(False, f"无法启动 Wireshark: {exc}")
    logger.info(f"已请求 Wireshark 打开帧 {number}")
    return _result(True, f"已在 Wireshark 中打开帧 {number}")


# ---------------------------------------------------------------------------
# Statistics menu
# ---------------------------------------------------------------------------
def port_scan(pcap: str, toolbox: ToolBox,
              cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    rows = tshark.fields(
        pcap, ["ip.dst", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack"],
        "tcp.flags.syn == 1 && tcp.flags.ack == 0", cancel=cancel)
    seen: dict[tuple[str, str], int] = Counter()
    for row in rows:
        row += [""] * (4 - len(row))
        if row[0] and row[1]:
            seen[(row[0], row[1])] += 1
    if not seen:
        return _result(False, "没有发现 TCP SYN 扫描流量")
    lines = [f"{'目标地址':<40s} {'端口':>6s} {'SYN 次数':>8s}"]
    for (host, port), count in sorted(seen.items(),
                                      key=lambda kv: (kv[0][0], int(kv[0][1]) if kv[0][1].isdigit() else 0)):
        lines.append(f"{host:<40s} {port:>6s} {count:>8d}")
    return _result(True, "\n".join(lines), count=len(seen))


def http_uri_stats(pcap: str, toolbox: ToolBox,
                   cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    rows = tshark.fields(pcap, ["http.request.uri"], "http.request",
                         cancel=cancel)
    counter = Counter(row[0] for row in rows if row and row[0])
    if not counter:
        return _result(False, "没有发现 HTTP 请求")
    lines = [f"{count:6d}  {uri}" for uri, count in counter.most_common(500)]
    return _result(True, "\n".join(lines), count=len(counter))


def ip_conversations(pcap: str, toolbox: ToolBox,
                     cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    text = conversations(tshark.path, pcap, "ip")
    if not text.strip():
        return _result(False, "没有发现 IP 会话")
    return _result(True, text)


def protocol_hierarchy(pcap: str, toolbox: ToolBox,
                       cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    from fnet.tools.runner import run

    code, out = run([tshark.path, "-r", pcap, "-q", "-z", "io,phs"],
                    cancel=cancel, echo=False)
    if code != 0:
        return _result(False, out or "协议分层统计失败")
    return _result(True, out)


def bucket_timeline(rows, buckets: int = 60) -> tuple[list[dict], float, float]:
    """Aggregate ``(time, length)`` samples into fixed-width buckets.

    Kept free of tshark so the chart maths can be unit tested.
    """
    samples: list[tuple[float, int]] = []
    for row in rows or []:
        row = list(row) + ["", ""]
        try:
            stamp = float(str(row[0]).strip())
        except (TypeError, ValueError):
            continue
        length = 0
        try:
            length = int(float(str(row[1]).strip()))
        except (TypeError, ValueError):
            pass
        samples.append((stamp, max(0, length)))
    if not samples:
        return [], 0.0, 0.0
    try:
        count = max(1, min(int(buckets), 240))
    except (TypeError, ValueError):
        count = 60
    low = min(stamp for stamp, _ in samples)
    high = max(stamp for stamp, _ in samples)
    width = max((high - low) / count, 1e-6)
    points = [{"time": low + index * width, "frames": 0, "bytes": 0}
              for index in range(count)]
    for stamp, length in samples:
        index = min(int((stamp - low) / width), count - 1)
        points[index]["frames"] += 1
        points[index]["bytes"] += length
    return points, low, high


TOPOLOGY_FIELDS = ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
                   "udp.srcport", "udp.dstport", "frame.len",
                   "_ws.col.protocol", "frame.number"]


def _endpoint(ip: str, port: str) -> str:
    return f"{ip}:{port}" if ip and port else (ip or "?")


def session_topology(pcap: str, toolbox: ToolBox,
                     cancel: threading.Event | None = None) -> dict:
    """Aggregate IP endpoints and their conversations for the topology view.

    Kept independent of the chart maths so the node/edge layout can be tested.
    """
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    rows = tshark.fields(pcap, TOPOLOGY_FIELDS, "ip", cancel=cancel)
    edges: dict[tuple[str, str], dict] = {}
    nodes: dict[str, dict] = {}
    for raw in rows:
        row = list(raw) + [""] * (len(TOPOLOGY_FIELDS) - len(raw))
        src, dst = row[0], row[1]
        if not src or not dst:
            continue
        sport = row[2] or row[4]
        dport = row[3] or row[5]
        try:
            length = int(float(row[6] or 0))
        except (TypeError, ValueError):
            length = 0
        protocol = (row[7] or "").split(",")[-1].strip() or "IP"
        frame = row[8]
        left, right = _endpoint(src, sport), _endpoint(dst, dport)
        first, second = sorted((left, right))
        key = (first, second)
        edge = edges.get(key)
        if edge is None:
            edge = edges[key] = {
                "source": left, "target": right, "frames": 0, "bytes": 0,
                "protocols": Counter(), "first_frame": frame,
                "last_frame": frame, "frames_list": [],
            }
        edge["frames"] += 1
        edge["bytes"] += length
        edge["protocols"][protocol] += 1
        edge["last_frame"] = frame
        if len(edge["frames_list"]) < 12:
            edge["frames_list"].append(frame)
        for endpoint, ip, port in ((left, src, sport), (right, dst, dport)):
            node = nodes.get(endpoint)
            if node is None:
                node = nodes[endpoint] = {
                    "id": endpoint, "ip": ip, "port": port,
                    "frames": 0, "bytes": 0, "protocols": Counter(),
                    "peers": set(),
                }
            node["frames"] += 1
            node["bytes"] += length
            node["protocols"][protocol] += 1
            node["peers"].add(right if endpoint == left else left)

    if not edges:
        return _result(False, "没有可用于拓扑的 IP 会话")
    ranked = sorted(nodes.values(), key=lambda item: item["bytes"],
                    reverse=True)[:60]
    kept = {item["id"] for item in ranked}
    selected = [edge for key, edge in edges.items()
                if key[0] in kept and key[1] in kept]
    selected.sort(key=lambda item: item["bytes"], reverse=True)
    selected = selected[:200]
    total_bytes = sum(item["bytes"] for item in edges.values())
    node_items = [{
        "id": item["id"], "ip": item["ip"], "port": item["port"],
        "frames": item["frames"], "bytes": item["bytes"],
        "peers": len(item["peers"]),
        "protocols": [name for name, _count in
                      item["protocols"].most_common(4)],
    } for item in ranked]
    edge_items = [{
        "source": item["source"], "target": item["target"],
        "frames": item["frames"], "bytes": item["bytes"],
        "protocol": item["protocols"].most_common(1)[0][0],
        "protocols": [name for name, _count in
                      item["protocols"].most_common(4)],
        "first_frame": item["first_frame"], "last_frame": item["last_frame"],
        "frames_list": item["frames_list"],
    } for item in selected]
    text = (f"{len(node_items)} 个节点 · {len(edge_items)} 条会话 · "
            f"{total_bytes} 字节 · {len(rows)} 帧")
    return _result(True, text, nodes=node_items, edges=edge_items,
                   total_bytes=total_bytes, total_frames=len(rows),
                   max_bytes=max((item["bytes"] for item in node_items),
                                 default=0))


def protocol_detail(pcap: str, toolbox: ToolBox, protocol: str,
                    limit: int = 300,
                    cancel: threading.Event | None = None) -> dict:
    """Packet list for one protocol label, used by the chart drilldown."""
    name = str(protocol or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", name):
        return _result(False, "协议名称无效")
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    known = {"http", "tls", "dns", "tcp", "udp", "quic", "smb2", "ldap",
             "websocket", "http2", "ftp", "smtp", "telnet", "icmp", "arp",
             "mqtt", "modbus", "s7comm", "goose", "gtp", "ssh", "rdp"}
    key = name.lower().replace("/", "")
    display = key if key in known else f'frame.protocols contains "{key}"'
    try:
        count = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        count = 300
    rows = tshark.fields(
        pcap, ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
               "_ws.col.protocol", "_ws.col.info", "frame.len"],
        display, cancel=cancel)[:count]
    packets = []
    for raw in rows:
        row = list(raw) + [""] * (7 - len(raw))
        packets.append({"frame": row[0], "time": row[1], "src": row[2],
                        "dst": row[3], "protocol": row[4], "info": row[5],
                        "length": row[6]})
    if not packets:
        return _result(False, f"没有找到 {name} 数据包")
    return _result(True, f"{name}: {len(packets)} 个数据包",
                   protocol=name, packets=packets, filter=display)


def traffic_timeline(pcap: str, toolbox: ToolBox, buckets=60,
                     cancel: threading.Event | None = None) -> dict:
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    rows = tshark.fields(pcap, ["frame.time_relative", "frame.len"], "",
                         cancel=cancel)
    points, low, high = bucket_timeline(rows, buckets)
    if not points:
        return _result(False, "没有可用于时间线的数据包")
    total_frames = sum(point["frames"] for point in points)
    total_bytes = sum(point["bytes"] for point in points)
    duration = max(0.0, high - low)
    text = (f"{total_frames} 帧 · {total_bytes} 字节 · 时间跨度 {duration:.3f}s "
            f"· {len(points)} 个时间桶")
    return _result(True, text, points=points, duration=duration,
                   total_frames=total_frames, total_bytes=total_bytes,
                   start=low, end=high, buckets=len(points))


def timeline_packets(pcap: str, toolbox: ToolBox, start, end,
                     limit: int = 200,
                     cancel: threading.Event | None = None) -> dict:
    """Packets inside a timeline bucket (click-to-drilldown)."""
    try:
        low, high = float(start), float(end)
    except (TypeError, ValueError):
        return _result(False, "时间范围无效")
    if not (0 <= low <= high < 1e9):
        return _result(False, "时间范围无效")
    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    try:
        count = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        count = 200
    display = (f"frame.time_relative >= {low:.6f} && "
               f"frame.time_relative <= {high:.6f}")
    rows = tshark.fields(
        pcap, ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
               "_ws.col.protocol", "_ws.col.info", "frame.len"],
        display, cancel=cancel)[:count]
    packets = []
    for raw in rows:
        row = list(raw) + [""] * (7 - len(raw))
        packets.append({"frame": row[0], "time": row[1], "src": row[2],
                        "dst": row[3], "protocol": row[4], "info": row[5],
                        "length": row[6]})
    if not packets:
        return _result(False, "该时间范围内没有数据包")
    return _result(True, f"{low:.2f}s–{high:.2f}s: {len(packets)} 个数据包",
                   packets=packets, start=low, end=high)


# ---------------------------------------------------------------------------
# Log stats: the 统计图表 page also works on plain-text log inputs.
# The shapes mirror the capture-side results so the WebUI renders both with
# the same code; ``kind="log"`` marks a log-derived payload (additive and
# backward compatible).  ``bytes`` is always 0 for logs: there is no packet
# size, so the UI falls back to counting events ("条").
# ---------------------------------------------------------------------------
_LOG_BUCKET_WIDTHS = (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 10800,
                      21600, 43200, 86400, 604800)

#: Entity ranking keys: user-ish first, then client IP-ish.
_LOG_ENTITY_KEYS = ("client_id", "user", "client_ip", "src_ip", "ip")

#: Peer keys for the log topology: a server/host/program-ish identifier.
_LOG_PEER_KEYS = ("server", "server_ip", "host", "dst_ip", "peer", "target",
                  "node", "program", "source")


def _log_parsed(path: str) -> tuple[logfile.LogFile | None, str]:
    """Parse a text-log input; ``(None, reason)`` when it cannot be read.

    Uses :func:`fnet.utils.logfile.parse_path`, which caps the file at
    ``MAX_RECORDS`` lines, so every stats sub inherits that guard.
    """
    try:
        parsed = logfile.parse_path(path)
    except Exception as exc:  # noqa: BLE001 - never raise into the HTTP layer
        logger.warn(f"日志统计解析失败 {path}: {exc}")
        return None, f"日志解析失败：{exc}"
    return parsed, ""


def _log_entity(record: logfile.LogRecord) -> str:
    """Best entity for one record: user/client id first, then an IP."""
    value = record.value(*_LOG_ENTITY_KEYS)
    if value:
        return value
    return record.ips[0] if record.ips else ""


def _log_peer(record: logfile.LogRecord) -> str:
    value = record.value(*_LOG_PEER_KEYS)
    return value if value and value != _log_entity(record) else ""


def _looks_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def log_timeline_points(log: logfile.LogFile,
                        buckets: int = 60) -> list[dict]:
    """Event counts per adaptive time bucket; pure and unit-testable.

    Bucket widths follow the same strategy as ``fnet.features.logs._buckets``
    (a ladder of fixed widths) and fall back to an even split so the point
    count always stays within ``max(buckets, 1) + 1``.
    """
    stamped = [record.epoch for record in log.records
               if record.epoch is not None]
    if len(stamped) < 2:
        return []
    try:
        count = max(1, min(int(buckets), 240))
    except (TypeError, ValueError):
        count = 60
    low, high = min(stamped), max(stamped)
    span = max(0.0, high - low)
    width = next((item for item in _LOG_BUCKET_WIDTHS if span / item <= count),
                 0.0)
    if width <= 0:
        width = max(span / count, 1e-6)
    counts: Counter = Counter()
    for epoch in stamped:
        counts[int((epoch - low) // width)] += 1
    return [{"time": low + index * width, "frames": counts[index], "bytes": 0}
            for index in range(int((high - low) // width) + 1)]


def log_timeline(path: str, buckets=60,
                 cancel: threading.Event | None = None) -> dict:
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    points = log_timeline_points(log, buckets)
    if not points:
        return _result(False, "日志任务：日志中没有可解析的时间戳，无法生成时间线",
                       kind="log")
    total = sum(point["frames"] for point in points)
    low, high = points[0]["time"], points[-1]["time"]
    duration = max(0.0, high - low)
    text = (f"日志时间线：{total} 条日志 · 时间跨度 {duration:.3f}s · "
            f"{len(points)} 个时间桶")
    return _result(True, text, points=points, duration=duration,
                   total_frames=total, total_bytes=0, start=low, end=high,
                   buckets=len(points), kind="log")


def log_level_items(log: logfile.LogFile) -> list[dict]:
    """Log-level "protocol hierarchy" items, sorted by count."""
    items = [{"label": level, "frames": count, "bytes": 0}
             for level, count in log.levels().items()]
    items.sort(key=lambda item: (-item["frames"], item["label"]))
    return items


def log_level_hierarchy(path: str,
                        cancel: threading.Event | None = None) -> dict:
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    items = log_level_items(log)
    if not items:
        return _result(False, "日志任务：日志中没有可解析的记录", kind="log")
    breakdown = " · ".join(f"{item['label']} {item['frames']}"
                           for item in items)
    text = f"日志级别分层：{breakdown}"
    return _result(True, text, items=items, kind="log")


def log_entity_items(log: logfile.LogFile, limit: int = 20) -> list[dict]:
    """Top entities (client_id/user first, then IPs) as bar-chart items."""
    counts: Counter = Counter()
    for record in log.records:
        entity = _log_entity(record)
        if entity:
            counts[entity] += 1
    try:
        capped = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        capped = 20
    return [{"label": name, "frames": count, "bytes": 0}
            for name, count in counts.most_common(capped)]


def log_top_entities(path: str, limit: int = 20,
                     cancel: threading.Event | None = None) -> dict:
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    items = log_entity_items(log, limit)
    if not items:
        return _result(False,
                       "日志任务：日志中没有可识别的实体"
                       "（client_id/user/IP）",
                       kind="log")
    total = sum(item["frames"] for item in items)
    text = f"Top 实体：{len(items)} 个实体 · 共 {total} 条日志"
    return _result(True, text, items=items, kind="log")


#: Cap on entity rows returned to the WebUI; the full table stays in the
#: job's ``log_entities.csv`` artifact.
LOG_ENTITY_STATS_LIMIT = 50


def log_entity_stats(path: str, dimension: str, limit: int = 50,
                     success_regex: str = "", subnet_prefix=None,
                     fail_regex: str = "",
                     cancel: threading.Event | None = None) -> dict:
    """Full per-entity statistics for one dimension (「实体统计」card).

    Reuses :func:`fnet.features.logs.entity_stats` so the WebUI table and
    the feature report share one implementation and can never drift.
    ``dimension`` must be one of the dimensions that actually occur in this
    log (:func:`fnet.features.logs._entity_dimensions`); anything else
    answers ``ok:false`` with the available list.  ``success_regex`` /
    ``fail_regex`` / ``subnet_prefix`` mirror the feature params and fall
    back gracefully on invalid input (default failure rules, "non-failing
    counts as success", /24 with the 8–32 range and IPv6 always /64).
    Never raises: parse failures and empty dimensions return ``ok:false``
    with a reason.
    """
    from fnet.features import logs as log_features

    kind = {"kind": "log"}
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, dimension=str(dimension or ""),
                       dimensions=[], items=[], total=0, **kind)
    if not log.records:
        return _result(False, "日志中没有可解析的记录",
                       dimension=str(dimension or ""), dimensions=[],
                       items=[], total=0, **kind)
    dimensions = log_features._entity_dimensions(log)
    name = str(dimension or "").strip()
    if name not in dimensions:
        available = "、".join(dimensions) if dimensions else "（无）"
        shown_name = name or "（空）"
        return _result(
            False, f"未知实体维度 {shown_name}；可用维度: {available}",
            dimension=name, dimensions=dimensions, items=[], total=0, **kind)
    fail_re = log_features.DEFAULT_FAIL_RE
    success_re = None
    notes: list[str] = []
    raw_fail = str(fail_regex or "").strip()
    if raw_fail:
        try:
            fail_re = re.compile(raw_fail, re.IGNORECASE)
        except re.error as exc:
            notes.append(f"fail_regex 无效（{exc}），使用默认失败规则")
    raw_success = str(success_regex or "").strip()
    if raw_success:
        try:
            success_re = re.compile(raw_success, re.IGNORECASE)
        except re.error as exc:
            notes.append(f"success_regex 无效（{exc}），"
                         "回退为“未命中失败关键字即成功”口径")
    prefix = log_features.DEFAULT_SUBNET_PREFIX
    if subnet_prefix not in ("", None):
        try:
            value = int(str(subnet_prefix).strip())
        except (TypeError, ValueError):
            value = 0
        if 8 <= value <= 32:
            prefix = value
        else:
            notes.append(f"subnet_prefix 超出范围 8-32（{value}），回退 /24")
    try:
        capped = max(1, min(int(limit), LOG_ENTITY_STATS_LIMIT))
    except (TypeError, ValueError):
        capped = LOG_ENTITY_STATS_LIMIT
    try:
        items = log_features.entity_stats(
            log, name, fail_re=fail_re, success_re=success_re,
            subnet_prefix=prefix)
    except Exception as exc:  # noqa: BLE001 - never raise into the HTTP layer
        logger.warn(f"实体统计失败 {path}/{name}: {exc}")
        return _result(False, f"实体统计失败：{exc}", dimension=name,
                       dimensions=dimensions, items=[], total=0, **kind)
    if not items:
        return _result(False, f"维度 {name} 没有统计到任何值", dimension=name,
                       dimensions=dimensions, items=[], total=0, **kind)
    shown = items[:capped]
    rule = ("命中 success_regex 的记录计一次成功" if success_re is not None
            else "未命中失败关键字（默认规则）的记录视为成功")
    text = (f"实体统计（{name}）：共 {len(items)} 个值 · 成功口径：{rule} · "
            f"网段前缀 /{prefix}（IPv6 固定 /64）")
    if notes:
        text += "；" + "；".join(notes)
    return _result(True, text, dimension=name, dimensions=dimensions,
                   items=shown, total=len(items),
                   truncated=len(items) > capped, subnet_prefix=prefix,
                   success_rule=rule, **kind)


def log_topology_base(log: logfile.LogFile) -> dict:
    """Client-IP → peer (server/host/program) graph for one parsed log.

    Returns ``{"nodes": [...], "edges": [...], "total_frames": n}``; empty
    lists when the log never pairs a client IP with a peer identifier.
    """
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}
    for record in log.records:
        client = _log_entity(record)
        peer = _log_peer(record)
        if not client or not peer or client == peer:
            continue
        key = (client, peer)
        edge = edges.get(key)
        if edge is None:
            edge = edges[key] = {"source": client, "target": peer,
                                 "frames": 0, "first_line": record.line,
                                 "last_line": record.line}
        edge["frames"] += 1
        edge["last_line"] = record.line
        for name, other in ((client, peer), (peer, client)):
            node = nodes.get(name)
            if node is None:
                node = nodes[name] = {"frames": 0, "peers": set()}
            node["frames"] += 1
            node["peers"].add(other)
    ranked = sorted(nodes.items(), key=lambda kv: -kv[1]["frames"])[:60]
    kept = {name for name, _info in ranked}
    selected = sorted(edges.values(), key=lambda item: -item["frames"])[:200]
    node_items = [{
        "id": name, "label": name,
        "ip": name if _looks_ip(name) else "", "port": "",
        "frames": info["frames"], "bytes": 0,
        "peers": len(info["peers"]), "protocols": [],
    } for name, info in ranked]
    edge_items = [{
        "source": item["source"], "target": item["target"],
        "frames": item["frames"], "bytes": 0, "protocol": "日志",
        "protocols": ["日志"], "first_frame": str(item["first_line"]),
        "last_frame": str(item["last_line"]), "frames_list": [],
    } for item in selected if item["source"] in kept
        and item["target"] in kept]
    return {"nodes": node_items, "edges": edge_items,
            "total_frames": sum(item["frames"] for item in edges.values()),
            "max_frames": max((item["frames"] for item in node_items),
                              default=0)}


def log_topology(path: str,
                 cancel: threading.Event | None = None) -> dict:
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    base = log_topology_base(log)
    if not base["nodes"]:
        return _result(False,
                       "日志任务：日志中无法同时得到客户端 IP 与对端标识"
                       "（server/host/program），无法生成拓扑",
                       kind="log")
    text = (f"{len(base['nodes'])} 个节点 · {len(base['edges'])} 条对端关系 · "
            f"{base['total_frames']} 条日志")
    return _result(True, text, nodes=base["nodes"], edges=base["edges"],
                   total_bytes=0, total_frames=base["total_frames"],
                   max_bytes=0, max_frames=base["max_frames"], kind="log")


def log_timeline_packets(path: str, start, end, limit: int = 200,
                         cancel: threading.Event | None = None) -> dict:
    """Log records inside one timeline bucket (click-to-drilldown)."""
    try:
        low, high = float(start), float(end)
    except (TypeError, ValueError):
        return _result(False, "时间范围无效", kind="log")
    if not (-1e12 <= low <= high < 1e12):
        return _result(False, "时间范围无效", kind="log")
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    try:
        count = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        count = 200
    packets = []
    for record in log.records:
        if record.epoch is None or not (low <= record.epoch <= high):
            continue
        client = _log_entity(record)
        packets.append({
            "frame": record.line, "time": record.time,
            "src": client, "dst": _log_peer(record),
            "protocol": record.level or "info",
            "info": (record.message or record.raw)[:200],
            "length": 0,
        })
        if len(packets) >= count:
            break
    if not packets:
        return _result(False, "该时间范围内没有日志记录", kind="log")
    return _result(True, f"{low:.2f}s–{high:.2f}s: {len(packets)} 条日志",
                   packets=packets, start=low, end=high, kind="log")


def log_protocol_detail(path: str, protocol: str, limit: int = 300,
                        cancel: threading.Event | None = None) -> dict:
    """Log records matching one level/source label (hierarchy drilldown)."""
    name = str(protocol or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", name):
        return _result(False, "日志级别/来源名称无效", kind="log")
    log, error = _log_parsed(path)
    if log is None:
        return _result(False, error, kind="log")
    try:
        count = max(1, min(int(limit), 1000))
    except (TypeError, ValueError):
        count = 300
    packets = []
    for record in log.records:
        level = record.level or "info"
        if name.lower() not in (level.lower(), (record.source or "").lower()):
            continue
        client = _log_entity(record)
        packets.append({
            "frame": record.line, "time": record.time,
            "src": client, "dst": _log_peer(record),
            "protocol": level,
            "info": (record.message or record.raw)[:200],
            "length": 0,
        })
        if len(packets) >= count:
            break
    if not packets:
        return _result(False, f"没有找到 {name} 相关日志记录", kind="log")
    return _result(True, f"{name}: {len(packets)} 条日志记录",
                   protocol=name, packets=packets, filter=name, kind="log")


# ---------------------------------------------------------------------------
# Text tools
# ---------------------------------------------------------------------------
def _readable(value: str, threshold: float = 0.75) -> bool:
    if not value:
        return False
    good = sum(ch in codec.PRINTABLE or ch.isprintable() for ch in value)
    return good / len(value) >= threshold


def decode_text(text: str) -> dict:
    candidates: list[dict] = []
    seen: set[str] = set()

    def add(label: str, value: str, threshold: float = 0.75) -> None:
        if not value or value == text or value in seen:
            return
        if not _readable(value, threshold) and not codec.find_flags(value):
            return
        seen.add(value)
        candidates.append({"label": label, "value": value[:8000]})

    add("Base64", codec.b64decode_text(text))
    add("Base32", codec.b32decode_text(text))
    add("Hex", codec.hexdecode_text(text))
    add("URL", codec.urldecode_text(text))
    add("ROT13", codec.rot13(text))
    add("GBK", codec.gbk_text(text))

    raw = None
    try:
        cleaned = re.sub(r"\s+", "", text)
        raw = base64.b64decode(cleaned + "=" * (-len(cleaned) % 4))
    except Exception:  # noqa: BLE001
        raw = None
    if raw:
        for label, func in (("Gzip", gzip.decompress), ("Zlib", zlib.decompress)):
            try:
                add(label, func(raw).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                pass
        for key, out in codec.single_byte_xor_candidates(raw, limit=3):
            decoded = out.decode("latin-1", "replace")
            if sum(ch.isalpha() for ch in decoded) >= 4:
                add(f"XOR 0x{key:02x}", decoded, threshold=0.95)

    for index, item in enumerate(codec.decode_chain(text, rounds=3)):
        if codec.find_flags(item) or (item.isascii() and item.isprintable()
                                      and any(ch.isalpha() for ch in item)):
            add(f"解码链 #{index + 1}", item)
    if not candidates:
        candidates.append({"label": "原始文本（未识别编码）", "value": text[:8000]})

    flags = sorted(set(codec.find_flags(text)) |
                   {f for c in candidates for f in codec.find_flags(c["value"])})
    return _result(True, "\n".join(f"[{c['label']}]\n{c['value']}" for c in candidates),
                   candidates=candidates, flags=flags)


# ---------------------------------------------------------------------------
# Job topology + attack replay snippets (tulip / pkappa2 style)
# ---------------------------------------------------------------------------
def network_topology(pcap: str, toolbox: ToolBox,
                     cancel: threading.Event | None = None) -> dict:
    """Compact endpoint graph for one capture, reshaped for ``/api/topology``.

    Reuses :func:`session_topology` so both the chart view and this API stay
    consistent; nodes carry ``{id,label,protocols,count}`` and links
    ``{source,target,protocol,frames}``.  Text-log inputs are graphed from
    :func:`log_topology` instead (client IP -> server/host/program).
    """
    if logfile.is_log_input(pcap):
        base = log_topology(pcap)
    else:
        base = session_topology(pcap, toolbox, cancel)
    if not base.get("ok"):
        return base
    nodes = [{
        "id": item["id"],
        "label": (str(item.get("label") or item["id"])
                  if item.get("label") else
                  (f"{item['ip']}:{item['port']}"
                   if item.get("port") else str(item.get("ip") or item["id"]))),
        "protocols": item.get("protocols") or [],
        "count": item.get("frames", 0),
        "bytes": item.get("bytes", 0),
    } for item in base.get("nodes") or []]
    links = [{
        "source": item["source"], "target": item["target"],
        "protocol": item.get("protocol") or "IP",
        "protocols": item.get("protocols") or [],
        "frames": item.get("frames", 0),
        "bytes": item.get("bytes", 0),
    } for item in base.get("edges") or []]
    return _result(True, base.get("text") or "", nodes=nodes, links=links,
                   total_bytes=base.get("total_bytes"),
                   total_frames=base.get("total_frames"))


REPLAY_METHODS = ("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS",
                  "PATCH", "CONNECT", "TRACE")
REPLAY_MAX_SPANS = 64
_SENSITIVE_HINT = ("Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization")


def _looks_sensitive(headers, body: bytes) -> bool:
    """True when a replayed request carries credentials worth a reminder."""
    for name, value in headers or []:
        if name.lower() in ("authorization", "cookie", "proxy-authorization"):
            return True
        if any(marker in value for marker in ("password", "passwd", "pwd=")):
            return True
    low = body[:8192].lower()
    return (b"password" in low or b"passwd" in low or b"pwd=" in low
            or b"pass=" in low)


def _parse_http_requests(data: bytes) -> list[dict]:
    """Split one client direction into HTTP requests (best effort).

    Returns an empty list when the direction is not plain HTTP, so callers
    can fall back to a raw TCP replay.
    """
    parsed: list[dict] = []
    offset = 0
    while offset < len(data):
        head_end = data.find(b"\r\n\r\n", offset)
        if head_end < 0:
            break
        lines = data[offset:head_end].decode("iso-8859-1", "replace").split("\r\n")
        first = lines[0].split(" ")
        if len(first) < 2 or first[0].upper() not in REPLAY_METHODS:
            break
        headers = []
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip():
                headers.append((name.strip(), value.strip()))
        length = 0
        for name, value in headers:
            if name.lower() == "content-length":
                try:
                    length = max(0, int(value))
                except ValueError:
                    length = 0
        body_start = head_end + 4
        body = bytes(data[body_start:body_start + length])
        offset = min(body_start + length, len(data))
        parsed.append({"method": first[0].upper(), "path": first[1],
                       "headers": headers, "body": body})
        if len(parsed) >= 64:
            break
    return parsed


def _replay_int(value, minimum: int = 0) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= minimum else None


def _http_replay_script(stream_id: str, client, server_reqs: list[dict]) -> list[str]:
    """requests-based replay for an HTTP session (sensitive data kept)."""
    host, port = client.dst or "0.0.0.0", client.dport or "80"
    lines = [
        "#!/usr/bin/env python3",
        f"# Fnet 攻击重放脚本（requests 版）· tcp.stream {stream_id}",
        f"# 来源会话: {client.src}:{client.sport} -> {host}:{port}",
        "# 警告: 以下请求头与请求体原样保留了会话中的凭据 / Cookie / 密码等敏感数据，",
        "#       仅用于在获得授权的环境中完整重放，请勿外传。",
        "import requests",
        "",
        f"HOST = {host!r}",
        f"PORT = {int(port) if str(port).isdigit() else port!r}",
        "session = requests.Session()",
        'base = f"http://{HOST}:{PORT}"',
        "",
    ]
    for index, req in enumerate(server_reqs, 1):
        path = req["path"]
        if path.startswith(("http://", "https://")):
            url = repr(path)
        else:
            url = f"base + {path!r}"
        lines.append(f"# ---- 请求 {index} · {req['method']} {path}")
        if _looks_sensitive(req["headers"], req["body"]):
            lines.append("# 注意: 该请求包含敏感凭据（Authorization/Cookie/密码），已原样保留。")
        headers = ", ".join(f"{name!r}: {value!r}"
                            for name, value in req["headers"])
        lines.append(f"resp = session.request(")
        lines.append(f"    {req['method']!r},")
        lines.append(f"    {url},")
        lines.append(f"    headers={{{headers}}},")
        if req["body"]:
            lines.append(f"    data={req['body']!r},")
        lines.append(")")
        lines.append("print(resp.status_code, resp.url, len(resp.content))")
        lines.append("")
    return lines


def _tcp_replay_script(stream_id: str, client, spans) -> list[str]:
    """socket-based replay that re-sends the client bytes verbatim."""
    host, port = client.dst or "0.0.0.0", client.dport or "0"
    lines = [
        "#!/usr/bin/env python3",
        f"# Fnet 攻击重放脚本（socket 版）· tcp.stream {stream_id}",
        f"# 来源会话: {client.src}:{client.sport} -> {host}:{port}",
        "# 警告: 以下二进制载荷原样保留了会话中的凭据等敏感数据，",
        "#       仅用于在获得授权的环境中完整重放，请勿外传。",
        "import socket",
        "",
        f"HOST = {host!r}",
        f"PORT = {int(port) if str(port).isdigit() else port!r}",
        "",
        "# 按捕获顺序原样重放客户端发送的数据段（帧号注释便于回溯抓包）。",
        "payloads = [",
    ]
    for start, end, frame in spans:
        chunk = client.data[start:end]
        lines.append(f"    ({chunk!r},  # 帧 {frame}")
        lines.append("    ),")
    lines += [
        "]",
        "",
        "conn = socket.create_connection((HOST, PORT), timeout=10)",
        "try:",
        "    for data, frame in payloads:",
        "        conn.sendall(data)",
        "        conn.settimeout(1.0)",
        "        try:",
        "            reply = conn.recv(65536)",
        "            print(frame, '->', len(reply), 'bytes', reply[:200])",
        "        except socket.timeout:",
        "            print(frame, '-> no reply within 1s')",
        "finally:",
        "    conn.close()",
    ]
    return lines


def replay_script(pcap: str, toolbox: ToolBox, stream=None, frame=None,
                  cancel: threading.Event | None = None) -> dict:
    """Generate a runnable Python replay script for one TCP session.

    ``stream`` is a ``tcp.stream`` index; ``frame`` locates the session that
    carried that frame.  HTTP sessions yield a ``requests`` script, anything
    else a raw ``socket`` script that re-sends the client bytes verbatim
    (credentials included, flagged with reminders).
    """
    from fnet.utils.stream import STREAM_FIELDS, reassemble_rows

    tshark, error = _tshark(toolbox, cancel)
    if error:
        return error
    stream_id = _replay_int(stream, minimum=0)
    if stream_id is None and frame not in ("", None):
        number = clamp_frame(frame)
        if number is None:
            return _result(False, "帧号无效")
        rows = tshark.fields(pcap, ["frame.number", "tcp.stream"],
                             f"frame.number == {number}", cancel=cancel)
        stream_id = next((_replay_int(row[1]) for row in rows
                          if len(row) > 1 and _replay_int(row[1]) is not None),
                         None)
        if stream_id is None:
            return _result(False, f"帧 {number} 不属于任何 TCP 会话")
    if stream_id is None:
        return _result(False, "需要 stream 或 frame 参数")
    rows = tshark.fields(pcap, STREAM_FIELDS, f"tcp.stream == {stream_id}",
                         cancel=cancel)
    directions = reassemble_rows(rows)
    if not directions:
        return _result(False, f"没有找到 tcp.stream {stream_id} 的会话数据")

    def first_frame(item):
        value = item.frame_at(0)
        return int(value) if str(value).isdigit() else 1 << 30

    client = min(directions, key=first_frame)
    if not client.data:
        return _result(False, f"tcp.stream {stream_id} 没有客户端发送的数据")
    requests_out = _parse_http_requests(client.data)
    if requests_out:
        lines = _http_replay_script(str(stream_id), client, requests_out)
        kind, steps, text_kind = "http", len(requests_out), "HTTP"
    else:
        spans = list(client.spans())
        if len(spans) > REPLAY_MAX_SPANS:
            head = spans[:REPLAY_MAX_SPANS]
            last = head[-1]
            head[-1] = (last[0], len(client.data), last[2])
            spans = head
        lines = _tcp_replay_script(str(stream_id), client, spans)
        kind, steps, text_kind = "tcp", len(spans), "裸 TCP"
    return _result(
        True, f"tcp.stream {stream_id} · {text_kind} 重放脚本（{steps} 步）",
        kind=kind, script="\n".join(lines) + "\n", stream=str(stream_id),
        client=f"{client.src}:{client.sport}",
        server=f"{client.dst}:{client.dport}")
