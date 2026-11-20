"""Extra protocol coverage: Redis, MongoDB, PostgreSQL, LDAP, WebSocket,
HTTP/2 and SMB2.

These handlers are intentionally modelled on the existing feature handlers:
they use ``tshark_rows`` for dissection, fall back to raw TCP payloads when a
protocol is not decoded (Redis has no Wireshark dissector), and record notable
credentials / files / flags as structured findings.

Raw payload handling is protocol-aware rather than line-oriented:

* ``fnet.utils.stream`` reassembles TCP streams by sequence number, dropping
  retransmissions/overlaps and tracking gaps before any parser sees the bytes;
* ``fnet.utils.redis`` decodes RESP2/RESP3 arrays, maps, pushes and attributes,
  inline commands, AUTH/HELLO, ACL and Pub/Sub traffic;
* ``fnet.utils.postgres`` walks the startup, simple-query, extended-query,
  COPY and cancel/SSL/GSS negotiation message flows, decoding binary Bind
  parameters and MD5/SASL authentication;
* ``fnet.utils.mongodb`` decodes BSON plus OP_MSG/OP_QUERY/OP_REPLY/legacy
  CRUD ops, SCRAM-SHA-1/256 handshakes and GridFS chunk reassembly.

PostgreSQL and MongoDB therefore prefer the deep parsers and only fall back to
the tshark-field path when a capture contains no parseable messages.

None of them owns a checkbox, so they are exposed as the "protocol
credentials" and "SMB2" special actions in the WebUI and can also be selected
from the CLI by handler name::

    python3 -m fnet -C capture.pcapng --features protocols.credentials
    python3 -m fnet -C capture.pcapng --features protocols.smb2
    python3 -m fnet -C capture.pcapng --features protocols.redis,protocols.mongodb,protocols.postgres
"""
from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
import threading
from collections import Counter
from pathlib import Path

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec, protocol_detect
from fnet.utils import http2 as http2_util
from fnet.utils import ldap as ldap_util
from fnet.utils import smb as smb_util
from fnet.utils import mongodb as mongo_util
from fnet.utils import postgres as pg_util
from fnet.utils import redis as redis_util
from fnet.utils import stream as stream_util
from fnet.utils.pcap import (file_magic_bytes, hex_to_bytes, payload_text,
                             printable_ratio)

MAX_LINES = 300
MAX_RAW = 200_000
MAX_DETECT_ROWS = 40_000


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
def _rows(ctx: FeatureContext, fields: list[str], display_filter: str,
          limit: int = MAX_RAW, extra: list[str] | None = None) -> list[list[str]]:
    return tshark_rows(ctx, fields, display_filter, limit=limit, extra=extra)


# Detection scans every TCP stream once per capture; the result is cached so
# the combined "protocol credentials" action does not rescan the pcap for each
# extractor.  The key includes size + mtime so edits invalidate the cache.
_DETECT_CACHE: dict[tuple, list[dict]] = {}
_DETECT_LOCK = threading.Lock()


def clear_detection_cache() -> None:
    """Drop cached detection results (used by the tests)."""
    with _DETECT_LOCK:
        _DETECT_CACHE.clear()


def _cache_key(pcap: str, params: dict | None = None) -> tuple:
    """Cache key: 文件身份 + 影响检测结果的参数指纹。

    早期实现只用 ``(路径, mtime, size)``，于是同一次任务里先跑
    ``protocol_min_confidence=90`` 再跑默认值，第二次会命中第一次的结果
    （反之亦然），``protocol_ignore`` 同理。
    """
    try:
        stat = Path(pcap).stat()
        identity = (str(Path(pcap).resolve()), stat.st_mtime_ns, stat.st_size)
    except OSError:
        identity = (str(pcap), 0, 0)
    settings = params or {}
    min_confidence = _int_param(settings.get("protocol_min_confidence"), 60)
    ignore = tuple(_patterns(settings.get("protocol_ignore")))
    return identity + (min_confidence, ignore)


#: 上限：一次任务通常只有一两个抓包，``--batch`` 才会多。超出后按插入
#: 顺序淘汰最旧的项，避免 ``--all`` 批量分析时把整份检测结果堆在内存里。
_DETECT_CACHE_LIMIT = 4


def detect_streams(ctx: FeatureContext, use_cache: bool = True) -> list[dict]:
    """Identify Redis/MongoDB/PostgreSQL/LDAP/SMB2/HTTP2 streams by payload.

    Only the first payload of each TCP stream is inspected, which keeps the
    scan cheap even for large captures.  Default-port streams are reported by
    tshark's normal dissectors and are not repeated here.
    """
    if ctx.tshark is None:
        return []
    key = _cache_key(ctx.pcap, ctx.params)
    if use_cache:
        with _DETECT_LOCK:
            cached = _DETECT_CACHE.get(key)
        if cached is not None:
            # 拷贝一层 dict，调用方即使就地改字段也不会污染缓存条目。
            return [dict(item) for item in cached]
    rows = tshark_rows(
        ctx, ["frame.number", "tcp.stream", "tcp.srcport", "tcp.dstport",
              "tcp.payload"], "tcp.len > 0", limit=MAX_DETECT_ROWS)
    detections: list[dict] = []
    seen: set[str] = set()
    min_confidence = _int_param(ctx.params.get("protocol_min_confidence"), 60)
    ignore = _patterns(ctx.params.get("protocol_ignore"))
    for row in rows:
        row += [""] * (5 - len(row))
        frame, stream, srcport, dstport, raw = row[:5]
        if not stream or stream in seen:
            continue
        seen.add(stream)
        data = hex_to_bytes(raw)
        protocol, confidence = protocol_detect.detect_protocol_scored(data)
        if not protocol or confidence < min_confidence:
            continue
        try:
            sport = int(srcport)
        except (TypeError, ValueError):
            sport = 0
        try:
            dport = int(dstport)
        except (TypeError, ValueError):
            dport = 0
        ports = protocol_detect.default_ports(protocol)
        if dport in ports:
            port = dport
        elif sport in ports:
            port = sport
        else:
            port = dport or sport
        if _ignored_detection(ignore, protocol, port, stream):
            ctx.report(f"协议识别: 已按忽略规则跳过 {protocol} "
                       f"port {port} stream {stream}", "debug")
            continue
        detections.append({
            "frame": frame,
            "stream": stream,
            "protocol": protocol,
            "port": port,
            "srcport": sport,
            "dstport": dport,
            "confidence": confidence,
            "non_default": bool(port and port not in ports),
        })
        ctx.check_cancel()
    if use_cache:
        with _DETECT_LOCK:
            # 先删后插，让重复命中的键移到末尾（真 LRU）；存副本，
            # 调用方**当次**拿到的列表/字典被改动不能污染缓存。
            _DETECT_CACHE.pop(key, None)
            _DETECT_CACHE[key] = [dict(item) for item in detections]
            while len(_DETECT_CACHE) > _DETECT_CACHE_LIMIT:
                _DETECT_CACHE.pop(next(iter(_DETECT_CACHE)))
    return detections


def _patterns(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        items = [str(item) for item in value]
    else:
        items = re.split(r"[;\n]+", str(value or ""))
    return [item.strip().lower() for item in items if item.strip()]


def _int_param(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ignored_detection(patterns: list[str], protocol: str, port: int,
                       stream: str) -> bool:
    """True when ``protocol/[port]/stream`` matches an ignore pattern."""
    if not patterns:
        return False
    haystacks = [protocol.lower(), f"{protocol.lower()}@{port}",
                 f"stream:{stream}"]
    return any(fnmatch.fnmatchcase(item, pattern) or item == pattern
               for pattern in patterns for item in haystacks)


def detected(ctx: FeatureContext, protocol: str) -> list[dict]:
    return [item for item in detect_streams(ctx)
            if item["protocol"] == protocol]


def _report_detections(ctx: FeatureContext, label: str,
                       detections: list[dict]) -> None:
    for item in detections:
        if not item["non_default"]:
            continue
        ctx.report(f"{label}: 在非默认端口 {item['port']} 识别到协议"
                   f"（stream {item['stream']}，帧 {item['frame']}）", "good")


def _detect_args(protocol: str, detections: list[dict]) -> list[str]:
    return protocol_detect.decode_args(
        protocol, [item["port"] for item in detections
                   if item["non_default"]])


def _stream_filter(detections: list[dict]) -> str:
    clauses = [f"tcp.stream == {item['stream']}" for item in detections]
    return " || ".join(clauses)


def _streams(ctx: FeatureContext, clauses: list[str],
             max_total: int = stream_util.MAX_TOTAL_BYTES):
    """Fetch and reassemble every direction matching ``clauses``."""
    if not clauses:
        return []
    return stream_util.reassemble_rows(
        tshark_rows(ctx, stream_util.STREAM_FIELDS, " || ".join(clauses),
                    limit=MAX_RAW),
        max_total_bytes=max_total)


def _stream_direction(item, server_ports) -> str:
    """Label one reassembled direction relative to the server port."""
    try:
        if int(item.dport) in server_ports:
            return "frontend"
        if int(item.sport) in server_ports:
            return "backend"
    except (TypeError, ValueError):
        pass
    return ""


def _frame_number(value) -> int:
    try:
        return int(str(value).split(",", 1)[0])
    except (TypeError, ValueError):
        return 10 ** 12


def _flag_texts(text: str, frame: str, label: str,
                ctx: FeatureContext) -> int:
    found = 0
    for flag in codec.find_flags(text or ""):
        found += 1
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=frame, detail=label, level="good")
    return found


def _safe_name(value: str, fallback: str = "file") -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._")
    return name[:80] or fallback



def _raw_protocol_scan(ctx: FeatureContext, title: str,
                       detections: list[dict], max_lines: int = 120) -> int:
    """Fallback: print printable payload lines when the dissector cannot help."""
    if not detections:
        return 0
    rows = _rows(ctx, ["frame.number", "tcp.stream", "ip.src", "ip.dst",
                       "tcp.payload"], _stream_filter(detections),
                 limit=MAX_RAW)
    lines = 0
    for row in rows:
        row += [""] * (5 - len(row))
        frame, stream, src, dst, raw = row[:5]
        data = hex_to_bytes(raw)
        if not data:
            continue
        text = payload_text(data)
        if printable_ratio(data) < 0.55:
            _flags(ctx, text, frame, f"{title} 原始载荷")
            continue
        for line in text.splitlines()[:30]:
            if not line.strip():
                continue
            ctx.report(f"[{frame}] {clean_cell(line, 260)}", "info")
            lines += 1
            if lines >= max_lines:
                ctx.report("原始载荷输出达到上限", "warn")
                return lines
        _flags(ctx, text, frame, f"{title} 原始载荷")
        ctx.check_cancel()
    if lines:
        ctx.report(f"{title}: dissector 不可用，已回退到原始载荷解析", "debug")
    return lines


def _text(value: str) -> str:
    data = hex_to_bytes(value)
    if not data:
        return ""
    return payload_text(data)


def _flags(ctx: FeatureContext, text: str, frame: str, detail: str) -> int:
    found = 0
    for flag in codec.find_flags(text or ""):
        found += 1
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=frame, detail=detail, level="good")
    return found


def _credential(ctx: FeatureContext, frame: str, summary: str,
                detail: str = "", *, protocol: str = "", account: str = "",
                secret: str = "") -> None:
    extra = {key: value for key, value in
             (("protocol", protocol), ("account", account),
              ("secret", secret)) if value}
    ctx.report(f"凭据: {summary}", "good")
    ctx.add_finding("credential", summary, frame=frame, detail=detail,
                    level="good", extra=extra or None)


def _decode_basic(value: str) -> str:
    """Decode ``Basic user:pass`` style header values."""
    raw = (value or "").strip()
    if not raw.lower().startswith("basic "):
        return ""
    try:
        return base64.b64decode(raw[6:].strip() + "===").decode(
            "utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _interesting_tokens(text: str) -> list[str]:
    """Pull user/password looking key/value pairs out of query documents."""
    tokens: list[str] = []
    for match in re.finditer(
            r"(?i)['\"]?(?P<key>user(?:name)?|login|account|pass(?:word|wd)?"
            r"|pwd|token)['\"]?\s*[:=]\s*['\"]?(?P<value>[^\"',}\s]+)",
            text or ""):
        value = match.group("value")
        if value and value not in tokens:
            tokens.append(f"{match.group('key')}={value}")
    return tokens


# ---------------------------------------------------------------------------
# Redis (no dissector: parse RESP from tcp.payload)
# ---------------------------------------------------------------------------
REDIS_PORTS = (6379, 6380)
REDIS_COMMANDS = {
    "AUTH", "HELLO", "SELECT", "GET", "SET", "SETEX", "PSETEX", "MSET",
    "MGET", "DEL", "EXISTS", "HGET", "HSET", "HGETALL", "LPUSH", "RPUSH",
    "LRANGE", "SADD", "SMEMBERS", "CONFIG", "INFO", "KEYS", "SCAN", "EVAL",
    "FLUSHALL", "FLUSHDB", "CLIENT", "ACL", "MONITOR", "SUBSCRIBE",
}


def redis_commands(payload: bytes) -> list[list[str]]:
    """Parse RESP commands (inline and array form) out of one TCP payload."""
    commands: list[list[str]] = []
    data = bytes(payload or b"")
    index = 0
    size = len(data)
    while index < size:
        while index < size and data[index] in b"\r\n \t":
            index += 1
        if index >= size:
            break
        if data[index:index + 1] == b"*":
            line_end = data.find(b"\r\n", index)
            if line_end < 0:
                break
            try:
                count = int(data[index + 1:line_end])
            except ValueError:
                break
            cursor = line_end + 2
            args: list[str] = []
            valid = 0 <= count <= 1024
            for _ in range(max(0, count)):
                if not valid or data[cursor:cursor + 1] != b"$":
                    valid = False
                    break
                head_end = data.find(b"\r\n", cursor)
                if head_end < 0:
                    valid = False
                    break
                try:
                    length = int(data[cursor + 1:head_end])
                except ValueError:
                    valid = False
                    break
                start = head_end + 2
                if length < 0 or start + length > size:
                    valid = False
                    break
                args.append(data[start:start + length].decode(
                    "utf-8", "replace"))
                cursor = start + length
                if data[cursor:cursor + 2] == b"\r\n":
                    cursor += 2
            if valid and args:
                commands.append(args)
                index = cursor
            else:
                break
            continue
        line_end = data.find(b"\r\n", index)
        if line_end < 0:
            line_end = size
        line = data[index:line_end].decode("utf-8", "replace").strip()
        if line and not line.startswith(("+", "-", ":", "$")):
            commands.append(line.split())
        index = line_end + 2
    return commands


def redis(ctx: FeatureContext) -> None:
    extra_streams = [item for item in detected(ctx, "redis")
                     if item["non_default"]]
    clauses = [f"tcp.port == {port}" for port in REDIS_PORTS]
    clauses += [f"tcp.stream == {item['stream']}" for item in extra_streams]
    streams = _streams(ctx, clauses)
    if not streams:
        ctx.report("===== Redis =====", "good")
        ctx.report("没有发现 Redis 流量（默认端口 6379/6380 或 RESP 特征）",
                   "warn")
        return
    _report_detections(ctx, "Redis", extra_streams)
    parsed: list[tuple[object, list]] = []
    for item in streams:
        messages = redis_util.parse_messages(item.data, item.frame_at)
        if messages:
            parsed.append((item, messages))
    if not parsed:
        ctx.report("发现 Redis 端口流量，但没有解析出 RESP 命令", "warn")
        return

    ctx.report("===== Redis 命令与凭据 =====", "good")
    if any(item.gaps or item.truncated for item in streams):
        ctx.report("部分 Redis 流存在丢包/截断，跨包命令可能不完整", "warn")
    all_messages = sorted(
        (message for _item, messages in parsed for message in messages),
        key=lambda message: _frame_number(message.frame))
    counts = redis_util.command_counts(all_messages)
    lines: list[str] = []
    shown = 0
    seen_flags: set[tuple[str, str]] = set()

    def scan_flags(text: str, frame: str, label: str) -> None:
        for flag in codec.find_flags(text or ""):
            key = (frame, flag)
            if key in seen_flags:
                continue
            seen_flags.add(key)
            ctx.report(f"发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag, frame=frame, detail=label,
                            level="good")

    for message in all_messages:
        frame = message.frame
        if message.kind == "command":
            rendered = " ".join(clean_cell(part, 120)
                                for part in message.args[:8])
            lines.append(f"{frame}\t{rendered}")
            shown += 1
            if shown <= MAX_LINES:
                ctx.report(f"[{frame}] {rendered}", "info")
            elif shown == MAX_LINES + 1:
                ctx.report("命令输出达到上限，后续命令仅写入文件", "warn")
            scan_flags(" ".join(message.args), frame,
                       f"Redis {message.command}")
            message_text = " ".join(message.args)
        else:
            message_text = str(message.value or "")
        scan_flags(message_text, frame, "Redis 响应/推送")
        ctx.check_cancel()

    for event in redis_util.auth_events(all_messages):
        if event["kind"] == "requirepass":
            summary = f"Redis requirepass {event['secret']}"
        elif event["account"]:
            summary = f"Redis AUTH {event['account']}:{event['secret']}"
        else:
            summary = f"Redis AUTH {event['secret']}"
        _credential(ctx, event["frame"], summary,
                    detail=f"凭据来源: {event['detail']}", protocol="redis",
                    account=event["account"], secret=event["secret"])

    for redirect in redis_util.cluster_redirects(all_messages):
        ctx.report(f"[{redirect['frame']}] Redis 集群重定向 "
                   f"{redirect['kind']} slot {redirect['slot']} -> "
                   f"{redirect['host']}:{redirect['port']}", "warn")
        ctx.add_finding("protocol",
                        f"Redis 集群重定向 {redirect['kind']} "
                        f"slot {redirect['slot']}",
                        frame=redirect["frame"],
                        detail=f"目标节点 {redirect['host']}:{redirect['port']}",
                        level="warn")

    for change in redis_util.acl_changes(all_messages):
        detail = " ".join(change["rules"]) if change["rules"] else ""
        ctx.report(f"[{change['frame']}] Redis ACL {change['action']} "
                   f"{change['user']} {clean_cell(detail, 200)}", "warn")
        ctx.add_finding("protocol",
                        f"Redis ACL {change['action']} {change['user']}",
                        frame=change["frame"], detail=change["command"],
                        level="warn")
        if change["action"] == "SETUSER":
            for rule in change["rules"]:
                if rule.startswith(">"):
                    _credential(ctx, change["frame"],
                                f"Redis ACL 密码 {change['user']}:{rule[1:]}",
                                detail=change["command"], protocol="redis",
                                account=change["user"], secret=rule[1:])

    for event in redis_util.pubsub_events(all_messages):
        ctx.report(f"[{event['frame']}] Redis Pub/Sub {event['kind']} "
                   f"{event['channel']} {clean_cell(event['payload'], 200)}",
                   "info")
        if event["payload"]:
            scan_flags(event["payload"], event["frame"], "Redis Pub/Sub")

    for script in redis_util.eval_scripts(all_messages):
        ctx.report(f"[{script['frame']}] Redis {script['command']} "
                   f"numkeys={script['numkeys']} "
                   f"keys={','.join(script['keys']) or '-'}", "warn")
        preview = script["script"].replace("\n", " ")
        ctx.report(f"[{script['frame']}] Lua ({script['encoding']}): "
                   f"{clean_cell(preview, 300)}", "info")
        for value in [script["script"], *script["keys"], *script["args"]]:
            scan_flags(value, script["frame"], f"Redis {script['command']}")
        ctx.add_finding("protocol",
                        f"Redis {script['command']} Lua 脚本",
                        frame=script["frame"],
                        detail=clean_cell(script["script"], 1000),
                        level="warn")

    for read in redis_util.sensitive_reads(all_messages):
        ctx.add_finding("protocol",
                        f"Redis 读取敏感键 {clean_cell(read['key'], 120)}",
                        frame=read["frame"],
                        detail=f"命令: {read['command']} {read['key']}",
                        level="warn")

    if counts:
        ctx.report("命令统计: " + ", ".join(
            f"{name}×{count}" for name, count in
            sorted(counts.items(), key=lambda item: -item[1])[:15]), "info")
    if lines:
        ctx.write_output("redis_commands.txt", "\n".join(lines))
    ctx.report(f"共解析 {shown} 条 Redis 命令", "good")


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
def _postgres_tshark(ctx: FeatureContext, detections: list[dict],
                     extra: list[str]) -> None:
    fields = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "pgsql.type",
              "pgsql.query", "pgsql.parameter_name", "pgsql.parameter_value",
              "pgsql.password", "pgsql.error"]
    rows = _rows(ctx, fields, "pgsql", limit=MAX_RAW, extra=extra)
    if not rows:
        ctx.report("===== PostgreSQL =====", "good")
        ctx.report("没有发现 PostgreSQL 流量", "warn")
        _report_detections(ctx, "PostgreSQL", detections)
        _raw_protocol_scan(ctx, "PostgreSQL", detections)
        return
    _report_detections(ctx, "PostgreSQL", detections)
    ctx.report("===== PostgreSQL 查询与凭据 =====", "good")
    summary: list[list[str]] = []
    users: dict[str, str] = {}
    databases: dict[str, str] = {}
    queries = 0
    for row in rows:
        row += [""] * (len(fields) - len(row))
        frame, stream, src, dst, _ptype, query, pname, pvalue, password, error = row
        if pname:
            name = pname.lower()
            value = pvalue
            if name in ("user", "username"):
                users[value] = frame
                _credential(ctx, frame, f"PostgreSQL 用户 {value}",
                            detail=f"{src} -> {dst}", protocol="postgres",
                            account=value)
            elif name == "database":
                databases[value] = frame
                ctx.report(f"PostgreSQL 数据库: {value}", "info")
        if password:
            _credential(ctx, frame, f"PostgreSQL 明文密码 {password}",
                        detail=f"stream {stream}", protocol="postgres",
                        secret=password)
        if query:
            queries += 1
            summary.append([frame, clean_cell(query, 260)])
            if queries <= MAX_LINES:
                ctx.report(f"[{frame}] {clean_cell(query, 260)}", "info")
            _flags(ctx, query, frame, "PostgreSQL 查询")
            if re.search(r"(?i)(pass|pwd|token|secret|flag)", query):
                ctx.add_finding("protocol", f"PostgreSQL 敏感查询 帧 {frame}",
                                frame=frame, detail=clean_cell(query, 500),
                                level="warn")
        if error:
            ctx.report(f"[{frame}] PostgreSQL 错误: {clean_cell(error, 200)}",
                       "warn")
        ctx.check_cancel()
    table(ctx, "PostgreSQL 摘要", ["帧", "查询/错误"], summary, limit=MAX_LINES)
    if users:
        ctx.report("用户: " + ", ".join(sorted(users)), "info")
    if databases:
        ctx.report("数据库: " + ", ".join(sorted(databases)), "info")
    if not queries and not users and not databases:
        ctx.report("发现 PostgreSQL 流量，但没有可读的查询或凭据", "warn")


def postgres(ctx: FeatureContext) -> None:
    detections = [item for item in detected(ctx, "postgres")
                  if item["non_default"]]
    extra = _detect_args("postgres", detections)
    ports = set(protocol_detect.default_ports("postgres"))
    ports.update(item["port"] for item in detections)
    clauses = [f"tcp.port == {port}" for port in sorted(ports)]
    clauses += [f"tcp.stream == {item['stream']}" for item in detections]
    streams = _streams(ctx, clauses)
    messages = []
    for item in streams:
        direction = _stream_direction(item, ports)
        messages.extend(pg_util.parse_stream(
            item.data, item.frame_at, direction=direction))
    messages.sort(key=lambda message: _frame_number(message.frame))

    if not messages:
        _postgres_tshark(ctx, detections, extra)
        return

    _report_detections(ctx, "PostgreSQL", detections)
    if any(item.gaps or item.truncated for item in streams):
        ctx.report("部分 PostgreSQL 流存在丢包/截断，扩展查询可能不完整", "warn")
    ctx.report("===== PostgreSQL 启动、查询与凭据 =====", "good")

    startup = pg_util.startup_info(messages)
    users: dict[str, str] = {}
    databases: dict[str, str] = {}
    for info in startup:
        kind = info.get("kind") or "StartupMessage"
        frame = next((message.frame for message in messages
                      if message.type == "startup"
                      and message.fields is info), "")
        ctx.report(f"[{frame}] PostgreSQL {kind}", "info")
        if kind in ("SSLRequest", "GSSENCRequest"):
            ctx.add_finding("protocol", f"PostgreSQL {kind}", frame=frame,
                            detail="客户端请求加密/协商连接", level="info")
        elif kind == "CancelRequest":
            ctx.add_finding("protocol", "PostgreSQL CancelRequest", frame=frame,
                            detail=f"pid={info.get('pid')}", level="warn")
        params = info.get("params") or {}
        if params.get("user"):
            users[str(params["user"])] = frame
            _credential(ctx, frame, f"PostgreSQL 用户 {params['user']}",
                        detail="启动包 user 参数", protocol="postgres",
                        account=str(params["user"]))
        if params.get("database"):
            databases[str(params["database"])] = frame
        if params.get("application_name"):
            ctx.report(f"客户端 application_name: "
                       f"{params['application_name']}", "info")

    for event in pg_util.auth_events(messages):
        frame = event["frame"]
        if "password" in event:
            _credential(ctx, frame, f"PostgreSQL 明文密码 {event['password']}",
                        detail="PasswordMessage", protocol="postgres",
                        secret=str(event["password"]))
            continue
        request = event.get("request")
        fields = event.get("fields") or {}
        if request == "md5":
            ctx.add_finding("hash", "PostgreSQL MD5 认证挑战",
                            frame=frame,
                            detail=f"user={','.join(users) or '-'} "
                                   f"salt={fields.get('salt', '')}",
                            level="warn")
        elif request in ("cleartext", "sasl", "sasl-continue", "sasl-final"):
            detail = request
            if fields.get("mechanisms"):
                detail += " " + ",".join(fields["mechanisms"])
            if fields.get("data"):
                detail += " " + clean_cell(fields["data"], 200)
            ctx.report(f"[{frame}] PostgreSQL 认证请求: {detail}", "info")
            ctx.add_finding("protocol", f"PostgreSQL 认证 {request}",
                            frame=frame, detail=detail, level="info")

    query_lines: list[str] = []
    sensitive_queries = 0
    for query in pg_util.queries(messages):
        frame = query["frame"]
        text = query["query"]
        if not text:
            continue
        params = query.get("params") or []
        rendered = " ".join(
            f"${item['index'] + 1}={item['value'] or 'NULL'}"
            f"({item['type'] or '?'},{item['format']})"
            for item in params)
        ctx.report(f"[{frame}] {clean_cell(text, 260)}"
                   + (f" 参数: {clean_cell(rendered, 240)}" if params else ""),
                   "info")
        query_lines.append("\t".join([
            frame, query.get("statement") or "", query.get("portal") or "",
            text.replace("\n", " "), rendered]))
        _flags(ctx, text, frame, "PostgreSQL 查询")
        for item in params:
            _flags(ctx, str(item.get("value") or ""), frame,
                   f"PostgreSQL 绑定参数 {item['index'] + 1}")
        if "execute_frames" in query:
            for execute_frame in query["execute_frames"]:
                if execute_frame and execute_frame != frame:
                    ctx.report(f"[{execute_frame}] Execute portal="
                               f"{query.get('portal') or '-'}", "debug")
        if re.search(r"(?i)(pass|pwd|token|secret|flag)", text):
            sensitive_queries += 1
            ctx.add_finding("protocol", f"PostgreSQL 敏感查询 帧 {frame}",
                            frame=frame, detail=clean_cell(text, 800),
                            level="warn")
        ctx.check_cancel()

    for error in messages:
        if error.type == "E" and error.direction == "backend":
            fields = error.fields or {}
            message = fields.get("M") or fields.get("S") or ""
            if message:
                ctx.report(f"[{error.frame}] PostgreSQL 错误: "
                           f"{clean_cell(message, 220)}", "warn")

    for copy in pg_util.copy_data(messages):
        data = copy["data"]
        if not data:
            continue
        extension = "txt" if printable_ratio(data) >= 0.85 else "bin"
        name = f"postgres_copy_{copy['frame']}_{copy['direction']}.{extension}"
        ctx.write_output(name, data)
        digest = hashlib.md5(data).hexdigest()
        ctx.report(f"[{copy['frame']}] PostgreSQL COPY "
                   f"({copy['direction']}) {len(data)} 字节 MD5 {digest}",
                   "good")
        ctx.add_finding("file", f"PostgreSQL COPY 数据 {len(data)} 字节",
                        frame=copy["frame"], detail=f"{name}\nMD5 {digest}",
                        level="warn")
        _flags(ctx, payload_text(data), copy["frame"], "PostgreSQL COPY 数据")

    if query_lines:
        ctx.write_output("postgres_queries.txt", "\n".join(query_lines))
    if users:
        ctx.report("用户: " + ", ".join(sorted(users)), "good")
    if databases:
        ctx.report("数据库: " + ", ".join(sorted(databases)), "info")
    if not query_lines and not users and not startup:
        ctx.report("发现 PostgreSQL 流量，但没有可读的查询或凭据", "warn")
    ctx.report(f"共解析 {len(messages)} 条 PostgreSQL 消息"
               f"（{sensitive_queries} 条敏感查询）", "good")


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
def _mongodb_tshark(ctx: FeatureContext, detections: list[dict],
                    extra: list[str]) -> None:
    fields = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "mongo.opcode",
              "mongo.database_name", "mongo.collection_name",
              "mongo.full_collection_name", "mongo.query", "mongo.document",
              "mongo.selector"]
    rows = _rows(ctx, fields, "mongo", limit=MAX_RAW, extra=extra)
    if not rows:
        clauses = [f"tcp.port == {port}"
                   for port in protocol_detect.default_ports("mongodb")]
        clauses += [f"tcp.stream == {item['stream']}" for item in detections]
        rows = _rows(ctx, ["frame.number", "tcp.stream", "tcp.payload"],
                     " || ".join(clauses), limit=MAX_RAW)
        if not rows:
            ctx.report("===== MongoDB =====", "good")
            ctx.report("没有发现 MongoDB 流量（默认端口 27017 或 OP_MSG 特征）",
                       "warn")
            _report_detections(ctx, "MongoDB", detections)
            return
        _report_detections(ctx, "MongoDB", detections)
        ctx.report("===== MongoDB 原始载荷 =====", "good")
        for row in rows:
            row += [""] * (3 - len(row))
            frame, _stream, raw = row[:3]
            text = _text(raw)
            if not text or printable_ratio(text.encode("utf-8", "replace")) < 0.55:
                continue
            for line in text.splitlines()[:30]:
                if line.strip():
                    ctx.report(f"[{frame}] {clean_cell(line, 260)}", "info")
            _flags(ctx, text, frame, "MongoDB 原始载荷")
        return
    _report_detections(ctx, "MongoDB", detections)
    ctx.report("===== MongoDB 数据库与查询 =====", "good")
    summary: list[list[str]] = []
    collections: dict[str, str] = {}
    for row in rows:
        row += [""] * (len(fields) - len(row))
        (frame, stream, src, dst, opcode, database, collection,
         full, query, document, selector) = row
        name = full or collection
        if name:
            collections[name] = frame
        text = "\n".join(part for part in (query, document, selector) if part)
        if text:
            if len(summary) < MAX_LINES:
                summary.append([frame, clean_cell(name, 80),
                                clean_cell(text, 260)])
                ctx.report(f"[{frame}] {clean_cell(name, 80)} "
                           f"{clean_cell(text, 260)}", "info")
            for token in _interesting_tokens(text):
                key, _, value = token.partition("=")
                lowered = key.lower()
                account = value if lowered.startswith(("user", "login",
                                                       "account")) else ""
                secret = value if lowered.startswith(("pass", "pwd",
                                                      "token")) else ""
                _credential(ctx, frame, f"MongoDB {token}",
                            detail=f"{src} -> {dst} {name}",
                            protocol="mongodb", account=account,
                            secret=secret)
            _flags(ctx, text, frame, f"MongoDB {name}")
        elif name:
            summary.append([frame, clean_cell(name, 80), ""])
        ctx.check_cancel()
    if collections:
        ctx.report("集合: " + ", ".join(sorted(collections)[:80]), "info")
        for name in sorted(collections)[:30]:
            ctx.add_finding("protocol",
                            f"MongoDB 集合 {clean_cell(name, 120)}",
                            frame=collections[name],
                            detail="MongoDB collection", level="info")
    table(ctx, "MongoDB 摘要", ["帧", "集合", "查询/文档"], summary,
          limit=MAX_LINES)


def _json_text(value) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def mongodb(ctx: FeatureContext) -> None:
    detections = [item for item in detected(ctx, "mongodb")
                  if item["non_default"]]
    extra = _detect_args("mongodb", detections)
    ports = set(protocol_detect.default_ports("mongodb"))
    ports.update(item["port"] for item in detections)
    clauses = [f"tcp.port == {port}" for port in sorted(ports)]
    clauses += [f"tcp.stream == {item['stream']}" for item in detections]
    streams = _streams(ctx, clauses)
    messages = []
    for item in streams:
        messages.extend(mongo_util.parse_stream(item.data, item.frame_at))
    messages.sort(key=lambda message: _frame_number(message.frame))
    if not messages:
        _mongodb_tshark(ctx, detections, extra)
        return

    _report_detections(ctx, "MongoDB", detections)
    if any(item.gaps or item.truncated for item in streams):
        ctx.report("部分 MongoDB 流存在丢包/截断，OP_MSG 可能不完整", "warn")
    ctx.report("===== MongoDB 命令、凭据与 GridFS =====", "good")
    op_counts = Counter(message.name for message in messages)
    ctx.report("消息类型: " + ", ".join(
        f"{name}×{count}" for name, count in op_counts.most_common(10)),
        "info")

    collections: dict[str, str] = {}
    query_lines: list[str] = []
    seen_tokens: set[tuple[str, str]] = set()
    seen_flags: set[tuple[str, str]] = set()
    for message in messages:
        frame = message.frame
        command = mongo_util.command_of(message)
        namespace = mongo_util.namespace(message)
        collection = mongo_util.collection_name(message)
        if collection:
            collections[collection] = frame
        if message.truncated:
            ctx.report(f"[{frame}] MongoDB {message.name} 消息无法解码"
                       f"（{len(message.raw)} 字节）", "warn")
        for document in mongo_util.documents(message):
            text = _json_text(document)
            label = namespace or collection or message.name
            query_lines.append(f"{frame}\t{message.name}\t{label}\t{text}")
            if command or collection:
                ctx.report(f"[{frame}] {message.name} "
                           f"{clean_cell(label, 100)} {clean_cell(text, 240)}",
                           "info")
            for token in mongo_util.sensitive_tokens(document):
                if (frame, token) in seen_tokens:
                    continue
                seen_tokens.add((frame, token))
                key, _, value = token.partition("=")
                lowered = key.lower()
                account = value if lowered.startswith(
                    ("user", "login", "account")) else ""
                secret = value if lowered.startswith(
                    ("pass", "pwd", "token", "secret", "key")) else ""
                _credential(ctx, frame, f"MongoDB {token}",
                            detail=f"{message.name} {label}".strip(),
                            protocol="mongodb", account=account,
                            secret=secret)
            for value in mongo_util.iter_strings(document):
                for flag in codec.find_flags(value):
                    if (frame, flag) in seen_flags:
                        continue
                    seen_flags.add((frame, flag))
                    ctx.report(f"发现 flag: {flag}", "good")
                    ctx.add_finding("flag", flag, frame=frame,
                                    detail=f"MongoDB {label}", level="good")
        ctx.check_cancel()

    for event in mongo_util.scram_exchanges(messages):
        frame = event["frame"]
        mechanism = event.get("mechanism") or "SCRAM"
        kind = event.get("kind")
        if event.get("user"):
            _credential(ctx, frame,
                        f"MongoDB {mechanism} 用户 {event['user']}",
                        detail=f"nonce={event.get('client_nonce', '')}",
                        protocol="mongodb", account=str(event["user"]))
        if kind == "scram-final" and event.get("proof"):
            ctx.add_finding("hash", f"MongoDB {mechanism} 客户端 proof",
                            frame=frame,
                            detail=f"proof={event['proof'][:200]} "
                                   f"nonce={event.get('client_nonce', '')}",
                            level="warn")
        elif kind == "scram-server":
            ctx.report(f"[{frame}] MongoDB {mechanism} 挑战: "
                       f"iterations={event.get('iterations')} "
                       f"salt={event.get('salt')}", "info")
        elif kind == "scram-verified":
            ctx.report(f"[{frame}] MongoDB {mechanism} 认证成功", "good")
        elif kind == "scram-error":
            ctx.report(f"[{frame}] MongoDB {mechanism} 认证失败: "
                       f"{event.get('error')}", "warn")
        elif kind == "mechanisms":
            ctx.report(f"[{frame}] MongoDB 支持认证机制: {mechanism}", "info")

    for item in mongo_util.gridfs_files(messages):
        data = item["data"]
        if not data:
            continue
        filename = _safe_name(item.get("filename") or f"gridfs_{item['id']}",
                              "gridfs_file")
        ctx.write_output(f"gridfs_{filename}", data)
        state = "完整" if item["complete"] else "不完整"
        ctx.report(f"GridFS 文件 {item.get('filename') or item['id']} "
                   f"{item['actual_length']} 字节 {state} "
                   f"MD5 {item['actual_md5']}", "good" if item["complete"]
                   else "warn")
        ctx.add_finding("file",
                        f"GridFS {item.get('filename') or item['id']} "
                        f"({item['actual_length']} 字节, {state})",
                        frame=item.get("frame") or "",
                        detail=f"chunks={item['chunks']} "
                               f"content_type={item.get('content_type') or '-'} "
                               f"MD5={item['actual_md5']}",
                        level="warn" if item["complete"] else "info")
        _flags(ctx, payload_text(data), item.get("frame") or "",
               "GridFS 文件内容")

    if collections:
        ctx.report("集合: " + ", ".join(sorted(collections)[:80]), "info")
    if query_lines:
        ctx.write_output("mongodb_queries.txt", "\n".join(query_lines))
    ctx.report(f"共解析 {len(messages)} 条 MongoDB 消息", "good")


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------
def _ldap_raw(ctx: FeatureContext, detections: list[dict]) -> int:
    """Parse LDAP binds/searches/entries from reassembled streams."""
    clauses = ["ldap"]
    if detections:
        clauses.append(_stream_filter(detections))
    streams = _streams(ctx, clauses)
    if not streams:
        return 0
    messages: list[ldap_util.LdapMessage] = []
    starttls: list[ldap_util.LdapMessage] = []
    for item in streams:
        ctx.check_cancel()
        if item.gaps or item.truncated:
            ctx.report(f"LDAP stream {item.stream} 存在丢包/截断，"
                       f"部分消息可能不完整", "warn")
        parsed = ldap_util.parse_messages(item.data)
        for message in parsed:
            message.frame = item.frame_at(message.offset)
            if message.is_starttls:
                starttls.append(message)
            messages.append(message)
    if not messages:
        return 0

    binds = 0
    searches = 0
    entries = 0
    queries: list[list[str]] = []
    object_lines: list[str] = []
    seen_creds: set[tuple[str, str]] = set()
    for message in messages:
        frame = message.frame or "-"
        if message.op == "BindRequest":
            binds += 1
            account = message.bind_dn or "-"
            if message.sasl_mechanism:
                detail = f"SASL {message.sasl_mechanism}"
                if message.sasl_credentials:
                    detail += f" · {len(message.sasl_credentials)} 字节凭据"
                ctx.report(f"[{frame}] LDAP SASL 绑定 {account} ({detail})",
                           "good")
                ctx.add_finding("protocol", f"LDAP SASL 绑定 {account}",
                                frame=frame, level="good", detail=detail)
                if message.sasl_credentials:
                    text = payload_text(message.sasl_credentials)
                    if printable_ratio(message.sasl_credentials) > 0.7:
                        _credential(ctx, frame, f"LDAP SASL {account}:{text}",
                                    detail=message.sasl_mechanism,
                                    protocol="ldap", account=account,
                                    secret=text)
            elif message.password:
                ctx.report(f"[{frame}] LDAP 简单绑定 {account}:"
                           f"{clean_cell(message.password, 120)}", "good")
                key = (account, message.password)
                if key not in seen_creds:
                    seen_creds.add(key)
                    _credential(ctx, frame, f"LDAP {account}:{message.password}",
                                detail=f"SASL/简单绑定 · stream {message.offset}",
                                protocol="ldap", account=account,
                                secret=message.password)
            else:
                ctx.report(f"[{frame}] LDAP 匿名/空密码绑定 {account}", "info")
        elif message.op == "BindResponse":
            name = message.result_name
            level = "good" if message.result_code == 0 else "warn"
            ctx.report(f"[{frame}] LDAP 绑定结果: {name}"
                       + (f" · {clean_cell(message.diagnostic, 160)}"
                          if message.diagnostic else ""), level)
            if message.result_code not in (0, -1):
                ctx.add_finding(
                    "protocol", f"LDAP 绑定失败 {name}", frame=frame,
                    level="warn", detail=clean_cell(message.diagnostic, 300))
        elif message.op == "SearchRequest":
            searches += 1
            query = [frame, message.base or "-", message.scope or "-",
                     clean_cell(message.filter_text, 260),
                     clean_cell(", ".join(message.attributes), 160)]
            queries.append(query)
            if searches <= MAX_LINES:
                ctx.report(f"[{frame}] LDAP 搜索 base={message.base or '-'} "
                           f"scope={message.scope or '-'} "
                           f"filter={clean_cell(message.filter_text, 200)}",
                           "good")
                if message.attributes:
                    ctx.report(f"  请求属性: {clean_cell(', '.join(message.attributes), 300)}",
                               "info")
            _flags(ctx, message.filter_text, frame, "LDAP 查询过滤器")
        elif message.op == "SearchResultEntry":
            entries += 1
            name = message.object_name or "-"
            ctx.report(f"[{frame}] LDAP 条目 {clean_cell(name, 240)}", "good")
            object_lines.append(f"# frame {frame}")
            object_lines.append(f"dn: {name}")
            for line in ldap_util.entry_lines(message):
                ctx.report("  " + clean_cell(line, 300), "info")
                object_lines.append(line)
                _flags(ctx, line, frame, f"LDAP 条目 {name}")
            object_lines.append("")
            for attr, value in message.sensitive_values():
                ctx.report(f"  敏感属性 {attr}: {clean_cell(value, 120)}",
                           "warn")
                _credential(ctx, frame, f"LDAP {attr} {value}",
                            detail=f"DN {name}", protocol="ldap",
                            account=name, secret=value)
        elif message.op == "SearchResultDone":
            if message.result_code not in (0, -1):
                ctx.report(f"[{frame}] LDAP 搜索结束: {message.result_name}"
                           + (f" · {clean_cell(message.diagnostic, 160)}"
                              if message.diagnostic else ""), "warn")
        elif message.op == "ExtendedRequest" and message.is_starttls:
            ctx.report(f"[{frame}] LDAP StartTLS 请求：后续流量为 TLS，"
                       f"需要 keylog/私钥才能继续解析", "warn")
            ctx.add_finding("protocol", "LDAP StartTLS", frame=frame,
                            level="warn", detail=ldap_util.STARTTLS_OID)
        elif message.op == "ExtendedResponse":
            if message.response_name:
                ctx.report(f"[{frame}] LDAP 扩展响应 {message.response_name}",
                           "info")
            if message.result_code not in (0, -1):
                ctx.report(f"[{frame}] LDAP 扩展操作失败: {message.result_name}",
                           "warn")
        if message.referral:
            for referral in message.referral:
                ctx.report(f"[{frame}] LDAP 引用: {clean_cell(referral, 240)}",
                           "info")
        ctx.check_cancel()

    table(ctx, "LDAP 搜索", ["帧", "Base", "范围", "过滤器", "属性"],
          queries, limit=MAX_LINES)
    if object_lines:
        ctx.write_output("ldap_objects.txt", "\n".join(object_lines) + "\n")
        ctx.report(f"已导出 {entries} 个 LDAP 条目到 ldap_objects.txt", "good")
    if queries:
        ctx.write_output("ldap_queries.txt", "\n".join(
            "\t".join(row) for row in queries) + "\n")
    ctx.report(f"LDAP 消息 {len(messages)} 条：绑定 {binds}、搜索 {searches}、"
               f"条目 {entries}" + (f"、StartTLS {len(starttls)}" if starttls else ""),
               "good" if (binds or searches or entries) else "info")
    return len(messages)


def _ldap_tshark(ctx: FeatureContext, detections: list[dict]) -> int:
    extra = _detect_args("ldap", detections)
    fields = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "ldap.name",
              "ldap.simple", "ldap.filter", "ldap.authentication",
              "ldap.objectName", "ldap.requestName", "ldap.responseName"]
    rows = _rows(ctx, fields, "ldap", limit=MAX_RAW, extra=extra)
    if not rows:
        return 0
    summary: list[list[str]] = []
    filters: Counter = Counter()
    bound = 0
    for row in rows:
        row += [""] * (len(fields) - len(row))
        (frame, stream, src, dst, name, simple, search_filter,
         _auth, object_name, request_name, response_name) = row
        if name and simple:
            bound += 1
            _credential(ctx, frame, f"LDAP {name}:{simple}",
                        detail=f"{src} -> {dst} stream {stream}",
                        protocol="ldap", account=name, secret=simple)
        if search_filter:
            filters[search_filter] += 1
            summary.append([frame, clean_cell(name, 80),
                            clean_cell(search_filter, 260)])
            if len(summary) <= MAX_LINES:
                ctx.report(f"[{frame}] {clean_cell(name, 80)} "
                           f"filter={clean_cell(search_filter, 260)}", "info")
            _flags(ctx, search_filter, frame, "LDAP 查询过滤器")
        for value in (object_name, request_name, response_name):
            if value:
                _flags(ctx, value, frame, "LDAP 对象/响应")
        ctx.check_cancel()
    if filters:
        ctx.report("常见过滤器: " + ", ".join(
            f"{clean_cell(name, 80)}×{count}"
            for name, count in filters.most_common(10)), "info")
    table(ctx, "LDAP 搜索", ["帧", "DN", "过滤器"], summary, limit=MAX_LINES)
    return len(rows)


def ldap(ctx: FeatureContext) -> None:
    detections = [item for item in detected(ctx, "ldap")
                  if item["non_default"]]
    ctx.report("===== LDAP =====", "good")
    try:
        count = _ldap_raw(ctx, detections)
    except (ValueError, IndexError) as exc:
        ctx.report(f"LDAP 原始解析失败，回退 tshark: {exc}", "warn")
        count = 0
    if not count:
        count = _ldap_tshark(ctx, detections)
    _report_detections(ctx, "LDAP", detections)
    if not count:
        ctx.report("没有发现 LDAP 流量", "warn")
        _raw_protocol_scan(ctx, "LDAP", detections)


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
WS_OPCODES = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}


def _ws_stream_ids(ctx: FeatureContext) -> list[str]:
    rows = _rows(ctx, ["tcp.stream"], "websocket", limit=MAX_RAW)
    streams: list[str] = []
    for row in rows:
        value = row[0] if row else ""
        if value and value not in streams:
            streams.append(value)
    return streams


def _ws_raw_messages(ctx: FeatureContext, streams: list[str],
                     inflate: bool) -> list[tuple[str, str, object]]:
    """Parse raw TCP payloads into per-direction WebSocket messages."""
    from fnet.utils import websocket as ws

    if not streams:
        return []
    clauses = [f"tcp.stream == {stream}" for stream in streams]
    rows = tshark_rows(ctx, stream_util.STREAM_FIELDS,
                       " || ".join(clauses), limit=MAX_RAW)
    messages: list[tuple[str, str, object]] = []
    for item in stream_util.reassemble_rows(rows):
        ctx.check_cancel()
        if item.gaps or item.truncated:
            ctx.report(f"WebSocket stream {item.stream} 存在丢包/截断，"
                       f"部分消息可能不完整", "warn")
        parser = ws.FrameParser()
        stripped = item.data.lstrip()
        if (stripped and not stripped.startswith((b"GET ", b"POST ",
                                                  b"HTTP/"))
                and ws.looks_like_frame(stripped)):
            # Mid-capture stream: no HTTP Upgrade handshake to skip.
            parser.handshake_done = True
        frames = []
        for start, end, frame in item.spans():
            frames.extend(parser.feed(item.data[start:end], frame))
        # Incomplete trailing frames are intentionally kept out of the report.
        for message in ws.reassemble(frames, inflate=inflate):
            messages.append((item.stream, item.src, message))
    return messages


def websocket(ctx: FeatureContext) -> None:
    inflate = str(ctx.params.get("websocket_deflate", "1")).lower() not in (
        "0", "false", "no", "off")
    streams = _ws_stream_ids(ctx)
    raw_messages = _ws_raw_messages(ctx, streams, inflate)
    fields = ["frame.number", "tcp.stream", "websocket.opcode",
              "websocket.payload.text", "websocket.payload"]
    rows = _rows(ctx, fields, "websocket", limit=MAX_RAW)
    if not rows and not raw_messages:
        ctx.report("===== WebSocket =====", "good")
        ctx.report("没有发现 WebSocket 消息", "warn")
        return

    ctx.report("===== WebSocket 消息 =====", "good")
    summary: list[list[str]] = []
    count = 0
    if raw_messages:
        ctx.report(f"消息级还原：{len(raw_messages)} 条（含分片与控制帧）",
                   "good")
        for stream, src, message in raw_messages:
            frames = ",".join(message.frames[:8]) or "-"
            op_name = message.name
            data = message.payload
            text = payload_text(data) if data else ""
            printable = bool(data) and printable_ratio(data) >= 0.6
            if message.control:
                ctx.report(f"[{frames}] {op_name} stream {stream} "
                           f"{src or '-'} ({len(data)} 字节)", "debug")
                continue
            count += 1
            suffix = " [deflate]" if message.compressed else ""
            if text and printable:
                for line in text.splitlines()[:20]:
                    if line.strip():
                        ctx.report(f"[{frames}] {op_name}{suffix}: "
                                   f"{clean_cell(line, 260)}", "info")
            else:
                ctx.report(f"[{frames}] {op_name}{suffix} stream {stream} "
                           f"{src or '-'} ({len(data)} 字节二进制)", "info")
                first = message.frames[0] if message.frames else "0"
                ctx.write_output(f"ws_bin_{first}_{stream}.bin", data)
            summary.append([frames, stream, op_name + suffix,
                            clean_cell(text, 120) if printable else "<binary>"])
            _flags(ctx, text, frames, f"WebSocket {op_name}")
            if printable:
                for method, value in _decoded_candidates(text):
                    ctx.report(f"[{frames}] {method} 解码: "
                               f"{clean_cell(value, 200)}", "good")
                    _flags(ctx, value, frames, f"WebSocket {method} 解码")
            ctx.check_cancel()
    else:
        # tshark path (no raw stream available, e.g. capture lacks TCP data).
        for row in rows:
            row += [""] * (len(fields) - len(row))
            frame, stream, opcode, text_value, raw = row
            data = hex_to_bytes(raw)
            text = text_value or payload_text(data)
            op_name = WS_OPCODES.get(
                int(opcode) if str(opcode).isdigit() else 0, opcode or "-")
            if not text:
                summary.append([frame, stream, str(op_name), ""])
                continue
            count += 1
            for line in text.splitlines()[:20]:
                if line.strip():
                    ctx.report(f"[{frame}] {op_name}: {clean_cell(line, 260)}",
                               "info")
            summary.append([frame, stream, str(op_name), clean_cell(text, 120)])
            _flags(ctx, text, frame, f"WebSocket {op_name}")
            for method, value in _decoded_candidates(text):
                ctx.report(f"[{frame}] {method} 解码: {clean_cell(value, 200)}",
                           "good")
                _flags(ctx, value, frame, f"WebSocket {method} 解码")
            ctx.check_cancel()
    table(ctx, "WebSocket 摘要", ["帧", "流", "类型", "内容"], summary,
          limit=MAX_LINES)
    if count:
        ctx.report(f"共解析 {count} 条可读 WebSocket 消息", "good")


def _decoded_candidates(text: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    stripped = (text or "").strip()
    if len(stripped) >= 8:
        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped):
            decoded = codec.b64decode_text(re.sub(r"\s+", "", stripped))
            if decoded and decoded not in seen and _looks_readable(decoded):
                seen.add(decoded)
                results.append(("base64", decoded))
        if re.fullmatch(r"[0-9a-fA-F\s]+", stripped) and len(stripped) >= 16:
            decoded = codec.hexdecode_text(re.sub(r"\s+", "", stripped))
            if decoded and decoded not in seen and _looks_readable(decoded):
                seen.add(decoded)
                results.append(("hex", decoded))
    return results


def _looks_readable(value: str) -> bool:
    if len(value) < 4:
        return False
    good = sum(ch.isprintable() or ch in "\r\n\t" for ch in value)
    return good / len(value) >= 0.85


# ---------------------------------------------------------------------------
# HTTP/2
# ---------------------------------------------------------------------------
def _h2_side_kind(side) -> str:
    """Classify one direction of an HTTP/2 connection by its headers."""
    methods = sum(1 for item in side.streams.values()
                  if item.header(":method") or item.header(":path"))
    statuses = sum(1 for item in side.streams.values() if item.header(":status"))
    if methods and not statuses:
        return "request"
    if statuses and not methods:
        return "response"
    if methods and statuses:
        return "mixed"
    return "unknown"


def _h2_pick_sides(first, second, first_item, second_item, server_ports: set):
    """Return ``(request_side, response_side)`` with their StreamData objects."""
    kind_first = _h2_side_kind(first)
    kind_second = _h2_side_kind(second)
    if kind_first == "request" and kind_second != "request":
        return first, second, first_item, second_item
    if kind_second == "request" and kind_first != "request":
        return second, first, second_item, first_item
    # Fall back to the well-known server port direction.
    def is_client_to_server(item) -> bool:
        try:
            return int(item.dport) in server_ports
        except (TypeError, ValueError):
            return False

    if is_client_to_server(first_item) and not is_client_to_server(second_item):
        return first, second, first_item, second_item
    return second, first, second_item, first_item


def _h2_header_text(headers: list[tuple[str, str]]) -> list[str]:
    """Keep the interesting headers, redacting nothing (CTF analysis)."""
    interesting = ("authorization", "proxy-authorization", "cookie", "set-cookie",
                   "content-type", "user-agent", "x-api-key", "x-auth-token",
                   "grpc-status", "grpc-message", "te", "referer", "origin")
    lines: list[str] = []
    for name, value in headers:
        lowered = name.lower()
        if lowered.startswith(":") or lowered in interesting:
            lines.append(f"{name}: {clean_cell(value, 400)}")
    return lines


def _h2_body_summary(body: bytes, headers: list[tuple[str, str]]) -> list[str]:
    """Human readable view of a request/response body, including gRPC."""
    if not body:
        return []
    lines: list[str] = []
    if http2_util.is_grpc(headers):
        messages = http2_util.grpc_messages(body)
        lines.append(f"gRPC 消息 {len(messages)} 条")
        for index, (compressed, payload) in enumerate(messages[:10]):
            suffix = " (压缩)" if compressed else ""
            lines.append(f"  #{index + 1}{suffix} {len(payload)} 字节")
            for field in http2_util.protobuf_fields(payload)[:20]:
                lines.append("    " + field)
        return lines
    if printable_ratio(body) >= 0.7:
        text = payload_text(body)
        for line in text.splitlines()[:30]:
            if line.strip():
                lines.append(clean_cell(line, 300))
    else:
        lines.append(f"二进制正文 {len(body)} 字节，已导出")
    return lines


def _http2_raw(ctx: FeatureContext, detections: list[dict]) -> int:
    """Parse HTTP/2 from reassembled TCP payloads; returns request count."""
    clauses = ["http2"]
    if detections:
        clauses.append(_stream_filter(detections))
    streams = _streams(ctx, clauses)
    if not streams:
        return 0
    groups: dict[str, list] = {}
    for item in streams:
        groups.setdefault(item.stream, []).append(item)
    server_ports = set(protocol_detect.default_ports("http2"))
    server_ports.update(item["port"] for item in detections)

    requests = 0
    responses = 0
    summary: list[list[str]] = []
    exported = 0
    for stream_id, items in groups.items():
        ctx.check_cancel()
        if len(items) < 2:
            # One direction only: still parse frames for statistics.
            side = http2_util.parse_direction(items[0].data, items[0].frame_at)
            if side.goaway:
                ctx.report(f"HTTP/2 stream {stream_id} GOAWAY "
                           f"{side.goaway['name']} last={side.goaway['last_stream']}",
                           "warn")
            continue
        first, second = items[0], items[1]
        side_a = http2_util.parse_direction(first.data, first.frame_at)
        side_b = http2_util.parse_direction(second.data, second.frame_at)
        req_side, resp_side, req_item, resp_item = _h2_pick_sides(
            side_a, side_b, first, second, server_ports)
        if side_a.decode_errors or side_b.decode_errors:
            ctx.report(f"HTTP/2 stream {stream_id}: HPACK 解码错误 "
                       f"{side_a.decode_errors + side_b.decode_errors} 帧", "warn")
        if side_a.truncated or side_b.truncated:
            ctx.report(f"HTTP/2 stream {stream_id}: 存在截断帧或正文，"
                       f"部分内容可能不完整", "warn")
        if side_a.goaway or side_b.goaway:
            goaway = side_a.goaway or side_b.goaway
            ctx.report(f"HTTP/2 GOAWAY {goaway['name']} "
                       f"last_stream={goaway['last_stream']}"
                       + (f" debug={clean_cell(goaway['debug'], 120)}"
                          if goaway.get("debug") else ""), "warn")
        if side_a.resets or side_b.resets:
            for number, code in {**side_a.resets, **side_b.resets}.items():
                ctx.report(f"HTTP/2 RST_STREAM {number}: "
                           f"{http2_util.ERROR_CODES.get(code, code)}", "warn")
        if side_a.pushes or side_b.pushes:
            ctx.report("HTTP/2 PUSH_PROMISE streams: "
                       + ", ".join(str(value) for value in
                                   side_a.pushes + side_b.pushes), "info")
        if side_a.settings or side_b.settings:
            for settings in (side_a.settings + side_b.settings)[:4]:
                if settings["entries"]:
                    ctx.report("HTTP/2 SETTINGS: " + ", ".join(
                        f"{entry['name']}={entry['value']}"
                        for entry in settings["entries"]), "debug")
        if side_a.priorities or side_b.priorities:
            for number, priority in list(
                    {**side_a.priorities, **side_b.priorities}.items())[:10]:
                ctx.report(f"HTTP/2 优先级 stream {number}: 依赖 "
                           f"{priority['dependency']} 权重 {priority['weight']}"
                           + (" 独占" if priority["exclusive"] else ""), "debug")

        numbers = set(req_side.streams) | set(resp_side.streams)
        for number in sorted(numbers):
            request = req_side.streams.get(number)
            response = resp_side.streams.get(number)
            if not request or not (request.headers or request.body):
                continue
            exchange_headers = request.headers + (response.headers if response else [])
            method = request.header(":method") or request.header(":path")
            if not method and not request.headers:
                continue
            requests += 1
            if response is not None:
                responses += 1
            authority = request.header(":authority") or request.header("host")
            scheme = request.header(":scheme") or "https"
            path = request.header(":path") or "/"
            url = f"{scheme}://{authority or '-'}{path}"
            status = response.header(":status") if response else ""
            grpc = http2_util.is_grpc(exchange_headers)
            request.frames.extend(response.frames if response else [])
            frames = ",".join(dict.fromkeys(request.frames)) or "-"
            tag = " [gRPC]" if grpc else ""
            ctx.report(f"[{frames}] HTTP/2 {method or '-'} {clean_cell(url, 240)}"
                       f" -> {status or '-'}{tag}", "good")
            for line in _h2_header_text(request.headers):
                ctx.report("  " + line, "info")
            if response:
                for line in _h2_header_text(response.headers + response.trailers):
                    ctx.report("  " + line, "info")
            for line in _h2_body_summary(request.body_bytes, request.headers):
                ctx.report("  请求: " + line, "info")
            for line in _h2_body_summary(response.body_bytes if response else b"",
                                         response.headers if response else []):
                ctx.report("  响应: " + line, "info")
            summary.append([frames, str(stream_id), clean_cell(method or "-", 16),
                            clean_cell(url, 220), status or "-",
                            str(len(request.body)), str(len(response.body)
                                                        if response else 0)])
            ctx.add_finding("http", f"HTTP/2 {method or '-'} {url}",
                            frame=frames, level="info",
                            detail=f"stream {stream_id} · status {status or '-'}"
                                   + (" · gRPC" if grpc else ""))
            auth = request.header("authorization")
            if auth:
                basic = _decode_basic(auth)
                if basic:
                    account, _, secret = basic.partition(":")
                    _credential(ctx, frames, f"HTTP/2 Basic {basic}",
                                detail=clean_cell(url, 300), protocol="http",
                                account=account, secret=secret)
                else:
                    _credential(ctx, frames,
                                f"HTTP/2 Authorization {clean_cell(auth, 180)}",
                                detail=clean_cell(url, 300), protocol="http")
            for label, value in (("Cookie", request.header("cookie")),
                                 ("Set-Cookie", response.header("set-cookie")
                                  if response else "")):
                if value:
                    ctx.report(f"  {label}: {clean_cell(value, 240)}", "info")
                    if re.search(r"(?i)(session|token|auth|jwt|remember)", value):
                        ctx.add_finding("protocol", f"HTTP/2 {label}",
                                        frame=frames,
                                        detail=clean_cell(value, 500),
                                        level="info")
            for label, body, side_item in (
                    ("请求", request.body_bytes, req_item),
                    ("响应", response.body_bytes if response else b"", resp_item)):
                if not body:
                    continue
                text = payload_text(body) if printable_ratio(body) >= 0.6 else ""
                _flags(ctx, text, frames, f"HTTP/2 {label}正文 stream {number}")
                suffix = "req" if label == "请求" else "resp"
                filename = (f"http2_body_{_safe_name(stream_id)}_{number}_"
                            f"{suffix}.bin")
                ctx.write_output(filename, body)
                exported += 1
                digest = hashlib.md5(body).hexdigest()
                kind = file_magic_bytes(body)
                ctype = (request.header("content-type") if label == "请求"
                         else (response.header("content-type") if response else ""))
                ctx.report(f"  导出 {filename}: {len(body)} 字节 · "
                           f"{kind} · md5={digest}"
                           + (f" · {ctype}" if ctype else ""), "info")
                ctx.add_finding(
                    "file", f"HTTP/2 {label}正文 stream {number}",
                    frame=frames, level="info",
                    detail=f"{len(body)} 字节 · {kind} · md5={digest}"
                           + (f" · {ctype}" if ctype else ""),
                    extra={"protocol": "http2"})
            ctx.check_cancel()
    table(ctx, "HTTP/2 摘要", ["帧", "流", "方法", "URL", "状态",
                               "请求字节", "响应字节"], summary, limit=MAX_LINES)
    if summary:
        ctx.write_output("http2_streams.txt", "\n".join(
            "\t".join(row) for row in summary) + "\n")
    if exported:
        ctx.report(f"已导出 {exported} 个 HTTP/2 正文", "good")
    return requests


def _http2_tshark(ctx: FeatureContext) -> int:
    fields = ["frame.number", "tcp.stream", "http2.headers.method",
              "http2.headers.path", "http2.headers.authority",
              "http2.headers.scheme", "http2.headers.authorization",
              "http2.headers.cookie", "http2.headers.set_cookie",
              "http2.headers.content_type", "http2.data.data"]
    rows = _rows(ctx, fields, "http2", limit=MAX_RAW)
    if not rows:
        return 0
    summary: list[list[str]] = []
    requests = 0
    for row in rows:
        row += [""] * (len(fields) - len(row))
        (frame, stream, method, path, authority, scheme, authorization,
         cookie, set_cookie, content_type, raw_body) = row
        url = ""
        if method or path or authority:
            requests += 1
            url = f"{scheme or 'https'}://{authority or '-'}{path or '/'}"
            summary.append([frame, stream, clean_cell(method or "", 16),
                            clean_cell(url, 240)])
            if requests <= MAX_LINES:
                ctx.report(f"[{frame}] {method or '-'} {url}", "good")
            ctx.add_finding("http", f"HTTP/2 {method or '-'} {url}",
                            frame=frame, detail=f"stream {stream}",
                            level="info")
        if authorization:
            basic = _decode_basic(authorization)
            if basic:
                account, _, secret = basic.partition(":")
                _credential(ctx, frame, f"HTTP/2 Basic {basic}",
                            detail=clean_cell(url, 300), protocol="http",
                            account=account, secret=secret)
            else:
                _credential(ctx, frame,
                            f"HTTP/2 Authorization {clean_cell(authorization, 180)}",
                            detail=clean_cell(url, 300), protocol="http")
        for value, label in ((cookie, "Cookie"), (set_cookie, "Set-Cookie")):
            if value:
                ctx.report(f"[{frame}] {label}: {clean_cell(value, 240)}",
                           "info")
                if re.search(r"(?i)(session|token|auth|jwt|remember)", value):
                    ctx.add_finding("protocol", f"HTTP/2 {label}",
                                    frame=frame,
                                    detail=clean_cell(value, 500),
                                    level="info")
        body = _text(raw_body)
        if body:
            for line in body.splitlines()[:20]:
                if line.strip():
                    ctx.report(f"[{frame}] 数据: {clean_cell(line, 240)}",
                               "info")
            _flags(ctx, body, frame, "HTTP/2 数据帧")
        ctx.check_cancel()
    table(ctx, "HTTP/2 摘要", ["帧", "流", "方法", "URL"], summary,
          limit=MAX_LINES)
    return requests


def http2(ctx: FeatureContext) -> None:
    detections = [item for item in detected(ctx, "http2")
                  if item["non_default"]]
    ctx.report("===== HTTP/2 =====", "good")
    requests = 0
    try:
        requests = _http2_raw(ctx, detections)
    except (ValueError, IndexError) as exc:
        ctx.report(f"HTTP/2 原始解析失败，回退 tshark: {exc}", "warn")
    if not requests:
        requests = _http2_tshark(ctx)
    if not requests:
        ctx.report("没有发现可解析的 HTTP/2 请求", "warn")


# ---------------------------------------------------------------------------
# SMB2 file access + NTLM context
# ---------------------------------------------------------------------------
SMB2_COMMANDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
    4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH", 8: "READ",
    9: "WRITE", 10: "LOCK", 11: "IOCTL", 12: "CANCEL", 13: "KEEPALIVE",
    14: "FIND", 15: "NOTIFY", 16: "GETINFO", 17: "SETINFO", 18: "BREAK",
    19: "SERVER_NOTIFY",
}
SMB2_FILE_OPS = {"CREATE", "READ", "WRITE", "SETINFO", "FIND"}
SMB2_WRITE_OPS = {"WRITE"}


def smb2_command_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.isdigit():
        return SMB2_COMMANDS.get(int(text), f"CMD_{text}")
    return text.upper()


def _smb2_path(share: str, name: str) -> str:
    share = (share or "").strip()
    name = (name or "").strip()
    if share and name:
        sep = "" if share.endswith("\\") or name.startswith("\\") else "\\"
        return share + sep + name
    return share or name


def _smb2_add_data(store: dict[int, bytes], offset: int, data: bytes) -> None:
    """Keep the first copy of each segment (SMB retransmits are identical)."""
    if data:
        store.setdefault(offset, data)


def _smb2_data(store: dict[int, bytes]) -> tuple[bytes, bool]:
    """Join ordered segments and report whether any gap was left."""
    if not store:
        return b"", False
    buffer = bytearray()
    expected = min(store)
    incomplete = False
    for offset in sorted(store):
        data = store[offset]
        if offset > expected:
            incomplete = True
            buffer.extend(b"\x00" * (offset - expected))
        elif offset < expected:
            data = data[expected - offset:]
        buffer.extend(data)
        expected = offset + len(data)
    return bytes(buffer), incomplete


def _smb2_raw(ctx: FeatureContext, detections: list[dict]) -> int:
    """Parse SMB2/3 directly from reassembled TCP streams."""
    clauses = ["smb2"]
    if detections:
        clauses.append(_stream_filter(detections))
    streams = _streams(ctx, clauses)
    if not streams:
        return 0
    groups: dict[str, list] = {}
    for item in streams:
        groups.setdefault(item.stream, []).append(item)
    server_ports = set(protocol_detect.default_ports("smb2"))
    server_ports.update(item["port"] for item in detections)

    total = 0
    shares: dict[str, str] = {}
    dialects: Counter = Counter()
    encrypted: list[tuple[str, int]] = []
    pending_encrypted = 0
    files: dict[tuple, dict] = {}
    tree_shares: dict[tuple[int, int], str] = {}
    users: dict[str, str] = {}
    dfs_paths: list[str] = []
    failures: list[tuple[str, str, str]] = []
    ops: Counter = Counter()

    for stream_id, items in groups.items():
        parsed: list[tuple[object, object]] = []
        for item in items:
            for message in smb_util.parse_messages(item.data):
                message.frame = item.frame_at(message.offset)
                parsed.append((item, message))
        # Server->client messages answer client->server ones with the same
        # MessageId; a global frame order lets us pair them in one pass.
        parsed.sort(key=lambda pair: _frame_number(pair[1].frame))
        by_message: dict[tuple[int, int], object] = {}
        for item, message in parsed:
            ctx.check_cancel()
            total += 1
            if getattr(message, "encrypted", False):
                pending_encrypted += 1
                encrypted.append((getattr(message, "frame", ""),
                                  getattr(message, "session_id", 0)))
                continue
            if getattr(message, "compressed", False):
                ctx.report(f"[{getattr(message, 'frame', '-')}] SMB3 压缩消息 "
                           f"（原始 {getattr(message, 'original_size', 0)} 字节）",
                           "info")
                continue
            frame = getattr(message, "frame", "") or "-"
            command = getattr(message, "command", -1)
            name = getattr(message, "command_name", "") or f"CMD_{command}"
            ops[name] += 1
            mid_key = (message.session_id, message.message_id)
            if not message.is_response:
                by_message[mid_key] = message
            if getattr(message, "status", 0) and message.is_failure:
                failures.append((frame, name, smb_util.decode_status(message.status)))
            if command == 0:  # NEGOTIATE
                if message.dialects:
                    for dialect in message.dialects:
                        dialects[smb_util.DIALECTS.get(dialect, f"0x{dialect:04x}")] += 1
                if message.dialect:
                    dialects[smb_util.DIALECTS.get(message.dialect,
                                                   f"0x{message.dialect:04x}")] += 1
                if message.is_response and (message.capabilities
                                            & smb_util.GLOBAL_CAP_ENCRYPTION):
                    ctx.report(f"[{frame}] SMB 服务端支持加密 "
                               f"(security_mode={message.security_mode:#x})",
                               "info")
            elif command == 1:  # SESSION_SETUP
                if message.user:
                    account = (f"{message.domain}\\{message.user}"
                               if message.domain else message.user)
                    users[account] = frame
                    ctx.report(f"[{frame}] SMB 认证账号 {account}"
                               + (f"（{message.auth_package}）"
                                  if message.auth_package else ""), "good")
                    _credential(ctx, frame, f"SMB2 账号 {account}",
                                detail=f"{message.auth_package} · "
                                       f"主机 {message.workstation or '-'}",
                                protocol="smb", account=account)
                elif message.auth_package:
                    ctx.report(f"[{frame}] SMB 认证使用 {message.auth_package}",
                               "info")
            elif command == 3:  # TREE_CONNECT
                if message.is_response:
                    request = by_message.get(mid_key)
                    share = getattr(request, "share", "") if request else ""
                    tree_shares[(message.session_id, message.tree_id)] = share
                    if share:
                        shares[share] = frame
                        level = "warn" if message.share_flags & smb_util.SHAREFLAG_ENCRYPT_DATA else "good"
                        ctx.report(f"[{frame}] 连接共享 {share}"
                                   + (f"（{message.share_type}）"
                                      if message.share_type else "")
                                   + (" [要求加密]"
                                      if message.share_flags
                                      & smb_util.SHAREFLAG_ENCRYPT_DATA else ""),
                                   level)
                        ctx.add_finding("protocol", f"SMB 共享 {share}",
                                        frame=frame, level="info",
                                        detail=f"类型 {message.share_type or '-'} · "
                                               f"flags {message.share_flags:#x}")
            elif command == 5:  # CREATE
                if message.is_response:
                    request = by_message.get(mid_key)
                    file_name = getattr(request, "file_name", "") if request else ""
                    key = (message.session_id, message.tree_id, message.file_id)
                    share = tree_shares.get((message.session_id, message.tree_id), "")
                    files[key] = {"name": file_name, "share": share,
                                  "frame": frame, "writes": {}, "reads": {},
                                  "attributes": message.file_attributes,
                                  "id": message.file_id.hex()}
                    if file_name:
                        path = _smb2_path(share, file_name)
                        level = "warn" if _is_pipe_path(path) else "info"
                        ctx.report(f"[{frame}] SMB 打开 {clean_cell(path, 240)}",
                                   level)
                        ctx.add_finding("file", f"SMB 打开 {path}",
                                        frame=frame, level=level,
                                        detail=f"create_options={message.create_options:#x}")
                else:
                    # The request was stored above; remember its attribute set.
                    pass
            elif command == 8:  # READ
                if message.is_response:
                    request = by_message.get(mid_key)
                    if request is not None:
                        key = (request.session_id, request.tree_id,
                               request.file_id)
                        entry = files.setdefault(key, {
                            "name": "", "share": "", "frame": frame,
                            "writes": {}, "reads": {}, "attributes": 0,
                            "id": request.file_id.hex()})
                        _smb2_add_data(entry["reads"], request.file_offset,
                                       message.read_data)
            elif command == 9:  # WRITE
                if not message.is_response:
                    key = (message.session_id, message.tree_id, message.file_id)
                    entry = files.setdefault(key, {
                        "name": "", "share": "", "frame": frame,
                        "writes": {}, "reads": {}, "attributes": 0,
                        "id": message.file_id.hex()})
                    _smb2_add_data(entry["writes"], message.file_offset,
                                   message.write_data)
            elif command == 11:  # IOCTL
                if message.ctl_name:
                    ctx.report(f"[{frame}] SMB IOCTL {message.ctl_name}"
                               f" ({message.ctl_code:#x})", "debug")
                if message.is_response and message.dfs_paths:
                    for path in message.dfs_paths:
                        if path not in dfs_paths:
                            dfs_paths.append(path)
                            ctx.report(f"[{frame}] DFS 引用 {path}", "warn")
                            ctx.add_finding("protocol", f"SMB DFS 引用 {path}",
                                            frame=frame, level="warn",
                                            detail=f"ctl {message.ctl_name}")
                if message.ctl_name == "PIPE_TRANSCEIVE":
                    entry = files.get((message.session_id, message.tree_id,
                                       message.file_id))
                    if entry is not None:
                        if message.ioctl_input:
                            _smb2_add_data(entry["writes"], 0,
                                           message.ioctl_input)
                        if message.ioctl_output:
                            _smb2_add_data(entry["reads"], 0,
                                           message.ioctl_output)
            elif command in (6, 7):  # CLOSE / FLUSH
                if message.is_response:
                    request = by_message.get(mid_key)
                    if request is not None:
                        key = (request.session_id, request.tree_id,
                               request.file_id)
                        entry = files.get(key)
                        if entry:
                            entry.setdefault("closed", frame)
            ctx.check_cancel()

    if pending_encrypted:
        ctx.report(f"SMB3 加密消息 {pending_encrypted} 条；"
                   f"需要会话密钥才能还原文件内容", "warn")
        sessions = sorted({session for _frame, session in encrypted if session})
        if sessions:
            ctx.report("加密会话 ID: " + ", ".join(f"{value:#x}"
                                                  for value in sessions[:20]),
                       "info")
    if dialects:
        ctx.report("SMB 协商方言: " + ", ".join(
            f"{name}×{count}" for name, count in dialects.most_common()), "info")
    if shares:
        ctx.report(f"共享 {len(shares)} 个: " + ", ".join(
            clean_cell(name, 120) for name in list(shares)[:20]), "good")
    if users:
        ctx.report("SMB 账号: " + ", ".join(sorted(users)), "good")

    exported = 0
    file_lines: list[str] = []
    pipe_lines: list[str] = []
    for entry in files.values():
        name = entry.get("name") or ""
        share = entry.get("share") or ""
        path = _smb2_path(share, name) or f"file_{entry.get('id', '')[:16]}"
        frame = entry.get("frame") or "-"
        is_pipe = _is_pipe_path(path)
        variants = []
        if entry.get("writes"):
            variants.append(("写入", *_smb2_data(entry["writes"])))
        if entry.get("reads"):
            variants.append(("读取", *_smb2_data(entry["reads"])))
        if not variants and is_pipe:
            pipe = smb_util.normalize_pipe(path)
            if pipe and pipe not in pipe_lines:
                pipe_lines.append(f"{frame}\t{pipe}\t0\t-")
                ctx.report(f"[{frame}] 命名管道 {pipe}（无数据）", "info")
            continue
        for direction, data, incomplete in variants:
            if not data:
                continue
            digest = hashlib.md5(data).hexdigest()
            kind = file_magic_bytes(data)
            safe = _safe_name(Path(path.replace("\\", "/")).name, "smb_file")
            if is_pipe:
                pipe = smb_util.normalize_pipe(path)
                pipe_lines.append(f"{frame}\t{pipe}\t{len(data)}\t{digest}")
                ctx.report(f"[{frame}] 命名管道 {pipe} {len(data)} 字节 "
                           f"({direction}) MD5 {digest}", "warn")
                ctx.write_output(
                    f"smb2_pipe_{_safe_name(pipe)}_{direction}.bin", data)
            else:
                file_lines.append(f"{frame}\t{path}\t{direction}\t"
                                  f"{len(data)}\t{kind}\t{digest}\t"
                                  f"{'不完整' if incomplete else '完整'}")
                ctx.report(f"[{frame}] SMB 文件 {clean_cell(path, 200)} "
                           f"{len(data)} 字节 ({direction}) {kind} "
                           f"MD5 {digest}"
                           + (" · 存在空洞" if incomplete else ""),
                           "warn" if incomplete else "good")
                ctx.write_output(
                    f"smb2_file_{frame}_{direction}_{safe}.bin", data)
                ctx.add_finding(
                    "file", f"SMB {direction} {path}", frame=frame,
                    level="warn" if incomplete else "info",
                    detail=f"{len(data)} 字节 · {kind} · md5={digest}"
                           + (" · 存在空洞" if incomplete else ""))
            exported += 1
            _flags(ctx, payload_text(data), frame,
                   f"SMB {'管道' if is_pipe else '文件'} {path}")
            ctx.check_cancel()

    for frame, operation, status in failures[:80]:
        ctx.report(f"[{frame}] SMB2 {operation} 失败: {status}", "warn")
    if ops:
        ctx.report("SMB2 命令统计: " + ", ".join(
            f"{name}×{count}" for name, count in ops.most_common(12)), "info")
    if file_lines:
        ctx.write_output("smb2_files.txt", "\n".join(file_lines) + "\n")
    if pipe_lines:
        ctx.write_output("smb2_pipes.txt", "\n".join(pipe_lines) + "\n")
    if dfs_paths:
        ctx.write_output("smb2_dfs.txt", "\n".join(dfs_paths) + "\n")
    if exported:
        ctx.report(f"还原 {exported} 个 SMB 文件/管道内容", "good")
    return total


def _is_pipe_path(path: str) -> bool:
    upper = (path or "").upper()
    return "IPC$" in upper or "\\PIPE\\" in upper or upper.startswith("PIPE\\")


def _smb2_tshark(ctx: FeatureContext, detections: list[dict]) -> int:
    extra = _detect_args("smb2", detections)
    fields = ["frame.number", "tcp.stream", "ip.src", "ip.dst", "smb2.cmd",
              "smb2.tree", "smb2.filename", "smb2.nt_status",
              "smb2.write_data", "smb2.read_data",
              "ntlmssp.auth.username", "ntlmssp.auth.domain",
              "ntlmssp.auth.hostname"]
    rows = _rows(ctx, fields, "smb2", limit=MAX_RAW, extra=extra)
    if not rows:
        return 0
    summary: list[list[str]] = []
    files: dict[str, str] = {}
    users: dict[str, str] = {}
    ops: Counter = Counter()
    for row in rows:
        row += [""] * (len(fields) - len(row))
        (frame, stream, src, dst, command, tree, filename, status,
         write_data, read_data, user, domain, hostname) = row
        op = smb2_command_name(command)
        if op:
            ops[op] += 1
        share = (tree or "").strip()
        name = (filename or "").strip()
        path = share + ("" if not name else ("\\" if share and not share.endswith("\\") else "") + name)
        if op in SMB2_FILE_OPS and (path or name):
            display = clean_cell(path or name, 240)
            files[display] = frame
            summary.append([frame, op, display, status or ""])
            if len(summary) <= MAX_LINES:
                ctx.report(f"[{frame}] {op} {display}"
                           + (f" status={status}" if status and status != "0" else ""),
                           "good" if op == "WRITE" else "info")
            ctx.add_finding("file", f"SMB2 {op} {display}", frame=frame,
                            detail=f"{src} -> {dst} stream {stream}",
                            level="warn" if op == "WRITE" else "info")
        if status and status not in ("0", "STATUS_SUCCESS"):
            ctx.report(f"[{frame}] SMB2 {op or '响应'} 状态 {status}", "warn")
        if user:
            account = f"{domain}\\{user}" if domain else user
            users[account] = frame
            _credential(ctx, frame, f"SMB2 NTLM {account}",
                        detail=f"host {hostname or '-'} · {src} -> {dst}",
                        protocol="smb", account=account)
        for raw, label in ((write_data, "写入"), (read_data, "读取")):
            text = _text(raw)
            if text:
                _flags(ctx, text, frame, f"SMB2 {label}数据")
        ctx.check_cancel()
    table(ctx, "SMB2 文件操作", ["帧", "操作", "共享/文件", "状态"], summary,
          limit=MAX_LINES)
    if ops:
        ctx.report("SMB2 命令统计: " + ", ".join(
            f"{name}×{count}" for name, count in ops.most_common(12)), "info")
    if files:
        ctx.write_output("smb2_files.txt",
                         "\n".join(f"{frame}\t{name}"
                                   for name, frame in files.items()))
    if users:
        ctx.report("NTLM 账号: " + ", ".join(sorted(users)), "good")
    return len(rows)


def smb2(ctx: FeatureContext) -> None:
    detections = [item for item in detected(ctx, "smb2")
                  if item["non_default"]]
    ctx.report("===== SMB2/3 =====", "good")
    _report_detections(ctx, "SMB2", detections)
    try:
        count = _smb2_raw(ctx, detections)
    except (ValueError, IndexError) as exc:
        ctx.report(f"SMB2 原始解析失败，回退 tshark: {exc}", "warn")
        count = 0
    if not count:
        count = _smb2_tshark(ctx, detections)
    if not count:
        ctx.report("没有发现 SMB2 流量", "warn")
        _raw_protocol_scan(ctx, "SMB2", detections)


# ---------------------------------------------------------------------------
# Port-independent protocol detection
# ---------------------------------------------------------------------------
def detect(ctx: FeatureContext) -> None:
    """Report protocols found on non-standard ports without a Decode As rule."""
    detections = detect_streams(ctx)
    ctx.report("===== 端口/协议自动识别 =====", "good")
    if not detections:
        ctx.report("没有识别到扩展协议流量", "warn")
        return
    rows = [[item["frame"], item["stream"], item["protocol"],
             str(item["port"]), f"{item['srcport']}->{item['dstport']}",
             "默认端口" if not item["non_default"] else "非默认端口"]
            for item in detections]
    table(ctx, "协议识别结果", ["帧", "流", "协议", "端口", "方向", "说明"],
          rows, limit=200)
    non_default = [item for item in detections if item["non_default"]]
    for item in non_default:
        ctx.report(f"非默认端口: {item['protocol']} 端口 {item['port']}"
                   f"（stream {item['stream']}，帧 {item['frame']}）", "good")
        ctx.add_finding(
            "protocol", f"{item['protocol']} 非默认端口 {item['port']}",
            frame=item["frame"], level="good",
            detail=f"stream {item['stream']} · "
                   f"{item['srcport']} -> {item['dstport']}")
    counts = Counter(item["protocol"] for item in detections)
    ctx.report("识别统计: " + ", ".join(
        f"{name}×{count}" for name, count in counts.most_common()), "info")
    if not non_default:
        ctx.report("所有识别结果都在默认端口，无需额外 Decode As", "info")
    lines = ["帧,流,协议,端口,说明"]
    for item in detections:
        lines.append(",".join([
            item["frame"], item["stream"], item["protocol"], str(item["port"]),
            "默认端口" if not item["non_default"] else "非默认端口",
        ]))
    ctx.write_output("protocol_detection.csv", "\n".join(lines) + "\n")
    ctx.set_progress(100)


# ---------------------------------------------------------------------------
# Combined special action
# ---------------------------------------------------------------------------
def credentials(ctx: FeatureContext) -> None:
    """Run the request/credential extractors for the extra protocols."""
    detect(ctx)
    handlers = [
        ("Redis", redis), ("MongoDB", mongodb), ("PostgreSQL", postgres),
        ("LDAP", ldap), ("WebSocket", websocket), ("HTTP/2", http2),
    ]
    for index, (name, handler) in enumerate(handlers):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(handlers) * 100))
        ctx.report(f"----- {name} -----", "debug")
        handler(ctx)
    ctx.report("多协议凭据/请求提取完成", "good")
    ctx.set_progress(100)
