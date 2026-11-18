"""Log-evidence import and correlation (Suricata eve.json / Zeek logs).

Roadmap item "日志证据关联": analysts often have a pcap plus the sensor logs
produced around the same incident (Suricata ``eve.json``, Zeek TSV/JSON logs).
This module imports those logs into one normalised event shape — a small
Common-Event-Model-style record with timestamp, 5-tuple, source, type and a
human summary — and correlates them with the structured findings of a pcap
job by IP pair / port overlap / time window.  The correlation pairs are meant
to be rendered as the corroborating-evidence section of a report by a later
wiring step (the module itself stays UI-free and stdlib-only).

Nothing here touches tshark or the job pipeline: both ``parse_events`` and
``correlate`` are pure functions over text/lists so they are trivially
unit-testable and reusable from the CLI, WebUI or plugins.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Iterable

#: Hard caps so a huge eve.json cannot exhaust memory or produce endless pairs.
MAX_EVENTS = 20_000
MAX_PAIRS = 2_000

#: Default match window in seconds (event time vs. finding capture time).
DEFAULT_WINDOW = 300.0

#: Zeek log types understood by the importer.  Any other log type is still
#: imported with its 5-tuple fields when present.
ZEEK_LOG_TYPES = ("conn", "http", "dns", "ssl", "notice")

#: Canonical keys of a normalised evidence event.
EVENT_FIELDS = ("time", "epoch", "src_ip", "src_port", "dst_ip", "dst_port",
                "proto", "source", "type", "summary", "category", "severity",
                "signature", "ref")

_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_PORT_PATTERNS = (
    # Explicit protocol suffix or Chinese/English "port" wording.
    re.compile(r"(?<![\d.])(\d{1,5})/(?:tcp|udp)", re.IGNORECASE),
    re.compile(r"(?:端口|port)[=:：\s]+(\d{1,5})", re.IGNORECASE),
    # ip:port pairs next to an extracted IPv4 address.
    re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?![\d.])"),
)

_EMPTY_TOKENS = {"-", "(empty)", "", "(unknown)"}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _clean(value) -> str:
    text = str(value if value is not None else "").strip()
    return "" if text.lower() in _EMPTY_TOKENS else text


def _as_port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _epoch_from_naive(stamp: _dt.datetime) -> float:
    """Naive 时间按 UTC 处理；带时区的 datetime 保留其原始偏移。"""
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=_dt.timezone.utc)
    return stamp.timestamp()


def parse_timestamp(value) -> float | None:
    """Best-effort conversion of a log/finding timestamp to a Unix epoch.

    Accepts epoch numbers, Suricata/ISO-8601 strings (``...T...+0000``),
    ``YYYY-MM-DD HH:MM:SS[.fff]`` strings and plain ``HH:MM:SS``.  Returns
    ``None`` when nothing parseable remains; naive times are read as UTC,
    which keeps correlation consistent within one evidence set.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    candidate = text
    if candidate[-1:] in ("Z", "z"):
        candidate = candidate[:-1] + "+00:00"
    # Python 3.10 的 datetime.fromisoformat 不接受 "+0000"/"+00" 这种紧凑偏移，
    # 3.11+ 才放宽；这里统一补成 "+00:00"，仅在含时间（冒号）的字符串上处理，
    # 避免把日期 "2026-01-01" 的 "-01" 误当成时区。
    if ":" in candidate:
        candidate = re.sub(r"([+-])(\d{2})(\d{2})$", r"\1\2:\3", candidate)
        candidate = re.sub(r"([+-])(\d{2})$", r"\1\2:00", candidate)
    try:
        return _epoch_from_naive(_dt.datetime.fromisoformat(candidate))
    except ValueError:
        pass
    for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S", "%H:%M:%S.%f", "%H:%M:%S"):
        stamp = candidate.split(" ")[0] if pattern.startswith("%H") else candidate
        try:
            return _epoch_from_naive(_dt.datetime.strptime(stamp, pattern))
        except ValueError:
            continue
    return None


def _valid_ipv4(text: str) -> bool:
    parts = str(text or "").split(".")
    return len(parts) == 4 and all(
        part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def extract_ips(text) -> list[str]:
    """Ordered, de-duplicated IPv4 addresses found in free text.

    Octets outside ``0..255`` are rejected so version strings such as
    ``999.1.2.3`` never become correlation indicators.
    """
    seen: list[str] = []
    for match in _IP_RE.finditer(str(text or "")):
        ip = match.group(0)
        if _valid_ipv4(ip) and ip not in seen:
            seen.append(ip)
    return seen


def extract_ports(text) -> list[int]:
    """Ordered, de-duplicated port numbers found in free text."""
    ports: list[int] = []
    for pattern in _PORT_PATTERNS:
        for match in pattern.finditer(str(text or "")):
            port = _as_port(match.group(1))
            if port and port not in ports:
                ports.append(port)
    return ports


def _event(**fields) -> dict:
    record = {key: "" for key in EVENT_FIELDS}
    record["epoch"] = None
    record["src_port"] = None
    record["dst_port"] = None
    record["severity"] = None
    record.update(fields)
    return record


def finding_epoch(finding: dict) -> float | None:
    """Finding-side timestamp for correlation.

    Prefers the capture-side timestamp (``frame.time`` style) over
    ``extra.time``; the wall-clock ``time`` field is only used when it carries
    a date (a bare ``HH:MM:SS`` says nothing about the capture day and would
    poison the time window).  Returns ``None`` when nothing usable remains.
    """
    if not isinstance(finding, dict):
        return None
    for key in ("capture", "extra.time"):
        value = finding
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        stamp = parse_timestamp(value)
        if stamp is not None:
            return stamp
    time_field = str(finding.get("time") or "")
    if any(sep in time_field for sep in ("-", "/")):
        stamp = parse_timestamp(time_field)
        if stamp is not None:
            return stamp
    return None


def _finding_endpoints(finding: dict) -> tuple[list[str], list[int]]:
    """Best-effort IP/port extraction from a finding record's free text.

    ``ips`` / ``ports`` keys (top level or inside ``extra``) override the
    regex extraction so handlers can supply structured values later.
    """
    extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
    ips: list[str] = []
    ports: list[int] = []
    raw_ips = finding.get("ips") or extra.get("ips")
    raw_ports = finding.get("ports") or extra.get("ports")
    if raw_ips:
        items = (raw_ips if isinstance(raw_ips, (list, tuple))
                 else str(raw_ips).split(","))
        ips = [str(item).strip() for item in items if str(item).strip()]
    if raw_ports:
        if isinstance(raw_ports, (list, tuple)):
            ports = [_as_port(item) for item in raw_ports]
        else:
            ports = [_as_port(item) for item in re.split(r"[,\s]+", str(raw_ports))]
        ports = [port for port in ports if port]
    text = " ".join(str(finding.get(key) or "") for key in
                    ("summary", "detail", "frame", "feature"))
    if not ips:
        ips = extract_ips(text)
    if not ports:
        ports = extract_ports(text)
    return ips, ports


# ---------------------------------------------------------------------------
# Suricata eve.json
# ---------------------------------------------------------------------------
def parse_suricata_eve(text: str,
                       event_types: Iterable[str] | None = None) -> list[dict]:
    """Parse Suricata ``eve.json`` (one JSON object per line).

    ``event_types`` filters the imported ``event_type`` values (``None`` keeps
    everything); pass ``("alert", "flow")`` to restrict imports to those
    event types.  Malformed or non-JSON lines are skipped silently.
    """
    wanted = None
    if event_types is not None:
        wanted = {str(item).strip().lower()
                  for item in event_types if str(item).strip()}
    events: list[dict] = []
    for line in str(text or "").splitlines():
        if len(events) >= MAX_EVENTS:
            break
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        event_type = _clean(data.get("event_type")).lower()
        if wanted is not None and event_type not in wanted:
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        signature = _clean(alert.get("signature"))
        category = _clean(alert.get("category"))
        try:
            severity = (int(alert["severity"])
                        if alert.get("severity") is not None else None)
        except (TypeError, ValueError):
            severity = None
        if event_type == "alert":
            summary = signature or "alert"
            if category:
                summary = f"{summary} [{category}]"
            if severity is not None:
                summary = f"{summary} (severity {severity})"
        elif event_type == "dns":
            dns = data.get("dns") if isinstance(data.get("dns"), dict) else {}
            target = _clean(dns.get("rrname") or dns.get("query"))
            summary = f"DNS 查询 {target}" if target else "DNS 事件"
        elif event_type == "http":
            http = data.get("http") if isinstance(data.get("http"), dict) else {}
            method = _clean(http.get("http_method"))
            hostname = _clean(http.get("hostname"))
            url = _clean(http.get("url"))
            target = f"{hostname}{url}" if hostname or url else ""
            summary = " ".join(part for part in (method, target) if part) \
                or "HTTP 请求"
        elif event_type == "fileinfo":
            info = data.get("fileinfo") \
                if isinstance(data.get("fileinfo"), dict) else {}
            filename = _clean(info.get("filename"))
            summary = f"文件 {filename}" if filename else "文件事件"
        else:
            summary = f"{event_type or 'event'} 事件"
        events.append(_event(
            time=str(data.get("timestamp") or ""),
            epoch=parse_timestamp(data.get("timestamp")),
            src_ip=_clean(data.get("src_ip")),
            src_port=_as_port(data.get("src_port")),
            dst_ip=_clean(data.get("dest_ip")),
            dst_port=_as_port(data.get("dest_port")),
            proto=_clean(data.get("proto")).lower(),
            source="suricata:eve",
            type=event_type or "event",
            summary=summary,
            category=category,
            severity=severity,
            signature=signature,
            ref=_clean(data.get("flow_id")),
        ))
    return events


# ---------------------------------------------------------------------------
# Zeek logs (TSV with #headers and JSON streaming)
# ---------------------------------------------------------------------------
def _first_value(value) -> str:
    """First element of a Zeek set/list field (``tx_hosts`` is comma-joined)."""
    text = _clean(value)
    return re.split(r"[,\s]+", text)[0] if text else ""


def _zeek_endpoints(record: dict) -> tuple[str, int | None, str, int | None]:
    """Extract the 5-tuple endpoints from nested (``id.orig_h``) or flat keys.

    ``files``/``ssl``-style logs that only carry ``tx_hosts``/``rx_hosts`` or
    IPv6 ``id.orig_h6``/``id.resp_h6`` columns are supported too.
    """
    identifiers = record.get("id") if isinstance(record.get("id"), dict) else {}
    src_ip = _clean(identifiers.get("orig_h") or record.get("id.orig_h")) \
        or _first_value(record.get("tx_hosts") or record.get("id.orig_h6"))
    dst_ip = _clean(identifiers.get("resp_h") or record.get("id.resp_h")) \
        or _first_value(record.get("rx_hosts") or record.get("id.resp_h6"))
    src_port = _as_port(identifiers.get("orig_p") or record.get("id.orig_p"))
    dst_port = _as_port(identifiers.get("resp_p") or record.get("id.resp_p"))
    return src_ip, src_port, dst_ip, dst_port


def _zeek_summary(log_type: str, record: dict, event: dict) -> str:
    src_ip, src_port, dst_ip, dst_port = (event["src_ip"], event["src_port"],
                                          event["dst_ip"], event["dst_port"])
    if log_type == "http":
        host, uri = _clean(record.get("host")), _clean(record.get("uri"))
        method = _clean(record.get("method"))
        parts = [part for part in (method, f"{host}{uri}" if host or uri else "")
                 if part]
        summary = " ".join(parts) or "http 请求"
        if _clean(record.get("status_code")):
            summary += f" -> {_clean(record.get('status_code'))}"
        return summary
    if log_type == "dns":
        rcode = _clean(record.get("rcode_name"))
        summary = f"DNS 查询 {_clean(record.get('query')) or '?'}"
        return summary + (f" ({rcode})" if rcode else "")
    if log_type == "ssl":
        sni = _clean(record.get("server_name"))
        version = _clean(record.get("version"))
        summary = "TLS 会话"
        if sni:
            summary += f" SNI={sni}"
        if version:
            summary += f" ({version})"
        return summary
    if log_type == "notice":
        note, message = _clean(record.get("note")), _clean(record.get("msg"))
        if note and message:
            return f"{note}: {message}"
        return note or message or "notice"
    if log_type in ("conn", ""):
        service = _clean(record.get("service"))
        summary = (f"连接 {src_ip or '?'}:{src_port or '?'} -> "
                   f"{dst_ip or '?'}:{dst_port or '?'}")
        tail = "/".join(part for part in (event["proto"], service) if part)
        return summary + (f" ({tail})" if tail else "")
    return f"{log_type or 'event'} 事件"


def _zeek_event(log_type: str, record: dict, source: str) -> dict:
    src_ip, src_port, dst_ip, dst_port = _zeek_endpoints(record)
    epoch = parse_timestamp(record.get("ts"))
    event = _event(
        time=str(record.get("ts") or ""),
        epoch=epoch,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=_clean(record.get("proto")).lower(),
        source=source,
        type=log_type or "event",
        summary="",
        category=_clean(record.get("note")) if log_type == "notice"
        else _clean(record.get("category")),
        signature=_clean(record.get("signature")),
        ref=_clean(record.get("uid") or record.get("flow_id")),
    )
    event["summary"] = _zeek_summary(log_type, record, event)
    return event


def _zeek_json_event(record: dict) -> dict:
    log_type = _clean(record.get("_path")).lower()
    return _zeek_event(log_type, record, f"zeek:{log_type}" if log_type else "zeek")


def _zeek_tsv_type(field_names: set[str]) -> str:
    if "uri" in field_names or "host" in field_names:
        return "http"
    if "query" in field_names:
        return "dns"
    if "server_name" in field_names:
        return "ssl"
    if "note" in field_names:
        return "notice"
    if "id.orig_h" in field_names or "uid" in field_names:
        return "conn"
    return "event"


def _zeek_fields(line: str, fields: dict[int, str]) -> None:
    """Update the column map from an inline ``#fields`` header line.

    Headers are handled per line instead of per file so a single evidence set
    can contain several Zeek log blocks (or Zeek blocks after other input).
    """
    if not line.startswith("#fields"):
        return
    for index, name in enumerate(line.split("\t")[1:]):
        fields[index] = name.strip()


def _zeek_tsv_event(line: str, fields: dict[int, str]) -> dict | None:
    row = {fields.get(index, f"col{index}"): value
           for index, value in enumerate(line.split("\t"))}
    if not any(key in row for key in ("ts", "id.orig_h", "uid")):
        return None
    # A stray short line under a #fields map must not become a fake record.
    has_ts = parse_timestamp(row.get("ts")) is not None
    has_endpoints = any(_clean(row.get(key)) for key in
                        ("id.orig_h", "id.resp_h")) or _clean(row.get("uid"))
    if not (has_ts or has_endpoints):
        return None
    log_type = _zeek_tsv_type(set(fields.values()))
    event = _zeek_event(log_type, row, "zeek:tsv")
    if not log_type or log_type == "event":
        event["type"] = "event"
    return event


def parse_zeek(text: str) -> list[dict]:
    """Parse Zeek logs in either the classic TSV or the JSON streaming format.

    Supports ``conn`` / ``http`` / ``dns`` / ``ssl`` / ``notice`` (and imports
    any other log's 5-tuple fields generically).  TSV header lines
    (``#separator``, ``#fields``, ``#types`` …), ``-`` / ``(empty)`` values and
    malformed lines are tolerated; Zeek JSON records (``_path``) are mapped the
    same way.
    """
    lines = str(text or "").splitlines()
    fields: dict[int, str] = {}
    events: list[dict] = []
    for line in lines:
        if len(events) >= MAX_EVENTS:
            break
        line = line.rstrip("\r")
        if not line or line.startswith("#"):
            _zeek_fields(line, fields)
            continue
        if line.lstrip().startswith("{"):
            try:
                record = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(record, dict):
                events.append(_zeek_json_event(record))
            continue
        event = _zeek_tsv_event(line, fields)
        if event is not None:
            events.append(event)
    return events


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------
def detect_format(text: str) -> str | None:
    """Sniff an evidence log without normalising it.

    Returns ``"suricata"`` for ``eve.json`` JSON Lines, ``"zeek"`` for Zeek TSV
    (``#fields``/``#separator`` headers) or Zeek JSON streaming (``_path``) and
    ``None`` when no line looks like either format.  Uses the same per-line
    rules as :func:`parse_events` so callers do not re-implement detection.
    """
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("#separator", "#fields", "#path", "#types")):
            return "zeek"
        if not stripped.startswith("{"):
            continue
        try:
            record = json.loads(stripped)
        except (ValueError, TypeError):
            continue
        if not isinstance(record, dict):
            continue
        if "timestamp" in record or "event_type" in record:
            return "suricata"
        if "_path" in record:
            return "zeek"
    return None


def parse_events(text: str) -> list[dict]:
    """Auto-detect and import evidence logs (eve.json / Zeek TSV / Zeek JSON).

    Lines are dispatched individually: JSON objects that look like Suricata
    events (``timestamp`` / ``event_type``) go to the eve parser, other JSON
    objects go to the Zeek JSON path and everything else is treated as Zeek
    TSV.  Unknown or malformed lines are skipped, so partially corrupted
    exports still import.
    """
    lines = str(text or "").splitlines()
    fields: dict[int, str] = {}
    events: list[dict] = []
    for line in lines:
        if len(events) >= MAX_EVENTS:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            _zeek_fields(line, fields)
            continue
        if not line.startswith("{"):
            event = _zeek_tsv_event(line, fields)
            if event is not None:
                events.append(event)
            continue
        try:
            record = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(record, dict):
            continue
        if "timestamp" in record or "event_type" in record:
            events.extend(parse_suricata_eve(line))
        else:
            events.append(_zeek_json_event(record))
    return events


def parse_file(path) -> list[dict]:
    """Read an evidence log from disk with :func:`parse_events`."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_events(text)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
def correlate(events: Iterable[dict], findings: Iterable[dict],
              window: float = DEFAULT_WINDOW,
              min_score: int = 3) -> list[dict]:
    """Correlate evidence events with structured pcap findings.

    Scoring per (finding, event) pair:

    - **IP 对（任意方向）**: ``+2`` when both endpoints of the event appear in
      the finding's IPs, ``+1`` when one matches;
    - **端口重叠**: ``+1`` when the event src/dst port is among the finding's
      ports (neutral when the finding has no extractable ports);
    - **时间窗口**: ``+2`` when ``|event - finding| <= window`` seconds.  When
      both timestamps are parseable but outside the window the pair is
      rejected; when either side has no usable time the criterion is neutral.

    A pair is returned when ``ip_score >= 1`` and ``score >= min_score`` (so
    the default requires, e.g., both IPs + a port, both IPs + time, or one IP
    + port + time).  Each item carries ``finding_index`` / ``event_index``,
    the matched records, the score and a ``reasons`` list (``ip:both`` /
    ``ip:<addr>`` / ``port`` / ``time``) so a report can explain why the
    evidence corroborates the finding.
    """
    window = float(window)
    prepared: list[tuple[int, dict, set[str], set[int], float | None]] = []
    for index, finding in enumerate(findings or []):
        if not isinstance(finding, dict):
            continue
        ips, ports = _finding_endpoints(finding)
        prepared.append((index, finding, set(ips), set(ports),
                         finding_epoch(finding)))
    if not prepared:
        return []
    # Inverted index over finding IPs: only findings sharing an IP with the
    # event can ever reach ``min_score``, so a 20k-event import stays fast.
    by_ip: dict[str, list[tuple[int, dict, set[str], set[int], float | None]]] = {}
    for entry in prepared:
        for ip in entry[2]:
            by_ip.setdefault(ip, []).append(entry)

    pairs: list[dict] = []
    for event_index, event in enumerate(events or []):
        if not isinstance(event, dict):
            continue
        event_ips = {str(event.get("src_ip") or ""), str(event.get("dst_ip") or "")}
        event_ips.discard("")
        event_ports = {event.get("src_port"), event.get("dst_port")}
        event_ports.discard(None)
        event_epoch = event.get("epoch")
        if not isinstance(event_epoch, (int, float)) or isinstance(event_epoch, bool):
            event_epoch = parse_timestamp(event.get("time"))
        else:
            event_epoch = float(event_epoch)
        candidates = {entry[0]: entry for ip in event_ips
                      for entry in by_ip.get(ip, ())}
        for finding_index, finding, ips, ports, finding_time in \
                sorted(candidates.values(), key=lambda entry: entry[0]):
            matched_ips = event_ips & ips
            if not matched_ips:
                continue
            ip_score = 2 if len(matched_ips) >= 2 and len(event_ips) >= 2 else 1
            reasons = ["ip:both" if ip_score == 2
                       else f"ip:{sorted(matched_ips)[0]}"]
            port_hit = bool(ports and event_ports & ports)
            if port_hit:
                reasons.append("port")
            time_delta: float | None = None
            if event_epoch is not None and finding_time is not None:
                time_delta = abs(event_epoch - finding_time)
                if time_delta > window:
                    continue
                reasons.append("time")
            score = ip_score + (1 if port_hit else 0) + (2 if time_delta is not None else 0)
            if score < min_score:
                continue
            pairs.append({
                "finding_index": finding_index,
                "event_index": event_index,
                "score": score,
                "reasons": reasons,
                "ip_score": ip_score,
                "port_overlap": port_hit,
                "time_delta": time_delta,
                "finding": finding,
                "event": event,
            })
            if len(pairs) >= MAX_PAIRS:
                break
        if len(pairs) >= MAX_PAIRS:
            break
    pairs.sort(key=lambda pair: (-pair["score"], pair["finding_index"],
                                 pair["event_index"]))
    return pairs[:MAX_PAIRS]
