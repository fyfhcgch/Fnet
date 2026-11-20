"""Plain-text log ingestion for Fnet.

Fnet's primary input is a capture, but incident triage often starts from a
plain-text log (Ceph audit logs, syslog/sshd, nginx access logs, JSON Lines,
CSV exports ...).  This module normalises those files into one small record
model so the handlers in :mod:`fnet.features.logs` share a single parser and
one set of statistics.

Only the standard library is used and nothing here calls tshark: a log job
therefore works on machines without Wireshark installed.

The parser is deliberately forgiving.  Format detection uses the first lines
of the file; records that do not fit are still kept as ``plain`` records so a
partially corrupted export never loses the whole file.  Both ``parse_text``
and ``parse_path`` are pure functions (the latter with a tiny mtime cache) and
are easy to unit test.
"""
from __future__ import annotations

import csv as _csv
import datetime as _dt
import ipaddress
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

#: Recognised capture suffixes (the existing pcap pipeline).
PCAP_SUFFIXES = frozenset({".pcap", ".pcapng", ".cap", ".dmp", ".etl"})

#: Suffixes treated as text logs even when the content sniff is inconclusive.
LOG_SUFFIXES = frozenset({".log", ".txt", ".out", ".jsonl", ".ndjson",
                          ".json", ".csv", ".tsv"})

#: Format names used by the WebUI/report (Chinese, like the rest of Fnet).
FORMAT_NAMES = {
    "ceph": "Ceph 审计日志",
    "syslog": "Syslog",
    "sshd": "SSH 认证日志",
    "apache": "HTTP 访问日志",
    "jsonl": "JSON Lines",
    "csv": "CSV/TSV 表格",
    "kv": "结构化文本（key: value）",
    "plain": "纯文本",
}

#: Guard rails: a huge log must not exhaust memory.  Parsing stops at the cap
#: and the handler reports that the file was truncated.
MAX_RECORDS = 200_000
MAX_LINE = 16_384
MAX_CSV_FIELDS = 128

#: pcap / pcapng magic numbers, used only when the suffix is unknown.
_PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
               b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")

_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![:0-9a-fA-F])(?:[0-9a-fA-F]{0,4}:){2,7}"
                      r"[0-9a-fA-F]{0,4}(?![:0-9a-fA-F])")
_ISO_RE = re.compile(
    r"^\s*\[?(\d{4}[-/]\d{2}[-/]\d{2})[T ](\d{2}:\d{2}:\d{2})"
    r"(?:[.,](\d{1,6}))?(Z|[+-]\d{2}:?\d{2})?\]?")
_EPOCH_RE = re.compile(r"^\s*\[?(\d{10}(?:\.\d+)?)(?:\]|\s)")
_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|"
    r"Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$")
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[[^\]]*\])\s*(?P<msg>.*)$")
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?')
_CEPH_RE = re.compile(
    r"^\s*\[?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\]?\s+ceph:\s*")
_SSHD_RE = re.compile(
    r"(?:Failed|Accepted)\s+(?:password|publickey|keyboard-interactive)"
    r"|Invalid user|Connection (?:closed|reset)|Disconnected from user",
    re.IGNORECASE)
_SSH_FAIL_RE = re.compile(
    r"Failed\s+(?P<method>password|publickey|keyboard-interactive/pam)"
    r"(?:\s+for\s+(?:invalid user\s+)?(?P<user>\S+))?"
    r"(?:\s+from\s+(?P<ip>\S+))?(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE)
_SSH_ACCEPT_RE = re.compile(
    r"Accepted\s+(?P<method>password|publickey|keyboard-interactive/pam)"
    r"\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE)
_SSH_INVALID_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)(?:\s+from\s+(?P<ip>\S+))?", re.IGNORECASE)

#: ``key: value`` pairs as seen in Ceph/structured text.  The lookahead ends a
#: value at the next ``, Label:`` so values may contain spaces ("Invalid key").
_KV_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9 _./-]{0,32}?)\s*:\s*"
    r"([^,;|]+?)(?=\s*(?:,\s*[A-Za-z][A-Za-z0-9 _./-]{0,32}?\s*:)|$)")
_EQ_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z_][A-Za-z0-9_.-]{0,32})="
    r"(\"[^\"]*\"|'[^']*'|\S+)")
_URL_LABELS = {"http", "https", "ftp", "file", "s3", "hdfs"}

_LEVEL_WORDS = (
    ("fatal", "error"), ("critical", "error"), ("crit", "error"),
    ("panic", "error"), ("emerg", "error"), ("alert", "error"),
    ("error", "error"), ("err", "error"),
    ("failed", "warn"), ("failure", "warn"), ("denied", "warn"),
    ("invalid", "warn"), ("unauthorized", "warn"), ("forbidden", "warn"),
    ("warn", "warn"), ("timeout", "warn"), ("timed out", "warn"),
    ("debug", "debug"), ("trace", "debug"),
)

_TIME_KEYS = ("time", "timestamp", "datetime", "date", "@timestamp", "ts",
              "event_time", "eventtime", "logged_at")
_LEVEL_KEYS = ("level", "severity", "loglevel", "log_level", "priority",
               "levelname")
_SOURCE_KEYS = ("logger", "service", "component", "program", "facility",
                "module", "source", "app", "application", "process")
_MESSAGE_KEYS = ("message", "msg", "event", "log", "text", "description",
                 "summary")
_IP_KEYS = ("client_ip", "src_ip", "source_ip", "remote_ip", "ip", "ip_address",
            "clientip")


def classify_input(path: str | Path) -> str | None:
    """Classify an input file as ``"pcap"``, ``"log"`` or ``None``.

    The suffix decides first; unknown suffixes fall back to a magic-byte
    sniff (capture) and finally to "looks like text".  This keeps the CLI and
    the WebUI in agreement about what can be opened.
    """
    target = Path(path).expanduser()
    suffix = target.suffix.lower()
    if suffix in PCAP_SUFFIXES:
        return "pcap"
    if suffix in LOG_SUFFIXES:
        return "log"
    try:
        with target.open("rb") as handle:
            head = handle.read(32)
    except OSError:
        return None
    if not head:
        return None
    if head[:4] in _PCAP_MAGIC:
        return "pcap"
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "log"
        except UnicodeDecodeError:
            # Latin-1 text is still text; arbitrary binary usually contains NUL.
            return "log" if head.isascii() else None
    return None


def is_log_input(path: str | Path) -> bool:
    return classify_input(path) == "log"


# ---------------------------------------------------------------------------
# Record model
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class LogRecord:
    """One normalised log line."""

    line: int
    raw: str
    time: str = ""
    epoch: float | None = None
    level: str = ""
    source: str = ""
    message: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    ips: tuple[str, ...] = ()

    def value(self, *names: str) -> str:
        """First non-empty value among ``names`` (case/format tolerant)."""
        for name in names:
            key = norm_key(name)
            for field_name, value in self.fields.items():
                if field_name == key and str(value).strip():
                    return str(value).strip()
        return ""


@dataclass(slots=True)
class LogFile:
    """Parsed log plus the metadata handlers need for their reports."""

    path: str
    format: str
    records: list[LogRecord]
    total_lines: int = 0
    skipped: int = 0
    truncated: bool = False
    size: int = 0

    @property
    def format_name(self) -> str:
        return FORMAT_NAMES.get(self.format, self.format)

    @property
    def fields(self) -> list[str]:
        """Field names in first-seen order."""
        seen: dict[str, None] = {}
        for record in self.records:
            for key in record.fields:
                seen.setdefault(key, None)
        return list(seen)

    def timespan(self) -> tuple[str, str, float]:
        """``(first_display, last_display, duration_seconds)`` of parsed times."""
        stamps = [record for record in self.records if record.epoch is not None]
        if not stamps:
            return "", "", 0.0
        first = min(stamps, key=lambda item: item.epoch)
        last = max(stamps, key=lambda item: item.epoch)
        return first.time, last.time, max(0.0, float(last.epoch - first.epoch))

    def levels(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            name = record.level or "info"
            counts[name] = counts.get(name, 0) + 1
        return counts

    def sources(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.records:
            name = record.source or record.value(*_SOURCE_KEYS) or "unknown"
            counts[name] = counts.get(name, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def norm_key(label: str) -> str:
    """``"Client IP"`` / ``"ClientID"`` -> ``"client_ip"`` / ``"client_id"``."""
    text = re.sub(r"[^0-9A-Za-z]+", "_", str(label or "").strip())
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return text.strip("_").lower()


def extract_ips(text: str) -> tuple[str, ...]:
    """Ordered, de-duplicated IP addresses found in ``text``."""
    found: dict[str, None] = {}
    for match in _IPV4_RE.finditer(str(text or "")):
        value = match.group(0)
        try:
            if ipaddress.ip_address(value).version == 4:
                found.setdefault(value, None)
        except ValueError:
            continue
    for match in _IPV6_RE.finditer(str(text or "")):
        value = match.group(0)
        if value.count(":") < 2:
            continue
        try:
            if ipaddress.ip_address(value).version == 6:
                found.setdefault(value, None)
        except ValueError:
            continue
    return tuple(found)


def level_from_text(text: str) -> str:
    lowered = str(text or "").lower()
    for word, level in _LEVEL_WORDS:
        if re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])",
                     lowered):
            return level
    return ""


def parse_time(value: str) -> tuple[str, float | None]:
    """Best-effort timestamp parser for the formats this module understands.

    Returns ``(display, epoch)``; ``display`` is always human readable and
    ``epoch`` is ``None`` when the string has no usable time.  Naive times are
    interpreted as UTC, matching :mod:`fnet.utils.evidence`.
    """
    text = str(value or "").strip().strip("[]")
    if not text:
        return "", None
    match = _ISO_RE.match(text)
    if match:
        date, clock, fraction, zone = match.groups()
        date = date.replace("/", "-")
        candidate = f"{date}T{clock}"
        if fraction:
            candidate += "." + fraction.ljust(6, "0")
        if zone:
            candidate += "+00:00" if zone in ("Z", "z") else zone
            if re.fullmatch(r"[+-]\d{2}", zone):
                candidate += ":00"
            else:
                candidate = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", candidate)
        try:
            stamp = _dt.datetime.fromisoformat(candidate)
        except ValueError:
            return f"{date} {clock}", None
        return stamp.strftime("%Y-%m-%d %H:%M:%S"), _epoch(stamp)
    match = _EPOCH_RE.match(text)
    if match:
        try:
            stamp = _dt.datetime.fromtimestamp(float(match.group(1)),
                                               tz=_dt.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return "", None
        return stamp.strftime("%Y-%m-%d %H:%M:%S"), float(match.group(1))
    apache = re.match(r"^(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})(?:\s+([+-]\d{4}))?", text)
    if apache:
        raw = apache.group(1) + (" " + apache.group(2) if apache.group(2) else "")
        pattern = "%d/%b/%Y:%H:%M:%S %z" if apache.group(2) else "%d/%b/%Y:%H:%M:%S"
        try:
            stamp = _dt.datetime.strptime(raw, pattern)
        except ValueError:
            return "", None
        return stamp.strftime("%Y-%m-%d %H:%M:%S"), _epoch(stamp)
    match = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})",
                     text)
    if match:
        mon, day, clock = match.groups()
        try:
            stamp = _dt.datetime.strptime(
                f"{mon} {day} {clock} {_dt.datetime.now().year}",
                "%b %d %H:%M:%S %Y")
        except ValueError:
            return "", None
        return stamp.strftime("%m-%d %H:%M:%S"), _epoch(stamp)
    return "", None


def _epoch(stamp: _dt.datetime) -> float:
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=_dt.timezone.utc)
    return stamp.timestamp()


def _level_from_priority(pri) -> str:
    try:
        severity = int(pri) % 8
    except (TypeError, ValueError):
        return ""
    if severity <= 3:
        return "error"
    if severity == 4:
        return "warn"
    if severity == 7:
        return "debug"
    return "info"


def _strip_time(text: str, match: re.Match | None) -> str:
    return text[match.end():].strip() if match else text.strip()


def _kv_fields(text: str) -> tuple[dict[str, str], str]:
    """Extract ``key: value`` / ``key=value`` pairs and the bare message."""
    fields: dict[str, str] = {}
    spans: list[tuple[int, int]] = []
    for match in _KV_RE.finditer(text):
        label = match.group(1).strip()
        value = match.group(2).strip()
        if not value or label.lower() in _URL_LABELS:
            continue
        key = norm_key(label)
        if not key or key.isdigit():
            continue
        fields.setdefault(key, value)
        spans.append((match.start(), match.end()))
    for match in _EQ_RE.finditer(text):
        label = match.group(1).strip()
        value = match.group(2).strip().strip("\"'")
        if not value or label.lower() in _URL_LABELS:
            continue
        key = norm_key(label)
        if key and not key.isdigit():
            fields.setdefault(key, value)
            spans.append((match.start(), match.end()))
    bare = text
    for start, end in sorted(spans, reverse=True):
        bare = bare[:start] + " " + bare[end:]
    parts = [part.strip() for part in re.split(r"[,;|]", bare) if part.strip()]
    return fields, ", ".join(parts)


def _ip_fields(records_fields: dict[str, str], raw: str) -> tuple[str, ...]:
    """Used only to expose the parsed fields; IPs are read from the raw line."""
    return extract_ips(raw)


def _finish(record: LogRecord, message: str = "") -> LogRecord:
    record.raw = record.raw[:MAX_LINE]
    if not record.message:
        record.message = (message or record.raw).strip()
    if not record.level:
        record.level = level_from_text(record.raw)
    if not record.time:
        match = _ISO_RE.match(record.raw) or _EPOCH_RE.match(record.raw)
        if match:
            record.time, record.epoch = parse_time(match.group(0))
    record.ips = _ip_fields(record.fields, record.raw)
    return record


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------
def _parse_ceph(line: str, lineno: int) -> LogRecord:
    match = _ISO_RE.match(line)
    time_text, epoch = parse_time(match.group(0)) if match else ("", None)
    body = _strip_time(line, match)
    body = re.sub(r"^ceph:\s*", "", body)
    fields, bare = _kv_fields(body)
    source = "ceph"
    message = bare or body
    if bare:
        fields.setdefault("event", bare)
    record = LogRecord(line=lineno, raw=line, time=time_text, epoch=epoch,
                       source=source, message=message, fields=fields)
    # Ceph's "Client IP" is the useful entity; also expose a short alias.
    if "client_ip" in fields:
        fields.setdefault("ip", fields["client_ip"])
    if "client_id" in fields:
        fields.setdefault("user", fields["client_id"])
    return _finish(record, message)


def _parse_generic(line: str, lineno: int) -> LogRecord:
    match = _ISO_RE.match(line) or _EPOCH_RE.match(line)
    time_text, epoch = parse_time(match.group(0)) if match else ("", None)
    body = _strip_time(line, match)
    source = ""
    source_match = re.match(r"^([A-Za-z][\w.-]{0,40})(?:\[\d+\])?:\s+", body)
    if source_match:
        source = source_match.group(1)
        body = body[source_match.end():]
    fields, bare = _kv_fields(body)
    message = bare or body
    record = LogRecord(line=lineno, raw=line, time=time_text, epoch=epoch,
                       source=source, message=message, fields=fields)
    return _finish(record, message)


def _parse_syslog(line: str, lineno: int) -> LogRecord:
    match = _RFC5424_RE.match(line)
    if match:
        time_text, epoch = parse_time(match.group("ts"))
        fields = {"host": match.group("host"),
                  "program": match.group("app"),
                  "pid": match.group("pid"),
                  "msgid": match.group("msgid")}
        fields = {key: value for key, value in fields.items()
                  if value and value != "-"}
        message = match.group("msg").strip()
        record = LogRecord(line=lineno, raw=line, time=time_text, epoch=epoch,
                           level=_level_from_priority(match.group("pri")),
                           source=match.group("app") if match.group("app") != "-" else "",
                           message=message, fields=fields)
        return _finish(record, message)
    match = _SYSLOG_RE.match(line)
    if not match:
        return _parse_generic(line, lineno)
    time_text, epoch = parse_time(
        f"{match.group('mon')} {match.group('day')} {match.group('hms')}")
    fields = {"host": match.group("host"), "program": match.group("proc"),
              "pid": match.group("pid")}
    fields = {key: value for key, value in fields.items() if value}
    message = match.group("msg").strip()
    record = LogRecord(line=lineno, raw=line, time=time_text, epoch=epoch,
                       level=_level_from_priority(match.group("pri")),
                       source=match.group("proc"), message=message,
                       fields=fields)
    return _finish(record, message)


def _parse_sshd(line: str, lineno: int) -> LogRecord:
    record = _parse_syslog(line, lineno)
    message = record.message
    failed = _SSH_FAIL_RE.search(message)
    accepted = _SSH_ACCEPT_RE.search(message)
    invalid = _SSH_INVALID_RE.search(message)
    match = failed or accepted or invalid
    if match:
        for key in ("user", "ip", "port", "method"):
            value = match.groupdict().get(key)
            if value:
                record.fields.setdefault(key, value)
    if failed:
        record.fields.setdefault("auth_result", "failed")
        record.level = "warn"
    elif accepted:
        record.fields.setdefault("auth_result", "accepted")
        record.level = "good"
    elif invalid:
        record.fields.setdefault("auth_result", "invalid_user")
        record.level = "warn"
    if not record.source:
        record.source = "sshd"
    return record


def _parse_apache(line: str, lineno: int) -> LogRecord:
    match = _APACHE_RE.match(line)
    if not match:
        return _parse_generic(line, lineno)
    time_text, epoch = parse_time(match.group("time"))
    request = match.group("request") or ""
    parts = request.split()
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    protocol = parts[2] if len(parts) > 2 else ""
    fields = {
        "ip": match.group("ip"),
        "user": match.group("user") if match.group("user") != "-" else "",
        "method": method,
        "path": path,
        "protocol": protocol,
        "status": match.group("status"),
        "bytes": match.group("bytes"),
        "referer": match.group("referer") or "",
        "user_agent": match.group("agent") or "",
    }
    fields = {key: value for key, value in fields.items()
              if value and value != "-"}
    try:
        status = int(match.group("status"))
    except ValueError:
        status = 0
    level = "error" if status >= 500 else "warn" if status >= 400 else "info"
    message = request or line
    record = LogRecord(line=lineno, raw=line, time=time_text, epoch=epoch,
                       level=level, source="http", message=message,
                       fields=fields)
    if "ip" in fields:
        fields.setdefault("client_ip", fields["ip"])
    return _finish(record, message)


def _flatten_json(value, prefix: str = "", out: dict | None = None,
                  depth: int = 0) -> dict:
    out = {} if out is None else out
    if depth > 6 or len(out) >= MAX_CSV_FIELDS:
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            _flatten_json(item, name, out, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value[:50]):
            _flatten_json(item, f"{prefix}.{index}" if prefix else str(index),
                          out, depth + 1)
    elif value is not None:
        out[prefix] = str(value)
    return out


def _parse_jsonl(payload: str, lineno: int, raw: str) -> LogRecord | None:
    try:
        value = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    fields = _flatten_json(value)
    lowered = {key.lower(): key for key in fields}

    def pick(keys) -> str:
        for name in keys:
            actual = lowered.get(name.lower())
            if actual is not None and str(fields[actual]).strip():
                return str(fields[actual]).strip()
        return ""

    time_text, epoch = parse_time(pick(_TIME_KEYS))
    level = pick(_LEVEL_KEYS).lower()
    if level not in ("debug", "info", "good", "warn", "error"):
        level = level_from_text(pick(_LEVEL_KEYS))
    source = pick(_SOURCE_KEYS)
    message = pick(_MESSAGE_KEYS)
    # Keep the display message readable: fall back to the JSON itself.
    record = LogRecord(line=lineno, raw=raw, time=time_text, epoch=epoch,
                       level=level, source=source, message=message,
                       fields=fields)
    if not message:
        record.message = raw
    return _finish(record, record.message)


def _parse_csv_row(fields: dict[str, str], raw: str, lineno: int) -> LogRecord:
    lowered = {key.lower(): key for key in fields}

    def pick(keys) -> str:
        for name in keys:
            actual = lowered.get(name.lower())
            if actual is not None and str(fields[actual]).strip():
                return str(fields[actual]).strip()
        return ""

    time_text, epoch = parse_time(pick(_TIME_KEYS))
    level = pick(_LEVEL_KEYS).lower()
    if level not in ("debug", "info", "good", "warn", "error"):
        level = level_from_text(pick(_LEVEL_KEYS))
    message = pick(_MESSAGE_KEYS)
    record = LogRecord(line=lineno, raw=raw, time=time_text, epoch=epoch,
                       level=level, source=pick(_SOURCE_KEYS),
                       message=message or raw, fields=dict(fields))
    if not record.fields.get("ip"):
        for key in _IP_KEYS:
            actual = lowered.get(key)
            if actual and record.fields.get(actual):
                record.fields.setdefault("ip", record.fields[actual])
                break
    return _finish(record, record.message)


# ---------------------------------------------------------------------------
# Detection + entry points
# ---------------------------------------------------------------------------
def detect_format(lines: Iterable[str], name: str = "") -> str:
    """Sniff a log format from its first lines (suffix hints included)."""
    sample = [str(line).strip() for line in lines if str(line).strip()]
    if not sample:
        return "plain"
    suffix = Path(name).suffix.lower()
    first = sample[0]
    if first.startswith("{"):
        for line in sample[:20]:
            if not line.startswith("{"):
                continue
            try:
                if isinstance(json.loads(line), dict):
                    return "jsonl"
            except (ValueError, TypeError):
                continue
    if suffix in (".csv", ".tsv"):
        return "csv"
    if _CEPH_RE.match(first) or re.search(r"(?:^|\s)ceph:\s", first):
        return "ceph"
    if _APACHE_RE.match(first):
        return "apache"
    if any(_SSHD_RE.search(line) for line in sample[:200]):
        return "sshd"
    if _SYSLOG_RE.match(first) or _RFC5424_RE.match(first):
        return "syslog"
    # Generic "timestamp + key: value" text without a process name.
    hits = 0
    inspected = 0
    for line in sample[:200]:
        inspected += 1
        if _ISO_RE.match(line) and _KV_RE.search(line):
            hits += 1
    if inspected and hits >= max(1, inspected // 2):
        return "kv"
    return "plain"


def parse_text(text: str, name: str = "") -> LogFile:
    """Parse a log held in memory (used by tests and pasted input)."""
    raw_lines = str(text or "").splitlines()
    fmt = detect_format(raw_lines[:200], name)
    return _parse_lines(raw_lines, name=name, fmt=fmt, size=len(text or ""))


def parse_path(path: str | Path, limit: int = MAX_RECORDS) -> LogFile:
    """Parse a log file from disk (mtime/size cached, capped in memory).

    The cache only holds the *immutable* raw material (``fmt``/``lines``/
    ``truncated``); the :class:`LogFile` itself is rebuilt on every call so
    callers can mutate ``records`` freely.  Handing out a shared ``LogFile``
    used to let two concurrent jobs (``logs.*`` + ``text_scan.*``) see each
    other's edits under ``ThreadingHTTPServer``.
    """
    target = Path(path).expanduser()
    try:
        stat = target.stat()
    except OSError:
        return LogFile(str(target), "plain", [], size=0)
    fmt, lines, truncated = _read_path_cached(
        str(target), stat.st_mtime_ns, stat.st_size, stat.st_ctime_ns,
        max(1, int(limit)))
    return _parse_lines(lines, name=str(target), fmt=fmt, size=stat.st_size,
                        limit=max(1, int(limit)), truncated=truncated)


@lru_cache(maxsize=2)
def _read_path_cached(path: str, mtime_ns: int, size: int, ctime_ns: int,
                      limit: int) -> tuple[str, tuple[str, ...], bool]:
    """Return ``(format, lines, truncated)`` — never a mutable ``LogFile``.

    ``ctime_ns`` participates in the key because ``tar -x`` / ``rsync -t``
    restore ``mtime`` and size, which used to make a stale parse look fresh.
    """
    del mtime_ns, ctime_ns  # part of the cache key only
    try:
        with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
            head: list[str] = []
            for line in handle:
                stripped = line.rstrip("\r\n")
                if stripped.strip():
                    head.append(stripped)
                if len(head) >= 200:
                    break
            fmt = detect_format(head, path)
            handle.seek(0)
            lines: list[str] = []
            truncated = False
            for index, line in enumerate(handle, 1):
                if index > limit:
                    truncated = True
                    break
                lines.append(line.rstrip("\r\n"))
    except OSError:
        return "plain", (), False
    return fmt, tuple(lines), truncated


def _parse_lines(lines: list[str], name: str, fmt: str, size: int,
                 limit: int = MAX_RECORDS,
                 truncated: bool = False) -> LogFile:
    records: list[LogRecord] = []
    skipped = 0
    header: list[str] | None = None
    delimiter = "\t" if (Path(name).suffix.lower() == ".tsv") else ","
    for index, raw in enumerate(lines, 1):
        if len(records) >= limit:
            truncated = True
            break
        line = raw.strip("\ufeff").rstrip("\r\n")
        if not line.strip():
            skipped += 1
            continue
        if fmt == "csv":
            if header is None:
                header = _csv_header(line, delimiter)
                continue
            row = _csv_row(line, header, delimiter)
            if row is None:
                skipped += 1
                continue
            records.append(_parse_csv_row(row, line, index))
            continue
        if fmt == "jsonl":
            record = _parse_jsonl(line, index, line)
            if record is None:
                skipped += 1
            else:
                records.append(record)
            continue
        parser = {
            "ceph": _parse_ceph,
            "syslog": _parse_syslog,
            "sshd": _parse_sshd,
            "apache": _parse_apache,
            "kv": _parse_generic,
        }.get(fmt, _parse_generic)
        try:
            records.append(parser(line, index))
        except Exception:  # noqa: BLE001 - one bad line must not kill the file
            skipped += 1
    return LogFile(name, fmt, records, total_lines=len(lines),
                   skipped=skipped, truncated=truncated, size=size)


def _csv_header(line: str, delimiter: str) -> list[str]:
    try:
        row = next(_csv.reader([line], delimiter=delimiter))
    except (_csv.Error, StopIteration):
        row = line.split(delimiter)
    names = []
    seen: dict[str, int] = {}
    for index, cell in enumerate(row[:MAX_CSV_FIELDS], 1):
        name = norm_key(cell) or f"col_{index}"
        count = seen.get(name, 0)
        seen[name] = count + 1
        names.append(name if not count else f"{name}_{count + 1}")
    return names


def _csv_row(line: str, header: list[str], delimiter: str) -> dict | None:
    try:
        row = next(_csv.reader([line], delimiter=delimiter))
    except (_csv.Error, StopIteration):
        return None
    if not row or all(not str(cell).strip() for cell in row):
        return None
    fields = {}
    for index, cell in enumerate(row[:MAX_CSV_FIELDS]):
        key = header[index] if index < len(header) else f"col_{index + 1}"
        fields[key] = str(cell).strip()
    return fields
