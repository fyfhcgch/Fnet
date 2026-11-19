"""Structured findings collected by feature handlers.

Handlers keep writing human readable log lines, but notable results
(credentials, hashes, flags, decoded payloads, exported files ...) are also
recorded as small, tab friendly records.  The job worker persists them next to
the reports as ``findings.json`` and ``findings.csv`` so the WebUI result table,
the report exporters and the CLI can all reuse the same data.
"""
from __future__ import annotations

import csv
import datetime as _dt
import io
from typing import Iterable

#: Hard limits so a noisy capture cannot exhaust memory or disk.
MAX_FINDINGS = 5_000
MAX_SUMMARY = 400
MAX_DETAIL = 4_000

#: Kinds are deliberately coarse: the UI groups by them and reports label them.
KINDS: tuple[dict[str, str], ...] = (
    {"key": "flag", "name": "Flag", "level": "good"},
    {"key": "credential", "name": "凭据", "level": "good"},
    {"key": "hash", "name": "哈希", "level": "good"},
    {"key": "http", "name": "HTTP", "level": "info"},
    {"key": "webshell", "name": "Webshell", "level": "warn"},
    {"key": "sql", "name": "SQL 注入", "level": "good"},
    {"key": "dns", "name": "DNS", "level": "warn"},
    {"key": "file", "name": "文件", "level": "info"},
    {"key": "protocol", "name": "协议", "level": "info"},
    {"key": "tls_fingerprint", "name": "TLS 指纹", "level": "info"},
    {"key": "rule", "name": "自定义规则", "level": "warn"},
    {"key": "log", "name": "日志", "level": "info"},
    {"key": "other", "name": "其他", "level": "info"},
)
KIND_KEYS = tuple(item["key"] for item in KINDS)
KIND_NAMES = {item["key"]: item["name"] for item in KINDS}
LEVELS = ("debug", "info", "good", "warn", "error")
COLUMNS = ("类别", "级别", "帧", "时间", "功能", "摘要", "详情")


def kind_catalogue() -> list[dict]:
    """Serializable kind list for ``GET /api/meta`` and the filter dropdown."""
    return [dict(item) for item in KINDS]


def _clean(value, limit: int) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    text = text.strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def make(kind: str, summary: str, *, frame="", detail: str = "",
         level: str = "info", feature: str = "", checkbox: str = "",
         capture: str = "", extra: dict | None = None) -> dict:
    """Build one finding record with clipped, JSON-safe fields."""
    kind = str(kind or "other").strip().lower()
    if kind not in KIND_KEYS:
        kind = "other"
    level = str(level or "info").strip().lower()
    if level not in LEVELS:
        level = "info"
    record = {
        "kind": kind,
        "level": level,
        "frame": _clean(frame, 40),
        "summary": _clean(summary, MAX_SUMMARY),
        "detail": _clean(detail, MAX_DETAIL),
        "time": _dt.datetime.now().strftime("%H:%M:%S"),
        #: Capture-side timestamp (e.g. ``frame.time``) when a handler can
        #: supply it; the WebUI timeline prefers it over the wall-clock time.
        "capture": _clean(capture, 40),
        "feature": _clean(feature, 120),
        "checkbox": _clean(checkbox, 40),
    }
    if extra:
        record["extra"] = {str(key): _clean(value, MAX_DETAIL)
                           for key, value in extra.items()}
    return record


def normalise(record, feature: str = "", checkbox: str = "") -> dict | None:
    """Coerce a persisted/derived record into the canonical shape."""
    if not isinstance(record, dict):
        return None
    summary = _clean(record.get("summary") or record.get("text") or "", MAX_SUMMARY)
    if not summary:
        return None
    kind = str(record.get("kind") or "other").strip().lower()
    if kind not in KIND_KEYS:
        kind = "other"
    level = str(record.get("level") or "info").strip().lower()
    if level not in LEVELS:
        level = "info"
    out = {
        "kind": kind,
        "level": level,
        "frame": _clean(record.get("frame") or "", 40),
        "summary": summary,
        "detail": _clean(record.get("detail") or "", MAX_DETAIL),
        "time": _clean(record.get("time") or "", 40),
        "capture": _clean(record.get("capture") or "", 40),
        "feature": _clean(record.get("feature") or feature, 120),
        "checkbox": _clean(record.get("checkbox") or checkbox, 40),
    }
    if isinstance(record.get("extra"), dict):
        out["extra"] = {str(key): _clean(value, MAX_DETAIL)
                        for key, value in record["extra"].items()}
    if record.get("seq") is not None:
        try:
            out["seq"] = int(record["seq"])
        except (TypeError, ValueError):
            pass
    return out


def normalise_all(records: Iterable) -> list[dict]:
    items = []
    for record in records or []:
        item = normalise(record)
        if item is not None:
            items.append(item)
    return items


def matches(item: dict, query: str = "", kind: str = "", level: str = "") -> bool:
    """Case-insensitive substring filter used by the CLI and the tests."""
    if kind and kind != "all" and item.get("kind") != kind:
        return False
    if level and level != "all" and item.get("level") != level:
        return False
    query = str(query or "").strip().lower()
    if not query:
        return True
    haystack = " ".join(str(item.get(key) or "") for key in
                        ("summary", "detail", "frame", "feature", "kind")).lower()
    return query in haystack


def filter_items(records: Iterable, query: str = "", kind: str = "",
                 level: str = "") -> list[dict]:
    return [item for item in records or [] if matches(item, query, kind, level)]


def kind_counts(records: Iterable) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in records or []:
        key = str(item.get("kind") or "other")
        counts[key] = counts.get(key, 0) + 1
    return counts


def to_csv(records: Iterable) -> str:
    """Render findings as UTF-8 CSV with a header row (Excel friendly)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(COLUMNS)
    for item in records or []:
        writer.writerow([
            KIND_NAMES.get(item.get("kind"), item.get("kind") or ""),
            item.get("level") or "",
            item.get("frame") or "",
            #: Same display rule as the WebUI result table: capture-side
            #: timestamp first, wall-clock time as fallback.
            item.get("capture") or item.get("time") or "",
            item.get("feature") or "",
            item.get("summary") or "",
            item.get("detail") or "",
        ])
    return buffer.getvalue()
