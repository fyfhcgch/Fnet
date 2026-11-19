"""Log-file analysis features (``checkBox_61`` … ``checkBox_64``).

These handlers run on the plain-text logs normalised by
:mod:`fnet.utils.logfile` and never call tshark, so a log job works without
Wireshark installed.  Four focused analyses mirror the capture-side workflow:

* ``logs.summary``   — format, volume, time range, levels, sources, fields;
* ``logs.entities``  — per-client / per-IP / per-subnet / per-host activity
  profiles with success/failure counters;
* ``logs.anomalies`` — failure keywords, suspicious entities, bursts, rare values;
* ``logs.iocs``      — flags, credentials, hashes, URLs, domains and IP inventory.

Everything is stdlib-only and bounded, matching the rest of Fnet.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import statistics
from collections import Counter
from functools import lru_cache
from pathlib import Path

from fnet.features.common import clean_cell
from fnet.features.registry import FeatureContext
from fnet.utils import logfile

#: Fields worth profiling as an "entity", in display order.  ``ip`` and
#: ``source`` are synthetic dimensions filled from parsed IPs / components;
#: ``网段`` groups client IPs into subnets (IPv4 /24 by default, IPv6 /64).
PREFERRED_ENTITIES = (
    "client_id", "user", "username", "account", "client_ip", "src_ip",
    "remote_ip", "ip", "网段", "host", "program", "source", "service",
    "operation", "action", "status", "auth_result", "key",
)

#: Default failure/anomaly keywords.  Override with ``log_fail_regex``.
DEFAULT_FAIL_RE = re.compile(
    r"invalid key|invalid|failed|failure|denied|unauthori[sz]ed|forbidden|"
    r"error|exception|timeout|timed out|refused|rejected|panic|fatal|"
    r"critical|corrupt|unreachable|out of memory|\boom\b|killed|"
    r"reset by peer|disconnect(?:ed|ion)",
    re.IGNORECASE,
)

#: Authentication failures get a higher severity than generic errors.
AUTH_FAIL_RE = re.compile(
    r"invalid key|failed password|authentication failure|auth(?:entication)? "
    r"failed|access denied|unauthori[sz]ed|invalid user|permission denied|"
    r"login failed|bad password",
    re.IGNORECASE,
)

IOC_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("URL", re.compile(r"https?://[^\s\"'<>]+")),
    ("邮箱", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("域名", re.compile(
        r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|cn|io|ru|xyz|top|info|biz|"
        r"site|online|club|pw|cc|me|dev|cloud|local)\b", re.IGNORECASE)),
    ("MD5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("SHA1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("SHA256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("JWT", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("云访问密钥", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Flag", re.compile(
        r"\b(?:flag|ctf|ctfshow|hgame|begin)\{[^}\r\n]{1,200}\}",
        re.IGNORECASE)),
    ("凭据", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*"
        r"[\"']?([^\s\"';,]{3,80})")),
    ("Key 标识", re.compile(r"\bkey_[A-Za-z0-9]{4,}\b")),
)

_MAX_IOC_VALUES = 5_000
_MAX_FINDINGS_PER_IOC = 30
#: 单个日志任务的 findings 软上限；四个日志功能共享 job.findings，
#: 因此每个发射循环前检查剩余额度即可控制总量。
_MAX_FINDINGS_TOTAL = 80
#: 实体画像最多下钻的维度数与每个维度的实体数。
_PROFILE_DIMENSIONS = 4
_PROFILE_TOP_ENTITIES = 3
#: 逐条失败样本：认证类最多 10 条，无认证类时回退普通失败样本条数。
_MAX_FAIL_SAMPLES = 10
_MAX_FAIL_FALLBACK_SAMPLES = 3
#: 概览分布 finding 的 detail 最多列出的条目数。
_MAX_DIST_ITEMS = 8
#: 网段成功统计 finding 列出的网段数（Top N）。
_SUBNET_TOP_ITEMS = 8


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _load(ctx: FeatureContext):
    """Parse the job input as a log, or log a clear skip message."""
    kind = getattr(ctx, "input_kind", "pcap")
    if kind != "log" and not logfile.is_log_input(ctx.pcap):
        ctx.report("当前输入不是日志文件，跳过日志分析功能", "warn")
        return None
    log = logfile.parse_path(ctx.pcap)
    if not log.records:
        ctx.report(f"日志中没有可解析的记录: {ctx.pcap}", "warn")
        return None
    return log


def _fmt_size(size: int) -> str:
    value = float(size or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} 秒"
    if seconds < 3600:
        return f"{seconds // 60} 分 {seconds % 60} 秒"
    if seconds < 86400:
        return f"{seconds // 3600} 小时 {seconds % 3600 // 60} 分"
    return f"{seconds // 86400} 天 {seconds % 86400 // 3600} 小时"


def _table(ctx: FeatureContext, title: str, headers: list[str],
           rows, limit: int = 20) -> list[list[str]]:
    rows = [list(row) for row in rows]
    if not rows:
        ctx.report(f"{title}: 没有匹配的日志记录", "warn")
        return []
    ctx.report(f"===== {title} ({len(rows)} 条) =====", "good")
    ctx.report(" | ".join(headers), "debug")
    for row in rows[:limit]:
        ctx.report(" | ".join(clean_cell(str(cell), 160) for cell in row),
                   "info")
    if len(rows) > limit:
        ctx.report(f"仅显示前 {limit} 条（共 {len(rows)} 条）", "warn")
    return rows


#: Default IPv4 prefix for the ``网段`` dimension; ``log_subnet_prefix``
#: overrides it (clamped to 8–32, invalid values fall back with a warning).
#: IPv6 is always grouped by /64 regardless of this parameter.
DEFAULT_SUBNET_PREFIX = 24


def _subnet_label(ip_text: str, prefix: int) -> str:
    """Group one address into its subnet label, e.g. ``10.1.1.0/24``.

    IPv4 uses ``prefix`` (``log_subnet_prefix``), IPv6 always /64.  Invalid
    addresses return ``""`` so the record simply does not join the subnet
    dimension.  ``lru_cache`` keeps the per-record cost O(1) for the many
    repeated client addresses in a typical log.
    """
    text = str(ip_text or "").strip()
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if address.version == 6:
        prefix = 64
    try:
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except ValueError:
        return ""


def _record_values(record: logfile.LogRecord, field: str,
                   subnet_prefix: int = DEFAULT_SUBNET_PREFIX) -> list[str]:
    if field == "ip":
        value = record.value("ip", "client_ip", "src_ip", "remote_ip",
                             "source_ip")
        if value:
            return [value]
        return list(record.ips)
    if field == "网段":
        # Subnet dimension: first client-IP-like field wins, otherwise the
        # first extracted IP.  Multi-IP records are grouped by that first
        # client IP only (documented behaviour, keeps grouping deterministic).
        ip_text = (record.value("client_ip", "ip", "src_ip", "remote_ip",
                                "source_ip")
                   or (record.ips[0] if record.ips else ""))
        label = _subnet_label(ip_text, subnet_prefix) if ip_text else ""
        return [label] if label else []
    if field == "source":
        value = record.value("source", *logfile._SOURCE_KEYS)
        return [value] if value else ([record.source] if record.source else [])
    value = record.value(field)
    return [value] if value else []


def _entity_dimensions(log: logfile.LogFile) -> list[str]:
    """Preferred entity fields that actually occur, plus low-cardinality fields."""
    available = set(log.fields)
    has_ips = any(record.ips for record in log.records)
    dimensions: list[str] = []
    for name in PREFERRED_ENTITIES:
        if name in available or (name in ("ip", "网段") and has_ips):
            dimensions.append(name)
    if len(dimensions) < 8:
        for name in log.fields:
            if name in dimensions:
                continue
            values = {record.value(name) for record in log.records
                      if record.value(name)}
            if 2 <= len(values) <= 30:
                dimensions.append(name)
            if len(dimensions) >= 10:
                break
    return dimensions[:10]


def _aggregate(log: logfile.LogFile, dimension: str,
               fail_re: re.Pattern, success_re: re.Pattern | None = None,
               subnet_prefix: int = DEFAULT_SUBNET_PREFIX) -> list[dict]:
    """One pass over the log for ``dimension`` -> per-value statistics.

    Success and failure are independent counters: ``success_re`` (custom
    ``log_success_regex``) counts a record as one success when it matches;
    without it every non-failing record (``not fail_re.search``) counts as a
    success.  Subnet grouping for the ``网段`` dimension stays O(1) per record
    via ``_subnet_label``'s cache.
    """
    stats: dict[str, dict] = {}
    for record in log.records:
        failed = bool(fail_re.search(record.raw))
        succeeded = (bool(success_re.search(record.raw)) if success_re is not None
                     else not failed)
        for value in _record_values(record, dimension, subnet_prefix):
            entry = stats.get(value)
            if entry is None:
                entry = stats[value] = {
                    "value": value, "count": 0, "fail": 0, "success": 0,
                    "first": record.time, "last": record.time,
                    "first_epoch": record.epoch, "last_epoch": record.epoch,
                    "raw": record.raw, "raw_line": record.line,
                    "fail_raw": "", "fail_line": 0,
                }
            entry["count"] += 1
            if failed:
                entry["fail"] += 1
                if not entry["fail_raw"]:
                    entry["fail_raw"] = record.raw
                    entry["fail_line"] = record.line
            if succeeded:
                entry["success"] += 1
            if record.time:
                if entry["first_epoch"] is None or (
                        record.epoch is not None
                        and record.epoch < entry["first_epoch"]):
                    entry["first"] = record.time
                    entry["first_epoch"] = record.epoch
                if entry["last_epoch"] is None or (
                        record.epoch is not None
                        and record.epoch > entry["last_epoch"]):
                    entry["last"] = record.time
                    entry["last_epoch"] = record.epoch
    return sorted(stats.values(), key=lambda item: (-item["count"],
                                                    item["value"]))


def _buckets(log: logfile.LogFile, max_buckets: int = 60) -> list[tuple[float, int]]:
    """Event counts per time bucket; bucket width adapts to the time span."""
    stamped = [record for record in log.records if record.epoch is not None]
    if len(stamped) < 2:
        return []
    start = min(record.epoch for record in stamped)
    end = max(record.epoch for record in stamped)
    span = max(0.0, end - start)
    widths = (1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 10800,
              21600, 43200, 86400, 604800)
    width = next((item for item in widths if span / item <= max_buckets),
                 widths[-1])
    counts: Counter = Counter()
    for record in stamped:
        counts[int((record.epoch - start) // width)] += 1
    return [(start + index * width, count)
            for index, count in sorted(counts.items())]


def _bucket_label(epoch: float) -> str:
    import datetime as _dt
    try:
        return _dt.datetime.fromtimestamp(
            epoch, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return str(int(epoch))


def _write_csv(name: str, headers: list[str], rows) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow([clean_cell(str(cell), 500) for cell in row])
    return buffer.getvalue()


def _int_param(value, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _float_param(value, default: float) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return default


def _success_re(ctx: FeatureContext) -> re.Pattern | None:
    """Compile ``log_success_regex`` (IGNORECASE); graceful fallback to None.

    ``None`` means "no custom success rule": the handler then treats every
    non-failing record (``not fail_re.search``) as one success and says so in
    the log.
    """
    raw_regex = str(ctx.params.get("log_success_regex") or "").strip()
    if not raw_regex:
        return None
    try:
        return re.compile(raw_regex, re.IGNORECASE)
    except re.error as exc:
        ctx.report(f"log_success_regex 无效（{exc}），"
                   "回退为“未命中失败关键字即成功”口径", "warn")
        return None


def _subnet_prefix(ctx: FeatureContext) -> int:
    """``log_subnet_prefix`` as an IPv4 prefix, 8–32; invalid -> warn + /24."""
    raw = ctx.params.get("log_subnet_prefix")
    text = "" if raw is None else str(raw).strip()
    if not text:
        return DEFAULT_SUBNET_PREFIX
    try:
        value = int(text)
    except (TypeError, ValueError):
        ctx.report(f"log_subnet_prefix 无效（{text!r}），回退 /24", "warn")
        return DEFAULT_SUBNET_PREFIX
    if not 8 <= value <= 32:
        ctx.report(f"log_subnet_prefix 超出范围 8-32（{value}），回退 /24",
                   "warn")
        return DEFAULT_SUBNET_PREFIX
    return value


def _budget_left(ctx: FeatureContext) -> int:
    """Remaining findings quota for this job (the list is shared per job)."""
    return max(0, _MAX_FINDINGS_TOTAL - len(ctx.findings))


def _representative(entry: dict) -> tuple[str, int]:
    """A raw line that best illustrates the entity: prefer a failed one."""
    if entry.get("fail_raw"):
        return entry["fail_raw"], entry["fail_line"]
    return entry.get("raw", ""), entry.get("raw_line", 0)


def entity_stats(log: logfile.LogFile, dimension: str, fail_re=None,
                 success_re: re.Pattern | None = None,
                 subnet_prefix: int = DEFAULT_SUBNET_PREFIX,
                 limit: int | None = None) -> list[dict]:
    """Public, reusable per-entity statistics for one dimension.

    One pass over ``log.records`` (via :func:`_aggregate`) returning shaped
    entries shared by the feature report and the WebUI 实体统计 stats API so
    both stay on the same口径:

    ``value`` / ``count`` / ``share`` / ``fail`` / ``fail_rate`` /
    ``success`` / ``success_rate`` / ``first`` / ``last`` / ``line`` /
    ``sample``（代表性原始行，优先取失败行）.

    ``fail_re`` defaults to :data:`DEFAULT_FAIL_RE`; ``success_re=None``
    means "no custom success rule" — every non-failing record counts as one
    success.  ``subnet_prefix`` follows the /24 default with IPv6 always
    /64 (see :func:`_subnet_label`); ``limit`` truncates the ranked list
    (``None`` keeps everything).
    """
    pattern = DEFAULT_FAIL_RE if fail_re is None else fail_re
    total = max(1, len(log.records))
    shaped: list[dict] = []
    for entry in _aggregate(log, dimension, pattern, success_re,
                            subnet_prefix):
        raw, line = _representative(entry)
        count = max(1, entry["count"])
        shaped.append({
            "value": entry["value"],
            "count": entry["count"],
            "share": round(entry["count"] / total, 4),
            "fail": entry["fail"],
            "fail_rate": round(entry["fail"] / count, 4),
            "success": entry["success"],
            "success_rate": round(entry["success"] / count, 4),
            "first": entry["first"],
            "last": entry["last"],
            "line": line,
            "sample": raw,
        })
    if limit is not None:
        try:
            shaped = shaped[:max(0, int(limit))]
        except (TypeError, ValueError):
            pass
    return shaped


def _entity_finding(ctx: FeatureContext, dimension: str, entry: dict,
                    total: int) -> None:
    """One drill-down finding for a single top entity of ``dimension``."""
    raw = str(entry.get("sample") or "")
    line = entry.get("line", 0)
    count = max(1, entry["count"])
    ctx.add_finding(
        "log", f"实体画像（{dimension}）：{clean_cell(entry['value'], 80)}"
               f" ×{entry['count']}",
        detail=(f"占比 {entry['count'] * 100.0 / max(1, total):.1f}%；"
                f"记录 {entry['count']} 条；失败 {entry['fail']} 次"
                f"（{entry['fail'] * 100.0 / count:.1f}%）；"
                f"{entry['first'] or '-'} ~ {entry['last'] or '-'}；"
                f"第 {line} 行: {clean_cell(raw, 160)}"),
        level="info",
        extra={"dimension": dimension, "value": entry["value"],
               "count": entry["count"], "fail": entry["fail"],
               "fail_rate": round(entry["fail"] / count, 4),
               "first": entry["first"], "last": entry["last"],
               "line": line})


def _entity_label(record: logfile.LogRecord) -> str:
    """Short identity for a per-record finding, e.g. ``client3 @ 10.0.0.5``."""
    ident = record.value("client_id", "user", "username", "account")
    ip = (record.value("client_ip", "ip", "src_ip", "remote_ip", "source_ip")
          or (record.ips[0] if record.ips else ""))
    if ident and ip and ip != ident:
        return f"{clean_cell(ident, 60)} @ {ip}"
    if ident or ip:
        return clean_cell(ident or ip, 80)
    if record.source:
        return clean_cell(record.source, 60)
    return f"行 {record.line}"


def _dist_lines(counts: dict, total: int, limit: int = _MAX_DIST_ITEMS) -> str:
    """Compact multi-line distribution text, e.g. ``info 11355（79.9%）``."""
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    return "\n".join(f"{name} {count}"
                     f"（{count * 100.0 / max(1, total):.1f}%）"
                     for name, count in top)


def _sample_evenly(records: list, limit: int) -> list:
    """Spread at most ``limit`` samples across the whole list, in order."""
    if len(records) <= limit:
        return list(records)
    step = max(1, len(records) // limit)
    return records[::step][:limit]


# ---------------------------------------------------------------------------
# checkBox_61 — overview and timeline
# ---------------------------------------------------------------------------
def summary(ctx: FeatureContext) -> None:
    """Volume, time span, levels, sources and field coverage."""
    log = _load(ctx)
    if log is None:
        return
    path = Path(log.path)
    ctx.report(f"日志文件: {path}", "info")
    ctx.report(f"日志格式: {log.format_name}", "good")
    ctx.report(f"文件大小: {_fmt_size(log.size)}；总行数 {log.total_lines}；"
               f"解析记录 {len(log.records)} 条；跳过 {log.skipped} 行", "info")
    if log.truncated:
        ctx.report(f"日志超过解析上限，仅分析前 {len(log.records)} 条记录", "warn")

    first, last, duration = log.timespan()
    if first:
        ctx.report(f"时间范围: {first} ~ {last}（持续 {_fmt_duration(duration)}）",
                   "info")
    else:
        ctx.report("日志中没有可识别的时间戳，时间线统计不可用", "warn")

    levels = log.levels()
    ctx.check_cancel()
    _table(ctx, "日志级别分布", ["级别", "数量", "占比"],
           [[name, count, f"{count * 100.0 / len(log.records):.1f}%"]
            for name, count in sorted(levels.items(), key=lambda kv: -kv[1])])

    sources = log.sources()
    _table(ctx, "日志来源 / 组件 Top 15",
           ["来源", "数量", "占比", "首次记录"],
           [[name, count, f"{count * 100.0 / len(log.records):.1f}%",
             next((item.time for item in log.records
                   if (item.source or item.value(*logfile._SOURCE_KEYS)
                       or "unknown") == name), "-")]
            for name, count in sorted(sources.items(), key=lambda kv: -kv[1])[:15]])

    field_rows = []
    for name in log.fields[:40]:
        values = [record.value(name) for record in log.records
                  if record.value(name)]
        if not values:
            continue
        counter = Counter(values)
        top_value, top_count = counter.most_common(1)[0]
        field_rows.append([name, len(values), len(counter),
                           f"{clean_cell(top_value, 80)} ×{top_count}"])
    _table(ctx, "字段覆盖率（Top 40）",
           ["字段", "非空记录", "唯一值", "最常见值"], field_rows, limit=40)
    if log.fields:
        ctx.report("可用字段: " + "、".join(log.fields[:60]), "debug")
    # 字段覆盖率也进"分析结果"，WebUI 不需要下载 log_fields.csv 就能读到。
    if field_rows:
        ctx.add_finding(
            "log", "日志字段覆盖率",
            detail="\n".join(f"{name} {nonempty}/{unique}"
                             for name, nonempty, unique, _ in field_rows[:12]),
            level="info",
            extra={"fields": {name: f"{nonempty}/{unique}"
                              for name, nonempty, unique, _ in field_rows},
                   "top_values": {row[0]: row[3] for row in field_rows}})

    ctx.check_cancel()
    buckets = _buckets(log)
    if buckets:
        peak = max(count for _, count in buckets)
        ctx.report(f"===== 事件时间线（{len(buckets)} 个时间桶，"
                   f"峰值 {peak} 条）=====", "good")
        for start, count in buckets:
            bar = "█" * max(1, round(count * 30 / max(1, peak)))
            ctx.report(f"{_bucket_label(start)} {bar} {count}", "info")
    else:
        ctx.report("时间线: 日志缺少可解析时间戳，已跳过", "warn")

    top_sources = dict(sorted(sources.items(), key=lambda kv: -kv[1])[:10])
    detail = (f"格式 {log.format_name}；记录 {len(log.records)} 条；"
              f"来源 {len(sources)} 个；级别 {_dist_lines(levels, len(log.records), 4)}")
    ctx.add_finding("log", f"日志概览：{len(log.records)} 条记录 / "
                            f"{len(sources)} 个来源",
                    detail=detail, level="info",
                    extra={"log_format": log.format, "records": len(log.records),
                           "first": first, "last": last,
                           "duration_seconds": int(duration),
                           "top_sources": top_sources, "levels": dict(levels)})
    ctx.add_finding("log", "日志级别分布",
                    detail=_dist_lines(levels, len(log.records)),
                    level="info",
                    extra={"levels": dict(levels),
                           "total": len(log.records)})
    ctx.add_finding("log", "日志来源分布",
                    detail=_dist_lines(sources, len(log.records)),
                    level="info",
                    extra={"top_sources": top_sources,
                           "total": len(log.records)})
    if log.truncated:
        ctx.add_finding("log", f"日志解析达到上限 {len(log.records)} 条",
                        detail=f"文件 {log.path} 未完整分析",
                        level="warn")
    ctx.write_output("log_fields.csv",
                     _write_csv("log_fields.csv",
                                ["字段", "非空记录", "唯一值", "最常见值",
                                 "次数"],
                                [[row[0], row[1], row[2],
                                  row[3].rsplit(" ×", 1)[0],
                                  row[3].rsplit(" ×", 1)[-1]]
                                 for row in field_rows]))
    ctx.set_progress(100)


# ---------------------------------------------------------------------------
# checkBox_62 — entity profiles
# ---------------------------------------------------------------------------
def entities(ctx: FeatureContext) -> None:
    """Per-client / per-IP / per-subnet / per-host activity profiles."""
    log = _load(ctx)
    if log is None:
        return
    fail_re = DEFAULT_FAIL_RE
    success_re = _success_re(ctx)
    prefix = _subnet_prefix(ctx)
    if success_re is not None:
        ctx.report("成功口径: 命中 log_success_regex 的记录计一次成功", "info")
    else:
        ctx.report("成功口径: 未提供 log_success_regex，"
                   "未命中失败关键字（log_fail_regex 默认规则）的记录视为成功",
                   "info")
    ctx.report(f"网段口径: IPv4 按前缀 /{prefix} 归组（IPv6 固定 /64），"
               "多 IP 记录取第一个客户端 IP", "info")
    dimensions = _entity_dimensions(log)
    if not dimensions:
        ctx.report("日志中没有适合做实体统计的字段", "warn")
        ctx.set_progress(100)
        return
    ctx.report(f"实体维度: {'、'.join(dimensions)}", "info")
    total = len(log.records)
    aggregated: dict[str, list[dict]] = {}
    artifact_rows: list[list[str]] = []
    for dimension in dimensions:
        ctx.check_cancel()
        entries = aggregated[dimension] = entity_stats(log, dimension, fail_re,
                                                       success_re, prefix)
        rows = []
        for entry in entries[:15]:
            rows.append([
                entry["value"], entry["count"],
                f"{entry['count'] * 100.0 / total:.1f}%",
                entry["fail"],
                f"{entry['fail'] * 100.0 / entry['count']:.1f}%",
                entry["first"] or "-", entry["last"] or "-",
                entry["success"],
                f"{entry['success'] * 100.0 / entry['count']:.1f}%",
            ])
        _table(ctx, f"实体统计 · {dimension}",
               ["值", "次数", "占比", "失败次数", "失败率", "首次", "末次",
                "成功次数", "成功率"],
               rows, limit=15)
        for entry in entries:
            artifact_rows.append([
                dimension, entry["value"], entry["count"],
                f"{entry['count'] * 100.0 / total:.2f}%", entry["fail"],
                f"{entry['fail'] * 100.0 / entry['count']:.2f}%",
                entry["first"], entry["last"],
                entry["success"],
                f"{entry['success'] * 100.0 / entry['count']:.2f}%",
            ])
    # Per-dimension drill-down: the top entities of each dimension get their
    # own finding with share, failure rate, time span and a raw sample line.
    for dimension in dimensions[:_PROFILE_DIMENSIONS]:
        for entry in aggregated.get(dimension, [])[:_PROFILE_TOP_ENTITIES]:
            if _budget_left(ctx) <= 0:
                break
            _entity_finding(ctx, dimension, entry, total)
    # Subnet roll-up: which /24 (or /64) accumulated the most successes is a
    # common CTF/incident question; keep the tool generic (no md5/flag here).
    subnet_entries = aggregated.get("网段") or []
    if len(subnet_entries) >= 2 and _budget_left(ctx) > 0:
        top = sorted(subnet_entries,
                     key=lambda item: (-item["success"],
                                       -item["count"]))[:_SUBNET_TOP_ITEMS]
        ctx.report(f"===== 网段成功统计（成功最多的前 {len(top)} 个网段）=====",
                   "good")
        for item in top:
            ctx.report(f"{item['value']} 成功 {item['success']} / "
                       f"共 {item['count']}"
                       f"（{item['success'] * 100.0 / max(1, item['count']):.1f}%）",
                       "info")
        ctx.add_finding(
            "log", "网段成功统计",
            detail="\n".join(
                f"{item['value']} 成功 {item['success']} / 共 {item['count']}"
                f"（{item['success'] * 100.0 / max(1, item['count']):.1f}%）"
                for item in top),
            level="info",
            extra={"top": [{"subnet": item["value"],
                            "success": item["success"],
                            "total": item["count"]} for item in top]})
    ctx.write_output("log_entities.csv",
                     _write_csv("log_entities.csv",
                                ["维度", "值", "次数", "占比", "失败次数",
                                 "失败率", "首次", "末次", "成功次数",
                                 "成功率"], artifact_rows))
    ctx.set_progress(100)


# ---------------------------------------------------------------------------
# checkBox_63 — failures, bursts and rare values
# ---------------------------------------------------------------------------
def anomalies(ctx: FeatureContext) -> None:
    """Failure keywords, suspicious entities, bursts and rare field values."""
    log = _load(ctx)
    if log is None:
        return
    raw_regex = str(ctx.params.get("log_fail_regex") or "").strip()
    if raw_regex:
        try:
            fail_re = re.compile(raw_regex, re.IGNORECASE)
        except re.error as exc:
            ctx.report(f"log_fail_regex 无效（{exc}），使用默认规则", "warn")
            fail_re = DEFAULT_FAIL_RE
    else:
        fail_re = DEFAULT_FAIL_RE
    fail_threshold = _int_param(ctx.params.get("log_fail_threshold"), 3)
    fail_ratio = _float_param(ctx.params.get("log_fail_ratio"), 0.5)
    min_events = _int_param(ctx.params.get("log_min_events"), 5)
    total = len(log.records)

    failures = [record for record in log.records if fail_re.search(record.raw)]
    auth_failures = [record for record in failures
                     if AUTH_FAIL_RE.search(record.raw)]
    ctx.report(f"失败/异常关键字命中 {len(failures)} 条"
               f"（{len(failures) * 100.0 / total:.1f}%），其中认证类 "
               f"{len(auth_failures)} 条", "warn" if failures else "info")
    for record in failures[:20]:
        ctx.report(f"[行 {record.line}] {clean_cell(record.raw, 200)}", "warn")
    if len(failures) > 20:
        ctx.report(f"仅显示前 20 条失败记录（共 {len(failures)} 条）", "debug")

    if failures:
        ctx.add_finding(
            "log", f"日志失败/异常事件 {len(failures)} 条"
                   f"（认证类 {len(auth_failures)} 条）",
            detail=clean_cell(failures[0].raw, 300), level="warn",
            extra={"failures": len(failures),
                   "auth_failures": len(auth_failures)})

    # -- per-entity failure profile ------------------------------------
    dimensions = _entity_dimensions(log)
    dimension = next((name for name in dimensions
                      if name in ("client_id", "user", "client_ip", "ip",
                                  "host", "source")), "")
    artifact_rows: list[list[str]] = []
    if dimension:
        entries = _aggregate(log, dimension, fail_re)
        suspect = [entry for entry in entries
                   if entry["fail"] >= fail_threshold
                   and entry["count"] >= min_events]
        suspect.sort(key=lambda item: (-item["fail"], -item["count"]))
        rows = [[entry["value"], entry["count"], entry["fail"],
                 f"{entry['fail'] * 100.0 / entry['count']:.1f}%",
                 entry["first"] or "-", entry["last"] or "-"]
                for entry in suspect[:20]]
        _table(ctx, f"失败最多的实体 · {dimension}",
               ["值", "次数", "失败次数", "失败率", "首次", "末次"],
               rows, limit=20)
        for entry in suspect:
            ratio = entry["fail"] / max(1, entry["count"])
            artifact_rows.append(["实体失败", entry["value"], entry["fail"],
                                  f"{ratio * 100.0:.1f}%"])
        for entry in suspect[:5]:
            ratio = entry["fail"] / max(1, entry["count"])
            raw, line = _representative(entry)
            level = "warn" if ratio >= fail_ratio else "info"
            ctx.add_finding(
                "log", f"实体 {clean_cell(entry['value'], 80)} 失败 "
                       f"{entry['fail']} 次（{dimension}）",
                detail=(f"共 {entry['count']} 条记录"
                        f"（占比 {entry['count'] * 100.0 / max(1, total):.1f}%），"
                        f"失败率 {ratio * 100:.1f}%；"
                        f"{entry['first']} ~ {entry['last']}；"
                        f"第 {line} 行: {clean_cell(raw, 160)}"),
                level=level,
                extra={"dimension": dimension, "value": entry["value"],
                       "count": entry["count"], "fail": entry["fail"],
                       "fail_rate": round(ratio, 4), "line": line})
        if len(suspect) > 5:
            ctx.report(f"另有 {len(suspect) - 5} 个实体存在失败记录，"
                       "详见 log_anomalies.csv", "info")

    # -- 逐条失败样本：认证类优先，便于在结果表中直接下钻 -------------
    samples = auth_failures or failures
    sample_limit = (_MAX_FAIL_SAMPLES if auth_failures
                    else _MAX_FAIL_FALLBACK_SAMPLES)
    prefix = "认证失败样本" if auth_failures else "失败样本"
    for record in _sample_evenly(samples, sample_limit):
        if _budget_left(ctx) <= 0:
            break
        ctx.add_finding(
            "log", f"{prefix}：{_entity_label(record)}",
            detail=(f"第 {record.line} 行；{record.time or '无时间戳'}；"
                    f"{clean_cell(record.raw, 200)}"),
            level="warn",
            extra={"line": record.line, "time": record.time})

    # -- bur-ts of activity --------------------------------------------
    buckets = _buckets(log)
    if len(buckets) >= 5:
        counts = [count for _, count in buckets]
        mean = statistics.fmean(counts)
        deviation = statistics.pstdev(counts) if len(counts) > 1 else 0.0
        threshold = max(5.0, mean + 3 * deviation, mean * 2)
        spikes = [(start, count) for start, count in buckets
                  if count >= threshold]
        if spikes:
            _table(ctx, "事件突增时间桶", ["时间", "数量", "平均值"],
                   [[_bucket_label(start), count, f"{mean:.1f}"]
                    for start, count in spikes[:15]], limit=15)
            for start, count in spikes[:5]:
                if _budget_left(ctx) <= 0:
                    break
                artifact_rows.append(["事件突增", _bucket_label(start), count,
                                      f"均值 {mean:.1f}"])
                ctx.add_finding(
                    "log", f"事件突增：{_bucket_label(start)} 共 {count} 条",
                    detail=f"时间桶均值 {mean:.1f}，阈值 {threshold:.1f}",
                    level="warn",
                    extra={"bucket": _bucket_label(start), "count": count,
                           "mean": round(mean, 2)})
        else:
            ctx.report("时间线未发现明显的事件突增", "info")

    # -- rare values in low-cardinality fields -------------------------
    rare_rows: list[list] = []
    for name in log.fields:
        ctx.check_cancel()
        values = [record.value(name) for record in log.records
                  if record.value(name)]
        if len(values) < 20:
            continue
        counter = Counter(values)
        if not 2 <= len(counter) <= 40:
            continue
        limit = max(1, int(len(values) * 0.005))
        for value, count in counter.items():
            if count <= limit:
                rare_rows.append([name, value, count])
    if rare_rows:
        _table(ctx, "低频字段值（可能是一次性操作/异常值）",
               ["字段", "值", "次数"], rare_rows, limit=20)
        for row in rare_rows[:10]:
            if _budget_left(ctx) <= 0:
                break
            artifact_rows.append(["低频值", f"{row[0]}={row[1]}", row[2], ""])
            ctx.add_finding(
                "log", f"低频字段值：{row[0]}={clean_cell(str(row[1]), 80)}"
                       f"（{row[2]} 次）",
                detail="该值在低基数字段中出现次数异常偏少",
                level="info",
                extra={"field": row[0], "value": row[1], "count": row[2]})
    else:
        ctx.report("未发现明显的低频异常字段值", "info")

    ctx.write_output("log_anomalies.csv",
                     _write_csv("log_anomalies.csv",
                                ["类型", "对象", "计数", "详情"], artifact_rows))
    ctx.set_progress(100)


# ---------------------------------------------------------------------------
# checkBox_64 — IOC and sensitive information
# ---------------------------------------------------------------------------
def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback
                or address.is_link_local or address.is_multicast
                or address.is_reserved)


def iocs(ctx: FeatureContext) -> None:
    """Extract flags, credentials, hashes, URLs, domains and IP inventory."""
    log = _load(ctx)
    if log is None:
        return
    hits: dict[str, dict[str, dict]] = {}
    public: Counter = Counter()
    private: Counter = Counter()
    for record in log.records:
        ctx.check_cancel()
        for address in record.ips:
            (public if _is_public_ip(address) else private)[address] += 1
        for name, pattern in IOC_PATTERNS:
            bucket = hits.setdefault(name, {})
            for match in pattern.finditer(record.raw):
                value = match.group(1) if pattern.groups else match.group(0)
                value = str(value or "").strip()
                if not value:
                    continue
                entry = bucket.get(value)
                if entry is None:
                    if len(bucket) >= _MAX_IOC_VALUES:
                        continue
                    entry = bucket[value] = {"count": 0, "line": record.line,
                                             "time": record.time,
                                             "raw": record.raw}
                entry["count"] += 1
    counts = [(name, len(values), sum(item["count"] for item in values.values()))
              for name, values in hits.items() if values]
    _table(ctx, "IOC 类型统计", ["类型", "唯一值", "出现次数"],
           [[name, unique, count]
            for name, unique, count in sorted(counts, key=lambda row: -row[2])])
    # 同源汇总进"分析结果"：每类 IOC 的唯一值/总次数，WebUI 直接可读。
    if counts and _budget_left(ctx) > 0:
        ordered = sorted(counts, key=lambda row: -row[2])
        ctx.add_finding(
            "log", "日志IOC统计",
            detail="\n".join(f"{name} {unique}/{total}"
                             for name, unique, total in ordered),
            level="info",
            extra={"counts": {name: f"{unique}/{total}"
                              for name, unique, total in ordered}})

    for name in ("Flag", "凭据", "云访问密钥", "私钥", "JWT", "URL", "域名",
                 "邮箱", "MD5", "SHA1", "SHA256", "Key 标识"):
        values = hits.get(name) or {}
        if not values:
            continue
        rows = [[value, item["count"], item["line"], item["time"] or "-"]
                for value, item in sorted(values.items(),
                                          key=lambda kv: -kv[1]["count"])[:15]]
        _table(ctx, f"IOC · {name}", ["值", "次数", "首次行号", "时间"],
               rows, limit=15)

    # IP inventory: public addresses first, because private RFC1918 addresses
    # are usually internal noise while public ones are worth pivoting on.
    ip_rows = [[value, count, "公网" if _is_public_ip(value) else "内网"]
               for value, count in
               (list(public.most_common(20)) + list(private.most_common(20)))]
    _table(ctx, "IP 地址（公网优先）", ["IP", "次数", "类型"],
           ip_rows, limit=40)
    ctx.report(f"IP 统计: 公网 {len(public)} 个，内网 {len(private)} 个", "info")

    flagged = 0
    for value in sorted(hits.get("Flag") or {},
                        key=lambda key: -hits["Flag"][key]["count"]):
        item = hits["Flag"][value]
        if _budget_left(ctx) <= 0:
            break
        ctx.report(f"发现 Flag: {value}", "good")
        ctx.add_finding("flag", f"日志中发现 Flag: {value}",
                        detail=clean_cell(item["raw"], 300), level="good",
                        extra={"line": item["line"], "time": item["time"]})
        flagged += 1
        if flagged >= _MAX_FINDINGS_PER_IOC:
            break

    written = 0
    for name in ("凭据", "云访问密钥", "私钥", "JWT"):
        for value, item in (hits.get(name) or {}).items():
            if written >= _MAX_FINDINGS_PER_IOC or _budget_left(ctx) <= 0:
                break
            ctx.add_finding("credential", f"日志中发现敏感信息（{name}）",
                            detail=(f"{clean_cell(value, 120)}；"
                                    f"出现 {item['count']} 次；"
                                    f"第 {item['line']} 行"),
                            level="warn",
                            extra={"type": name, "line": item["line"],
                                   "time": item["time"],
                                   "count": item["count"]})
            written += 1

    written = 0
    for name in ("MD5", "SHA1", "SHA256"):
        for value, item in (hits.get(name) or {}).items():
            if written >= _MAX_FINDINGS_PER_IOC or _budget_left(ctx) <= 0:
                break
            ctx.add_finding("hash", f"日志中发现 {name} 哈希",
                            detail=f"{value}；第 {item['line']} 行",
                            level="info",
                            extra={"type": name, "line": item["line"]})
            written += 1

    if public:
        ctx.add_finding(
            "log", f"日志中包含 {len(public)} 个公网 IP",
            detail="、".join(value for value, _ in public.most_common(10)),
            level="info",
            extra={"public_ips": len(public), "private_ips": len(private)})

    artifact_rows = []
    for name, values in hits.items():
        for value, item in values.items():
            artifact_rows.append([name, value, item["count"], item["line"],
                                  item["time"]])
    for value, count in public.items():
        artifact_rows.append(["公网IP", value, count, "", ""])
    for value, count in private.items():
        artifact_rows.append(["内网IP", value, count, "", ""])
    ctx.write_output("log_iocs.csv",
                     _write_csv("log_iocs.csv",
                                ["类型", "值", "次数", "首次行号", "时间"],
                                artifact_rows))
    ctx.set_progress(100)
