"""Cross-protocol credential correlation and an authentication timeline.

The individual handlers already record credentials as structured findings.  This
module does not talk to tshark itself; it consumes those findings so the same
account seen over HTTP Basic, FTP, LDAP, SMB2, Redis or a database can be
aggregated, de-duplicated and annotated with every source frame.

Two special handlers are exposed (they have no check box):

``forensics.correlate``
    Aggregate credentials, honour a suppression allow-list and write
    ``credentials_correlated.csv`` plus ``auth_timeline.txt``.

``forensics.timeline``
    Only build the authentication/file activity timeline.

Run them after the extractors that produce the findings, for example::

    python3 -m fnet -C capture.pcap --features \\
        checkBox_30,checkBox_27,checkBox_39,protocols.credentials,\\
        protocols.smb2,forensics.correlate
"""
from __future__ import annotations

import csv
import fnmatch
import io
import re

from fnet.features.common import clean_cell, table
from fnet.features.registry import FeatureContext
from fnet.utils import codec

#: Protocol names used for grouping (keep them short and stable).
PROTOCOL_ALIASES = {
    "http": "http",
    "https": "http",
    "basic": "http",
    "ftp": "ftp",
    "redis": "redis",
    "mongodb": "mongodb",
    "mongo": "mongodb",
    "postgres": "postgres",
    "postgresql": "postgres",
    "pgsql": "postgres",
    "ldap": "ldap",
    "smb": "smb",
    "smb2": "smb",
    "ntlm": "ntlm",
    "kerberos": "kerberos",
    "mysql": "mysql",
    "wifi": "wifi",
    "wpa": "wifi",
    "winrm": "winrm",
    "rdp": "rdp",
}

ACCOUNT_KEYS = ("user", "username", "account", "login", "email", "uname",
                "userid")
SECRET_KEYS = ("pass", "password", "passwd", "pwd", "secret", "token")
HOST_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_FIELD_RE = re.compile(
    r"(?i)\b(?:host|server|bssid|target)\s*[:=]?\s*([^\s,;]+)")
URL_HOST_RE = re.compile(r"(?i)\b(?:https?|ftp)://([^/\s:]+)")
PAIR_RE = re.compile(
    r"(?i)(?:认证|auth|登录|login|bind|basic|密码|password)\s*[:=]?\s*"
    r"([^\s:/]+)[:/]([^\s,;]+)")
KV_RE = re.compile(
    r"(?i)\b(user(?:name)?|account|login|email|pass(?:word|wd)?|pwd|token|"
    r"secret)\s*[:=]\s*['\"]?([^\"',}\s;]+)")


def _clean(value, limit: int = 200) -> str:
    return clean_cell(str(value or ""), limit)


def _normalise_protocol(value: str) -> str:
    text = str(value or "").strip().lower()
    return PROTOCOL_ALIASES.get(text, text)


def _split_patterns(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = re.split(r"[;\n]+", str(value or ""))
    return [str(item).strip() for item in raw if str(item).strip()]


def _first_host(text: str) -> str:
    for pattern in (HOST_FIELD_RE, URL_HOST_RE, HOST_RE):
        match = pattern.search(text or "")
        if match:
            return match.group(1).strip("[]()")
    return ""


def _protocol_from(item: dict, text: str) -> str:
    extra = item.get("extra") or {}
    if extra.get("protocol"):
        return _normalise_protocol(extra["protocol"])
    lowered = (text or "").lower()
    if "http/2" in lowered or "basic" in lowered or "authorization" in lowered:
        return "http"
    for name, alias in PROTOCOL_ALIASES.items():
        if re.search(rf"\b{re.escape(name)}\b", lowered):
            return alias
    return "other"


def _pair_from_text(text: str) -> tuple[str, str]:
    match = PAIR_RE.search(text or "")
    if not match:
        return "", ""
    account, secret = match.group(1), match.group(2)
    if account.lower() in ("user", "username", "account", "login"):
        return "", ""
    return account, secret


def _from_extra(item: dict) -> tuple[str, str, str]:
    extra = item.get("extra") or {}
    account = str(extra.get("account") or "").strip()
    secret = str(extra.get("secret") or "").strip()
    hashed = str(extra.get("hash") or "").strip()
    return account, secret, hashed


def _from_text(text: str) -> tuple[str, str]:
    account = secret = ""
    for match in KV_RE.finditer(text or ""):
        key = match.group(1).lower()
        value = match.group(2).strip()
        if not value:
            continue
        if key in ACCOUNT_KEYS and not account:
            account = value
        elif key in SECRET_KEYS and not secret:
            secret = value
    if not account and not secret:
        account, secret = _pair_from_text(text)
    if not account:
        # DOMAIN\user is common in SMB/NTLM summaries.
        match = re.search(r"\b([A-Za-z0-9_.-]+)\\([A-Za-z0-9_.$-]+)", text or "")
        if match:
            account = f"{match.group(1)}\\{match.group(2)}"
    return account, secret


def _hash_account(text: str) -> str:
    # NetNTLMv1/v2: user::domain:lm:nt:challenge
    match = re.search(r"\b([^\s:]+)::([^:\s]+):", text or "")
    if match:
        return f"{match.group(2)}\\{match.group(1)}"
    return ""


def parse_credential(item: dict) -> dict | None:
    """Turn one credential/hash finding into a normalised record."""
    if not isinstance(item, dict):
        return None
    kind = str(item.get("kind") or "")
    if kind not in ("credential", "hash"):
        return None
    summary = str(item.get("summary") or "")
    detail = str(item.get("detail") or "")
    text = "\n".join(part for part in (summary, detail) if part)
    protocol = _protocol_from(item, text)
    account, secret, hashed = _from_extra(item)
    text_account, text_secret = _from_text(text)
    account = account or text_account
    secret = secret or text_secret
    if not hashed and kind == "hash":
        hashed = detail.strip()
    if not account and hashed:
        account = _hash_account(hashed)
    if not account and not secret and not hashed:
        return None
    extra = item.get("extra") or {}
    host = str(extra.get("host") or "").strip() or _first_host(text)
    record = {
        "protocol": protocol,
        "account": _clean(account, 160),
        "secret": _clean(secret, 300),
        "hash": _clean(hashed, 1200),
        "host": _clean(host, 120),
        "frames": [str(item.get("frame") or "")] if item.get("frame") else [],
        "sources": [str(item.get("feature") or "")] if item.get("feature") else [],
        "kinds": [kind],
        "level": str(item.get("level") or "info"),
        "detail": _clean(detail, 500),
        "summary": _clean(summary, 300),
    }
    return record


def _merge(records: list[dict]) -> list[dict]:
    """Merge duplicates by protocol/account/secret/hash/host."""
    merged: dict[tuple, dict] = {}
    for record in records:
        key = (
            record["protocol"],
            record["account"].lower(),
            record["secret"],
            record["hash"],
            record["host"].lower(),
        )
        current = merged.get(key)
        if current is None:
            merged[key] = record
            continue
        current["frames"] = list(dict.fromkeys(
            current["frames"] + record["frames"]))
        current["sources"] = list(dict.fromkeys(
            current["sources"] + record["sources"]))
        current["kinds"] = list(dict.fromkeys(
            current["kinds"] + record["kinds"]))
        if record["level"] == "good":
            current["level"] = "good"
    # Drop account-only records when the same protocol/account/host has a
    # record with a secret or hash, but keep their frames/sources on the
    # surviving record (avoids "FTP USER alice" duplicates).
    secret_by_base: dict[tuple, list[dict]] = {}
    for item in merged.values():
        if item["secret"] or item["hash"]:
            base = (item["protocol"], item["account"].lower(),
                    item["host"].lower())
            secret_by_base.setdefault(base, []).append(item)
    result = []
    for item in merged.values():
        base = (item["protocol"], item["account"].lower(),
                item["host"].lower())
        if not item["secret"] and not item["hash"] and base in secret_by_base:
            for target in secret_by_base[base]:
                target["frames"] = list(dict.fromkeys(
                    target["frames"] + item["frames"]))
                target["sources"] = list(dict.fromkeys(
                    target["sources"] + item["sources"]))
            continue
        result.append(item)
    for item in result:
        item["frames"] = sorted(dict.fromkeys(item["frames"]),
                                key=_frame_key)
    return result


def is_allowlisted(record: dict, patterns) -> bool:
    """Return True when any allow-list pattern matches the record."""
    patterns = _split_patterns(patterns)
    if not patterns:
        return False
    haystack = " ".join([
        record.get("protocol", ""), record.get("account", ""),
        record.get("host", ""), record.get("secret", ""),
        record.get("summary", ""),
    ]).lower()
    for pattern in patterns:
        lowered = pattern.lower()
        if fnmatch.fnmatchcase(haystack, lowered) or lowered in haystack:
            return True
    return False


def correlate_credentials(items, allowlist=(), min_secret: int = 0) -> list[dict]:
    """Normalise, suppress and de-duplicate credential findings."""
    records = []
    for item in items or []:
        record = parse_credential(item)
        if record is None:
            continue
        if is_allowlisted(record, allowlist):
            continue
        if record["secret"] and len(record["secret"]) < max(0, min_secret):
            continue
        records.append(record)
    merged = _merge(records)
    return sorted(merged, key=lambda item: (
        -len(item["sources"]), item["protocol"], item["account"],
        item["host"], item["secret"]))


def _frame_key(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 10 ** 12


def _event_for(item: dict) -> dict | None:
    kind = str(item.get("kind") or "")
    summary = str(item.get("summary") or "")
    detail = str(item.get("detail") or "")
    level = str(item.get("level") or "info")
    text = f"{summary} {detail}".lower()
    extra = item.get("extra") or {}
    event = ""
    if kind in ("credential", "hash"):
        event = "登录/凭据"
        if "hash" in kind or "netntlm" in text:
            event = "凭据获取"
        success_flag = str(extra.get("success") or "").lower()
        if ("成功" in text or "success" in text or success_flag in ("1", "true", "yes")
                or "状态: 2" in detail or "状态: 3" in detail):
            event = "登录成功"
        elif ("失败" in text or "fail" in text or success_flag in ("0", "false", "no")
              or "状态: 401" in detail or " 401" in text):
            event = "登录失败"
    elif kind == "file":
        if "write" in text or "写入" in text or "上传" in text or "stor" in text:
            event = "文件写入"
        elif "read" in text or "读取" in text or "下载" in text or "retr" in text:
            event = "文件读取"
        else:
            event = "文件操作"
    elif kind == "webshell":
        event = "Webshell 活动"
        if "内存马" in text:
            event = "内存马"
    elif kind == "sql":
        event = "SQL 注入"
    elif kind == "dns":
        event = "DNS 隐蔽通道"
    elif kind == "flag":
        event = "Flag"
    elif kind == "http":
        event = "HTTP 请求"
    if not event:
        return None
    return {
        "frame": str(item.get("frame") or ""),
        "time": str(item.get("time") or ""),
        "kind": kind,
        "level": level,
        "event": event,
        "summary": _clean(summary, 300),
        "feature": str(item.get("feature") or ""),
    }


def build_timeline(items) -> list[dict]:
    """Build a frame-ordered authentication / file-activity timeline."""
    events = []
    seen: set[tuple] = set()
    for item in items or []:
        event = _event_for(item)
        if event is None:
            continue
        key = (event["frame"], event["event"], event["summary"])
        if key in seen:
            continue
        seen.add(key)
        events.append(event)
    # The combined "FTP 登录 user:pass" finding supersedes the bare USER/PASS
    # lines, which would otherwise produce three events for one login.
    if any(event["summary"].startswith("FTP 登录") for event in events):
        events = [event for event in events
                  if not re.match(r"^FTP (USER|PASS|ACCT) ",
                                  event["summary"])]
    return sorted(events, key=lambda item: (
        _frame_key(item["frame"]), item["time"], item["event"]))


def _credential_csv(records: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["协议", "账号", "密码", "哈希", "主机", "来源功能",
                     "来源帧", "次数"])
    for record in records:
        writer.writerow([
            record["protocol"], record["account"], record["secret"],
            record["hash"], record["host"], ",".join(record["sources"]),
            ",".join(record["frames"]), len(record["frames"]),
        ])
    return buffer.getvalue()


def _timeline_text(events: list[dict]) -> str:
    lines = ["帧\t时间\t类型\t事件\t来源功能\t摘要"]
    for event in events:
        lines.append("\t".join([
            event["frame"], event["time"], event["event"],
            event["summary"], event["feature"],
        ]))
    return "\n".join(lines) + "\n"


def _flag_scan(ctx: FeatureContext, records: list[dict]) -> int:
    """Scan correlated secrets/details for flags with source/confidence."""
    found = 0
    for record in records:
        for field, confidence in (("secret", "高"), ("detail", "中"),
                                  ("hash", "中")):
            for flag in codec.find_flags(record.get(field) or ""):
                found += 1
                ctx.report(f"凭据关联中发现 flag: {flag}（置信度 {confidence}）",
                           "good")
                ctx.add_finding(
                    "flag", flag, level="good",
                    detail=f"来源 {record['protocol']} "
                           f"{record['account'] or '-'} 置信度 {confidence}",
                    extra={"confidence": confidence,
                           "source": record["protocol"]})
    return found


def _int_param(value, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def correlate(ctx: FeatureContext) -> None:
    """Aggregate credentials and write the correlation + timeline artifacts."""
    snapshot = list(ctx.findings)
    records = correlate_credentials(
        snapshot, ctx.params.get("cred_allowlist") or (),
        _int_param(ctx.params.get("cred_min_secret")))
    events = build_timeline(snapshot)
    ctx.report("===== 跨协议凭据关联 =====", "good")
    if not records:
        ctx.report("没有可关联的凭据（请先运行 HTTP/FTP/NTLM/LDAP/SMB2/"
                   "数据库等提取功能）", "warn")
    else:
        rows = [[record["protocol"], record["account"],
                 record["secret"] or record["hash"][:60] or "-",
                 record["host"] or "-", ",".join(record["sources"]),
                 ",".join(record["frames"]), str(len(record["frames"]))]
                for record in records]
        table(ctx, "凭据汇总（已去重）",
              ["协议", "账号", "密码/哈希", "主机", "来源", "帧", "次数"], rows,
              limit=200)
        for record in records:
            sources = ",".join(record["sources"]) or "-"
            frames = ",".join(record["frames"]) or "-"
            ctx.report(f"{record['protocol']} {record['account'] or '-'}"
                       f" @ {record['host'] or '-'} 来源 {sources} 帧 {frames}",
                       "good" if record["level"] == "good" else "info")
            ctx.add_finding(
                "credential",
                f"关联 {record['protocol']} {record['account'] or '-'}"
                f" @ {record['host'] or '-'}",
                frame=",".join(record["frames"][:8]), level=record["level"],
                detail=f"来源功能: {sources}\n"
                       f"出现次数: {len(record['frames'])}",
                extra={"protocol": record["protocol"],
                       "account": record["account"],
                       "host": record["host"],
                       "sources": sources,
                       "frames": frames})
        ctx.write_output("credentials_correlated.csv",
                         _credential_csv(records))
        _flag_scan(ctx, records)

    ctx.report(f"===== 认证/文件时间线（{len(events)} 条）=====", "good")
    if events:
        for event in events[:200]:
            ctx.report(f"[{event['frame'] or '-'}] {event['event']}: "
                       f"{clean_cell(event['summary'], 220)}",
                       "good" if event["level"] == "good" else "info")
        ctx.write_output("auth_timeline.txt", _timeline_text(events))
    else:
        ctx.report("没有可用于时间线的凭据、文件或 Webshell 事件", "warn")
    ctx.set_progress(100)


def timeline(ctx: FeatureContext) -> None:
    """Build only the authentication/file activity timeline."""
    events = build_timeline(ctx.findings)
    ctx.report("===== 认证/文件时间线 =====", "good")
    if not events:
        ctx.report("没有可用于时间线的事件", "warn")
        return
    table(ctx, "时间线", ["帧", "时间", "事件", "摘要", "来源"],
          [[item["frame"], item["time"], item["event"],
            clean_cell(item["summary"], 180), item["feature"]]
           for item in events], limit=300)
    ctx.write_output("auth_timeline.txt", _timeline_text(events))
    ctx.add_finding("log", f"认证时间线 {len(events)} 条事件",
                    detail="\n".join(
                        f"[{item['frame']}] {item['event']} "
                        f"{item['summary']}" for item in events[:50]),
                    level="info")
    ctx.set_progress(100)
