"""Human readable analysis reports (plain text, Markdown and HTML).

The job worker keeps the authoritative ``report.txt`` stream and also renders a
Markdown and a self-contained HTML report next to it.  The same renderers are
used by ``GET /api/report`` so a historical job can be re-exported with a
different section selection.

Only the standard library is used: the HTML report embeds its own stylesheet
and can therefore be opened offline or printed to PDF from the browser.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
from pathlib import Path

from fnet.utils import codec

#: Ordered section catalogue shared by the API, the WebUI and the CLI.
SECTIONS: tuple[dict[str, str], ...] = (
    {"key": "summary", "title": "概要"},
    {"key": "features", "title": "功能清单"},
    {"key": "findings", "title": "关键发现"},
    {"key": "log", "title": "完整日志"},
    {"key": "artifacts", "title": "产出文件"},
    {"key": "params", "title": "分析参数"},
)
SECTION_KEYS = tuple(item["key"] for item in SECTIONS)
SECTION_TITLES = {item["key"]: item["title"] for item in SECTIONS}
DEFAULT_SECTIONS = ("summary", "features", "findings", "log", "artifacts")

#: Guard rails so an accidentally huge log cannot exhaust browser memory.
MAX_LOG_RECORDS = 40_000
MAX_REPORT_CHARS = 8 * 1024 * 1024
MAX_REPORT_FINDINGS = 2_000

STATUS_NAMES = {
    "queued": "排队中",
    "running": "运行中",
    "done": "完成",
    "error": "错误",
    "cancelled": "已取消",
    "paused": "已暂停",
    "interrupted": "已中断",
}

_TAG_LEVELS = {"[DEBUG]": "debug", "[*]": "info", "[+]": "good",
               "[!]": "warn", "[-]": "error"}
_LINE_RE = re.compile(r"^(\d{2}:\d{2}:\d{2}) (\[(?:DEBUG|\*|\+|!|-)\]) (.*)$")
_FLAG_RE = re.compile(r"flag\{[^}\r\n]{0,200}\}", re.IGNORECASE)
_FINDING_RE = re.compile(
    r"flag\{|NetNTLM|NTLMv|::|凭据|密码|密钥|password|passwd|Authorization|"
    r"解密|还原|命中|成功|失败|异常|疑似|攻击|漏洞|HASH|hashcat|john",
    re.IGNORECASE,
)
_NOISE_PREFIXES = ("开始分析:", "输出目录:", "功能:", "=====", "分析结束:")
_NOISE_SUFFIXES = ("完成", "已取消", "已停止")
_DATE_FALLBACK = "—"


# ---------------------------------------------------------------------------
# Section / metadata helpers
# ---------------------------------------------------------------------------
def normalise_sections(value) -> list[str]:
    """Parse ``"summary,log"`` (or a list) into a valid, ordered section list."""
    if value is None or value == "":
        return list(DEFAULT_SECTIONS)
    if isinstance(value, str):
        wanted = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, (list, tuple, set)):
        wanted = [str(part).strip() for part in value if str(part).strip()]
    else:
        return list(DEFAULT_SECTIONS)
    selected = [key for key in SECTION_KEYS if key in wanted]
    return selected or list(DEFAULT_SECTIONS)


def section_catalogue() -> list[dict]:
    """Serializable catalogue for ``GET /api/meta`` and the report dialog."""
    return [dict(item, default=item["key"] in DEFAULT_SECTIONS) for item in SECTIONS]


def parse_report_text(text: str) -> list[dict]:
    """Best-effort recovery of log records from a legacy ``report.txt``.

    Lines that do not start with a timestamp are appended to the previous
    record, which keeps multi-line feature output readable after a restart.
    """
    lines = str(text or "").splitlines()
    separators = 0
    start = 0
    for index, line in enumerate(lines):
        if line.startswith("=" * 60):
            separators += 1
            if separators >= 2:
                start = index + 1
                break
    records: list[dict] = []
    seq = 0
    for line in lines[start:]:
        match = _LINE_RE.match(line)
        if match:
            seq += 1
            tag = match.group(2)
            records.append({
                "seq": seq,
                "time": match.group(1),
                "tag": tag,
                "level": _TAG_LEVELS.get(tag, "info"),
                "text": match.group(3),
            })
        elif records and line:
            records[-1]["text"] += "\n" + line
    return records


def _status(meta: dict) -> str:
    raw = str(meta.get("status") or "")
    return STATUS_NAMES.get(raw, raw or "未知")


def _fmt_size(size) -> str:
    try:
        value = float(size)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _fmt_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def summary_rows(meta: dict) -> list[tuple[str, str]]:
    features = meta.get("feature_titles") or []
    rows = [
        ("流量包", str(meta.get("pcap") or "")),
        ("任务 ID", str(meta.get("id") or "")),
        ("状态", _status(meta)),
        ("功能数量", str(len(features))),
        ("创建时间", str(meta.get("created") or _DATE_FALLBACK)),
        ("开始时间", str(meta.get("started") or _DATE_FALLBACK)),
        ("结束时间", str(meta.get("finished") or _DATE_FALLBACK)),
    ]
    return [(label, value) for label, value in rows if value]


def feature_rows(meta: dict) -> list[tuple[int, str, str]]:
    titles = list(meta.get("feature_titles") or [])
    checkboxes = list(meta.get("features") or [])
    rows: list[tuple[int, str, str]] = []
    for index, title in enumerate(titles, 1):
        checkbox = checkboxes[index - 1] if index - 1 < len(checkboxes) else ""
        rows.append((index, str(title), str(checkbox)))
    return rows


def param_rows(meta: dict) -> list[tuple[str, str]]:
    params = meta.get("params") or {}
    if not isinstance(params, dict):
        return []
    return [(str(key), _fmt_value(value)) for key, value in sorted(params.items())]


def artifact_rows(artifacts) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for item in artifacts or []:
        if not isinstance(item, dict):
            continue
        rows.append((str(item.get("name") or ""), _fmt_size(item.get("size"))))
    return [(name, size) for name, size in rows if name]


def select_findings(logs) -> list[dict]:
    """Pick the log records that are worth highlighting at the top."""
    findings: list[dict] = []
    seen: set[str] = set()
    for record in logs or []:
        text = str(record.get("text") or "")
        stripped = text.strip()
        if not stripped or stripped.startswith(_NOISE_PREFIXES):
            continue
        if stripped.endswith(_NOISE_SUFFIXES):
            continue
        level = str(record.get("level") or "info")
        if level not in ("warn", "error") and not _FINDING_RE.search(stripped):
            continue
        if stripped in seen:
            continue
        seen.add(stripped)
        findings.append(record)
    return findings


def finding_rows(findings) -> list[tuple[str, str, str, str, str, str]]:
    """Tabular projection of the structured findings for both report formats."""
    from fnet.findings import KIND_NAMES

    rows: list[tuple[str, str, str, str, str, str]] = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        summary = str(item.get("summary") or "").strip()
        if not summary:
            continue
        rows.append((
            KIND_NAMES.get(str(item.get("kind") or ""),
                           str(item.get("kind") or "")),
            str(item.get("level") or "info"),
            str(item.get("frame") or ""),
            str(item.get("feature") or ""),
            summary,
            str(item.get("detail") or ""),
        ))
        if len(rows) >= MAX_REPORT_FINDINGS:
            break
    return rows


def _trim_logs(logs) -> list[dict]:
    records = list(logs or [])[-MAX_LOG_RECORDS:]
    total = 0
    trimmed: list[dict] = []
    for record in reversed(records):
        text = str(record.get("text") or "")
        if not trimmed and len(text) > MAX_REPORT_CHARS:
            # Keep at least one record even when a single line is enormous.
            clipped = dict(record)
            clipped["text"] = text[:MAX_REPORT_CHARS] + "\n…（已截断）"
            trimmed.append(clipped)
            break
        total += len(text)
        if total > MAX_REPORT_CHARS:
            break
        trimmed.append(record)
    trimmed.reverse()
    return trimmed


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _md_cell(value) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _md_fence(text: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", text)),
                  default=0)
    return "`" * max(3, longest + 1)


def render_markdown(meta: dict, logs, artifacts=None, sections=None,
                    generated: str | None = None,
                    findings=None) -> str:
    selected = normalise_sections(sections)
    records = _trim_logs(logs)
    generated = generated or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Fnet 分析报告",
        "",
        f"> 生成时间：{generated}",
        "",
    ]
    for key in selected:
        if key not in SECTION_KEYS:
            continue
        lines.extend([f"## {SECTION_TITLES[key]}", ""])
        if key == "summary":
            lines.append("| 项目 | 值 |")
            lines.append("| --- | --- |")
            for label, value in summary_rows(meta):
                lines.append(f"| {_md_cell(label)} | {_md_cell(value)} |")
        elif key == "features":
            rows = feature_rows(meta)
            if not rows:
                lines.append("（未记录功能清单）")
            else:
                lines.append("| # | 功能 | 复选框 |")
                lines.append("| --- | --- | --- |")
                for index, title, checkbox in rows:
                    lines.append(
                        f"| {index} | {_md_cell(title)} | `{_md_cell(checkbox)}` |")
        elif key == "findings":
            rows = finding_rows(findings)
            if rows:
                lines.append("| 类别 | 级别 | 帧 | 功能 | 摘要 | 详情 |")
                lines.append("| --- | --- | --- | --- | --- | --- |")
                for kind, level, frame, feature, summary, detail in rows:
                    lines.append(
                        f"| {_md_cell(kind)} | {_md_cell(level)} | "
                        f"{_md_cell(frame)} | {_md_cell(feature)} | "
                        f"{_md_cell(summary)} | {_md_cell(detail)} |")
            else:
                highlights = select_findings(records)
                if not highlights:
                    lines.append("（没有需要特别提示的发现）")
                else:
                    for record in highlights:
                        stamp = record.get("time") or ""
                        level = str(record.get("level") or "info")
                        lines.append(f"- **[{level}]** `{stamp}` "
                                     f"{_md_cell(record.get('text') or '')}")
        elif key == "log":
            text = "\n".join(
                f"{record.get('time') or ''} {record.get('tag') or ''} "
                f"{record.get('text') or ''}" for record in records).rstrip()
            if not text:
                lines.append("（没有日志）")
            else:
                fence = _md_fence(text)
                lines.extend([fence + "text", text, fence])
        elif key == "artifacts":
            rows = artifact_rows(artifacts)
            if not rows:
                lines.append("（没有产出文件）")
            else:
                lines.append("| 文件 | 大小 |")
                lines.append("| --- | --- |")
                for name, size in rows:
                    lines.append(f"| `{_md_cell(name)}` | {_md_cell(size)} |")
        elif key == "params":
            rows = param_rows(meta)
            if not rows:
                lines.append("（没有额外参数）")
            else:
                lines.append("| 参数 | 值 |")
                lines.append("| --- | --- |")
                for name, value in rows:
                    lines.append(f"| `{_md_cell(name)}` | {_md_cell(value)} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_STYLE = """
:root{color-scheme:light dark;--bg:#f7f8fa;--fg:#1f2328;--muted:#6a737d;
--line:#d8dee4;--card:#fff;--accent:#2563eb;--good:#0f7b3f;--warn:#9a6700;
--bad:#b42318;--code:#f0f2f5;--mark:#fff3a3}
@media (prefers-color-scheme:dark){:root{--bg:#161b22;--fg:#e6edf3;
--muted:#9aa4b2;--line:#30363d;--card:#1c2128;--accent:#6ea8fe;
--good:#4ac26b;--warn:#e3b341;--bad:#ff7b72;--code:#21262d;--mark:#5c4b00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans CJK SC",
"Microsoft YaHei",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 20px 64px}
header.report{border-bottom:2px solid var(--line);margin-bottom:20px;
padding-bottom:12px}
h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 10px;font-size:19px;
border-left:4px solid var(--accent);padding-left:10px}
.meta{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top}tr:last-child td{border-bottom:0}th{background:var(--code);
font-weight:600;white-space:nowrap}td.mono,code{font-family:ui-monospace,
SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:13px}
ul.findings{list-style:none;padding:0;margin:0}ul.findings li{background:var(--card);
border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:6px;
padding:8px 12px;margin:8px 0}
ul.findings li.warn{border-left-color:var(--warn)}
ul.findings li.error{border-left-color:var(--bad)}
ul.findings li.good{border-left-color:var(--good)}
.lvl{font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.04em;
color:var(--muted);margin-right:8px}.stamp{color:var(--muted);font-size:12px;
margin-right:8px}
pre.log{background:var(--code);border:1px solid var(--line);border-radius:8px;
padding:14px;margin:0;white-space:pre-wrap;word-break:break-word;
max-height:80vh;overflow:auto;font-size:12.5px;line-height:1.55}
mark{background:var(--mark);color:inherit;border-radius:3px;padding:0 2px}
.toc{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 0;padding:0;list-style:none}
.toc a{color:var(--accent);text-decoration:none;font-size:13px;border:1px solid
var(--line);border-radius:999px;padding:3px 10px;background:var(--card)}
.empty{color:var(--muted)}
footer{margin-top:40px;border-top:1px solid var(--line);padding-top:12px;
color:var(--muted);font-size:12px}
@media print{:root{--bg:#fff;--fg:#000;--card:#fff;--code:#f5f5f5}
body{font-size:12px}main{max-width:none;padding:0}h2{break-after:avoid}
pre.log{max-height:none;overflow:visible}.toc{display:none}}
""".strip()

_LEVEL_NAMES = {"debug": "DEBUG", "info": "INFO", "good": "OK",
                "warn": "WARN", "error": "ERROR"}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _flagify(escaped: str) -> str:
    """Wrap ``flag{...}`` in ``<mark>`` *after* escaping the surrounding text."""
    return _FLAG_RE.sub(lambda match: f"<mark>{match.group(0)}</mark>", escaped)


def _html_table(headers: list[str], rows: list[list[str]],
                mono: set[int] | None = None) -> str:
    mono = mono or set()
    head = "".join(f"<th>{_esc(item)}</th>" for item in headers)
    body = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            css = ' class="mono"' if index in mono else ""
            cells.append(f"<td{css}>{_esc(cell)}</td>")
        body.append(f"<tr>{''.join(cells)}</tr>")
    return (f"<table><thead><tr>{head}</tr></thead><tbody>"
            f"{''.join(body)}</tbody></table>")


def _html_findings_table(rows) -> str:
    head = "".join(f"<th>{_esc(name)}</th>" for name in
                   ("类别", "级别", "帧", "功能", "摘要", "详情"))
    body = []
    for kind, level, frame, feature, summary, detail in rows:
        level = level if level in _LEVEL_NAMES else "info"
        body.append(
            f'<tr class="lvl-{level}">'
            f'<td>{_esc(kind)}</td>'
            f'<td><span class="lvl">{_esc(_LEVEL_NAMES[level])}</span></td>'
            f'<td class="mono">{_esc(frame)}</td>'
            f'<td>{_esc(feature)}</td>'
            f'<td>{_flagify(_esc(summary))}</td>'
            f'<td class="mono">{_flagify(_esc(detail))}</td>'
            "</tr>")
    return (f"<table><thead><tr>{head}</tr></thead><tbody>"
            f"{''.join(body)}</tbody></table>")


def _html_log(records) -> str:
    lines = []
    for record in records:
        level = str(record.get("level") or "info")
        if level not in _LEVEL_NAMES:
            level = "info"
        text = _esc(record.get("text") or "")
        lines.append(
            f"{_esc(record.get('time') or '')} "
            f"{_esc(record.get('tag') or '')} {text}")
    if not lines:
        return '<p class="empty">（没有日志）</p>'
    return f'<pre class="log">{_flagify(chr(10).join(lines))}</pre>'


def render_html(meta: dict, logs, artifacts=None, sections=None,
                generated: str | None = None, findings=None) -> str:
    selected = normalise_sections(sections)
    records = _trim_logs(logs)
    highlights = select_findings(records)
    generated = generated or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"Fnet 分析报告 · {meta.get('pcap_name') or meta.get('pcap') or '任务'}"

    toc = "".join(
        f'<li><a href="#section-{key}">{_esc(SECTION_TITLES[key])}</a></li>'
        for key in selected)
    parts = [
        "<!doctype html>",
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="light dark">',
        f"<title>{_esc(title)}</title>",
        f"<style>{_STYLE}</style></head><body><main>",
        '<header class="report">',
        "<h1>Fnet 分析报告</h1>",
        f'<div class="meta">生成时间：{_esc(generated)} · '
        f'任务 {_esc(str(meta.get("id") or "")[:8])}</div>',
        f'<ul class="toc">{toc}</ul>',
        "</header>",
    ]

    for key in selected:
        if key not in SECTION_KEYS:
            continue
        parts.append(f'<section id="section-{key}">')
        parts.append(f"<h2>{_esc(SECTION_TITLES[key])}</h2>")
        if key == "summary":
            parts.append(_html_table(
                ["项目", "值"], [[label, value]
                                  for label, value in summary_rows(meta)], mono={1}))
        elif key == "features":
            rows = feature_rows(meta)
            if not rows:
                parts.append('<p class="empty">（未记录功能清单）</p>')
            else:
                parts.append(_html_table(
                    ["#", "功能", "复选框"],
                    [[str(index), title, checkbox]
                     for index, title, checkbox in rows], mono={2}))
        elif key == "findings":
            rows = finding_rows(findings)
            if rows:
                parts.append(_html_findings_table(rows))
            elif not highlights:
                parts.append('<p class="empty">（没有需要特别提示的发现）</p>')
            else:
                parts.append('<ul class="findings">')
                for record in highlights:
                    level = str(record.get("level") or "info")
                    if level not in _LEVEL_NAMES:
                        level = "info"
                    text = _flagify(_esc(record.get("text") or ""))
                    parts.append(
                        f'<li class="{_esc(level)}">'
                        f'<span class="lvl">{_esc(_LEVEL_NAMES[level])}</span>'
                        f'<span class="stamp">{_esc(record.get("time") or "")}</span>'
                        f"<span>{text}</span></li>")
                parts.append("</ul>")
        elif key == "log":
            parts.append(_html_log(records))
        elif key == "artifacts":
            rows = artifact_rows(artifacts)
            if not rows:
                parts.append('<p class="empty">（没有产出文件）</p>')
            else:
                parts.append(_html_table(["文件", "大小"], [list(row) for row in rows],
                                         mono={0}))
        elif key == "params":
            rows = param_rows(meta)
            if not rows:
                parts.append('<p class="empty">（没有额外参数）</p>')
            else:
                parts.append(_html_table(["参数", "值"], [list(row) for row in rows],
                                         mono={0, 1}))
        parts.append("</section>")

    status = _status(meta)
    parts.append(
        f'<footer>Fnet · {_esc(status)} · 使用浏览器打印可另存为 PDF。</footer>')
    parts.append("</main></body></html>")
    return "".join(parts)


def write_reports(job, logs, artifacts=None, sections=None,
                  findings=None) -> dict[str, Path]:
    """Render ``report.md`` / ``report.html`` next to a job's ``report.txt``.

    Failures are reported back to the caller instead of raising so a broken
    report can never turn a successful analysis into a failed job.
    """
    output = Path(job.output_dir)
    meta = {
        "id": job.id,
        "pcap": job.pcap,
        "pcap_name": Path(job.pcap).name,
        "features": [feature.checkbox for feature in job.features],
        "feature_titles": [feature.title for feature in job.features],
        "params": job.params,
        "status": job.status,
        "created": job.created,
        "started": job.started,
        "finished": job.finished,
    }
    written: dict[str, Path] = {}
    generated = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for suffix, renderer in (("md", render_markdown), ("html", render_html)):
        path = output / f"report.{suffix}"
        try:
            path.write_text(
                renderer(meta, logs, artifacts, sections, generated=generated,
                         findings=findings),
                encoding="utf-8")
            written[suffix] = path
        except OSError:
            continue
    return written


def find_existing_report(output: Path, suffix: str) -> Path | None:
    target = Path(output) / f"report.{suffix}"
    return target if target.is_file() else None
