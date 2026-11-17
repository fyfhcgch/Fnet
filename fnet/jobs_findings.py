"""Structured findings and human annotations on disk.

Split out of :mod:`fnet.jobs` so the JobManager facade stays readable.  This
module owns ``findings.json`` / ``findings.csv`` writing, the read side used
by ``findings_for`` / ``export_findings`` (including the report-derived
fallback for pre-``findings.json`` jobs) and ``annotations.json`` for the
per-finding human status/note store.

Functions take the :class:`~fnet.jobs.JobManager` instance as their first
argument so they can consult live jobs and the history while keeping the
cache-root monkeypatching semantics intact (via
:func:`fnet.jobs_checkpoint.cache_dir`).
"""
from __future__ import annotations

import datetime as _dt
import json

from fnet import findings as findings_mod
from fnet.jobs_checkpoint import job_dir
from fnet.report import parse_report_text, select_findings

#: Human annotation states for findings (empty string clears the status).
ANNOTATION_STATUSES = ("confirmed", "false_positive", "starred")


# -- annotations -----------------------------------------------------
def annotations_file(manager, job_id: str) -> str | None:
    """``annotations.json`` inside the job's own output directory."""
    output = manager.output_dir_for(job_id)
    if output is None:
        return None
    return output / "annotations.json"


def load_annotations(manager, job_id: str) -> dict | None:
    """Persisted human annotations keyed by finding ``seq``.

    Returns ``None`` when the job does not exist and ``{}`` when it has
    no annotations yet, so callers can tell the two apart.
    """
    path = annotations_file(manager, job_id)
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def set_annotation(manager, job_id: str, seq, status: str = "",
                   note: str = "") -> dict | None:
    """Set or clear one finding's annotation, persisted per job.

    ``status`` is one of :data:`ANNOTATION_STATUSES` (empty clears the
    status); an empty status *and* empty note removes the annotation.
    """
    path = annotations_file(manager, job_id)
    if path is None:
        return None
    try:
        number = int(str(seq).strip())
    except (TypeError, ValueError):
        raise ValueError("seq 必须是正整数")
    if number <= 0:
        raise ValueError("seq 必须是正整数")
    status = str(status or "").strip().lower()
    note = str(note or "").strip()
    if len(note) > 2000:
        note = note[:2000] + "…"
    if status and status not in ANNOTATION_STATUSES:
        raise ValueError("status 仅支持 confirmed / false_positive / starred")
    notes = load_annotations(manager, job_id) or {}
    key = str(number)
    if not status and not note:
        notes.pop(key, None)
        text = f"已清除结果 #{number} 的标注"
    else:
        notes[key] = {"status": status, "note": note,
                      "updated": _dt.datetime.now().isoformat(timespec="seconds")}
        text = f"已保存结果 #{number} 的标注"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(notes, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"标注写入失败: {exc}")
    return {"ok": True, "text": text, "annotations": notes}


def merge_annotations(manager, job_id: str, items: list) -> None:
    """Attach persisted annotations onto findings (in place, by seq)."""
    notes = load_annotations(manager, job_id) or {}
    if not notes:
        return
    for item in items or []:
        record = notes.get(str(item.get("seq") or ""))
        if record:
            item["annotation"] = record


# -- structured findings ----------------------------------------------
def derived_findings(report_text: str) -> list[dict]:
    """Fallback for jobs analysed before ``findings.json`` existed."""
    items: list[dict] = []
    for record in select_findings(parse_report_text(report_text)):
        item = findings_mod.normalise({
            "kind": "log",
            "level": record.get("level"),
            "time": record.get("time"),
            "summary": record.get("text"),
        })
        if item is not None:
            items.append(item)
    return items


def findings_for(manager, job_id: str, query: str = "", kind: str = "",
                 level: str = "", limit: int = 5000) -> dict | None:
    """Return structured findings for a live or historical job."""
    output = job_dir(job_id) if manager.get(job_id) is None else None
    live = manager.get(job_id)
    if live is None and output is None:
        return None
    derived = False
    items: list[dict] = []
    if live is not None:
        items = findings_mod.normalise_all(live.findings)
    else:
        path = output / "findings.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if isinstance(data, dict):
            items = findings_mod.normalise_all(data.get("findings") or [])
        elif isinstance(data, list):
            items = findings_mod.normalise_all(data)
        if not items:
            detail = manager.history_detail(job_id)
            if detail is not None:
                items = derived_findings(detail["report"])
                derived = bool(items)
    for index, item in enumerate(items, 1):
        item["seq"] = index
        item["id"] = f"f{index:05d}"
    kinds = findings_mod.kind_counts(items)
    selected = findings_mod.filter_items(items, query, kind, level)
    try:
        limit = max(1, int(limit))
    except (TypeError, ValueError):
        limit = 5000
    return {
        "findings": selected[:limit],
        "total": len(items),
        "count": len(selected),
        "kinds": kinds,
        "derived": derived,
        "truncated": len(selected) > limit,
    }


def export_findings(manager, job_id: str, fmt: str = "csv") -> dict | None:
    """Render findings as CSV (download) without truncating the table."""
    live = manager.get(job_id)
    if live is not None:
        items = findings_mod.normalise_all(live.findings)
    else:
        found = findings_for(manager, job_id, limit=findings_mod.MAX_FINDINGS)
        if found is None:
            return None
        items = found["findings"]
    if str(fmt or "csv").lower() != "csv":
        return None
    return {
        "filename": f"fnet-findings-{job_id[:8]}.csv",
        "content": findings_mod.to_csv(items),
        "count": len(items),
    }


def write_findings(job) -> None:
    """Persist structured findings as JSON + CSV next to the reports."""
    for index, item in enumerate(job.findings, 1):
        item.setdefault("seq", index)
        item.setdefault("id", f"f{index:05d}")
    json_path = job.output_dir / "findings.json"
    csv_path = job.output_dir / "findings.csv"
    try:
        json_path.write_text(
            json.dumps({"job": job.id, "count": len(job.findings),
                        "findings": job.findings},
                       ensure_ascii=False, indent=2),
            encoding="utf-8")
        job.findings_path = str(json_path)
    except OSError as exc:
        job.log.warn(f"结构化结果写入失败: {exc}")
    try:
        csv_path.write_text(findings_mod.to_csv(job.findings),
                            encoding="utf-8")
        job.findings_csv_path = str(csv_path)
    except OSError as exc:
        job.log.warn(f"结果 CSV 写入失败: {exc}")
    if job.findings:
        job.log.good(f"结构化结果 {len(job.findings)} 条，可在“分析结果”页查看")
