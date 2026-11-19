"""Persistence of ``job.json`` — the checkpoint behind pause/resume.

Split out of :mod:`fnet.jobs` so the JobManager facade stays readable.  This
module owns everything on disk that lets a paused or crashed job continue:
the ``completed`` list, per-feature ``status`` map and the job's terminal or
paused ``status`` field (cross-process ``--resume`` reads this file).

Cache paths are resolved through :func:`cache_dir`, which reads
``fnet.jobs.CACHE_DIR`` lazily so tests that monkeypatch that module
attribute keep working.
"""
from __future__ import annotations

import json
from pathlib import Path

from fnet.features.registry import BY_CHECKBOX, BY_HANDLER
from fnet.report import parse_report_text


def cache_dir() -> Path:
    """Current cache root, read lazily from ``fnet.jobs.CACHE_DIR``.

    Tests monkeypatch ``fnet.jobs.CACHE_DIR`` (see ``tests/test_api.py``), so
    every cache lookup here must go through the facade module at call time.
    """
    from fnet import jobs as _jobs_mod

    return _jobs_mod.CACHE_DIR


def job_dir(job_id: str) -> Path | None:
    """Resolve ``<cache>/jobs/<hex id>`` without allowing traversal."""
    if not job_id or any(ch not in "0123456789abcdef" for ch in job_id):
        return None
    root = (cache_dir() / "jobs").resolve()
    target = (root / job_id).resolve()
    if target.parent != root or not target.is_dir():
        return None
    return target


def snapshot(job) -> dict:
    """Serializable metadata persisted next to each job's artifacts."""
    return {
        "id": job.id,
        "pcap": job.pcap,
        "pcap_name": Path(job.pcap).name,
        "kind": getattr(job, "kind", "pcap"),
        "features": [f.checkbox for f in job.features],
        "feature_titles": [f.title for f in job.features],
        "params": job.params,
        "status": job.status,
        "progress": job.progress,
        "created": job.created,
        "started": job.started,
        "finished": job.finished,
        "succeeded": job.succeeded,
        "failed": job.failed,
        "completed": list(job.completed),
        "feature_status": dict(job.feature_status),
        "shards": job.shards,
        "report": job.report_path,
        "report_markdown": job.report_markdown_path,
        "report_html": job.report_html_path,
        "findings": job.findings_path,
        "findings_csv": job.findings_csv_path,
        "findings_count": len(job.findings),
    }


def write_history(job) -> None:
    """Best-effort ``job.json`` snapshot; history must never fail a job."""
    try:
        job.output_dir.mkdir(parents=True, exist_ok=True)
        (job.output_dir / "job.json").write_text(
            json.dumps(snapshot(job), ensure_ascii=False, indent=2,
                       default=str),
            encoding="utf-8")
    except OSError as exc:
        job.log.warn(f"任务历史写入失败: {exc}")


def load_disk_entries(active_ids: set[str]) -> dict[str, dict]:
    """Parse ``<cache>/jobs/*/job.json`` for the history listing.

    Jobs whose process exited before finishing are reported as
    ``interrupted``; live (active) job ids are skipped so the caller can
    overlay its in-memory snapshots.
    """
    entries: dict[str, dict] = {}
    root = cache_dir() / "jobs"
    if root.is_dir():
        for path in root.glob("*/job.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict) or not data.get("id"):
                continue
            job_id = str(data["id"])
            if not path.parent.name == job_id:
                continue
            if job_id not in active_ids and data.get("status") in ("queued", "running"):
                # The process exited before the job could finish.
                data["status"] = "interrupted"
            entries[job_id] = data
    return entries


def read_job_json(output: Path) -> dict | None:
    """Parse one job directory's ``job.json`` (``None`` when unreadable)."""
    try:
        data = json.loads((output / "job.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load_from_history(job_id: str):
    """Recreate an in-memory job from ``<cache>/jobs/<id>/job.json``."""
    from fnet.jobs import Job

    output = job_dir(job_id)
    if output is None:
        return None
    data = read_job_json(output)
    if data is None or data.get("id") != job_id:
        return None
    pcap = str(data.get("pcap") or "")
    if not pcap or not Path(pcap).is_file():
        return None
    features = []
    for item in data.get("features") or []:
        feature = BY_CHECKBOX.get(item) or BY_HANDLER.get(item)
        if feature is not None:
            features.append(feature)
    if not features:
        return None
    try:
        shards = max(1, min(int(data.get("shards") or 1), 64))
    except (TypeError, ValueError):
        shards = 1
    job = Job(job_id, pcap, features, dict(data.get("params") or {}),
              output, created=str(data.get("created") or ""), shards=shards,
              kind=str(data.get("kind") or "pcap"))
    job.status = str(data.get("status") or "interrupted")
    job.progress = int(data.get("progress") or 0)
    job.started = data.get("started")
    job.finished = data.get("finished")
    job.succeeded = int(data.get("succeeded") or 0)
    job.failed = int(data.get("failed") or 0)
    job.completed = [str(item) for item in data.get("completed") or []]
    statuses = data.get("feature_status")
    if isinstance(statuses, dict):
        job.feature_status.update({str(k): str(v) for k, v in statuses.items()})
    for feature in features:
        job.feature_status.setdefault(feature.checkbox, "pending")
    # Restore the old transcript so the resumed report keeps its history.
    try:
        report = (output / "report.txt").read_text(
            encoding="utf-8", errors="replace")
        if report:
            job.log.seed(parse_report_text(report))
    except OSError:
        pass
    return job


def pcap_from_history(job_id: str) -> str | None:
    """Capture path stored in a historical job's ``job.json``."""
    output = job_dir(job_id)
    if output is None:
        return None
    data = read_job_json(output)
    if data is None:
        return None
    pcap = str(data.get("pcap") or "")
    return pcap or None
