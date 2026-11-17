"""Background analysis jobs used by the WebUI and the CLI."""
from __future__ import annotations

import datetime as _dt
import json
import secrets
import shutil
import threading
import traceback
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from fnet import findings as findings_mod
from fnet.config import Config
from fnet.features.registry import (
    BY_CHECKBOX, BY_HANDLER, CancelledError, Feature, FeatureContext, call_feature,
)
from fnet.logger import JobLog, logger
from fnet.paths import CACHE_DIR
from fnet.report import (
    MAX_LOG_RECORDS, MAX_REPORT_FINDINGS, normalise_sections, parse_report_text,
    render_html, render_markdown, select_findings, write_reports,
)
from fnet.tools.runner import ToolBox


@dataclass
class Job:
    id: str
    pcap: str
    features: list[Feature]
    params: dict
    output_dir: Path
    created: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    started: str | None = None
    finished: str | None = None
    status: str = "queued"  # queued|running|done|error|cancelled
    progress: int = 0
    current: str = ""
    error: str = ""
    report_path: str = ""
    report_markdown_path: str = ""
    report_html_path: str = ""
    findings_path: str = ""
    findings_csv_path: str = ""
    findings: list = field(default_factory=list)
    log: JobLog = field(init=False)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    #: True for jobs created by :meth:`JobManager.submit_batch`; only those
    #: participate in the queue's active-slot accounting.
    batch: bool = False

    def __post_init__(self) -> None:
        self.log = JobLog(logger, prefix=self.id[:6])

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "pcap": self.pcap,
            "pcap_name": Path(self.pcap).name,
            "features": [f.checkbox for f in self.features],
            "feature_titles": [f.title for f in self.features],
            "status": self.status,
            "progress": self.progress,
            "current": self.current,
            "error": self.error,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "report": self.report_path,
            "report_markdown": self.report_markdown_path,
            "report_html": self.report_html_path,
            "findings": self.findings_path,
            "findings_csv": self.findings_csv_path,
            "findings_count": len(self.findings),
            "output_dir": str(self.output_dir),
            "log_seq": self.log.last_seq,
        }


class JobManager:
    def __init__(self, config: Config, toolbox: ToolBox) -> None:
        self.config = config
        self.toolbox = toolbox
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pending: deque[str] = deque()
        self._active_batch = 0
        self._concurrency = 1
        self._batch_paused = False

    # -- history -------------------------------------------------------
    @staticmethod
    def _history_path(job: Job) -> Path:
        return job.output_dir / "job.json"

    def _snapshot(self, job: Job) -> dict:
        """Serializable metadata persisted next to each job's artifacts."""
        return {
            "id": job.id,
            "pcap": job.pcap,
            "pcap_name": Path(job.pcap).name,
            "features": [f.checkbox for f in job.features],
            "feature_titles": [f.title for f in job.features],
            "params": job.params,
            "status": job.status,
            "progress": job.progress,
            "created": job.created,
            "started": job.started,
            "finished": job.finished,
            "report": job.report_path,
            "report_markdown": job.report_markdown_path,
            "report_html": job.report_html_path,
            "findings": job.findings_path,
            "findings_csv": job.findings_csv_path,
            "findings_count": len(job.findings),
        }

    def _write_history(self, job: Job) -> None:
        """Best-effort ``job.json`` snapshot; history must never fail a job."""
        try:
            job.output_dir.mkdir(parents=True, exist_ok=True)
            self._history_path(job).write_text(
                json.dumps(self._snapshot(job), ensure_ascii=False, indent=2,
                           default=str),
                encoding="utf-8")
        except OSError as exc:
            job.log.warn(f"任务历史写入失败: {exc}")

    def history(self, limit: int = 100) -> list[dict]:
        """Return on-disk job history merged with the live in-memory jobs."""
        entries: dict[str, dict] = {}
        active = {job.id for job in self._jobs.values()}
        root = CACHE_DIR / "jobs"
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
                if job_id not in active and data.get("status") in ("queued", "running"):
                    # The process exited before the job could finish.
                    data["status"] = "interrupted"
                entries[job_id] = data
        for job in self._jobs.values():
            entries[job.id] = self._snapshot(job)
        ordered = sorted(entries.values(),
                         key=lambda item: str(item.get("created") or ""),
                         reverse=True)
        return ordered[: max(1, limit)]

    def history_detail(self, job_id: str) -> dict | None:
        """Metadata, report text and artifacts for one historical job."""
        output = self._job_dir(job_id)
        if output is None:
            return None
        entry = None
        live = self.get(job_id)
        if live is not None:
            entry = self._snapshot(live)
        else:
            path = output / "job.json"
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("id") == job_id:
                    entry = data
            except (OSError, ValueError):
                entry = None
        if entry is None:
            return None
        report = ""
        try:
            report = (output / "report.txt").read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            pass
        return {
            "job": entry,
            "report": report[:200_000],
            "report_truncated": len(report) > 200_000,
            "artifacts": self.artifacts_in(output),
        }

    def report_source(self, job_id: str) -> dict | None:
        """Structured metadata, logs and artifacts used to render a report.

        Live jobs use the in-memory log buffer; jobs recovered from disk fall
        back to parsing ``report.txt`` so reports still work after a restart.
        """
        live = self.get(job_id)
        if live is not None:
            return {
                "job": self._snapshot(live),
                "logs": [record.as_dict() for record in
                         live.log.records_since(0, limit=MAX_LOG_RECORDS)],
                "artifacts": self.artifacts(live),
                "findings": findings_mod.normalise_all(live.findings),
            }
        detail = self.history_detail(job_id)
        if detail is None:
            return None
        found = self.findings_for(job_id, limit=MAX_REPORT_FINDINGS)
        return {
            "job": detail["job"],
            "logs": parse_report_text(detail["report"]),
            "artifacts": detail["artifacts"],
            "findings": found["findings"] if found else [],
        }

    # -- structured findings -------------------------------------------
    @staticmethod
    def _derived_findings(report_text: str) -> list[dict]:
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

    def findings_for(self, job_id: str, query: str = "", kind: str = "",
                     level: str = "", limit: int = 5000) -> dict | None:
        """Return structured findings for a live or historical job."""
        output = self._job_dir(job_id) if self.get(job_id) is None else None
        live = self.get(job_id)
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
                detail = self.history_detail(job_id)
                if detail is not None:
                    items = self._derived_findings(detail["report"])
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

    def export_findings(self, job_id: str, fmt: str = "csv") -> dict | None:
        """Render findings as CSV (download) without truncating the table."""
        live = self.get(job_id)
        if live is not None:
            items = findings_mod.normalise_all(live.findings)
        else:
            found = self.findings_for(job_id, limit=findings_mod.MAX_FINDINGS)
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

    def export_report(self, job_id: str, fmt: str = "html",
                      sections=None) -> dict | None:
        """Render one report as Markdown or a self-contained HTML document."""
        source = self.report_source(job_id)
        if source is None:
            return None
        fmt = str(fmt or "html").lower()
        if fmt in ("md", "markdown", "text/markdown"):
            suffix = "md"
            content_type = "text/markdown; charset=utf-8"
            renderer = render_markdown
        else:
            suffix = "html"
            content_type = "text/html; charset=utf-8"
            renderer = render_html
        content = renderer(source["job"], source["logs"],
                           source["artifacts"], sections,
                           findings=source.get("findings"))
        return {
            "filename": f"fnet-report-{job_id[:8]}.{suffix}",
            "content": content,
            "content_type": content_type,
            "sections": normalise_sections(sections),
        }

    def merged_report(self, job_ids: list[str], fmt: str = "md",
                      sections=None) -> dict | None:
        """Combine several jobs into one Markdown/HTML batch report."""
        ordered: list[str] = []
        for item in job_ids or []:
            value = str(item or "").strip()
            if value and value not in ordered:
                ordered.append(value)
        ordered = ordered[:50]
        if not ordered:
            return None
        sources = []
        for job_id in ordered:
            source = self.report_source(job_id)
            if source is not None:
                sources.append(source)
        if not sources:
            return None
        logs: list[dict] = []
        artifacts: list[dict] = []
        findings: list[dict] = []
        titles: list[str] = []
        checkboxes: list[str] = []
        created: list[str] = []
        finished: list[str] = []
        for source in sources:
            job = source["job"]
            name = job.get("pcap_name") or job.get("pcap") or job.get("id")
            logs.append({"time": "", "tag": "", "level": "info",
                         "text": f"===== 批量任务：{name} ====="})
            logs.extend(source["logs"])
            for item in source.get("artifacts") or []:
                artifacts.append({"name": f"{name}/{item.get('name')}",
                                  "size": item.get("size")})
            for item in source.get("findings") or []:
                entry = dict(item)
                entry["feature"] = f"{name} · {entry.get('feature') or ''}"
                findings.append(entry)
            for title, checkbox in zip(job.get("feature_titles") or [],
                                       job.get("features") or []):
                if title not in titles:
                    titles.append(title)
                if checkbox not in checkboxes:
                    checkboxes.append(checkbox)
            if job.get("created"):
                created.append(str(job["created"]))
            if job.get("finished"):
                finished.append(str(job["finished"]))
        meta = {
            "id": "batch-" + "-".join(item[:4] for item in ordered[:4]),
            "pcap": f"批量分析汇总（{len(sources)} 个流量包）",
            "pcap_name": f"批量分析汇总（{len(sources)} 个任务）",
            "status": "done",
            "feature_titles": titles,
            "features": checkboxes,
            "params": {"jobs": ", ".join(ordered)},
            "created": min(created) if created else "",
            "started": min(created) if created else "",
            "finished": max(finished) if finished else "",
        }
        fmt = str(fmt or "md").lower()
        if fmt in ("md", "markdown", "text/markdown"):
            suffix, content_type, renderer = (
                "md", "text/markdown; charset=utf-8", render_markdown)
        else:
            suffix, content_type, renderer = (
                "html", "text/html; charset=utf-8", render_html)
        content = renderer(meta, logs, artifacts, sections, findings=findings)
        return {
            "filename": f"fnet-batch-{len(sources)}-jobs.{suffix}",
            "content": content,
            "content_type": content_type,
            "sections": normalise_sections(sections),
            "count": len(sources),
            "jobs": ordered,
        }

    def _job_dir(self, job_id: str) -> Path | None:
        """Resolve ``<cache>/jobs/<hex id>`` without allowing traversal."""
        if not job_id or any(ch not in "0123456789abcdef" for ch in job_id):
            return None
        root = (CACHE_DIR / "jobs").resolve()
        target = (root / job_id).resolve()
        if target.parent != root or not target.is_dir():
            return None
        return target

    def output_dir_for(self, job_id: str) -> Path | None:
        """Output directory for live or historical jobs (``None`` if absent)."""
        live = self.get(job_id)
        if live is not None:
            return live.output_dir
        return self._job_dir(job_id)

    def pcap_for(self, job_id: str) -> str | None:
        """Capture path behind a job, recovered from ``job.json`` after restart."""
        live = self.get(job_id)
        if live is not None:
            return live.pcap
        output = self._job_dir(job_id)
        if output is None:
            return None
        try:
            data = json.loads((output / "job.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        pcap = str(data.get("pcap") or "")
        return pcap or None

    def delete_history(self, job_id: str) -> bool:
        """Delete a finished job's output directory. Active jobs are kept."""
        live = self.get(job_id)
        if live is not None and live.status in ("queued", "running"):
            raise ValueError("任务仍在运行，无法删除")
        target = self._job_dir(job_id)
        if target is None:
            return False
        shutil.rmtree(target)
        with self._lock:
            self._jobs.pop(job_id, None)
        return True

    # -- lifecycle -----------------------------------------------------
    def create(self, pcap: str, checkboxes: list[str], params: dict | None = None) -> Job:
        source = Path(pcap).expanduser()
        if not source.is_file():
            raise FileNotFoundError(f"流量包不存在: {source}")
        if source.suffix.lower() not in (".pcap", ".pcapng", ".cap", ".dmp", ".etl"):
            raise ValueError("仅支持 pcap / pcapng / cap / dmp / etl 文件")
        features: list[Feature] = []
        seen: set[str] = set()
        for item in checkboxes:
            feature = BY_CHECKBOX.get(item) or BY_HANDLER.get(item)
            if feature is None:
                # allow ad-hoc handlers from the "special features" menu
                feature = Feature(item, item, item, "misc", "临时功能")
            if feature.handler not in seen:
                seen.add(feature.handler)
                features.append(feature)
        if not features:
            raise ValueError("请至少选择一个分析功能")
        job_id = secrets.token_hex(8)
        output = CACHE_DIR / "jobs" / job_id
        output.mkdir(parents=True, exist_ok=True)
        job = Job(job_id, str(source.resolve()), features, params or {}, output)
        with self._lock:
            self._jobs[job_id] = job
            self._prune()
        self._write_history(job)
        return job

    def start(self, job: Job) -> Job:
        job.thread = threading.Thread(target=self._run, args=(job,),
                                      name=f"fnet-job-{job.id}", daemon=True)
        job.thread.start()
        return job

    def submit(self, pcap: str, checkboxes: list[str],
               params: dict | None = None) -> Job:
        job = self.create(pcap, checkboxes, params)
        return self.start(job)

    def submit_batch(self, pcaps: list[str], checkboxes: list[str],
                     params: dict | None = None, concurrency: int = 1) -> list[Job]:
        """Create several jobs and run at most ``concurrency`` at a time.

        The jobs are visible immediately with ``status="queued"``; the queue
        starts the next job whenever one finishes (or is cancelled).  This is
        the backend for the WebUI's drag-many-captures workflow.
        """
        if not pcaps:
            raise ValueError("批量分析至少需要一个流量包")
        jobs: list[Job] = []
        try:
            for pcap in pcaps:
                jobs.append(self.create(pcap, checkboxes, params))
        except Exception:
            # Do not leave half-created jobs behind when one path is bad.
            for job in jobs:
                with self._lock:
                    self._jobs.pop(job.id, None)
                shutil.rmtree(job.output_dir, ignore_errors=True)
            raise
        try:
            concurrency = max(1, min(int(concurrency), 8, len(jobs)))
        except (TypeError, ValueError):
            concurrency = 1
        for job in jobs:
            job.batch = True
        with self._lock:
            self._concurrency = concurrency
            self._pending.extend(job.id for job in jobs)
        self._drain()
        return jobs

    def batch_summary(self) -> dict:
        """Queue state for the batch view (counts, order and pause flag)."""
        with self._lock:
            jobs = [job for job in self._jobs.values() if job.batch]
            pending = list(self._pending)
            paused = self._batch_paused
            concurrency = self._concurrency
        counts: dict[str, int] = {}
        for job in jobs:
            counts[job.status] = counts.get(job.status, 0) + 1
        return {
            "total": len(jobs),
            "counts": counts,
            "pending": pending,
            "running": counts.get("running", 0),
            "queued": counts.get("queued", 0),
            "paused": paused,
            "concurrency": concurrency,
            "active": sum(1 for job in jobs
                          if job.status in ("queued", "running")),
        }

    def pause_batch(self) -> dict:
        """Stop starting queued jobs; running jobs are allowed to finish."""
        with self._lock:
            self._batch_paused = True
        return self.batch_summary()

    def resume_batch(self) -> dict:
        with self._lock:
            self._batch_paused = False
        self._drain()
        return self.batch_summary()

    def set_batch_concurrency(self, concurrency) -> dict:
        try:
            value = max(1, min(int(concurrency), 8))
        except (TypeError, ValueError):
            value = 1
        with self._lock:
            self._concurrency = value
        self._drain()
        return self.batch_summary()

    def reorder_batch(self, job_ids: list[str]) -> dict:
        """Apply a new order to the *queued* jobs, keeping unknown ids last."""
        wanted = [str(item) for item in job_ids or []]
        with self._lock:
            pending = list(self._pending)
            ordered = [item for item in wanted if item in pending]
            ordered += [item for item in pending if item not in ordered]
            self._pending = deque(ordered)
        self._drain()
        return self.batch_summary()

    def _drain(self) -> None:
        """Start queued batch jobs until the concurrency slot is full."""
        while True:
            with self._lock:
                if (self._batch_paused
                        or self._active_batch >= self._concurrency
                        or not self._pending):
                    return
                job_id = self._pending.popleft()
                job = self._jobs.get(job_id)
                if job is None or job.status != "queued":
                    continue
                self._active_batch += 1
            self.start(job)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created, reverse=True)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job or job.status not in ("queued", "running"):
            return False
        if job.status == "queued":
            with self._lock:
                try:
                    self._pending.remove(job_id)
                except ValueError:
                    pass
            job.status = "cancelled"
            job.finished = _dt.datetime.now().isoformat(timespec="seconds")
            job.log.warn("任务在队列中取消")
            self._write_history(job)
            self._drain()
            return True
        job.cancel_event.set()
        job.log.warn("收到取消请求，正在停止当前任务…")
        return True

    def _prune(self, keep: int = 40) -> None:
        if len(self._jobs) <= keep:
            return
        ordered = sorted(self._jobs.values(), key=lambda j: j.created)
        for job in ordered[: len(self._jobs) - keep]:
            if job.status in ("done", "error", "cancelled"):
                self._jobs.pop(job.id, None)

    # -- worker --------------------------------------------------------
    def _run(self, job: Job) -> None:
        try:
            self._run_job(job)
        finally:
            if job.batch:
                with self._lock:
                    self._active_batch = max(0, self._active_batch - 1)
            self._drain()

    def _run_job(self, job: Job) -> None:
        if job.cancel_event.is_set() or job.status == "cancelled":
            job.status = "cancelled"
            return
        job.status = "running"
        job.started = _dt.datetime.now().isoformat(timespec="seconds")
        total = len(job.features)
        tshark = self.toolbox.tshark()

        # Merge global configuration into params without overriding user input.
        params = dict(job.params)
        params.setdefault("wordlist", self.config.get("passwddir"))
        params.setdefault("tls_keylog", self.config.get("tls_keylog", "paths"))
        params.setdefault("tls_private_key",
                          self.config.get("tls_private_key", "paths"))
        params.setdefault("tls_key_passphrase",
                          self.config.get("tls_key_passphrase", "paths"))
        params.setdefault("cobaltstrike_keys",
                          self.config.get("cobaltstrike_keys", "paths"))
        params.setdefault("rdp_private_key",
                          self.config.get("rdp_private_key", "paths"))
        params.setdefault("sql_success", self.config.get("sql_success"))
        params.setdefault("sql_time_threshold",
                          self.config.get_float("sql_time_threshold", fallback=1.0))

        job.log.info(f"开始分析: {job.pcap}")
        job.log.info(f"输出目录: {job.output_dir}")
        job.log.info("功能: " + "、".join(f.title for f in job.features))
        if tshark is None:
            job.log.error("tshark 不可用，依赖 tshark 的功能将被跳过")

        succeeded = failed = 0
        for index, feature in enumerate(job.features):
            if job.cancel_event.is_set():
                job.status = "cancelled"
                break
            job.current = feature.title
            job.log.info(f"===== [{index + 1}/{total}] {feature.title} =====")
            base = index / total * 100
            span = 100 / total

            def progress(value: int, _base=base, _span=span) -> None:
                job.progress = int(_base + _span * (value / 100))

            ctx = FeatureContext(
                config=self.config,
                logger=job.log,
                tshark=tshark,
                pcap=job.pcap,
                params=params,
                progress=progress,
                cancel=job.cancel_event,
                output_dir=job.output_dir,
                findings=job.findings,
            )
            first_finding = len(job.findings)
            try:
                call_feature(ctx, feature.handler)
                succeeded += 1
                job.log.good(f"{feature.title} 完成")
            except CancelledError:
                job.status = "cancelled"
                job.log.warn(f"{feature.title} 已取消")
                break
            except Exception as exc:  # noqa: BLE001 - one feature must not kill the job
                failed += 1
                job.log.error(f"{feature.title} 失败: {exc}")
                job.log.debug(traceback.format_exc())
            finally:
                # Attribute whatever the handler recorded, even on failure.
                for item in job.findings[first_finding:]:
                    item["feature"] = feature.title
                    item["checkbox"] = feature.checkbox
            job.progress = int((index + 1) / total * 100)

        if job.cancel_event.is_set():
            job.status = "cancelled"
        elif failed and not succeeded:
            job.status = "error"
        else:
            job.status = "done"
        job.current = ""
        job.finished = _dt.datetime.now().isoformat(timespec="seconds")
        job.log.info(f"分析结束: {job.status}（成功 {succeeded}，失败 {failed}）")
        self._write_findings(job)
        self._write_report(job)

    def _write_findings(self, job: Job) -> None:
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

    def _write_report(self, job: Job) -> None:
        report = job.output_dir / "report.txt"
        lines = [
            "Fnet 分析报告",
            "=" * 60,
            f"流量包: {job.pcap}",
            f"任务 ID: {job.id}",
            f"开始时间: {job.started}",
            f"结束时间: {job.finished}",
            f"状态: {job.status}",
            "功能: " + "、".join(f.title for f in job.features),
            "=" * 60,
            "",
        ]
        records = job.log.records_since(0, limit=MAX_LOG_RECORDS)
        lines.extend(record.line for record in records)
        try:
            report.write_text("\n".join(lines), encoding="utf-8")
            job.report_path = str(report)
        except OSError as exc:
            job.log.warn(f"报告写入失败: {exc}")
        written = {}
        try:
            written = write_reports(
                job, [record.as_dict() for record in records], self.artifacts(job),
                findings=job.findings)
        except Exception as exc:  # noqa: BLE001 - reports must not fail a job
            job.log.warn(f"Markdown/HTML 报告生成失败: {exc}")
        job.report_markdown_path = str(written.get("md") or "")
        job.report_html_path = str(written.get("html") or "")
        if not written:
            job.log.warn("Markdown/HTML 报告生成失败，纯文本报告仍然可用")
        self._write_history(job)

    # -- artifact helpers ---------------------------------------------
    @staticmethod
    def artifacts_in(output_dir: Path) -> list[dict]:
        items = []
        if not output_dir.is_dir():
            return items
        for path in sorted(output_dir.rglob("*")):
            if path.is_file() and path.name != "job.json":
                items.append({
                    "name": path.relative_to(output_dir).as_posix(),
                    "size": path.stat().st_size,
                })
        return items

    def artifacts(self, job: Job) -> list[dict]:
        return self.artifacts_in(job.output_dir)

    def zip_artifacts(self, job: Job) -> Path:
        archive = job.output_dir / f"fnet-{job.id}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in job.output_dir.rglob("*"):
                if path.is_file() and path != archive and path.name != "job.json":
                    zf.write(path, path.relative_to(job.output_dir).as_posix())
        return archive
