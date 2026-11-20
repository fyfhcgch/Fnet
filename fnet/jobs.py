"""Background analysis jobs used by the WebUI and the CLI.

This module is the public facade: it keeps :class:`JobManager`, :class:`Job`,
``CACHE_DIR`` and :data:`ANNOTATION_STATUSES` importable from here, while the
implementation lives in focused modules:

* :mod:`fnet.jobs_shards` — frame-range splitting and shard clipping;
* :mod:`fnet.jobs_checkpoint` — ``job.json`` checkpoint/resume persistence;
* :mod:`fnet.jobs_findings` — findings JSON/CSV and human annotations.

``CACHE_DIR`` is read lazily through :func:`fnet.jobs_checkpoint.cache_dir` so
tests that monkeypatch ``fnet.jobs.CACHE_DIR`` keep working.
"""
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
from fnet import jobs_checkpoint as _ckpt
from fnet import jobs_findings as _jfnd
from fnet import jobs_shards as _shards
# Re-exported for backwards compatibility with ``from fnet.jobs import …``.
from fnet.jobs_findings import ANNOTATION_STATUSES
from fnet.config import Config
from fnet.features.registry import (
    BY_CHECKBOX, BY_HANDLER, CancelledError, Feature, FeatureContext,
    call_feature, default_features_for,
)
from fnet.logger import JobLog, logger
# ``CACHE_DIR`` stays importable/patchable on this module (``fnet.jobs.CACHE_DIR``)
# — internal code must read it lazily via ``_ckpt.cache_dir()`` so monkeypatching
# keeps working; do not use this binding inside the manager.
from fnet.paths import CACHE_DIR
from fnet.report import (
    MAX_LOG_RECORDS, MAX_REPORT_FINDINGS, REPORT_FILES, annotation_lines,
    is_analysis_artifact, normalise_sections, parse_report_text, render_html,
    render_markdown, write_reports,
)
from fnet.tools.runner import ToolBox
from fnet.utils.logfile import classify_input

#: First bytes of every capture format ``tshark`` reads natively (classic
#: libpcap both endiannesses, nanosecond variants and pcapng).  Mirrors
#: ``fnet.utils.logfile._PCAP_MAGIC``; kept local so the check stays readable.
CAPTURE_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                 b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")

#: ``_capture_problem`` 用它区分"硬错误（拒绝任务）"与"软警告（照常运行）"。
WARN_PREFIX = "WARN:"


@dataclass
class Job:
    id: str
    pcap: str
    features: list[Feature]
    params: dict
    output_dir: Path
    #: ``"pcap"`` for captures, ``"log"`` for text logs (see
    #: :func:`fnet.utils.logfile.classify_input`).  The field name ``pcap`` is
    #: kept for API/report compatibility and holds the input path either way.
    kind: str = "pcap"
    created: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    started: str | None = None
    finished: str | None = None
    status: str = "queued"  # queued|running|done|error|cancelled
    progress: int = 0
    current: str = ""
    error: str = ""
    #: 非致命输入问题（例如抓包损坏但部分可读）。写入报告顶部横幅，
    #: 不影响 ``status``：任务照常完成，但用户能看到"已读取的帧可能不完整"。
    input_warning: str = ""
    report_path: str = ""
    report_markdown_path: str = ""
    report_html_path: str = ""
    findings_path: str = ""
    findings_csv_path: str = ""
    findings: list = field(default_factory=list)
    log: JobLog = field(init=False)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    #: Set by :meth:`JobManager.pause`; the worker stops at the next
    #: feature boundary so a paused job can resume without redoing work.
    pause_event: threading.Event = field(default_factory=threading.Event)
    #: ``checkbox`` values that already ran to completion (checkpointed in
    #: ``job.json`` so a paused/interrupted job can continue).
    completed: list[str] = field(default_factory=list)
    #: ``checkbox -> pending|running|done|error|cancelled`` for the UI.
    feature_status: dict = field(default_factory=dict)
    succeeded: int = 0
    failed: int = 0
    #: Split stateless (``shardable``) features into this many frame ranges.
    shards: int = 1
    thread: threading.Thread | None = None
    #: True for jobs created by :meth:`JobManager.submit_batch`; only those
    #: participate in the queue's active-slot accounting.
    batch: bool = False
    #: Serialises ``job.json`` writes: the worker thread checkpoints after
    #: every feature while ``JobManager.cancel`` writes from the HTTP thread.
    history_lock: threading.Lock = field(default_factory=threading.Lock,
                                         repr=False, compare=False)

    def __post_init__(self) -> None:
        self.log = JobLog(logger, prefix=self.id[:6])

    @property
    def can_resume(self) -> bool:
        return self.status in ("paused", "interrupted") and bool(
            self.completed or self.feature_status or self.progress < 100)

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "pcap": self.pcap,
            "pcap_name": Path(self.pcap).name,
            "kind": self.kind,
            "input_type": "log" if self.kind == "log" else "pcap",
            "features": [f.checkbox for f in self.features],
            "feature_titles": [f.title for f in self.features],
            "status": self.status,
            "paused": self.pause_event.is_set(),
            "can_resume": self.can_resume,
            "progress": self.progress,
            "current": self.current,
            "error": self.error,
            "input_warning": self.input_warning,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "completed": list(self.completed),
            "feature_status": dict(self.feature_status),
            "shards": self.shards,
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

    # -- checkpoint / history ------------------------------------------
    @staticmethod
    def _history_path(job: Job) -> Path:
        return job.output_dir / "job.json"

    def _snapshot(self, job: Job) -> dict:
        return _ckpt.snapshot(job)

    def _write_history(self, job: Job) -> None:
        # The worker checkpoints after each feature while ``cancel`` writes from
        # the HTTP thread; a per-job lock keeps the two writes from interleaving
        # (and ``atomic_write`` keeps a torn file off disk in any case).
        with job.history_lock:
            _ckpt.write_history(job)

    def history(self, limit: int = 100) -> list[dict]:
        """Return on-disk job history merged with the live in-memory jobs."""
        active = {job.id for job in self._jobs.values()}
        entries = _ckpt.load_disk_entries(active)
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
                "findings": self._annotated_findings(job_id, live.findings),
            }
        detail = self.history_detail(job_id)
        if detail is None:
            return None
        found = self.findings_for(job_id, limit=MAX_REPORT_FINDINGS)
        items = found["findings"] if found else []
        if items:
            # ``findings_for`` already assigns seq; annotations are keyed by it.
            self.merge_annotations(job_id, items)
        return {
            "job": detail["job"],
            "logs": parse_report_text(detail["report"]),
            "artifacts": detail["artifacts"],
            "findings": items,
        }

    # -- annotations ----------------------------------------------------
    def _annotations_file(self, job_id: str) -> Path | None:
        return _jfnd.annotations_file(self, job_id)

    def load_annotations(self, job_id: str) -> dict | None:
        """Persisted human annotations keyed by finding ``seq``."""
        return _jfnd.load_annotations(self, job_id)

    def set_annotation(self, job_id: str, seq, status: str = "",
                       note: str = "") -> dict | None:
        """Set or clear one finding's annotation, persisted per job.

        Annotations are usually written after a job finished, so the three
        report files are re-rendered afterwards to keep them consistent.
        """
        result = _jfnd.set_annotation(self, job_id, seq, status, note)
        if result is not None:
            self._refresh_reports(job_id)
        return result

    def merge_annotations(self, job_id: str, items: list) -> None:
        """Attach persisted annotations onto findings (in place, by seq)."""
        _jfnd.merge_annotations(self, job_id, items)

    def _annotated_findings(self, job_id: str, items: list) -> list[dict]:
        """Normalised findings of a live job plus their persisted annotations."""
        annotated = findings_mod.normalise_all(items)
        for index, item in enumerate(annotated, 1):
            item.setdefault("seq", index)
        self.merge_annotations(job_id, annotated)
        return annotated

    @staticmethod
    def _split_report_body(text: str) -> tuple[list[str], list[str]]:
        """Split ``report.txt`` into its fixed header and the log body."""
        lines = str(text or "").splitlines()
        separators = [index for index, line in enumerate(lines)
                      if line.startswith("=" * 60)]
        if len(separators) >= 2:
            cut = separators[1] + 1
            return lines[:cut], lines[cut:]
        return [], lines

    @staticmethod
    def _strip_annotation_block(body: list[str]) -> list[str]:
        """Drop a previously rendered ``人工标注:`` block (idempotent rewrite)."""
        start = 0
        while start < len(body) and not body[start].strip():
            start += 1
        if start >= len(body) or body[start].strip() != "人工标注:":
            return body
        index = start + 1
        while index < len(body) and body[index].startswith("  "):
            index += 1
        while index < len(body) and not body[index].strip():
            index += 1
        return body[:start] + body[index:]

    def _refresh_reports(self, job_id: str) -> None:
        """Re-render the report files after an annotation change.

        Annotations are normally written *after* a job finished, so the three
        artifacts written by the worker would otherwise go stale.  Best effort
        by design: a report problem must never fail the annotation request.
        """
        live = self.get(job_id)
        if live is not None:
            if live.status in ("queued", "running"):
                # The worker renders the reports itself once it finishes.
                return
            try:
                self._write_report(live, live.status)
            except Exception as exc:  # noqa: BLE001 - reports are optional
                live.log.debug(f"标注后重生成报告失败: {exc}")
            return
        output = self.output_dir_for(job_id)
        source = self.report_source(job_id)
        if output is None or source is None:
            return
        have_txt = (output / "report.txt").is_file()
        have_rich = any((output / f"report.{suffix}").is_file()
                        for suffix in ("md", "html"))
        if not have_txt and not have_rich:
            return
        findings = source.get("findings") or []
        try:
            if have_rich:
                from types import SimpleNamespace

                entry = source["job"]
                features = [
                    SimpleNamespace(checkbox=str(checkbox), title=str(title))
                    for title, checkbox in zip(
                        entry.get("feature_titles") or [],
                        entry.get("features") or [])]
                stub = SimpleNamespace(
                    id=job_id, pcap=str(entry.get("pcap") or ""),
                    kind=str(entry.get("kind") or "pcap"),
                    features=features, params=entry.get("params") or {},
                    output_dir=output, status=str(entry.get("status") or ""),
                    created=entry.get("created"), started=entry.get("started"),
                    finished=entry.get("finished"))
                write_reports(stub, source["logs"], source["artifacts"],
                              findings=findings)
            if have_txt:
                path = output / "report.txt"
                header, body = self._split_report_body(
                    path.read_text(encoding="utf-8", errors="replace"))
                body = self._strip_annotation_block(body)
                while body and not body[0].strip():
                    body = body[1:]
                notes = annotation_lines(findings)
                lines = list(header)
                if notes:
                    lines.extend(["", "人工标注:", *notes])
                if body:
                    lines.extend([""] + body)
                _ckpt.atomic_write(path, "\n".join(lines))
        except Exception:  # noqa: BLE001 - never fail the annotation request
            return

    # -- structured findings -------------------------------------------
    @staticmethod
    def _derived_findings(report_text: str) -> list[dict]:
        """Fallback for jobs analysed before ``findings.json`` existed."""
        return _jfnd.derived_findings(report_text)

    def findings_for(self, job_id: str, query: str = "", kind: str = "",
                     level: str = "", limit: int = 5000) -> dict | None:
        """Return structured findings for a live or historical job."""
        return _jfnd.findings_for(self, job_id, query, kind, level, limit)

    def export_findings(self, job_id: str, fmt: str = "csv") -> dict | None:
        """Render findings as CSV (download) without truncating the table."""
        return _jfnd.export_findings(self, job_id, fmt)

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
        return _ckpt.job_dir(job_id)

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
        return _ckpt.pcap_from_history(job_id)

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
    def _capture_problem(self, source: Path, tshark=None) -> str:
        """Return why ``source`` is unreadable as a capture, or ``""``.

        ``classify_input`` trusts the suffix, so a text file renamed to
        ``.pcap`` (or any garbage) used to produce a "successful" job with no
        findings.  A capture must either start with a known magic (so a
        truncated-but-real capture still runs) or be parsed by ``tshark -c 1``.
        """
        try:
            with source.open("rb") as handle:
                head = handle.read(8)
        except OSError as exc:
            return f"无法读取输入文件: {exc}"
        trusted = head[:4] in CAPTURE_MAGIC
        problem = self._probe_capture(source, tshark)
        if problem.startswith(WARN_PREFIX):
            # 魔数正确说明"这确实是一个抓包"，只是损坏/截断：降级为
            # 非致命警告，任务照常运行（部分帧仍可读）。
            return problem if trusted else problem[len(WARN_PREFIX):]
        return problem

    def _probe_capture(self, source: Path, tshark=None) -> str:
        """用 ``tshark -c 1`` 判断能否读出至少一个协议层。

        返回空串表示可解析；``WARN_PREFIX`` 开头的字符串表示"是抓包但读不出
        帧"（损坏/截断），调用方据此设置非致命横幅而不是拒绝任务。
        """
        if tshark is None and self.toolbox is not None:
            # ``ToolBox.path`` is quiet, unlike ``tshark()`` which logs an error
            # when the binary is missing (we only need a path to probe with).
            # ``getattr`` keeps minimal test stubs (``SimpleNamespace``) working.
            lookup = getattr(self.toolbox, "path", None)
            path = lookup("tshark") if callable(lookup) else None
            tshark = getattr(path, "path", path) or None
        if not tshark:
            # Without tshark there is nothing to validate against; the
            # per-feature "tshark 不可用" warning covers this case.
            return ""
        from fnet.tools.runner import run

        # ``tshark`` guesses a file format for short garbage (``garbage`` is
        # read as one 7-byte "MP4" frame), so a zero exit code alone is not
        # enough: the first frame must also expose at least one protocol layer.
        code, out = run([str(tshark), "-r", str(source), "-c", "1",
                         "-T", "fields", "-e", "frame.number",
                         "-e", "frame.protocols"],
                        timeout=30, echo=False)
        if code == 0:
            row = str(out or "").strip().splitlines()
            columns = row[0].split("\t") if row else []
            if len(columns) > 1 and columns[1].strip():
                return ""
            return "无法识别链路层协议（可能不是抓包文件）"
        if code in (124, 130):
            # The probe timed out / was interrupted: inconclusive, so never
            # reject an input we could not actually inspect.
            return ""
        detail = " ".join(str(out or "").split())[:200]
        # 有合法魔数却读不出帧：抓包损坏或截断。任务仍可运行（部分帧可能
        # 可读），但必须在报告里说明，避免"零发现"被误读成"没有问题"。
        reason = detail or f"tshark 退出码 {code}"
        return WARN_PREFIX + reason

    def create(self, pcap: str, checkboxes: list[str], params: dict | None = None,
               shards: int = 1) -> Job:
        source = Path(pcap).expanduser()
        if not source.is_file():
            raise FileNotFoundError(f"输入文件不存在: {source}")
        kind = classify_input(source)
        if kind is None:
            raise ValueError(
                "仅支持 pcap / pcapng / cap / dmp / etl 流量包，"
                "或 log / txt / out / jsonl / ndjson / json / csv / tsv 日志文件")
        input_warning = ""
        if kind == "pcap":
            problem = self._capture_problem(source)
            if problem.startswith(WARN_PREFIX):
                # 抓包损坏/截断但仍可能读出部分帧：不拒绝任务，只记警告。
                input_warning = (
                    f"抓包可能损坏或截断，已读取的帧可能不完整（{problem[len(WARN_PREFIX):]}）")
            elif problem:
                hint = ""
                if source.suffix.lower() in (".etl", ".dmp"):
                    hint = "；ETL/内存转储请先在 WebUI 中转换为 pcapng"
                raise ValueError(
                    f"无法解析抓包: {source.name}（{problem}）{hint}")
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
        output = _ckpt.cache_dir() / "jobs" / job_id
        output.mkdir(parents=True, exist_ok=True)
        try:
            shards = max(1, min(int(shards or 1), 64))
        except (TypeError, ValueError):
            shards = 1
        job = Job(job_id, str(source.resolve()), features, params or {}, output,
                  kind=kind, shards=shards, input_warning=input_warning)
        for feature in features:
            job.feature_status[feature.checkbox] = "pending"
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
               params: dict | None = None, shards: int = 1) -> Job:
        job = self.create(pcap, checkboxes, params, shards=shards)
        return self.start(job)

    def submit_batch(self, pcaps: list[str], checkboxes: list[str],
                     params: dict | None = None, concurrency: int = 1,
                     shards: int = 1) -> list[Job]:
        """Create several jobs and run at most ``concurrency`` at a time.

        The jobs are visible immediately with ``status="queued"``; the queue
        starts the next job whenever one finishes (or is cancelled).  This is
        the backend for the WebUI's drag-many-captures workflow.
        """
        if not pcaps:
            raise ValueError("批量分析至少需要一个输入文件")
        jobs: list[Job] = []
        try:
            for pcap in pcaps:
                jobs.append(self.create(pcap, checkboxes, params, shards=shards))
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

    def pause(self, job_id: str) -> bool:
        """Ask a running job to stop at the next feature boundary."""
        job = self.get(job_id)
        if not job or job.status not in ("queued", "running"):
            return False
        job.pause_event.set()
        job.log.warn("收到暂停请求，将在当前功能结束后暂停…")
        return True

    def resume(self, job_id: str) -> Job | None:
        """Continue a paused job, or recover an interrupted one from disk."""
        job = self.get(job_id)
        if job is None:
            job = self._load_from_history(job_id)
        if job is None or not job.can_resume:
            return None
        job.pause_event.clear()
        job.cancel_event.clear()
        job.status = "queued"
        job.error = ""
        job.current = ""
        job.finished = None
        job.log.info(f"继续任务：已完成 {len(job.completed)}/{len(job.features)} 个功能")
        with self._lock:
            self._jobs[job.id] = job
            self._prune()
        self._write_history(job)
        return self.start(job)

    def _load_from_history(self, job_id: str) -> Job | None:
        """Recreate an in-memory job from ``<cache>/jobs/<id>/job.json``."""
        return _ckpt.load_from_history(job_id)

    def compare(self, base_id: str, target_id: str,
                limit: int = 5000) -> dict | None:
        """Diff the structured findings of two jobs (target minus base).

        The diff key covers the finding identity *and* its human annotation
        (status + note), so re-triaging the same finding shows up as a
        removed/added pair instead of silently staying "common".  Findings
        without annotations key on two empty strings, which keeps comparisons
        of historical jobs byte-for-byte equivalent to the old behaviour.
        """
        base = self.findings_for(base_id, limit=findings_mod.MAX_FINDINGS)
        target = self.findings_for(target_id, limit=findings_mod.MAX_FINDINGS)
        if base is None or target is None:
            return None
        base_items = base["findings"]
        target_items = target["findings"]
        self.merge_annotations(base_id, base_items)
        self.merge_annotations(target_id, target_items)

        def key(item: dict) -> tuple:
            annotation = item.get("annotation")
            if not isinstance(annotation, dict):
                annotation = {}
            return (str(item.get("kind") or ""),
                    str(item.get("summary") or ""),
                    str(item.get("detail") or ""),
                    str(annotation.get("status") or ""),
                    str(annotation.get("note") or ""))

        def unique(items: list[dict]) -> dict[tuple, dict]:
            seen: dict[tuple, dict] = {}
            for item in items:
                seen.setdefault(key(item), item)
            return seen

        base_map = unique(base_items)
        target_map = unique(target_items)
        added = [item for key_, item in target_map.items() if key_ not in base_map]
        removed = [item for key_, item in base_map.items()
                   if key_ not in target_map]
        common = [item for key_, item in target_map.items() if key_ in base_map]

        def kinds(items: list[dict]) -> dict:
            counts: dict[str, int] = {}
            for item in items:
                name = str(item.get("kind") or "other")
                counts[name] = counts.get(name, 0) + 1
            return counts

        base_job = self.history_detail(base_id)
        target_job = self.history_detail(target_id)
        try:
            limit = max(1, int(limit))
        except (TypeError, ValueError):
            limit = 5000
        return {
            "base": str(base_id),
            "target": str(target_id),
            "base_name": ((base_job or {}).get("job") or {}).get("pcap_name", ""),
            "target_name": ((target_job or {}).get("job") or {}).get("pcap_name", ""),
            "added": added[:limit],
            "removed": removed[:limit],
            "common": common[:limit],
            "counts": {
                "base": len(base_map),
                "target": len(target_map),
                "added": len(added),
                "removed": len(removed),
                "common": len(common),
            },
            "kinds": {"base": kinds(base_items),
                      "target": kinds(target_items),
                      "added": kinds(added)},
            "truncated": any(len(items) > limit for items in
                             (added, removed, common)),
        }

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
        except Exception as exc:  # noqa: BLE001 - a worker crash must not wedge the job
            # ``_run_job`` normally swallows handler errors, but an unexpected
            # failure (serialisation, disk, ...) used to escape this thread and
            # leave ``status="running"`` forever, making the CLI poll forever.
            job.failed += 1
            job.error = f"任务执行失败: {exc}"
            job.status = "error"
            job.current = ""
            job.finished = job.finished or _dt.datetime.now().isoformat(
                timespec="seconds")
            job.log.error(job.error)
            job.log.debug(traceback.format_exc())
            for write in (lambda: self._write_findings(job),
                          lambda: self._write_report(job, "error"),
                          lambda: self._write_history(job)):
                try:
                    write()
                except Exception:  # noqa: BLE001 - artifacts are best effort
                    job.log.debug(traceback.format_exc())
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
        job.started = job.started or _dt.datetime.now().isoformat(timespec="seconds")
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
        params.setdefault("rules",
                          self.config.get("rules_file", "paths"))
        params.setdefault("sql_success", self.config.get("sql_success"))
        params.setdefault("sql_time_threshold",
                          self.config.get_float("sql_time_threshold", fallback=1.0))

        job.log.info(f"开始分析{'日志' if job.kind == 'log' else ''}: {job.pcap}")
        job.log.info(f"输出目录: {job.output_dir}")
        job.log.info("功能: " + "、".join(f.title for f in job.features))
        if job.shards > 1:
            job.log.info(f"分片执行：无状态功能按 {job.shards} 个帧区间并行切片")
        if tshark is None and job.kind != "log":
            job.log.error("tshark 不可用，依赖 tshark 的功能将被跳过")

        resume_note = bool(job.completed)
        if resume_note:
            job.log.info("断点续跑：跳过已完成的功能 "
                         + "、".join(job.completed))
        for feature in job.features:
            job.feature_status.setdefault(feature.checkbox, "pending")

        succeeded = job.succeeded
        failed = job.failed
        paused = False
        for index, feature in enumerate(job.features):
            if job.cancel_event.is_set():
                job.status = "cancelled"
                break
            if job.pause_event.is_set():
                paused = True
                job.log.warn(f"已在功能边界暂停（{index}/{total}）")
                break
            if feature.checkbox in job.completed:
                job.feature_status[feature.checkbox] = "done"
                continue
            job.current = feature.title
            job.feature_status[feature.checkbox] = "running"
            self._write_history(job)
            job.log.info(f"===== [{index + 1}/{total}] {feature.title} =====")
            try:
                self._run_feature(job, feature, params, tshark, index, total)
                succeeded += 1
                job.feature_status[feature.checkbox] = "done"
                if feature.checkbox not in job.completed:
                    job.completed.append(feature.checkbox)
                job.log.good(f"{feature.title} 完成")
            except CancelledError:
                job.feature_status[feature.checkbox] = "cancelled"
                job.status = "cancelled"
                job.log.warn(f"{feature.title} 已取消")
                break
            except Exception as exc:  # noqa: BLE001 - one feature must not kill the job
                failed += 1
                job.feature_status[feature.checkbox] = "error"
                job.log.error(f"{feature.title} 失败: {exc}")
                job.log.debug(traceback.format_exc())
            job.succeeded, job.failed = succeeded, failed
            job.progress = int((index + 1) / total * 100)
            # Checkpoint after every feature so a crash/pause never loses work.
            self._write_history(job)

        if not paused and not job.cancel_event.is_set() and params.get("rules"):
            self._apply_rules(job, params, tshark, total)

        if job.cancel_event.is_set():
            terminal = "cancelled"
        elif paused:
            terminal = "paused"
        elif failed and not succeeded:
            terminal = "error"
        else:
            terminal = "done"
        job.current = ""
        job.finished = _dt.datetime.now().isoformat(timespec="seconds")
        job.log.info(f"分析结束: {terminal}（成功 {succeeded}，失败 {failed}）")
        # Optional online IOC enrichment (offline unless the user configured a
        # key) runs before the findings flush so the extra records land in the
        # same findings.json / report. Skipped for cancelled/paused jobs.
        if terminal == "done":
            self._enrich_intel(job)
        # Write all artifacts BEFORE flipping job.status: API clients and the
        # CLI break out of their poll loops as soon as they see the terminal
        # status, and must see the complete artifact list at that moment.
        self._write_findings(job)
        self._write_report(job, terminal)
        job.status = terminal
        # Persist the terminal/paused state: cross-process --resume reads
        # job.json from disk, and a stale status (e.g. "running") would make
        # can_resume False and the job unrestorable.
        self._write_history(job)

    def _run_feature(self, job: Job, feature: Feature, params: dict,
                     tshark, index: int, total: int) -> None:
        """Run one handler, optionally across frame-range shards."""
        base = index / total * 100
        span = 100 / total

        def progress(value: int, _base=base, _span=span) -> None:
            job.progress = int(_base + _span * (value / 100))

        ranges: list[tuple[int, int]] = []
        if feature.shardable and job.shards > 1 and job.kind == "pcap":
            count = self._frame_count(job.pcap, tshark)
            if count and count >= job.shards * 2:
                ranges = _shards.split_ranges(count, job.shards)
                job.log.info(f"{feature.title}: {count} 帧，按 {len(ranges)} 片执行")

        first_finding = len(job.findings)
        try:
            if not ranges:
                call_feature(self._context(job, params, tshark, progress), feature.handler)
                return
            for shard_index, (start, end) in enumerate(ranges, 1):
                clip = self._clip_shard(job, tshark, start, end, shard_index)
                if clip is None:
                    job.log.warn(f"{feature.title}: 切片失败，回退为整包执行")
                    call_feature(self._context(job, params, tshark, progress),
                                 feature.handler)
                    return
                from fnet.tools.runner import count_frames
                if not count_frames(clip, tshark.path if tshark else ""):
                    # A clip without frames would silently produce no results;
                    # fall back to the whole capture so the feature still runs.
                    job.log.warn(
                        f"{feature.title}: 切片 [{shard_index}/{len(ranges)}] "
                        "为空，回退为整包执行")
                    call_feature(self._context(job, params, tshark, progress),
                                 feature.handler)
                    return
                job.log.info(f"[{shard_index}/{len(ranges)}] 帧 {start}-{end}")
                ctx = self._context(job, params, tshark, None, pcap=str(clip),
                                    frame_offset=start - 1,
                                    shard=f"{shard_index}of{len(ranges)}")
                call_feature(ctx, feature.handler)
                progress(int(shard_index / len(ranges) * 100))
        finally:
            # Attribute whatever the handler recorded, even on failure.
            for item in job.findings[first_finding:]:
                item["feature"] = feature.title
                item["checkbox"] = feature.checkbox

    def _context(self, job: Job, params: dict, tshark, progress,
                 pcap: str | None = None, frame_offset: int = 0,
                 shard: str = "") -> FeatureContext:
        return FeatureContext(
            config=self.config,
            logger=job.log,
            tshark=tshark,
            pcap=pcap or job.pcap,
            params=params,
            progress=progress,
            cancel=job.cancel_event,
            output_dir=job.output_dir,
            findings=job.findings,
            input_kind=job.kind,
            frame_offset=frame_offset,
            shard=shard,
        )

    def _apply_rules(self, job: Job, params: dict, tshark, total: int) -> None:
        """Run imported regex/YARA-subset rules and record matches as findings."""
        from fnet.utils import rules as rules_mod

        path = str(params.get("rules")
                   or self.config.get("rules_file", "paths") or "").strip()
        if not path:
            return
        if job.feature_status.get("__rules__") == "done":
            return
        path_obj = Path(path).expanduser()
        if not path_obj.is_file():
            job.log.warn(f"自定义规则文件不存在: {path_obj}")
            return
        job.feature_status["__rules__"] = "running"
        job.current = "自定义规则"
        try:
            rule_set = rules_mod.load_rules(path_obj)
        except Exception as exc:  # noqa: BLE001 - a bad rule file is not fatal
            job.feature_status["__rules__"] = "error"
            job.log.error(f"自定义规则加载失败: {exc}")
            return
        if not rule_set:
            job.feature_status["__rules__"] = "done"
            job.log.warn(f"自定义规则文件没有有效规则: {path_obj}")
            return
        job.log.info(f"===== 自定义规则（{len(rule_set)} 条）=====")
        first = len(job.findings)
        try:
            if job.kind == "log":
                from fnet.utils import logfile

                log = logfile.parse_path(job.pcap)
                matches = []
                for record in log.records:
                    if job.cancel_event.is_set():
                        break
                    hits = rules_mod.match_text(
                        rule_set, record.raw, time=record.time,
                        protocol=record.source)
                    for hit in hits:
                        hit["detail"] = (f"第 {record.line} 行；"
                                         + str(hit.get("detail") or ""))
                    matches.extend(hits)
                    if len(matches) >= rules_mod.MAX_MATCHES:
                        break
                matches = matches[:rules_mod.MAX_MATCHES]
            else:
                matches = rules_mod.scan_pcap(rule_set, job.pcap, tshark,
                                              cancel=job.cancel_event)
        except CancelledError:
            job.feature_status["__rules__"] = "cancelled"
            return
        except Exception as exc:  # noqa: BLE001
            job.feature_status["__rules__"] = "error"
            job.log.error(f"自定义规则执行失败: {exc}")
            return
        for match in matches:
            item = findings_mod.make(
                "rule", match.get("summary") or "",
                frame=match.get("frame", ""), detail=match.get("detail", ""),
                level=match.get("level") or "warn",
                extra={"rule": match.get("rule", ""),
                       "tags": match.get("tags") or []})
            if item is not None:
                item["feature"] = "自定义规则"
                item["checkbox"] = "rules"
                job.findings.append(item)
        job.feature_status["__rules__"] = "done"
        for item in job.findings[first:]:
            item["feature"] = "自定义规则"
            item["checkbox"] = "rules"
        if matches:
            job.log.good(f"自定义规则命中 {len(matches)} 条")
        else:
            job.log.info("自定义规则未命中")
        job.progress = 100
        self._write_history(job)

    # -- sharding helpers ---------------------------------------------
    def _frame_count(self, pcap: str, tshark) -> int:
        """Total frame count using capinfos when available, tshark otherwise."""
        return _shards.frame_count(pcap, tshark)

    def _clip_shard(self, job: Job, tshark, start: int, end: int,
                    shard_index: int) -> Path | None:
        """Write frames ``start..end`` to a temporary pcapng for one shard."""
        return _shards.clip_shard(job, tshark, start, end, shard_index,
                                  cancel=job.cancel_event)

    def _enrich_intel(self, job: Job) -> int:
        """Optional online IOC enrichment of ``job.findings`` (in place).

        Building the client is free and side-effect free: only an explicitly
        configured ``[intel]`` API key enables lookups, so the default offline
        install performs zero network requests and adds no log line.  Any
        failure is swallowed (debug only) because intel is a nice-to-have and
        must never turn a finished analysis into a failed job.
        """
        try:
            from fnet.utils.intel import IntelClient, enrich_job

            if any(str(item.get("feature") or "").startswith("intel.")
                   for item in job.findings if isinstance(item, dict)):
                # Already enriched (e.g. after a resume): never duplicate rows.
                return 0
            client = IntelClient.from_config(self.config)
            if not client.enabled:
                return 0
            return enrich_job(job, client)
        except Exception as exc:  # noqa: BLE001 - optional enrichment
            job.log.debug(f"在线情报富化失败: {exc}")
            return 0

    def _write_findings(self, job: Job) -> None:
        """Persist structured findings as JSON + CSV next to the reports."""
        _jfnd.write_findings(job)

    def _write_report(self, job: Job, status: str | None = None) -> None:
        """Render the txt/md/html reports; ``status`` overrides job.status.

        The worker passes the terminal status here while ``job.status`` is
        still "running", so artifacts are fully written before clients can
        observe the terminal state.
        """
        report = job.output_dir / "report.txt"
        lines = [
            "Fnet 分析报告",
            "=" * 60,
            f"{'日志文件' if job.kind == 'log' else '流量包'}: {job.pcap}",
            f"任务 ID: {job.id}",
            f"开始时间: {job.started}",
            f"结束时间: {job.finished}",
            f"状态: {status or job.status}",
        ]
        if job.input_warning:
            lines.append(f"⚠ 输入警告: {job.input_warning}")
        lines += [
            "功能: " + "、".join(f.title for f in job.features),
            "=" * 60,
            "",
        ]
        records = job.log.records_since(0, limit=MAX_LOG_RECORDS)
        # Same normalisation + seq mapping as ``findings_for`` so annotations
        # (keyed by seq) line up; copies keep report-only keys out of the live
        # job object that is still being checkpointed.
        findings = self._annotated_findings(job.id, job.findings)
        notes = annotation_lines(findings)
        if notes:
            # Kept before the timestamped log lines so ``parse_report_text``
            # still recovers the log records unchanged after a restart.
            lines.append("人工标注:")
            lines.extend(notes)
            lines.append("")
        lines.extend(record.line for record in records)
        try:
            _ckpt.atomic_write(report, "\n".join(lines))
            job.report_path = str(report)
        except (OSError, ValueError) as exc:
            job.log.warn(f"报告写入失败: {exc}")
        written = {}
        try:
            written = write_reports(
                job, [record.as_dict() for record in records], self.artifacts(job),
                findings=findings, status=status)
        except Exception as exc:  # noqa: BLE001 - reports must not fail a job
            job.log.warn(f"Markdown/HTML 报告生成失败: {exc}")
        job.report_markdown_path = str(written.get("md") or "")
        job.report_html_path = str(written.get("html") or "")
        if not written:
            job.log.warn("Markdown/HTML 报告生成失败，纯文本报告仍然可用")

    # -- artifact helpers ---------------------------------------------
    @staticmethod
    def artifacts_in(output_dir: Path) -> list[dict]:
        """Deliverables of a job: report/analysis-result files are not listed.

        ``report.*`` files are exported from the result view and pure analysis
        results (``findings.*``, ``annotations.json``, ``log_*.csv`` …) are
        shown in the "分析结果" tab; the files stay on disk and remain
        downloadable via ``/api/download?path=``.
        """
        items = []
        if not output_dir.is_dir():
            return items
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file() or path.name in REPORT_FILES \
                    or is_analysis_artifact(path.name):
                continue
            items.append({
                "name": path.relative_to(output_dir).as_posix(),
                "size": path.stat().st_size,
            })
        return items

    def artifacts(self, job: Job) -> list[dict]:
        return self.artifacts_in(job.output_dir)

    def zip_artifacts(self, job: Job) -> Path:
        """Pack the job output; pure analysis-result files stay out of the ZIP.

        The three report files keep their historical behaviour here: they are
        hidden from the "产出文件" list but still travel inside the archive.
        """
        archive = job.output_dir / f"fnet-{job.id}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in job.output_dir.rglob("*"):
                if path.is_file() and path != archive \
                        and not is_analysis_artifact(path.name):
                    zf.write(path, path.relative_to(job.output_dir).as_posix())
        return archive
