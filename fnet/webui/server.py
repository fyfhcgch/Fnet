"""Local HTTP server for the Fnet WebUI.

The server binds to loopback by default.  Every mutating request must carry
the random per-process token embedded in ``index.html``; this blocks CSRF
from other sites while keeping the UI a plain browser tab.
"""
from __future__ import annotations

import json
import mimetypes
import re
import secrets
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fnet import APP_DISPLAY_NAME, __version__
from fnet.crack import CrackManager
from fnet.features.registry import default_features_for
from fnet.live import LiveCapture
from fnet.logger import logger
from fnet.ntlmcrack_service import NtlmCrackManager
from fnet.utils.logfile import LOG_SUFFIXES, PCAP_SUFFIXES, classify_input

STATIC_DIR = Path(__file__).with_name("static")
MAX_JSON = 4 * 1024 * 1024
SAFE_NAME = re.compile(r"[^A-Za-z0-9._\-\u4e00-\u9fff]+")

#: Fields the "SMB3 解密" dialog can auto-fill from what the job already knows.
SMB_HINT_FIELDS = ("password", "nt_hash", "session_key", "user", "domain",
                   "stream")
#: Chinese labels for those fields (same wording as the dialog itself).
SMB_HINT_LABELS = {
    "password": "明文密码",
    "nt_hash": "NT 哈希",
    "session_key": "会话密钥",
    "user": "账号",
    "domain": "域",
    "stream": "TCP 流",
}


def empty_smb_hints() -> dict:
    """An all-empty hints payload: the dialog stays manually fillable."""
    return {
        "hints": dict.fromkeys(SMB_HINT_FIELDS, ""),
        "sources": dict.fromkeys(SMB_HINT_FIELDS, ""),
        "accounts": [],
        "notes": [],
    }


def smb_hints_payload(jobs, job_id: str, stream: str = "",
                      cracked=None) -> dict:
    """Collect SMB3 auto-fill clues, degrading to empties on any failure.

    :mod:`fnet.smb_hints` is imported lazily (like :mod:`fnet.smb3` in the
    decrypt route) and every failure shape -- a missing module, a broken
    resolver, a payload with the wrong types -- just means "no clues", so
    the dialog stays usable by hand.
    """
    try:
        from fnet.smb_hints import hints_for_job
    except ImportError:  # the resolver is optional; manual filling still works
        return empty_smb_hints()
    try:
        payload = hints_for_job(jobs, job_id, stream=stream, cracked=cracked)
    except Exception as exc:  # noqa: BLE001 - hints are a convenience only
        logger.warn(f"SMB3 自动填入线索读取失败: {exc}")
        return empty_smb_hints()
    if not isinstance(payload, dict):
        return empty_smb_hints()
    hints = payload.get("hints")
    sources = payload.get("sources")
    hints = hints if isinstance(hints, dict) else {}
    sources = sources if isinstance(sources, dict) else {}
    accounts = payload.get("accounts")
    notes = payload.get("notes")
    fields = SMB_HINT_FIELDS
    return {
        "hints": {key: str(hints.get(key) or "") for key in fields},
        "sources": {key: str(sources.get(key) or "") for key in fields},
        "accounts": ([item for item in accounts if isinstance(item, dict)]
                     if isinstance(accounts, (list, tuple)) else []),
        "notes": ([str(item) for item in notes]
                  if isinstance(notes, (list, tuple)) else []),
    }


class FnetApp:
    """Process-wide application state shared by HTTP handlers and CLI."""

    def __init__(self, config, toolbox, jobs, plugins) -> None:
        self.config = config
        self.toolbox = toolbox
        self.jobs = jobs
        self.plugins = plugins
        self.live = LiveCapture(toolbox, config)
        self.crack = CrackManager(jobs, toolbox, config)
        self.ntlmcrack = NtlmCrackManager(jobs, toolbox, config)
        self.token = secrets.token_urlsafe(24)
        self.server: ThreadingHTTPServer | None = None
        #: Pre-selected capture/features from ``fnet capture.pcapng --features ...``.
        self.initial_pcap = ""
        self.initial_features: list[str] = []

    def meta(self) -> dict:
        from fnet.features.registry import CATEGORIES, FEATURES, feature_dict
        from fnet.findings import kind_catalogue
        from fnet.paths import CACHE_DIR, DEFAULT_WORDLIST, LOG_DIR, USER_DIR
        from fnet.report import DEFAULT_SECTIONS, section_catalogue
        from fnet.themes import THEMES

        tools = {}
        for key, available in self.toolbox.availability().items():
            tools[key] = {"available": available, "path": self.toolbox.path(key)}
        return {
            "app": APP_DISPLAY_NAME,
            "version": __version__,
            "token": self.token,
            "features": [feature_dict(f) for f in FEATURES],
            "categories": CATEGORIES,
            "themes": [
                {"key": key, "name": value["name"],
                 "colors": {k: v for k, v in value.items() if k != "name"}}
                for key, value in THEMES.items()
            ],
            "theme": self.config.get("theme") or "dark",
            "language": self.config.get("language") or "zh",
            "tools": tools,
            "plugins": self.plugins.as_list(),
            "rules": {
                "file": self.config.get("rules_file", "paths"),
                "count": self._rule_count(),
            },
            "live": {"available": bool(tools.get("tshark", {}).get("available"))},
            "paths": {
                "user": str(USER_DIR),
                "logs": str(LOG_DIR),
                "cache": str(CACHE_DIR),
                "wordlist": str(DEFAULT_WORDLIST),
            },
            "config": self.config_snapshot(),
            "recent": self.config.recent_files(),
            "report": {
                "sections": section_catalogue(),
                "default_sections": list(DEFAULT_SECTIONS),
            },
            "findings": {"kinds": kind_catalogue()},
            "crack": {
                "available": bool(tools.get("hashcat", {}).get("available")),
                "settings": self.crack_settings(),
            },
            "smb": {
                "available": bool(tools.get("tshark", {}).get("available")),
                "hints": True,
            },
            "initial": {
                "pcap": self.initial_pcap,
                "features": list(self.initial_features),
            },
        }

    def config_snapshot(self) -> dict:
        return {
            "config": self.config.as_dict("config"),
            "paths": self.config.as_dict("paths"),
            "plugins": self.config.as_dict("plugins"),
        }

    def crack_settings(self) -> dict:
        """hashcat knobs persisted in ``config.ini`` (shared with the UI)."""
        from fnet.paths import DEFAULT_WORDLIST

        return {
            "wordlist": self.config.get("passwddir") or str(DEFAULT_WORDLIST),
            "workload": self.config.get("hashcat_workload") or "3",
            "optimized": self.config.get_bool("hashcat_optimized",
                                              fallback=True),
            "force": self.config.get_bool("hashcat_force", fallback=False),
            "timeout": self.config.get_int("hashcat_timeout", fallback=300),
            "extra": self.config.get("hashcat_extra") or "",
        }

    def _rule_count(self) -> int:
        path = str(self.config.get("rules_file", "paths") or "").strip()
        if not path:
            return 0
        try:
            from fnet.utils import rules as rules_mod

            return len(rules_mod.load_rules(path))
        except Exception:  # noqa: BLE001 - a bad path is reported in the UI
            return 0


class Handler(BaseHTTPRequestHandler):
    server_version = "FnetWebUI"
    protocol_version = "HTTP/1.1"
    #: Bytes of the current POST body already pulled off the socket.
    _body_used = 0

    # -- plumbing ------------------------------------------------------
    @property
    def app(self) -> FnetApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        logger.debug("http " + (fmt % args))

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8",
                   {"Cache-Control": "no-store"})

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"ok": False, "error": message}, status)

    def _query(self) -> dict[str, list[str]]:
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

    def _token_ok(self) -> bool:
        supplied = (self.headers.get("X-Fnet-Token")
                    or (self._query().get("token") or [""])[0])
        return secrets.compare_digest(supplied, self.app.token)

    def _declared_body(self) -> int:
        try:
            return max(0, int(self.headers.get("Content-Length") or 0))
        except (TypeError, ValueError):
            return 0

    def _body(self, limit: int = MAX_JSON) -> bytes:
        length = self._declared_body()
        if length > limit:
            raise ValueError("请求体过大")
        data = self.rfile.read(length) if length else b""
        self._body_used += len(data)
        return data

    def _drain_body(self) -> None:
        """Consume any request-body bytes the route did not read.

        ``protocol_version`` is HTTP/1.1, so the connection is reused for the
        next request.  Routes that answer without parsing the body (delete,
        cancel, pause, ...) would otherwise leave e.g. the ``{}`` sent by the
        UI's ``body: {}`` in the socket, and it would be parsed as part of the
        next request line (``{}GET /api/history`` -> 501).
        """
        remaining = self._declared_body() - self._body_used
        if remaining <= 0:
            return
        if remaining > MAX_JSON:
            # Too large to swallow safely; make the server close the socket
            # instead of misreading the leftover bytes as a new request.
            self.close_connection = True
            return
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def _json_body(self) -> dict:
        raw = self._body()
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON 必须是对象")
        return data

    # -- routes --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path in ("/", "/index.html"):
                return self._index()
            if path == "/favicon.ico":
                return self._favicon()
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/api/health":
                return self._json({"ok": True, "version": __version__})
            if not path.startswith("/api/"):
                return self._error("未找到", 404)
            if not self._token_ok():
                return self._error("无效的访问令牌，请刷新页面", 403)
            if path == "/api/meta":
                return self._json(self.app.meta())
            if path == "/api/config":
                return self._json({"ok": True, **self.app.config_snapshot()})
            if path == "/api/jobs":
                return self._json({"ok": True, "jobs": [j.as_dict() for j in self.app.jobs.list()]})
            if path == "/api/history":
                return self._json({"ok": True, "jobs": self.app.jobs.history()})
            match = re.fullmatch(r"/api/history/([0-9a-f]+)", path)
            if match:
                detail = self.app.jobs.history_detail(match.group(1))
                if detail is None:
                    return self._error("任务历史不存在", 404)
                return self._json({"ok": True, **detail})
            match = re.fullmatch(r"/api/jobs/([0-9a-f]+)", path)
            if match:
                return self._job(match.group(1))
            if path == "/api/download":
                return self._download()
            if path == "/api/findings":
                return self._findings()
            if path == "/api/smb/hints":
                return self._smb_hints()
            if path == "/api/crack":
                return self._crack_status()
            if path == "/api/ntlmcrack":
                return self._ntlmcrack_get()
            if path == "/api/packet":
                return self._packet()
            if path == "/api/report":
                return self._report()
            if path == "/api/batch":
                return self._json({"ok": True,
                                   "summary": self.app.jobs.batch_summary()})
            if path == "/api/batch/report":
                return self._batch_report()
            if path == "/api/compare":
                return self._compare()
            if path == "/api/topology":
                return self._topology()
            if path == "/api/annotations":
                return self._annotations_info()
            if path == "/api/capture/interfaces":
                return self._json({"ok": True,
                                   "interfaces": self.app.live.interfaces()})
            if path == "/api/capture/status":
                return self._json({"ok": True,
                                   "capture": self.app.live.status()})
            if path == "/api/rules":
                return self._rules_info()
            if path == "/api/log":
                return self._log_tail()
            return self._error("未找到", 404)
        except Exception as exc:  # noqa: BLE001 - return a clean API error
            logger.error(f"HTTP GET {path} 失败: {exc}")
            return self._error(str(exc), 500)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        self._body_used = 0
        try:
            if path == "/api/upload":
                if not self._token_ok():
                    return self._error("无效的访问令牌", 403)
                return self._upload()
            if not path.startswith("/api/"):
                return self._error("未找到", 404)
            if not self._token_ok():
                return self._error("无效的访问令牌，请刷新页面", 403)
            if path == "/api/analyze":
                return self._analyze()
            if path == "/api/batch":
                return self._batch()
            if path == "/api/batch/pause":
                return self._json({"ok": True,
                                   "summary": self.app.jobs.pause_batch()})
            if path == "/api/batch/resume":
                return self._json({"ok": True,
                                   "summary": self.app.jobs.resume_batch()})
            if path == "/api/batch/reorder":
                data = self._json_body()
                ids = data.get("ids") or data.get("jobs") or []
                if not isinstance(ids, list):
                    return self._error("ids 必须是数组")
                return self._json({
                    "ok": True,
                    "summary": self.app.jobs.reorder_batch(ids),
                })
            if path == "/api/batch/concurrency":
                data = self._json_body()
                return self._json({
                    "ok": True,
                    "summary": self.app.jobs.set_batch_concurrency(
                        data.get("concurrency", 1)),
                })
            if path == "/api/action":
                return self._action()
            if path == "/api/decode":
                return self._decode()
            if path == "/api/config":
                return self._set_config()
            if path == "/api/shutdown":
                self._json({"ok": True, "message": "服务正在关闭"})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            match = re.fullmatch(r"/api/jobs/([0-9a-f]+)/cancel", path)
            if match:
                ok = self.app.jobs.cancel(match.group(1))
                return self._json({"ok": ok})
            match = re.fullmatch(r"/api/jobs/([0-9a-f]+)/pause", path)
            if match:
                ok = self.app.jobs.pause(match.group(1))
                return self._json({"ok": ok,
                                   "text": "将在当前功能结束后暂停" if ok
                                           else "任务未在运行"})
            match = re.fullmatch(r"/api/jobs/([0-9a-f]+)/resume", path)
            if match:
                job = self.app.jobs.resume(match.group(1))
                if job is None:
                    return self._error("任务不可恢复", 400)
                return self._json({"ok": True, "job": job.as_dict()})
            if path == "/api/capture/start":
                data = self._json_body()
                capture = self.app.live.start(
                    str(data.get("interface") or ""),
                    str(data.get("filter") or ""),
                    str(data.get("name") or ""))
                return self._json({"ok": True, "capture": capture})
            if path == "/api/capture/stop":
                data = self._json_body()
                capture = self.app.live.stop()
                job = None
                if data.get("analyze") and capture.get("path"):
                    features = data.get("features") or []
                    handlers = data.get("handlers") or []
                    params = data.get("params") or {}
                    selection = list(features) + list(handlers)
                    if selection:
                        job = self.app.jobs.submit(
                            capture["path"], selection, params,
                            shards=data.get("shards", 1))
                return self._json({"ok": True, "capture": capture,
                                   "job": job.as_dict() if job else None})
            if path == "/api/rules":
                return self._set_rules()
            if path == "/api/replay":
                return self._replay()
            if path == "/api/annotations":
                return self._annotations_set()
            if path == "/api/crack":
                return self._crack_start()
            if path == "/api/crack/cancel":
                return self._crack_cancel()
            if path == "/api/ntlmcrack":
                return self._ntlmcrack_start()
            if path == "/api/ntlmcrack/cancel":
                return self._ntlmcrack_cancel()
            if path == "/api/smb/decrypt":
                return self._smb_decrypt()
            match = re.fullmatch(r"/api/history/([0-9a-f]+)/delete", path)
            if match:
                ok = self.app.jobs.delete_history(match.group(1))
                return self._json({"ok": ok, "text": "历史任务已删除" if ok else "任务不存在"})
            return self._error("未找到", 404)
        except json.JSONDecodeError as exc:
            return self._error(f"JSON 解析失败: {exc}", 400)
        except (FileNotFoundError, ValueError) as exc:
            return self._error(str(exc), 400)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"HTTP POST {path} 失败: {exc}")
            return self._error(str(exc), 500)
        finally:
            self._drain_body()

    # -- static --------------------------------------------------------
    def _index(self) -> None:
        template = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        html = (template
                .replace("__TOKEN__", self.app.token)
                .replace("__VERSION__", __version__)
                .replace("__APP__", APP_DISPLAY_NAME))
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8",
                   {"Cache-Control": "no-store",
                    "Content-Security-Policy":
                        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                        "connect-src 'self'"})

    def _favicon(self) -> None:
        for candidate in (STATIC_DIR / "favicon.ico",):
            if candidate.exists():
                return self._send(200, candidate.read_bytes(), "image/x-icon")
        return self._error("未找到", 404)

    def _static(self, relative: str) -> None:
        relative = urllib.parse.unquote(relative)
        target = (STATIC_DIR / relative).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            return self._error("未找到", 404)
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), ctype,
                   {"Cache-Control": "public, max-age=300"})

    # -- API -----------------------------------------------------------
    def _job(self, job_id: str) -> None:
        job = self.app.jobs.get(job_id)
        if job is None:
            return self._error("任务不存在", 404)
        cursor = int((self._query().get("cursor") or ["0"])[0] or 0)
        records = job.log.records_since(cursor)
        self._json({
            "ok": True,
            "job": job.as_dict(),
            "logs": [r.as_dict() for r in records],
            "cursor": job.log.last_seq,
            "artifacts": self.app.jobs.artifacts(job) if job.status in
                         ("done", "error", "cancelled") else [],
        })

    def _analyze(self) -> None:
        data = self._json_body()
        pcap = str(data.get("pcap") or "").strip()
        features = data.get("features") or data.get("checkboxes") or []
        handlers = data.get("handlers") or []
        params = data.get("params") or {}
        if not isinstance(features, list) or not isinstance(params, dict):
            return self._error("features 必须是数组，params 必须是对象")
        selection = list(features) + list(handlers)
        if not selection:
            selection = default_features_for(classify_input(pcap) or "pcap")
        job = self.app.jobs.submit(pcap, selection, params,
                                   shards=data.get("shards", 1))
        self.app.config.add_recent(pcap)
        self.app.config.save()
        logger.info(f"新任务 {job.id}: {Path(pcap).name} / {len(job.features)} 个功能")
        return self._json({"ok": True, "job": job.as_dict()})

    def _upload(self) -> None:
        limit = self.app.config.get_int("max_upload_mb", fallback=1024) * 1024 * 1024
        ctype = self.headers.get("Content-Type", "")
        from fnet.paths import CACHE_DIR
        upload_dir = CACHE_DIR / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        kind = (self.headers.get("X-Kind")
                or (self._query().get("kind") or [""])[0]).strip().lower()

        temp: Path | None = None
        try:
            if ctype.startswith("multipart/form-data"):
                match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", ctype)
                if not match:
                    return self._error("缺少 multipart boundary")
                boundary = (match.group(1) or match.group(2)).strip().encode()
                filename, temp = self._receive_multipart(
                    boundary, limit, upload_dir)
            else:
                filename = urllib.parse.unquote(
                    self.headers.get("X-Filename", "capture.pcap"))
                temp = upload_dir / f"upload-{secrets.token_hex(8)}.part"
                with temp.open("wb") as handle:
                    size = self._stream_body(handle, limit)
                if not size:
                    return self._error("上传内容为空")

            if temp is None or not temp.is_file() or temp.stat().st_size == 0:
                return self._error("上传内容为空")
            size = temp.stat().st_size
            name = SAFE_NAME.sub("_", Path(filename or "capture.pcap").name)

            if kind in ("keylog", "tls_keylog", "tls-keylog", "tls_key",
                        "key", "private_key", "tls_private_key", "tls-key"):
                payload = temp.read_bytes()
                temp.unlink(missing_ok=True)
                temp = None
                return self._upload_key(name, payload, kind)

            if kind in ("rules", "rule", "yara"):
                return self._upload_rules(name, temp)

            if not Path(name).suffix:
                name += ".pcap"
            if Path(name).suffix.lower() not in (PCAP_SUFFIXES | LOG_SUFFIXES):
                # Unlink before responding: the ``finally`` cleanup runs after
                # the HTTP response is sent, and a client checking uploads for
                # leftovers right after the 400 would still see the .part.
                temp.unlink(missing_ok=True)
                temp = None
                return self._error("仅支持 pcap/pcapng/cap/dmp/etl 流量包，"
                                   "或 log/txt/out/jsonl/ndjson/json/csv/tsv 日志文件")
            target = upload_dir / f"{secrets.token_hex(4)}_{name}"
            temp.replace(target)
            temp = None
            logger.good(f"已上传文件 {name} ({size} 字节)")
            return self._json({"ok": True, "path": str(target), "name": name,
                               "size": size})
        finally:
            if temp is not None:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    pass

    def _stream_body(self, handle, limit: int) -> int:
        """Copy the request body to ``handle`` with constant memory."""
        try:
            length = max(0, int(self.headers.get("Content-Length") or 0))
        except (TypeError, ValueError):
            length = 0
        if length > limit:
            raise ValueError("文件超过大小限制")
        remaining = length
        total = 0
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            handle.write(chunk)
            total += len(chunk)
            remaining -= len(chunk)
            self._body_used += len(chunk)
        return total

    def _receive_multipart(self, boundary: bytes, limit: int,
                           upload_dir: Path) -> tuple[str, Path]:
        """Stream a multipart upload to disk without buffering the whole body."""
        try:
            length = max(0, int(self.headers.get("Content-Length") or 0))
        except (TypeError, ValueError):
            length = 0
        if length > limit:
            raise ValueError("文件超过大小限制")
        reader = _MultipartStream(self.rfile, boundary, length, limit)
        try:
            filename = "capture.pcap"
            temp: Path | None = None
            # Skip the preamble and stop on the first boundary line.
            line = reader.readline()
            while line and reader.delimiter not in line:
                line = reader.readline()
            if not line:
                raise ValueError("multipart 中没有文件字段")
            while True:
                headers: dict[str, str] = {}
                while True:
                    line = reader.readline()
                    if not line or line in (b"\r\n", b"\n"):
                        break
                    text = line.decode("utf-8", "replace").rstrip("\r\n")
                    key, _, value = text.partition(":")
                    if key:
                        headers[key.strip().lower()] = value.strip()
                disposition = headers.get("content-disposition", "")
                found = re.search(r'filename="([^"]*)"', disposition)
                if found and temp is None:
                    filename = found.group(1) or filename
                    temp = upload_dir / f"upload-{secrets.token_hex(8)}.part"
                    with temp.open("wb") as handle:
                        reader.stream_to(handle)
                else:
                    reader.drain_part()
                line = reader.readline()
                if not line or line.startswith(b"--"):
                    break
            if temp is None:
                raise ValueError("multipart 中没有文件字段")
            return filename, temp
        finally:
            # Bytes already pulled off the socket count as consumed even if
            # they only sit in the reader's buffer.
            self._body_used += length - reader.remaining

    def _upload_rules(self, name: str, temp: Path) -> None:
        """Validate and store an imported regex/YARA-subset rule file."""
        from fnet.paths import CACHE_DIR
        from fnet.utils import rules as rules_mod

        text = temp.read_text(encoding="utf-8", errors="replace")
        parsed = rules_mod.parse_rules(text, Path(name).suffix)
        if not parsed:
            return self._error("规则文件中没有可用的规则")
        target_dir = CACHE_DIR / "rules"
        target_dir.mkdir(parents=True, exist_ok=True)
        safe = SAFE_NAME.sub("_", Path(name).stem)[:80] or "rules"
        suffix = Path(name).suffix or ".txt"
        target = target_dir / f"{secrets.token_hex(4)}_{safe}{suffix}"
        temp.replace(target)
        self.app.config.set("rules_file", str(target), "paths")
        self.app.config.save()
        logger.good(f"已导入自定义规则 {len(parsed)} 条: {target}")
        return self._json({
            "ok": True, "path": str(target), "count": len(parsed),
            "names": [rule.name for rule in parsed[:50]],
            "text": f"已导入 {len(parsed)} 条规则",
        })

    def _rules_info(self) -> None:
        from fnet.utils import rules as rules_mod

        path = str(self.app.config.get("rules_file", "paths") or "").strip()
        info = {"file": path, "count": 0, "names": [], "error": ""}
        if path:
            try:
                parsed = rules_mod.load_rules(path)
                info.update(count=len(parsed),
                            names=[rule.name for rule in parsed[:100]])
            except Exception as exc:  # noqa: BLE001 - report, don't fail
                info["error"] = str(exc)
        return self._json({"ok": True, **info})

    def _set_rules(self) -> None:
        data = self._json_body()
        path = str(data.get("file") or data.get("path") or "").strip()
        if not path:
            self.app.config.set("rules_file", "", "paths")
            self.app.config.save()
            return self._json({"ok": True, "file": "", "count": 0})
        from pathlib import Path as _Path
        from fnet.utils import rules as rules_mod

        target = _Path(path).expanduser()
        if not target.is_file():
            return self._error("规则文件不存在")
        parsed = rules_mod.load_rules(target)
        self.app.config.set("rules_file", str(target), "paths")
        self.app.config.save()
        return self._json({"ok": True, "file": str(target),
                           "count": len(parsed),
                           "names": [rule.name for rule in parsed[:100]]})

    def _compare(self) -> None:
        query = self._query()
        base = (query.get("base") or [""])[0]
        target = (query.get("target") or [""])[0]
        if not base or not target:
            return self._error("需要 base 和 target 任务 ID")
        result = self.app.jobs.compare(base, target)
        if result is None:
            return self._error("任务不存在", 404)
        return self._json({"ok": True, **result})

    def _upload_key(self, name: str, payload: bytes, kind: str) -> None:
        """Store a TLS keylog / private key and remember it in the config."""
        from fnet.paths import CACHE_DIR

        if len(payload) > 8 * 1024 * 1024:
            return self._error("密钥文件过大（上限 8 MiB）")
        text = payload.decode("utf-8", "replace")
        is_keylog = kind in ("keylog", "tls_keylog", "tls-keylog", "tls_key")
        if is_keylog:
            markers = ("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                       "SERVER_HANDSHAKE_TRAFFIC_SECRET", "EXPORTER_SECRET",
                       "EARLY_EXPORTER_SECRET", "RESUMPTION_MASTER_SECRET")
            if not any(marker in text for marker in markers):
                return self._error("不是有效的 NSS keylog（缺少 CLIENT_RANDOM 等标签）")
            target_dir = CACHE_DIR / "keys"
            config_key = "tls_keylog"
            suffix = Path(name).suffix or ".log"
        else:
            if "PRIVATE KEY" not in text:
                return self._error("不是有效的 PEM 私钥（缺少 PRIVATE KEY）")
            target_dir = CACHE_DIR / "keys"
            config_key = "tls_private_key"
            suffix = Path(name).suffix or ".pem"
        target_dir.mkdir(parents=True, exist_ok=True)
        safe = SAFE_NAME.sub("_", Path(name).stem)[:80] or config_key
        target = target_dir / f"{secrets.token_hex(4)}_{safe}{suffix}"
        target.write_bytes(payload)
        self.app.config.set(config_key, str(target), "paths")
        self.app.config.save()
        logger.good(f"已保存 TLS {'keylog' if is_keylog else '私钥'}: {target}")
        self._json({
            "ok": True, "path": str(target), "kind": "keylog" if is_keylog else "key",
            "config": config_key, "size": len(payload),
            "text": f"已保存 {name}，并写入设置 {config_key}",
        })

    def _batch(self) -> None:
        data = self._json_body()
        pcaps = data.get("pcaps")
        features = data.get("features") or data.get("checkboxes") or []
        handlers = data.get("handlers") or []
        params = data.get("params") or {}
        if not isinstance(pcaps, list) or not pcaps:
            return self._error("pcaps 必须是非空数组")
        if len(pcaps) > 50:
            return self._error("一次最多提交 50 个文件")
        if not all(isinstance(item, str) and item.strip() for item in pcaps):
            return self._error("pcaps 中只能包含路径字符串")
        if not isinstance(features, list) or not isinstance(params, dict):
            return self._error("features 必须是数组，params 必须是对象")
        if not isinstance(handlers, list):
            return self._error("handlers 必须是数组")
        selection = list(features) + list(handlers)
        if not selection:
            kinds = {classify_input(item) or "pcap" for item in pcaps}
            selection = []
            for kind in sorted(kinds):
                for checkbox in default_features_for(kind):
                    if checkbox not in selection:
                        selection.append(checkbox)
        jobs = self.app.jobs.submit_batch(
            [item.strip() for item in pcaps], selection, params,
            data.get("concurrency", 1), shards=data.get("shards", 1))
        for pcap in pcaps:
            self.app.config.add_recent(pcap.strip())
        self.app.config.save()
        logger.info(f"新批量任务 {len(jobs)} 个: "
                    + "、".join(Path(item).name for item in pcaps))
        return self._json({"ok": True, "count": len(jobs),
                           "jobs": [job.as_dict() for job in jobs],
                           "summary": self.app.jobs.batch_summary()})

    def _batch_report(self) -> None:
        """Download one merged report for the selected batch jobs."""
        query = self._query()
        raw = (query.get("jobs") or [""])[0]
        ids = [item.strip() for item in raw.split(",") if item.strip()]
        result = self.app.jobs.merged_report(
            ids, (query.get("format") or ["md"])[0],
            (query.get("sections") or [""])[0] or None)
        if result is None:
            return self._error("没有可用于合并报告的任务", 404)
        filename = urllib.parse.quote(result["filename"])
        self._send(200, result["content"].encode("utf-8"),
                   result["content_type"],
                   {"Content-Disposition":
                    f"attachment; filename*=UTF-8''{filename}",
                    "Cache-Control": "no-store"})

    @staticmethod
    def _log_stats(sub: str, path: str, data: dict) -> dict:
        """Stats subs for a text-log input; same keys as the capture side."""
        from fnet import services

        if sub == "timeline":
            return services.log_timeline(path, data.get("buckets", 60))
        if sub == "hierarchy":
            return services.log_level_hierarchy(path)
        if sub == "ip":
            return services.log_top_entities(path)
        if sub == "entities":
            return services.log_entity_stats(
                path, data.get("dimension") or "", data.get("limit", 50),
                success_regex=data.get("success_regex") or "",
                subnet_prefix=data.get("subnet_prefix"),
                fail_regex=data.get("fail_regex") or "")
        if sub == "topology":
            return services.log_topology(path)
        if sub == "protocol":
            return services.log_protocol_detail(
                path, data.get("protocol") or "", data.get("limit", 300))
        if sub == "timeline_packets":
            return services.log_timeline_packets(
                path, data.get("start"), data.get("end"),
                data.get("limit", 200))
        return {"ok": False, "text": "日志任务不支持该统计项", "kind": "log"}

    def _action(self) -> None:
        data = self._json_body()
        action = str(data.get("action") or "")
        pcap = str(data.get("pcap") or "")
        toolbox = self.app.toolbox
        from fnet import services

        if action == "stats":
            sub = data.get("sub") or ""
            from fnet.utils import logfile

            if logfile.is_log_input(pcap):
                return self._json(self._log_stats(sub, pcap, data))
            if sub == "ports":
                return self._json(services.port_scan(pcap, toolbox))
            if sub == "http_uri":
                return self._json(services.http_uri_stats(pcap, toolbox))
            if sub == "ip":
                return self._json(services.ip_conversations(pcap, toolbox))
            if sub == "hierarchy":
                return self._json(services.protocol_hierarchy(pcap, toolbox))
            if sub == "timeline":
                return self._json(services.traffic_timeline(
                    pcap, toolbox, data.get("buckets", 60)))
            if sub == "topology":
                return self._json(services.session_topology(pcap, toolbox))
            if sub == "protocol":
                return self._json(services.protocol_detail(
                    pcap, toolbox, data.get("protocol") or "",
                    data.get("limit", 300)))
            if sub == "timeline_packets":
                return self._json(services.timeline_packets(
                    pcap, toolbox, data.get("start"), data.get("end"),
                    data.get("limit", 200)))
            return self._error("未知统计项")
        if action == "export_objects":
            return self._json(services.export_all_objects(pcap, toolbox))
        if action == "carve":
            return self._json(services.carve_files(pcap, toolbox))
        if action == "repair":
            return self._json(services.repair_pcap(pcap, toolbox))
        if action == "etl":
            return self._json(services.etl_to_pcapng(pcap, toolbox))
        if action == "http_login":
            job = self.app.jobs.submit(pcap, ["flows.http_login"])
            return self._json({"ok": True, "job": job.as_dict()})
        if action == "open_path":
            from fnet.utils.system import open_path

            target = Path(str(data.get("path") or ""))
            if not target.exists():
                return self._error("路径不存在")
            ok = open_path(target)
            return self._json({"ok": ok, "text": f"已交给系统打开: {target}"})
        if action == "open_wireshark":
            from fnet import services

            job_id = str(data.get("job") or "")
            pcap = self.app.jobs.pcap_for(job_id)
            if not pcap:
                return self._error("任务不存在或流量包已被删除")
            return self._json(services.open_wireshark(
                pcap, data.get("frame"), toolbox))
        if action == "open_log":
            from fnet.paths import LOG_DIR
            from fnet.utils.system import open_path

            open_path(LOG_DIR)
            return self._json({"ok": True, "text": f"日志目录: {LOG_DIR}"})
        if action == "plugin_add":
            name = str(data.get("name") or "").strip()
            command = str(data.get("command") or "").strip()
            if not name or not command:
                return self._error("需要工具名称和命令")
            self.app.plugins.add(name, command)
            return self._json({"ok": True, "text": f"已添加 {name}",
                               "plugins": self.app.plugins.as_list()})
        if action == "plugin_remove":
            name = str(data.get("name") or "")
            ok = self.app.plugins.remove(name)
            return self._json({"ok": ok, "plugins": self.app.plugins.as_list()})
        if action == "plugin_run":
            key = str(data.get("key") or "")
            target = str(data.get("target") or "")
            text = self.app.plugins.run(key, target)
            return self._json({"ok": True, "text": text})
        if action == "open_url":
            from fnet.utils.system import open_url

            url = str(data.get("url") or "")
            if not url.startswith(("http://", "https://")):
                return self._error("仅支持 http(s) URL")
            open_url(url)
            return self._json({"ok": True, "text": url})
        if action == "update_check":
            return self._json({
                "ok": True,
                "text": ("Fnet 不主动联网检查更新。\n"
                         "请通过项目仓库获取最新版本。"),
            })
        if action == "save_config":
            self.app.config.save()
            return self._json({"ok": True, "text": "配置已保存"})
        if action == "reload_config":
            self.app.config.load()
            self.app.toolbox.config = self.app.config
            return self._json({"ok": True, "text": "配置已重新加载",
                               "config": self.app.config_snapshot()})
        return self._error(f"未知操作: {action}")

    def _decode(self) -> None:
        from fnet.services import decode_text

        data = self._json_body()
        text = str(data.get("text") or "")
        if len(text) > 2_000_000:
            return self._error("文本过长")
        return self._json(decode_text(text))

    def _set_config(self) -> None:
        data = self._json_body()
        section = str(data.get("section") or "config")
        values = data.get("values") or {}
        if section not in ("config", "paths", "plugins"):
            return self._error("未知配置节")
        if not isinstance(values, dict):
            return self._error("values 必须是对象")
        self.app.config.set_many({k: str(v) for k, v in values.items()}, section)
        self.app.config.save()
        if section == "config" and "theme" in values:
            self.app.config.save()
        return self._json({"ok": True, "config": self.app.config_snapshot()})

    def _download(self) -> None:
        job_id = (self._query().get("job") or [""])[0]
        relative = (self._query().get("path") or [""])[0]
        job = self.app.jobs.get(job_id)
        if job is None:
            return self._error("任务不存在", 404)
        if not relative:
            target = self.app.jobs.zip_artifacts(job)
        else:
            base = job.output_dir.resolve()
            target = (base / relative).resolve()
            if not str(target).startswith(str(base)) or not target.is_file():
                return self._error("文件不存在", 404)
        data = target.read_bytes()
        name = urllib.parse.quote(target.name)
        self._send(200, data, "application/octet-stream",
                   {"Content-Disposition": f"attachment; filename*=UTF-8''{name}",
                    "Cache-Control": "no-store"})

    def _findings(self) -> None:
        """Structured findings as JSON, or as a CSV download."""
        query = self._query()
        job_id = (query.get("job") or [""])[0]
        fmt = (query.get("format") or ["json"])[0].strip().lower()
        if fmt == "csv":
            result = self.app.jobs.export_findings(job_id, "csv")
            if result is None:
                return self._error("任务不存在", 404)
            filename = urllib.parse.quote(result["filename"])
            self._send(200, result["content"].encode("utf-8"),
                       "text/csv; charset=utf-8",
                       {"Content-Disposition":
                        f"attachment; filename*=UTF-8''{filename}",
                        "Cache-Control": "no-store"})
            return
        found = self.app.jobs.findings_for(
            job_id,
            query=(query.get("q") or [""])[0],
            kind=(query.get("kind") or [""])[0],
            level=(query.get("level") or [""])[0],
            limit=safe_limit((query.get("limit") or [""])[0]),
        )
        if found is None:
            return self._error("任务不存在", 404)
        self.app.jobs.merge_annotations(job_id, found["findings"])
        return self._json({"ok": True, "job": job_id, **found})

    def _packet(self) -> None:
        """Packet detail + context, or a downloadable pcapng clip."""
        from fnet import services

        query = self._query()
        job_id = (query.get("job") or [""])[0]
        frame = services.clamp_frame((query.get("frame") or [""])[0])
        if frame is None:
            return self._error("帧号无效")
        pcap = self.app.jobs.pcap_for(job_id)
        if not pcap:
            return self._error("任务不存在或流量包已被删除", 404)
        context = services.clamp_context((query.get("context") or [""])[0])
        if (query.get("format") or ["json"])[0].strip().lower() == "pcap":
            output = self.app.jobs.output_dir_for(job_id)
            if output is None:
                return self._error("任务输出目录不存在", 404)
            name = f"frame-{frame}-ctx{context}.pcapng"
            result = services.extract_frames(
                pcap, frame, self.app.toolbox, output / "frames" / name,
                context)
            if not result.get("ok"):
                return self._error(result.get("text") or "片段导出失败")
            target = Path(result["path"])
            data = target.read_bytes()
            filename = urllib.parse.quote(target.name)
            self._send(200, data, "application/vnd.tcpdump.pcap",
                       {"Content-Disposition":
                        f"attachment; filename*=UTF-8''{filename}",
                        "Cache-Control": "no-store"})
            return
        detail = services.frame_detail(
            pcap, frame, self.app.toolbox, context)
        if not detail.get("ok"):
            return self._error(detail.get("text") or "无法读取数据包", 404)
        return self._json({"ok": True, "job": job_id, **detail})

    def _report(self) -> None:
        """Render a Markdown/HTML report for a live or historical job."""
        query = self._query()
        job_id = (query.get("job") or [""])[0]
        fmt = (query.get("format") or ["html"])[0]
        sections = (query.get("sections") or [""])[0] or None
        result = self.app.jobs.export_report(job_id, fmt, sections)
        if result is None:
            return self._error("任务不存在", 404)
        inline = (query.get("inline") or ["0"])[0].lower() in ("1", "true", "yes")
        disposition = "inline" if inline else "attachment"
        filename = urllib.parse.quote(result["filename"])
        extra = {
            "Content-Disposition": f"{disposition}; filename*=UTF-8''{filename}",
            "Cache-Control": "no-store",
        }
        if result["content_type"].startswith("text/html"):
            extra["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
        self._send(200, result["content"].encode("utf-8"),
                   result["content_type"], extra)

    def _log_tail(self) -> None:
        from fnet.logger import logger as global_logger

        limit = int((self._query().get("limit") or ["300"])[0] or 300)
        self._json({"ok": True,
                    "logs": [r.as_dict() for r in global_logger.tail(limit)]})

    def _annotations_set(self) -> None:
        """Set/clear one finding's human annotation (note + status)."""
        data = self._json_body()
        job_id = str(data.get("job") or "")
        result = self.app.jobs.set_annotation(
            job_id,
            data.get("seq") if data.get("seq") is not None
            else data.get("id") or "",
            str(data.get("status") or ""),
            str(data.get("note") or data.get("annotation") or ""))
        if result is None:
            return self._error("任务不存在", 404)
        return self._json(result)

    def _annotations_info(self) -> None:
        """Persisted annotations for one job, keyed by finding ``seq``."""
        job_id = (self._query().get("job") or [""])[0]
        notes = self.app.jobs.load_annotations(job_id)
        if notes is None:
            return self._error("任务不存在", 404)
        return self._json({"ok": True, "job": job_id, "annotations": notes})

    def _crack_status(self) -> None:
        """Live state (log, password, elapsed) of one hashcat task."""
        task_id = (self._query().get("id") or [""])[0]
        if not task_id:
            return self._error("缺少破解任务 id")
        task = self.app.crack.get(task_id)
        if task is None:
            return self._error("破解任务不存在", 404)
        return self._json({"ok": True, "task": task.as_dict()})

    def _crack_start(self) -> None:
        """Start hashcat for one finding; the UI polls ``/api/crack``."""
        data = self._json_body()
        job_id = str(data.get("job") or "")
        if not job_id:
            return self._error("缺少任务 ID")
        task = self.app.crack.start(
            job_id,
            data.get("seq") if data.get("seq") is not None
            else data.get("id") or "",
            wordlist=data.get("wordlist"),
            workload=data.get("workload"),
            optimized=data.get("optimized"),
            force=data.get("force"),
            timeout=data.get("timeout"),
            extra=data.get("extra"),
        )
        return self._json({"ok": True, "task": task.as_dict(),
                           "settings": self.app.crack_settings()})

    def _crack_cancel(self) -> None:
        data = self._json_body()
        ok = self.app.crack.cancel(str(data.get("id") or ""))
        return self._json({"ok": ok,
                           "text": "已停止破解" if ok else "破解任务未在运行"})

    def _ntlmcrack_get(self) -> None:
        """Live state (attempts, password) of one local NTLM crack task."""
        task_id = (self._query().get("id") or [""])[0]
        if not task_id:
            return self._error("缺少 NTLM 破解任务 id")
        task = self.app.ntlmcrack.get(task_id)
        if task is None:
            return self._error("NTLM 破解任务不存在", 404)
        return self._json({"ok": True, "task": task.as_dict()})

    def _ntlmcrack_start(self) -> None:
        """Start local NetNTLMv2 cracking for one finding; the UI polls it."""
        data = self._json_body()
        job_id = str(data.get("job") or "")
        if not job_id:
            return self._error("缺少任务 ID")
        task = self.app.ntlmcrack.start(
            job_id,
            data.get("seq") if data.get("seq") is not None
            else data.get("id") or "",
            candidates=data.get("candidates"),
            min_len=data.get("min_len"),
            max_len=data.get("max_len"),
            alphabet=data.get("alphabet"),
            max_attempts=data.get("max_attempts"),
            timeout=data.get("timeout"),
        )
        return self._json({"ok": True, "task": task.as_dict()})

    def _ntlmcrack_cancel(self) -> None:
        data = self._json_body()
        ok = self.app.ntlmcrack.cancel(str(data.get("id") or ""))
        return self._json({"ok": ok,
                           "text": "已停止 NTLM 破解" if ok
                           else "NTLM 破解任务未在运行"})

    def _cracked_passwords(self, job_id: str) -> list[dict]:
        """Cracked plaintexts of this job (hashcat tasks + local NTLM tasks)."""
        entries: list[dict] = []
        for attribute in ("crack", "ntlmcrack"):
            manager = getattr(self.app, attribute, None)
            if manager is None:
                continue
            try:
                found = manager.passwords_for(job_id)
            except Exception as exc:  # noqa: BLE001 - a hint never breaks an API
                logger.warn(f"{attribute} 已破解口令读取失败: {exc}")
                continue
            if isinstance(found, (list, tuple)):
                entries.extend(item for item in found if isinstance(item, dict))
        return entries

    def _smb_hints(self) -> None:
        """Auto-fill clues for the "SMB3 解密" dialog of one job."""
        query = self._query()
        job_id = (query.get("job") or [""])[0].strip()
        stream = (query.get("stream") or [""])[0].strip()
        if not job_id:
            return self._error("缺少任务 ID")
        if self.app.jobs.findings_for(job_id, limit=1) is None:
            return self._error("任务不存在", 404)
        cracked = self._cracked_passwords(job_id)
        return self._json({"ok": True, "job": job_id, "stream": stream,
                           "cracked": cracked,
                           **smb_hints_payload(self.app.jobs, job_id, stream,
                                               cracked)})

    def _smb_decrypt(self) -> None:
        """Derive SMB3 keys from credentials and decrypt the job's capture."""
        from fnet.smb3 import decrypt_capture

        data = self._json_body()
        job_id = str(data.get("job") or "")
        if not job_id:
            return self._error("缺少任务 ID")
        pcap = self.app.jobs.pcap_for(job_id)
        if not pcap:
            return self._error("任务不存在或流量包已被删除", 404)
        output = self.app.jobs.output_dir_for(job_id)
        tshark = self.app.toolbox.tshark()
        if tshark is None:
            return self._error("未找到 tshark，无法读取流量包")
        values = {
            "password": str(data.get("password") or ""),
            "nt_hash": str(data.get("nt_hash") or data.get("hash") or ""),
            "session_key": str(data.get("session_key") or ""),
            "user": str(data.get("user") or ""),
            "domain": str(data.get("domain") or ""),
            "stream": str(data.get("stream") or ""),
        }
        autofill: list[str] = []
        secret_keys = ("password", "nt_hash", "session_key")
        if not any(values[key].strip() for key in secret_keys):
            # Nothing was typed: reuse what the job already revealed (SMB NTLM
            # credentials, cracked plaintexts, keys of a previous decrypt).
            hints = smb_hints_payload(self.app.jobs, job_id, values["stream"],
                                      self._cracked_passwords(job_id))
            for key in SMB_HINT_FIELDS:
                value = str(hints["hints"].get(key) or "")
                if values[key].strip() or not value.strip():
                    continue
                values[key] = value
                source = str(hints["sources"].get(key) or "").strip()
                autofill.append(f"已自动填入：{SMB_HINT_LABELS[key]} 来自 "
                                f"{source or '分析结果'}")
            if not any(values[key].strip() for key in secret_keys):
                return self._error("缺少 NT 哈希、密码或会话密钥，"
                                   "也没有可用的自动填入线索")
        result = decrypt_capture(
            pcap, tshark,
            password=values["password"],
            nt_hash=values["nt_hash"],
            session_key=values["session_key"],
            user=values["user"],
            domain=values["domain"],
            stream=values["stream"],
            output_dir=output,
        )
        payload = {
            "ok": bool(result.get("ok")),
            "job": job_id,
            "text": result.get("text") or "",
            "log": autofill + list(result.get("log") or []),
            "files": result.get("files") or [],
            "keys": result.get("keys") or [],
            "flags": result.get("flags") or [],
            "sessions": result.get("sessions") or [],
            "decrypted": result.get("decrypted") or 0,
        }
        if not payload["ok"]:
            payload["error"] = result.get("error") or "SMB3 解密失败"
        return self._json(payload)

    def _topology(self) -> None:
        """Compact endpoint graph for one job's capture."""
        from fnet.services import network_topology

        job_id = (self._query().get("job") or [""])[0]
        pcap = self.app.jobs.pcap_for(job_id)
        if not pcap:
            return self._error("任务不存在或流量包已被删除", 404)
        result = network_topology(pcap, self.app.toolbox)
        if not result.get("ok"):
            return self._error(result.get("text") or "拓扑统计失败")
        return self._json({"ok": True, "job": job_id,
                           "nodes": result.get("nodes") or [],
                           "links": result.get("links") or [],
                           "text": result.get("text") or ""})

    def _replay(self) -> None:
        """Runnable Python replay script for one TCP/HTTP session."""
        from fnet.services import replay_script

        data = self._json_body()
        job_id = str(data.get("job") or "")
        if not job_id:
            return self._error("需要任务 ID")
        if data.get("stream") in ("", None) and data.get("frame") in ("", None):
            return self._error("需要 stream 或 frame 参数")
        pcap = self.app.jobs.pcap_for(job_id)
        if not pcap:
            return self._error("任务不存在或流量包已被删除", 404)
        result = replay_script(pcap, self.app.toolbox,
                               stream=data.get("stream"),
                               frame=data.get("frame"))
        if not result.get("ok"):
            return self._error(result.get("text") or "生成重放脚本失败")
        return self._json({"ok": True, "job": job_id,
                           "kind": result.get("kind"),
                           "script": result.get("script"),
                           "text": result.get("text") or "",
                           "stream": result.get("stream"),
                           "client": result.get("client"),
                           "server": result.get("server")})


def safe_limit(value, default: int = 5000, maximum: int = 50_000) -> int:
    """Parse a user supplied row limit, clamping bad input to a default."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return max(1, min(number, maximum))


def _parse_multipart(raw: bytes, boundary: bytes) -> tuple[str, bytes]:
    """Tiny multipart/form-data parser (``cgi`` is gone in Python 3.13+)."""
    delimiter = b"--" + boundary
    filename = "capture.pcap"
    for part in raw.split(delimiter):
        if not part or part in (b"--\r\n", b"--", b"\r\n"):
            continue
        part = part.lstrip(b"\r\n")
        head, sep, body = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = head.decode("utf-8", "replace")
        match = re.search(r'filename="([^"]*)"', headers)
        if match is None:
            continue
        filename = match.group(1) or filename
        if body.endswith(b"\r\n"):
            body = body[:-2]
        return filename, body
    raise ValueError("multipart 中没有文件字段")


class _NullWriter:
    """Discard a multipart field without growing memory."""

    def write(self, data) -> int:
        return len(data)


class _MultipartStream:
    """Incremental multipart reader that writes file parts straight to disk.

    Browsers send a ``Content-Length`` for ``FormData`` uploads; the reader
    consumes exactly that many bytes and keeps only one chunk plus the
    boundary-length tail in memory.  This is what lets the 1 GiB upload limit
    work without the previous O(file size) allocation.
    """

    def __init__(self, rfile, boundary: bytes, length: int, limit: int) -> None:
        self.rfile = rfile
        self.delimiter = b"--" + boundary
        self.remaining = max(0, int(length))
        self.limit = max(0, int(limit))
        self.total = 0
        self.buffer = b""

    def _fill(self, size: int = 65536) -> bool:
        if self.remaining <= 0:
            return False
        data = self.rfile.read(min(size, self.remaining))
        if not data:
            self.remaining = 0
            return False
        self.remaining -= len(data)
        self.total += len(data)
        if self.limit and self.total > self.limit:
            raise ValueError("文件超过大小限制")
        self.buffer += data
        return True

    def readline(self, limit: int = 65536) -> bytes:
        while b"\r\n" not in self.buffer and len(self.buffer) < limit:
            if not self._fill():
                break
        index = self.buffer.find(b"\r\n")
        if index < 0:
            line, self.buffer = self.buffer, b""
            return line
        line = self.buffer[:index + 2]
        self.buffer = self.buffer[index + 2:]
        return line

    def stream_to(self, handle) -> bool:
        """Write one part body to ``handle`` up to the next CRLF+boundary."""
        marker = b"\r\n" + self.delimiter
        keep = len(marker) - 1
        while True:
            index = self.buffer.find(marker)
            if index >= 0:
                handle.write(self.buffer[:index])
                self.buffer = self.buffer[index + len(marker):]
                return True
            if len(self.buffer) > keep:
                cut = len(self.buffer) - keep
                handle.write(self.buffer[:cut])
                self.buffer = self.buffer[cut:]
            if not self._fill():
                handle.write(self.buffer)
                self.buffer = b""
                return False

    def drain_part(self) -> None:
        self.stream_to(_NullWriter())


def make_server(app: FnetApp, host: str = "127.0.0.1",
                port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.app = app  # type: ignore[attr-defined]
    app.server = server
    return server


def serve(app: FnetApp, host: str = "127.0.0.1", port: int = 8765,
          open_browser: bool = True, block: bool = True) -> ThreadingHTTPServer:
    server = make_server(app, host, port)
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    logger.good(f"Fnet WebUI 已启动: {url}")
    logger.info("按 Ctrl+C 停止服务")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    if block:
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            logger.info("收到中断信号，正在关闭…")
        finally:
            app.live.shutdown()
            server.shutdown()
            server.server_close()
    return server
