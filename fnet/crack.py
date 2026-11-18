"""One-click hashcat cracking for structured findings.

The WebUI's finding detail modal offers "用 hashcat 破解" for findings that
carry a crackable hash (NetNTLMv1/v2, Kerberos AS-REP/TGS-REP, WPA 22000 ...).
Cracking runs in a background thread so the HTTP request returns immediately;
the UI polls ``GET /api/crack?id=...`` for the live hashcat log and the
cracked password.

Only findings that already contain a hashcat-compatible hash line are
accepted.  Handlers add it through ``extra={"hash": ..., "mode": ...}``;
older jobs without ``extra.mode`` are inferred from the summary, so results
persisted before this module existed still work.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from fnet import paths as fnet_paths
from fnet.logger import logger
from fnet.tools.runner import run

#: hashcat modes Fnet can name (the UI shows the label next to the mode).
MODE_LABELS = {
    1000: "NTLM",
    5500: "NetNTLMv1",
    5600: "NetNTLMv2",
    13100: "Kerberos 5 TGS-REP etype 23",
    18200: "Kerberos 5 AS-REP etype 23",
    19600: "Kerberos 5 AS-REP etype 17",
    19700: "Kerberos 5 AS-REP etype 18",
    19800: "Kerberos 5 TGS-REP etype 17",
    19900: "Kerberos 5 TGS-REP etype 18",
    22000: "WPA-PBKDF2-PMKID+EAPOL",
}

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
MAX_LOG = 12_000
MAX_TASKS = 40
MAX_EXTRA = 400


def mode_label(mode: int) -> str:
    return MODE_LABELS.get(int(mode), f"hashcat -m {mode}")


def crack_target(finding: dict) -> tuple[int, str] | None:
    """Return ``(hashcat mode, hash line)`` for a finding, or ``None``.

    ``extra.hash`` is the authoritative source; the format fallbacks keep
    findings written by older Fnet versions (which only stored ``detail``)
    working.
    """
    extra = finding.get("extra") or {}
    if not isinstance(extra, dict):
        extra = {}
    line = str(extra.get("hash") or "").strip()
    mode = str(extra.get("mode") or "").strip()
    summary = str(finding.get("summary") or "")
    if line and mode.isdigit():
        return int(mode), line
    protocol = str(extra.get("protocol") or "").strip().lower()
    if protocol == "ntlm" and line:
        # NetNTLMv1 and v2 both have five colons; the summary is the only
        # reliable discriminator here.
        if "NetNTLMv1" in summary:
            return 5500, line
        return 5600, line
    if protocol == "wifi" and line.startswith("WPA*"):
        return 22000, line
    if protocol == "kerberos" and line:
        found = re.search(r"hashcat -m (\d+)", summary)
        if found:
            return int(found.group(1)), line
    return None


def _as_int(value, default: int = 0) -> int:
    """Best-effort int for task bookkeeping; never raises."""
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def identity_from_hash_line(line) -> tuple[str, str]:
    """Return ``(user, domain)`` from a hash line, ``("", "")`` otherwise.

    NetNTLMv1/v2 lines look like ``user::domain:challenge:...``; the user may
    be empty and the NetNTLMv2 client blob holds further colons, so only the
    first three colon-separated fields are read.  Any other hashcat format
    (NTLM, Kerberos, WPA ...) carries no account info here.
    """
    try:
        user, sep, rest = str(line or "").strip().partition("::")
        if not sep:
            return "", ""
        return user.strip(), (rest.split(":")[0].strip() if rest else "")
    except Exception:  # noqa: BLE001 - hints must never break a caller
        return "", ""


def _append_log(task, text: str) -> None:
    """Append streamed hashcat output, keeping only the tail of the log."""
    text = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    combined = (task.log or "") + text
    if len(combined) > MAX_LOG:
        combined = "…\n" + combined[-MAX_LOG:]
    task.log = combined


def _decode(data: bytes | None) -> str:
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    return (data or b"").decode("utf-8", "replace")


@dataclass
class CrackTask:
    """State of one background hashcat run."""

    id: str
    job: str
    seq: int
    mode: int
    hash_line: str
    status: str = "running"       # running | cracked | exhausted | error | cancelled
    password: str = ""
    log: str = ""
    error: str = ""
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    timeout: int = DEFAULT_TIMEOUT
    hash_file: str = ""
    potfile: str = ""
    command: list[str] = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    def as_dict(self) -> dict:
        elapsed = max(0, int((self.finished or time.time()) - self.started))
        return {
            "id": self.id,
            "job": self.job,
            "seq": self.seq,
            "mode": self.mode,
            "mode_label": mode_label(self.mode),
            "status": self.status,
            "finished": bool(self.finished),
            "elapsed": elapsed,
            "timeout": self.timeout,
            "password": self.password,
            "error": self.error,
            "log": self.log,
            "command": list(self.command),
        }


class CrackManager:
    """Runs hashcat for one finding at a time per call, in a daemon thread."""

    def __init__(self, jobs, toolbox, config) -> None:
        self.jobs = jobs
        self.toolbox = toolbox
        self.config = config
        self._tasks: dict[str, CrackTask] = {}
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------
    def get(self, task_id: str) -> CrackTask | None:
        with self._lock:
            return self._tasks.get(str(task_id or ""))

    def cancel(self, task_id: str) -> bool:
        task = self.get(task_id)
        if task is None or task.finished:
            return False
        task.cancel.set()
        task.status = "cancelled"
        return True

    def start(self, job_id: str, seq, *, wordlist: str | None = None,
              workload=None, optimized=None, force=None, timeout=None,
              extra: str | None = None) -> CrackTask:
        job_id = str(job_id or "").strip()
        if not job_id:
            raise ValueError("缺少任务 ID")
        found = self.jobs.findings_for(job_id, limit=1_000_000)
        if found is None:
            raise ValueError("任务不存在")
        try:
            number = int(str(seq).strip())
        except (TypeError, ValueError):
            raise ValueError("seq 必须是正整数")
        finding = next((item for item in found.get("findings") or []
                        if int(item.get("seq") or 0) == number), None)
        if finding is None:
            raise ValueError("找不到该分析结果")
        target = crack_target(finding)
        if target is None:
            raise ValueError("该结果不是可直接破解的哈希格式")
        mode, hash_line = target

        hashcat = self.toolbox.path("hashcat")
        if not hashcat:
            raise ValueError("未找到 hashcat，请先安装或在设置中指定路径")

        raw_wordlist = str(wordlist if wordlist is not None
                           else self.config.get("passwddir") or "").strip()
        resolved = fnet_paths.wordlist(raw_wordlist)
        if resolved is None or not resolved.is_file():
            raise ValueError(f"字典不存在: {raw_wordlist or '未配置字典'}")

        output = self.jobs.output_dir_for(job_id)
        if output is None:
            raise ValueError("任务输出目录不存在")
        workdir = Path(output) / "hashcat"
        workdir.mkdir(parents=True, exist_ok=True)
        hash_file = workdir / f"hash_{number}_{mode}.txt"
        potfile = workdir / f"hashcat_{mode}.potfile"
        hash_file.write_text(hash_line + "\n", encoding="utf-8")

        level = str(workload if workload is not None
                    else self.config.get("hashcat_workload") or "3").strip()
        try:
            level_number = int(level)
        except ValueError:
            level_number = 3
        level_number = min(4, max(1, level_number))
        opt = (self.config.get_bool("hashcat_optimized", fallback=True)
               if optimized is None else bool(optimized))
        forced = (self.config.get_bool("hashcat_force", fallback=False)
                  if force is None else bool(force))
        limit = self.config.get_int("hashcat_timeout", fallback=DEFAULT_TIMEOUT)
        if timeout is not None:
            try:
                limit = int(timeout)
            except (TypeError, ValueError):
                limit = DEFAULT_TIMEOUT
        limit = min(MAX_TIMEOUT, max(10, limit))
        extra_args = str(extra if extra is not None
                         else self.config.get("hashcat_extra") or "").strip()
        if len(extra_args) > MAX_EXTRA:
            raise ValueError("附加参数过长")

        argv = [
            hashcat, "-m", str(mode), "-a", "0",
            str(hash_file), str(resolved),
            "--potfile-path", str(potfile),
            "--status", "--status-timer", "2",
            "-w", str(level_number),
        ]
        if opt:
            argv.append("-O")
        if forced:
            argv.append("--force")
        if extra_args:
            try:
                argv.extend(shlex.split(extra_args))
            except ValueError as exc:
                raise ValueError(f"附加参数无法解析: {exc}")

        # Persist the knobs the user just chose so the next run starts from
        # the same settings ("字典路径持久化保存").
        if raw_wordlist:
            self.config.set("passwddir", raw_wordlist)
        self.config.set("hashcat_workload", str(level_number))
        self.config.set("hashcat_optimized", "1" if opt else "0")
        self.config.set("hashcat_force", "1" if forced else "0")
        self.config.set("hashcat_timeout", str(limit))
        self.config.set("hashcat_extra", extra_args)
        self.config.save()

        task = CrackTask(
            id=uuid.uuid4().hex[:12], job=job_id, seq=number, mode=mode,
            hash_line=hash_line, timeout=limit,
            hash_file=str(hash_file), potfile=str(potfile), command=argv,
        )
        with self._lock:
            self._prune_locked()
            self._tasks[task.id] = task
        logger.info(f"hashcat 破解开始: 任务 {job_id} 结果 #{number} "
                    f"模式 {mode} 字典 {resolved}")
        threading.Thread(target=self._run, args=(task,), daemon=True,
                         name=f"fnet-crack-{task.id}").start()
        return task

    def passwords_for(self, job_id: str) -> list[dict]:
        """Cracked passwords of this job's finished hashcat tasks.

        Used by the SMB3 解密 dialog to auto-fill a password it already
        recovered.  Entries are ``{user, domain, password, stream, source,
        mode, seq}`` sorted by ``seq``; nothing ever raises here because the
        caller treats a missing hint as "no hint".
        """
        wanted = str(job_id or "").strip()
        if not wanted:
            return []
        try:
            with self._lock:
                tasks = [task for task in self._tasks.values()
                         if str(task.job) == wanted
                         and task.status == "cracked" and task.password]
            if not tasks:
                return []
            streams = self._streams_by_seq(wanted)
            entries: list[dict] = []
            for task in tasks:
                seq = _as_int(task.seq)
                mode = _as_int(task.mode)
                user, domain = identity_from_hash_line(task.hash_line)
                entries.append({
                    "user": user,
                    "domain": domain,
                    "password": str(task.password),
                    "stream": streams.get(seq, ""),
                    "source": f"hashcat -m {mode}",
                    "mode": mode,
                    "seq": seq,
                })
            entries.sort(key=lambda item: item["seq"])
            return entries
        except Exception:  # noqa: BLE001 - a hint is never worth an error
            return []

    # -- internals -----------------------------------------------------
    def _streams_by_seq(self, job_id: str) -> dict[int, str]:
        """Map finding ``seq`` to its ``extra.stream`` (empty when unknown)."""
        try:
            found = self.jobs.findings_for(job_id, limit=1_000_000) or {}
            items = found.get("findings") or []
        except Exception:  # noqa: BLE001 - old jobs may not record findings
            return {}
        streams: dict[int, str] = {}
        try:
            for item in items:
                if not isinstance(item, dict):
                    continue
                extra = item.get("extra")
                if not isinstance(extra, dict):
                    continue
                stream = str(extra.get("stream") or "").strip()
                seq = _as_int(item.get("seq"))
                if seq and stream:
                    streams[seq] = stream
        except Exception:  # noqa: BLE001
            return {}
        return streams

    def _prune_locked(self) -> None:
        if len(self._tasks) < MAX_TASKS:
            return
        finished = sorted((task for task in self._tasks.values() if task.finished),
                          key=lambda task: task.finished)
        for task in finished[:max(1, len(self._tasks) - MAX_TASKS + 1)]:
            self._tasks.pop(task.id, None)

    def _show(self, task: CrackTask) -> str:
        """Ask hashcat what is already in the potfile (empty when nothing)."""
        code, out = run(
            [task.command[0], "-m", str(task.mode), task.hash_file,
             "--show", "--potfile-path", task.potfile],
            timeout=60, echo=False)
        if code != 0:
            return ""
        prefix = task.hash_line.lower() + ":"
        for line in out.replace("\r\n", "\n").replace("\r", "\n").splitlines():
            line = line.strip()
            # hashcat uppercases the user name on output for NetNTLM, so the
            # comparison must ignore case while keeping the password intact.
            if line.lower().startswith(prefix):
                return line[len(task.hash_line) + 1:]
        return ""

    def _run(self, task: CrackTask) -> None:
        try:
            code, timed_out = self._spawn(task)
            password = self._show(task)
            if task.cancel.is_set():
                task.status = "cancelled"
            elif password:
                task.status = "cracked"
                task.password = password
                _append_log(task, f"\n[+] 已破解: {password}")
            elif timed_out:
                task.status = "error"
                task.error = f"超过 {task.timeout} 秒仍未破解，已停止"
            elif code == 1:
                task.status = "exhausted"
            elif code in (2, 3):
                task.status = "cancelled"
            else:
                task.status = "error"
                log = task.log or ""
                if "No hashes loaded" in log:
                    task.error = "hashcat 未加载任何哈希：哈希格式或模式不匹配"
                elif re.search(r"Token length exception|Separator unmatched"
                               r"|Salt-length exception|Hash parsing error", log):
                    task.error = "hashcat 无法解析该哈希（格式或模式不匹配）"
                elif re.search(r"No devices found|CL_PLATFORM_NOT_FOUND"
                               r"|No OpenCL|No CUDA", log):
                    task.error = ("hashcat 找不到可用的 GPU/OpenCL 设备，"
                                  "可勾选强制模式 --force 后重试")
                else:
                    task.error = f"hashcat 退出码 {code}"
        except Exception as exc:  # noqa: BLE001 - the UI must see the reason
            task.status = "error"
            task.error = str(exc)
            logger.error(f"hashcat 破解失败: {exc}")
        finally:
            task.finished = time.time()
            logger.info(f"hashcat 破解结束: 结果 #{task.seq} {task.status}"
                        + (f" 密码 {task.password}" if task.password else ""))

    def _spawn(self, task: CrackTask) -> tuple[int, bool]:
        """Run hashcat, streaming its status lines into ``task.log``.

        ``run()`` only returns the output once the child exits, but hashcat
        reports progress every couple of seconds and the UI shows that log
        live, so this loop reads the pipe as it fills.
        """
        try:
            proc = subprocess.Popen(
                task.command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError as exc:
            raise ValueError(f"找不到 hashcat: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"无法执行 hashcat: {exc}") from exc

        def pump() -> None:
            stream = proc.stdout
            # ``read(n)`` on a BufferedReader blocks until the buffer is full,
            # which would hide hashcat's status lines for many seconds;
            # ``read1`` returns as soon as one raw read completes.
            reader_fn = getattr(stream, "read1", stream.read)
            while True:
                try:
                    chunk = reader_fn(4096)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                _append_log(task, _decode(chunk))

        reader = threading.Thread(target=pump, daemon=True,
                                  name=f"fnet-crack-log-{task.id}")
        reader.start()
        deadline = time.time() + task.timeout
        timed_out = False
        while proc.poll() is None:
            if task.cancel.is_set():
                proc.kill()
                break
            if time.time() >= deadline:
                timed_out = True
                proc.kill()
                break
            time.sleep(0.2)
        proc.wait()
        reader.join(timeout=2)
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
        return proc.returncode or 0, timed_out
