"""NetNTLMv2 离线破解后台服务（hashcat 的纯 Python 本地回退）。

结果页对携带 NetNTLMv2 哈希的分析结果提供"NTLM 离线破解"按钮：Fnet 用
:mod:`fnet.utils.ntlmcrack` 在本地逐个验证候选口令，全程纯标准库、不调用
hashcat。纯 Python 计算速度有限（数千~数万次/秒），因此默认尝试上限受控
（20 万次）并带超时，UI 上也会提示优先使用候选口令列表或改用 hashcat。

与 :mod:`fnet.crack`（hashcat 后台任务）完全对齐的模式：

- ``start()`` 立即返回一个后台任务，破解在守护线程里进行；
- UI 通过 ``GET /api/ntlmcrack?id=...`` 轮询任务状态 / 已尝试次数 / 日志
  与命中的密码；
- ``cancel()`` 设置取消事件，计算循环在当前候选后立刻停止。

该服务只作为**结果页的可选后台动作**，绝不进入分析流水线 —— 流水线内的
SMB/NTLM 处理只做显式候选（≤8 个）验证，两者互不干扰。
"""
from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field

from fnet.logger import logger
from fnet.utils import ntlmcrack

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
MIN_TIMEOUT = 1
DEFAULT_MAX_ATTEMPTS = 200_000
MAX_ATTEMPTS_LIMIT = 5_000_000
MAX_TASKS = 40
MAX_LOG = 12_000
MAX_CANDIDATES = 200_000
MAX_CANDIDATE_LEN = 128
MAX_ALPHABET = 256
MIN_PASSWORD_LEN = 1
MAX_PASSWORD_LEN = 12
DEFAULT_MIN_LEN = 1
DEFAULT_MAX_LEN = 4
DEFAULT_ALPHABET = "ascii_letters+digits"
#: 每批喂给 ``brute_force_ntlmv2`` 的候选数：切批才能及时响应取消/超时，
#: 并把已尝试次数实时同步给轮询中的 UI。
BATCH_SIZE = 2_000
#: 每隔多少次尝试向任务日志追加一条进度行。
PROGRESS_EVERY = 20_000

HEX_CHALLENGE = re.compile(r"(?i)^(?:[0-9a-f]{2}){8}$")
HEX_PROOF = re.compile(r"(?i)^(?:[0-9a-f]{2}){16}$")
HEX_BLOB = re.compile(r"(?i)^(?:[0-9a-f]{2}){9,}$")
#: NTLMv2 响应 = proof(16 字节) + blob(≥9 字节)；NTLMv1 响应恒为 24 字节，
#: 因此 25 字节下限可把 v1 行（lm+nt=24 字节）挡在门外。
HEX_RESPONSE = re.compile(r"(?i)^(?:[0-9a-f]{2}){25,}$")


def _append_log(task, text: str) -> None:
    """追加任务日志，超长时只保留尾部（与 hashcat 任务一致）。"""
    text = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    combined = (task.log or "") + text
    if len(combined) > MAX_LOG:
        combined = "…\n" + combined[-MAX_LOG:]
    task.log = combined


def _clamp_int(value, default: int, lo: int, hi: int) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        number = default
    return min(hi, max(lo, number))


def _as_int(value, default: int = 0) -> int:
    """宽松取整（供结果序号解析使用，绝不抛异常）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _extra_of(finding: dict) -> dict:
    extra = finding.get("extra") if isinstance(finding, dict) else None
    return extra if isinstance(extra, dict) else {}


def _is_ntlmv1(finding: dict) -> bool:
    """该结果是否为 NetNTLMv1（纯 Python 回退不支持，只给 hashcat 提示）。"""
    extra = _extra_of(finding)
    if str(extra.get("mode") or "").strip() == "5500":
        return True
    return (str(extra.get("protocol") or "").strip().lower() == "ntlm"
            and "NetNTLMv1" in str(finding.get("summary") or ""))


def _parse_target(finding: dict) -> dict | None:
    """从 finding 提取 NetNTLMv2 目标；不可离线破解时返回 ``None``。

    优先解析 ``extra.hash`` 的 hashcat -m 5600 行
    （``user::domain:challenge:proof:blob``），其次接受 handler 直接持久化的
    结构化字段（``user``/``domain``/``challenge``/``nt_response``，或
    ``ntproofstr``+``blob``）。NetNTLMv1 行（``lm``+``nt`` 共 24 字节）会被
    长度下限挡下，由调用方给出"请改用 hashcat -m 5500"的明确提示。
    """
    extra = _extra_of(finding)
    line = str(extra.get("hash") or "").strip()
    if line and "::" in line:
        user, _, rest = line.partition("::")
        parts = rest.split(":")
        if (len(parts) == 4 and HEX_CHALLENGE.fullmatch(parts[1] or "")
                and HEX_PROOF.fullmatch(parts[2] or "")
                and HEX_BLOB.fullmatch(parts[3] or "")):
            challenge, nt_response = parts[1].lower(), (parts[2] + parts[3]).lower()
            if HEX_RESPONSE.fullmatch(nt_response):
                return {"user": user.strip(),
                        "domain": parts[0].strip(),
                        "challenge": challenge,
                        "nt_response": nt_response}
            return None  # NetNTLMv1 形状（24 字节响应）
    user = str(extra.get("user") or "").strip()
    if not user:
        account = str(extra.get("account") or "").strip()
        user = account.split("\\", 1)[-1].split("@", 1)[0].strip()
    challenge = str(extra.get("challenge") or "").strip().lower()
    nt_response = str(extra.get("nt_response") or "").strip().lower()
    if not nt_response:
        proof = str(extra.get("ntproofstr") or extra.get("proof")
                    or "").strip().lower()
        blob = str(extra.get("blob") or "").strip().lower()
        if proof and blob:
            nt_response = proof + blob
    if (user and HEX_CHALLENGE.fullmatch(challenge)
            and HEX_RESPONSE.fullmatch(nt_response)):
        return {"user": user,
                "domain": str(extra.get("domain") or "").strip(),
                "challenge": challenge,
                "nt_response": nt_response}
    return None


@dataclass
class NtlmCrackTask:
    """一次纯 Python NetNTLMv2 离线破解的后台任务状态。"""

    id: str
    job: str
    seq: int
    user: str
    domain: str
    challenge: str                 # 服务器挑战（16 位十六进制）
    nt_response: str               # proof+blob（十六进制）
    engine: str = "bruteforce"     # candidates（候选列表）| bruteforce（枚举）
    status: str = "running"        # running | cracked | exhausted | error | cancelled
    password: str = ""
    log: str = ""
    error: str = ""
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    timeout: int = DEFAULT_TIMEOUT
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    attempts: int = 0
    alphabet: str = DEFAULT_ALPHABET
    min_len: int = DEFAULT_MIN_LEN
    max_len: int = DEFAULT_MAX_LEN
    words: list[str] = field(default_factory=list, repr=False)
    cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    def as_dict(self) -> dict:
        elapsed = max(0, int((self.finished or time.time()) - self.started))
        return {
            "id": self.id,
            "job": self.job,
            "seq": self.seq,
            "status": self.status,
            "finished": bool(self.finished),
            "elapsed": elapsed,
            "timeout": self.timeout,
            "password": self.password,
            "error": self.error,
            "log": self.log,
            "user": self.user,
            "domain": self.domain,
            "challenge": self.challenge,
            "nt_response": self.nt_response,
            "engine": self.engine,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "alphabet": self.alphabet,
            "min_len": self.min_len,
            "max_len": self.max_len,
        }


class NtlmCrackManager:
    """对一条 NetNTLMv2 结果做后台离线破解（纯 Python，本地计算）。

    接口与 :class:`fnet.crack.CrackManager` 对齐（``jobs/toolbox/config``），
    便于在 ``FnetApp`` 上并列挂载；纯 Python 引擎不使用外部工具，``toolbox``
    仅作占位保存。
    """

    def __init__(self, jobs, toolbox, config) -> None:
        self.jobs = jobs
        self.toolbox = toolbox
        self.config = config
        self._tasks: dict[str, NtlmCrackTask] = {}
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------
    def get(self, task_id) -> NtlmCrackTask | None:
        with self._lock:
            return self._tasks.get(str(task_id or ""))

    def cancel(self, task_id) -> bool:
        task = self.get(task_id)
        if task is None or task.finished:
            return False
        task.cancel.set()
        task.status = "cancelled"
        return True

    def start(self, job_id, seq, *, candidates=None, min_len=None,
              max_len=None, alphabet=None, max_attempts=None,
              timeout=None) -> NtlmCrackTask:
        """对一条分析结果启动 NetNTLMv2 离线破解，立即返回后台任务。

        ``seq`` 可以是结果序号（整数）或结果页的 finding id（如 ``f00003``）。
        ``candidates`` 为空时按 ``min_len``/``max_len``/``alphabet`` 枚举。
        """
        job_id = str(job_id or "").strip()
        if not job_id:
            raise ValueError("缺少任务 ID")
        found = self.jobs.findings_for(job_id, limit=1_000_000)
        if found is None:
            raise ValueError("任务不存在")
        finding = self._resolve_finding(found.get("findings") or [], seq)
        if finding is None:
            raise ValueError("找不到该分析结果")
        if _is_ntlmv1(finding):
            raise ValueError("该结果是 NetNTLMv1，纯 Python 回退不支持 DES "
                             "运算；请改用 hashcat -m 5500")
        target = _parse_target(finding)
        if target is None:
            raise ValueError("该结果不包含可离线破解的 NetNTLMv2 目标"
                             "（需要 user + challenge + nt_response）")

        words = self._normalize_candidates(candidates)
        attempt_cap = _clamp_int(max_attempts, DEFAULT_MAX_ATTEMPTS,
                                 1, MAX_ATTEMPTS_LIMIT)
        limit = _clamp_int(timeout, DEFAULT_TIMEOUT, MIN_TIMEOUT, MAX_TIMEOUT)
        lo = _clamp_int(min_len, DEFAULT_MIN_LEN,
                        MIN_PASSWORD_LEN, MAX_PASSWORD_LEN)
        hi = _clamp_int(max_len, DEFAULT_MAX_LEN,
                        MIN_PASSWORD_LEN, MAX_PASSWORD_LEN)
        hi = max(lo, hi)
        alpha = str(alphabet if alphabet is not None
                    else DEFAULT_ALPHABET).strip() or DEFAULT_ALPHABET
        if len(alpha) > MAX_ALPHABET:
            raise ValueError(f"字母表过长（上限 {MAX_ALPHABET} 个字符）")

        task = NtlmCrackTask(
            id=uuid.uuid4().hex[:12], job=job_id,
            seq=int(finding.get("seq") or 0),
            user=target["user"], domain=target["domain"],
            challenge=target["challenge"], nt_response=target["nt_response"],
            engine="candidates" if words else "bruteforce",
            timeout=limit, max_attempts=attempt_cap,
            alphabet=alpha, min_len=lo, max_len=hi, words=words,
        )
        with self._lock:
            self._prune_locked()
            self._tasks[task.id] = task
        identity = f"{task.domain}\\{task.user}" if task.domain else task.user
        logger.info(f"NTLM 离线破解开始: 任务 {job_id} 结果 #{task.seq} "
                    f"账号 {identity} 引擎 {task.engine} "
                    f"上限 {attempt_cap} 次 / {limit} 秒")
        threading.Thread(target=self._run, args=(task,), daemon=True,
                         name=f"fnet-ntlmcrack-{task.id}").start()
        return task

    def passwords_for(self, job_id: str) -> list[dict]:
        """本任务中已命中明文的本地 NTLM 破解任务列表。

        结构与 :meth:`fnet.crack.CrackManager.passwords_for` 一致
        （``user/domain/password/stream/source/mode/seq``，按 ``seq`` 升序）：
        账号与域直接取任务自身字段，``mode`` 固定 5600（纯 Python 引擎只做
        NetNTLMv2），``stream`` 取自原始分析结果的 ``extra.stream``。
        任何异常都当作"没有线索"吞掉，绝不影响调用方。
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
                entries.append({
                    "user": str(task.user or ""),
                    "domain": str(task.domain or ""),
                    "password": str(task.password),
                    "stream": streams.get(seq, ""),
                    "source": "本地 NTLM 破解",
                    "mode": 5600,
                    "seq": seq,
                })
            entries.sort(key=lambda item: item["seq"])
            return entries
        except Exception:  # noqa: BLE001 - 线索缺失不值得报错
            return []

    # -- internals -----------------------------------------------------
    def _streams_by_seq(self, job_id: str) -> dict[int, str]:
        """结果序号 -> ``extra.stream``；读取失败时返回空表。"""
        try:
            found = self.jobs.findings_for(job_id, limit=1_000_000) or {}
            items = found.get("findings") or []
        except Exception:  # noqa: BLE001 - 老任务可能没有结果文件
            return {}
        streams: dict[int, str] = {}
        try:
            for item in items:
                stream = str(_extra_of(item).get("stream") or "").strip()
                seq = _as_int(item.get("seq")) if isinstance(item, dict) else 0
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

    @staticmethod
    def _resolve_finding(items: list[dict], seq) -> dict | None:
        wanted = str(seq if seq is not None else "").strip()
        if not wanted:
            return None
        try:
            number = int(wanted)
        except ValueError:
            number = None
        for item in items:
            if number is not None and int(item.get("seq") or 0) == number:
                return item
        for item in items:
            if str(item.get("id") or "") == wanted:
                return item
        return None

    @staticmethod
    def _normalize_candidates(candidates) -> list[str]:
        """候选口令归一化：支持逗号/分号/换行分隔的字符串或可迭代列表。"""
        if candidates is None:
            return []
        if isinstance(candidates, str):
            raw = candidates.replace(";", ",").replace("\n", ",").split(",")
        elif isinstance(candidates, (list, tuple, set)):
            raw = [str(item) for item in candidates]
        else:
            raise ValueError("候选口令格式不支持（请用逗号/分号分隔的文本）")
        words: list[str] = []
        for item in raw:
            word = item.strip()
            if not word:
                continue
            if len(word) > MAX_CANDIDATE_LEN:
                word = word[:MAX_CANDIDATE_LEN]
            if word not in words:
                words.append(word)
        if len(words) > MAX_CANDIDATES:
            raise ValueError(f"候选口令过多（上限 {MAX_CANDIDATES} 个），"
                             "请改用 hashcat 或缩小列表")
        return words

    def _batches(self, task: NtlmCrackTask, keep_going):
        """把候选流按 ``BATCH_SIZE`` 切批，并尊重剩余尝试次数预算。

        切批后 ``brute_force_ntlmv2`` 每批返回一次，服务即可在批间响应取消/
        超时并把 ``attempts`` 同步给轮询中的 UI。
        """
        if task.words:
            index = 0
            while index < len(task.words):
                remaining = task.max_attempts - task.attempts
                if remaining <= 0:
                    return
                size = min(BATCH_SIZE, remaining)
                yield task.words[index:index + size]
                index += size
            return
        batch: list[str] = []
        limit = min(BATCH_SIZE, max(1, task.max_attempts - task.attempts))
        for word in ntlmcrack.generate_candidates(
                min_len=task.min_len, max_len=task.max_len,
                alphabet=task.alphabet, cancel=keep_going):
            if len(batch) >= limit:
                yield batch
                batch = []
                remaining = task.max_attempts - task.attempts
                if remaining <= 0:
                    return
                limit = min(BATCH_SIZE, remaining)
            batch.append(word)
        if batch:
            yield batch

    def _run(self, task: NtlmCrackTask) -> None:
        try:
            self._execute(task)
        except Exception as exc:  # noqa: BLE001 - UI 必须看到原因
            task.status = "error"
            task.error = str(exc)
            logger.error(f"NTLM 离线破解失败: {exc}")
        finally:
            task.finished = time.time()
            logger.info(f"NTLM 离线破解结束: 任务 {task.job} 结果 #{task.seq} "
                        f"{task.status}"
                        + (f" 密码 {task.password}" if task.password else ""))

    def _execute(self, task: NtlmCrackTask) -> None:
        deadline = time.time() + task.timeout
        challenge = bytes.fromhex(task.challenge)
        nt_response = bytes.fromhex(task.nt_response)
        identity = f"{task.domain}\\{task.user}" if task.domain else task.user
        _append_log(task, f"目标: {identity}")
        _append_log(task, f"服务器挑战: {task.challenge}")
        if task.engine == "candidates":
            _append_log(task, f"模式: 候选口令列表（{len(task.words)} 个）")
        else:
            _append_log(task, f"模式: 枚举 长度 {task.min_len}~{task.max_len}，"
                         f"字母表 {task.alphabet}")
        _append_log(task, f"上限: 最多尝试 {task.max_attempts} 次 / "
                    f"超时 {task.timeout} 秒")
        _append_log(task, "提示: 纯 Python 本地计算较慢，大量候选请改用 hashcat。")

        def keep_going() -> bool:
            return not task.cancel.is_set() and time.time() < deadline

        next_progress = PROGRESS_EVERY
        capped = False
        for batch in self._batches(task, keep_going):
            if task.attempts >= task.max_attempts:
                capped = True
                break
            if not keep_going():
                break
            found = ntlmcrack.brute_force_ntlmv2(
                challenge, nt_response, task.user, task.domain,
                candidates=batch, max_attempts=len(batch), cancel=keep_going)
            if found:
                try:
                    task.attempts += batch.index(found) + 1
                except ValueError:
                    task.attempts += len(batch)
                task.status = "cracked"
                task.password = found
                _append_log(task, f"\n[+] 已破解: {found}"
                            f"（尝试 {task.attempts} 次）")
                return
            task.attempts += len(batch)
            if task.attempts >= next_progress:
                next_progress += PROGRESS_EVERY
                _append_log(task, f"[进度] 已尝试 {task.attempts} 个候选，未命中")
        if task.status == "cracked":
            return
        if task.cancel.is_set():
            task.status = "cancelled"
            _append_log(task, "\n[!] 已取消")
            return
        if time.time() >= deadline:
            task.status = "error"
            task.error = f"超过 {task.timeout} 秒仍未破解，已停止"
            _append_log(task, f"\n[!] {task.error}")
            return
        task.status = "exhausted"
        if capped:
            _append_log(task, f"\n[-] 已达尝试上限 {task.max_attempts}"
                        f"（共尝试 {task.attempts} 次），未命中；可调大上限、"
                        "改用候选列表或 hashcat")
        else:
            _append_log(task, f"\n[-] 候选已全部验证完毕"
                        f"（共尝试 {task.attempts} 次），未命中")
