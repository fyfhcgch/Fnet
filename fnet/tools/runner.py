"""Bridge to the external command line tools Fnet drives.

Everything is resolved through :func:`find_tool`, which honours an explicit
path from the configuration, ``$PATH``, a portable ``tools/`` directory and
the usual per-platform locations.  Commands are always executed without a
shell, so Linux/macOS behave exactly like Windows.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from fnet.config import Config
from fnet.logger import logger
from fnet import paths as fnet_paths
from fnet.paths import PROJECT_ROOT, TOOLS_DIR

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"

#: ``tshark -G fields`` is expensive, cache the valid names per binary.
#: A missing entry means "unknown"; ``set()`` means "probed, tshark knows
#: nothing" and is a valid cache entry.
_FIELD_CACHE: dict[str, set[str]] = {}

#: Appended to a field value cut down to ``TShark.max_field_bytes``.
TRUNCATION_MARKER = "…[已截断]"

#: Diagnostic lines tshark/dumpcap print on stderr.  :func:`run` merges stderr
#: into its output so callers can show the tail of a failure, therefore the
#: parsers must not mistake these for data rows.
_TOOL_NOISE_PREFIXES = (
    "Running as user ",
    "tshark: ",
    "wireshark: ",
    "dumpcap: ",
)


def _exe(name: str) -> str:
    return name + ".exe" if IS_WINDOWS else name


def _is_executable(path: Path) -> bool:
    """True when ``path`` is a file we are allowed to execute.

    Windows has no execute bit, so a regular file is enough there; on POSIX an
    unreadable/executable-less decoy must never shadow a real install.
    """
    try:
        if not path.is_file():
            return False
    except OSError:
        return False
    if os.name == "nt":
        return True
    return os.access(path, os.X_OK)


def _candidates(name: str) -> list[Path]:
    exe = _exe(name)
    paths = [
        TOOLS_DIR / exe,
        TOOLS_DIR / name / exe,
        PROJECT_ROOT / "plugins" / name / exe,
        PROJECT_ROOT / "plugins" / "Wireshark" / exe,
    ]
    if IS_WINDOWS:
        paths += [
            Path(r"C:\Program Files\Wireshark") / exe,
            Path(r"C:\Program Files (x86)\Wireshark") / exe,
        ]
    elif IS_MACOS:
        paths += [
            Path("/Applications/Wireshark.app/Contents/MacOS") / exe,
            Path("/opt/homebrew/bin") / exe,
            Path("/usr/local/bin") / exe,
        ]
    else:
        paths += [
            Path("/usr/bin") / exe,
            Path("/usr/local/bin") / exe,
            # tshark 在 Debian/Ubuntu 上装在 /usr/sbin；用户 $PATH 不含该目录时
            # 需要这里兜底。
            Path("/usr/sbin") / exe,
            Path("/usr/local/sbin") / exe,
            Path("/snap/bin") / exe,
            Path("/var/lib/flatpak/exports/bin") / exe,
        ]
    return paths


def find_tool(name: str, configured: str = "") -> str | None:
    """Resolve an external tool, preferring trustworthy locations.

    Order: the configured override, then ``$PATH``, then the bundled/portable
    and per-platform directories.  A same-named file in the *current working
    directory* is never picked up implicitly (that used to shadow
    ``/usr/bin/tshark``), and every candidate must be executable.
    """
    if configured:
        candidate = Path(configured).expanduser()
        if _is_executable(candidate):
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    for path in _candidates(name):
        if _is_executable(path):
            return str(path)
    return None


def tool_version(path: str, timeout: int = 10) -> str:
    for flag in ("--version", "-v", "-V"):
        code, out = run([path, flag], timeout=timeout, echo=False)
        if code == 0 and out.strip():
            return out.strip().splitlines()[0]
    return ""


def count_frames(pcap: str | Path, tshark_path: str = "",
                 timeout: int = 300) -> int:
    """Return the number of packets in ``pcap`` (0 when unknown).

    ``capinfos`` is preferred because it only reads the file headers; the
    ``tshark -z io,stat`` fallback works everywhere tshark does.  The result
    lets callers scan a capture in bounded frame ranges instead of materialising
    every packet payload at once.
    """
    capinfos = shutil.which("capinfos")
    if capinfos:
        try:
            out = subprocess.run([capinfos, "-c", "-M", str(pcap)],
                                 capture_output=True, text=True,
                                 timeout=timeout).stdout
            match = re.search(r"Number of packets:\s*(\d+)", out or "")
            if match:
                return int(match.group(1))
        except (OSError, subprocess.SubprocessError):
            pass
    if tshark_path:
        try:
            result = subprocess.run(
                [tshark_path, "-r", str(pcap), "-q", "-z", "io,stat,0"],
                capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return 0
        if result.returncode == 0:
            matches = re.findall(
                r"\|\s*[\d.]+ <>\s*[\d.]+\s*\|\s*(\d+)\s*\|",
                result.stdout or "")
            if matches:
                return int(matches[-1])
    return 0


def run(cmd: list[str], timeout: int = 600, stdin: bytes | None = None,
        cancel: threading.Event | None = None, echo: bool = True,
        env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run ``cmd`` and return ``(returncode, combined output)``.

    ``cancel`` is polled while the child runs so long jobs (aircrack-ng,
    hashcat, pyrdp) can be aborted from the WebUI.

    ``stderr`` is merged into the returned text on purpose: callers show the
    tail of the output when a tool fails, and tshark's diagnostics would
    otherwise disappear.  Parsers that expect tab-separated data rows must
    therefore ignore :data:`_TOOL_NOISE_PREFIXES` lines (see
    :meth:`TShark.fields`).

    ``stdin`` is handed to the *first* ``communicate`` call only; the
    following polls pass ``None`` because re-sending the payload raised
    ``ValueError: Cannot send input after starting communication`` while it
    was still being flushed.  ``timeout <= 0`` disables the watchdog, and the
    child is always killed on timeout/cancel so no orphan survives.
    """
    if echo:
        logger.info("执行: " + " ".join(str(c) for c in cmd))
    popen_env = dict(os.environ)
    popen_env.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        popen_env.update(env)
    try:
        proc = subprocess.Popen(
            [str(c) for c in cmd],
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=popen_env,
        )
    except FileNotFoundError:
        return 127, f"找不到可执行文件: {cmd[0]}"
    except OSError as exc:
        return 126, f"无法执行 {cmd[0]}: {exc}"

    expired = threading.Event()

    def _kill_on_timeout() -> None:
        expired.set()
        try:
            proc.kill()
        except OSError:
            pass

    timer = None
    if timeout and timeout > 0:
        timer = threading.Timer(timeout, _kill_on_timeout)
        timer.daemon = True
        timer.start()
    out: bytes | None = b""
    # ``communicate`` writes the payload incrementally from its selector loop,
    # so the first poll gets ``stdin`` and later polls must pass ``None``:
    # re-sending it raised ``ValueError: Cannot send input after starting
    # communication`` while the payload was still being flushed.
    pending: bytes | None = stdin
    try:
        while True:
            try:
                out, _ = proc.communicate(pending, timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                pending = None
                if cancel is not None and cancel.is_set():
                    proc.kill()
                    return 130, _decode(_drain(proc)) + "\n[已取消]"
                if expired.is_set() or proc.poll() is not None:
                    out = _drain(proc)
                    break
    finally:
        if timer is not None:
            timer.cancel()
        if proc.poll() is None:
            # 任何异常路径都不留下仍在运行的子进程。
            try:
                proc.kill()
            except OSError:
                pass
            _drain(proc)
    out = out or b""
    if proc.returncode is None:
        # 兜底 kill 后仍未回收：绝不把这种情况报告成成功。
        if expired.is_set():
            return 124, _decode(out) + "\n[命令执行超时]"
        return 1, _decode(out)
    if proc.returncode == -9 and expired.is_set():
        return 124, _decode(out) + "\n[命令执行超时]"
    return proc.returncode or 0, _decode(out)


def _drain(proc: subprocess.Popen, timeout: float = 5.0) -> bytes | None:
    """Read what is left of ``proc``'s output without ever blocking forever.

    A killed child whose grandchildren still hold the pipe would make a bare
    ``communicate()`` hang, so the read is bounded and the pipes are closed
    afterwards.  Returns the collected bytes (``None`` when unavailable).
    """
    try:
        out, _ = proc.communicate(timeout=timeout)
        return out
    except subprocess.TimeoutExpired:
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
        try:
            proc.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None
    except (OSError, ValueError):
        return None


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _decode_field(value: str) -> str:
    """Undo tshark's ``-E quote=d`` escaping (``""`` inside a quoted field)."""
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('""', '"')
    return value


def _first_diagnostic(text: str) -> str:
    """First non-empty, non-noise line of a failed tool run."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(_TOOL_NOISE_PREFIXES):
            return stripped
    return ""


def _truncate_bytes(value: str, limit: int) -> str:
    """Cut ``value`` to at most ``limit`` UTF-8 bytes, keeping text intact.

    Slicing by characters (``value[:limit]``) let a CJK cell occupy up to
    three bytes per character and blow past the byte cap, so the cut is done
    on the encoded form and backed off to a character boundary.  Values that
    already fit are returned unchanged; cut values get
    :data:`TRUNCATION_MARKER` appended.
    """
    if limit <= 0:
        return value
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value
    clipped = encoded[:limit]
    while clipped:
        try:
            return clipped.decode("utf-8") + TRUNCATION_MARKER
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return TRUNCATION_MARKER


#: 默认缓存上限。``tshark`` 每个唯一命令写一个 TSV，长时间使用会无限增长
#: （实测单机积累到 967 MB / 1489 文件），因此写入后按 LRU 修剪。
DEFAULT_CACHE_MAX_MB = 512
DEFAULT_CACHE_TTL_DAYS = 14


def prune_cache(directory: Path, max_bytes: int = 0,
                ttl_seconds: float = 0, now: float | None = None
                ) -> tuple[int, int]:
    """Evict old/oversized files from ``directory``; return ``(count, bytes)``.

    Two independent limits are applied:

    * **TTL** — anything untouched for longer than ``ttl_seconds`` goes first,
      because a stale TSV is useless: the cache key already contains the
      source ``mtime``/``size``.
    * **size cap** — if the survivors still exceed ``max_bytes``, the least
      recently used ones are dropped until the total fits.

    Both limits are opt-in (``0`` disables one), so callers can run a pure TTL
    sweep or a pure size sweep.  Errors are swallowed: cache maintenance must
    never break an analysis.
    """
    removed = freed = 0
    try:
        entries = [entry for entry in directory.iterdir()
                   if entry.is_file() and entry.suffix == ".tsv"]
    except OSError:
        return 0, 0
    reference = time.time() if now is None else now

    kept: list[tuple[float, int, Path]] = []
    for entry in entries:
        try:
            stat = entry.stat()
        except OSError:
            continue
        if ttl_seconds > 0 and reference - stat.st_mtime > ttl_seconds:
            try:
                entry.unlink()
                removed += 1
                freed += stat.st_size
            except OSError:
                pass
            continue
        kept.append((stat.st_mtime, stat.st_size, entry))

    if max_bytes > 0:
        total = sum(size for _, size, _ in kept)
        if total > max_bytes:
            for _, size, entry in sorted(kept):  # oldest first
                if total <= max_bytes:
                    break
                try:
                    entry.unlink()
                    removed += 1
                    freed += size
                    total -= size
                except OSError:
                    pass
    return removed, freed


#: 缓存维护的节流状态：``{目录: 上次修剪的 monotonic 时间}``。
#: 每次写缓存都全目录 ``stat`` 在 1489 文件时约 3 ms，但没必要；每 5 分钟
#: 修剪一次足够，也避免多个 worker 线程同时扫目录。
_CACHE_MAINTENANCE_LOCK = threading.Lock()
_CACHE_LAST_PRUNE: dict[str, float] = {}
_CACHE_PRUNE_INTERVAL = 300.0


def _schedule_cache_maintenance(directory: Path, max_bytes: int = 0,
                                ttl_seconds: float = 0) -> None:
    """按节流间隔修剪缓存目录；永不抛异常。"""
    key = str(directory)
    now = time.monotonic()
    with _CACHE_MAINTENANCE_LOCK:
        last = _CACHE_LAST_PRUNE.get(key)
        if last is not None and now - last < _CACHE_PRUNE_INTERVAL:
            return
        _CACHE_LAST_PRUNE[key] = now
    try:
        removed, freed = prune_cache(directory, max_bytes=max_bytes,
                                     ttl_seconds=ttl_seconds)
    except Exception:  # noqa: BLE001 - 缓存维护绝不影响分析
        return
    if removed:
        logger.debug(f"tshark 缓存清理: 删除 {removed} 个文件，"
                     f"释放 {freed / 1024 / 1024:.1f} MB")


@dataclass
class TShark:
    path: str
    cache: bool = True
    retries: int = 1
    timeout: int = 600
    max_field_bytes: int = 262_144
    max_rows: int = 2_000_000
    cache_max_bytes: int = DEFAULT_CACHE_MAX_MB * 1024 * 1024
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_DAYS * 86_400

    def _cache_dir(self) -> Path:
        # Resolve at call time so tests can patch fnet.paths.CACHE_DIR.
        return Path(fnet_paths.CACHE_DIR) / "tshark"

    def _cache_path(self, args: list[str]) -> Path | None:
        if not self.cache:
            return None
        source = Path(args[args.index("-r") + 1]) if "-r" in args else None
        if source is None or not source.is_file():
            return None
        try:
            stat = source.stat()
        except OSError:
            return None
        key = hashlib.sha256(json.dumps([
            self.path, args, stat.st_size, stat.st_mtime_ns,
        ], ensure_ascii=False).encode("utf-8", "replace")).hexdigest()
        return self._cache_dir() / (key + ".tsv")

    @staticmethod
    def _read_cache(path: Path) -> str | None:
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                # 命中即"使用"：刷新 mtime，让 TTL/LRU 按最后访问时间淘汰，
                # 而不是按写入时间（同一份抓包反复分析是常态）。
                try:
                    os.utime(path, None)
                except OSError:
                    pass
                return text
        except OSError:
            return None
        return None

    def _write_cache(self, path: Path, text: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, name = tempfile.mkstemp(prefix=path.name, dir=path.parent)
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(name, path)
        except OSError:
            try:
                if "name" in locals():
                    os.unlink(name)
            except OSError:
                pass
        else:
            _schedule_cache_maintenance(path.parent, self.cache_max_bytes,
                                        self.cache_ttl_seconds)

    def _run_tshark(self, cmd: list[str],
                    cancel: threading.Event | None) -> tuple[int, str]:
        attempts = max(0, int(self.retries)) + 1
        code, out = 1, ""
        for attempt in range(attempts):
            code, out = run(cmd, timeout=self.timeout, cancel=cancel,
                            echo=False)
            if cancel is not None and cancel.is_set():
                return code, out
            if code == 0:
                return code, out
            if code in (126, 127):
                break
            if attempt + 1 < attempts:
                logger.debug(f"tshark 退出码 {code}，重试 "
                             f"({attempt + 1}/{attempts - 1})")
                time.sleep(min(0.5 * (attempt + 1), 2.0))
        return code, out

    def known_fields(self) -> set[str] | None:
        """Field names this tshark understands (cached, one spawn per run).

        Requesting an unknown ``-e`` field makes tshark abort without any
        output, which used to silently disable a whole analysis.  The field
        list is therefore filtered and the dropped columns are re-inserted as
        empty strings so callers keep positional alignment.

        Returns ``None`` when the probe failed, i.e. "unknown".  A failure is
        never cached: caching the empty set made ``fields()`` query every
        field, tshark abort and the analysis stay empty for the rest of the
        process.  ``set()`` therefore means "probed successfully, tshark
        knows no fields" and must not be confused with ``None``.
        """
        if self.path in _FIELD_CACHE:
            return _FIELD_CACHE[self.path]
        code, out = run([self.path, "-G", "fields"], timeout=120, echo=False)
        if code != 0:
            logger.debug(f"tshark -G fields 失败（退出码 {code}），字段列表未知")
            return None
        names: set[str] = set()
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) > 2 and parts[0] == "F":
                names.add(parts[2])
        _FIELD_CACHE[self.path] = names
        return names

    def fields(self, pcap: str | Path, fields: list[str], display_filter: str = "",
               extra: list[str] | None = None,
               cancel: threading.Event | None = None,
               two_pass: bool = False) -> list[list[str]]:
        known = self.known_fields()
        queried = [name for name in fields if known is None or name in known]
        dropped = [name for name in fields if name not in queried]
        if dropped:
            logger.debug("tshark 不支持字段，已忽略: " + ", ".join(dropped))
        if not queried:
            return []
        cmd = [self.path, "-r", str(pcap)]
        if two_pass:
            cmd.append("-2")
        cmd += ["-T", "fields"]
        if display_filter:
            cmd += ["-Y", display_filter]
        for field in queried:
            cmd += ["-e", field]
        cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "quote=d"]
        if extra:
            cmd += extra

        cache_path = self._cache_path(cmd)
        cached = self._read_cache(cache_path) if cache_path else None
        if cached is not None:
            logger.debug(f"tshark 结果缓存命中: {cache_path.name}")
            out = cached
            code = 0
        else:
            code, out = self._run_tshark(cmd, cancel)
            if code == 0 and cache_path is not None:
                self._write_cache(cache_path, out)

        if code != 0 and not out.strip():
            logger.error(f"tshark 退出码 {code}")
            return []
        if code != 0:
            # tshark failed (bad filter/field, unreadable file).  Its error
            # text must never leak into the tab-separated data rows, so log
            # it and treat the whole run as empty instead of parsing it.
            logger.error(_first_diagnostic(out) or f"tshark 退出码 {code}")
            return []
        rows = []
        truncated = 0
        for line in out.splitlines():
            if not line.strip():
                continue
            if line.startswith(_TOOL_NOISE_PREFIXES) and not line.startswith('"'):
                # tshark/dumpcap 的诊断行（root 警告等）不是数据记录。
                # 真正的数据行被 -E quote=d 包成 "..."，不会被误伤。
                logger.debug("忽略工具诊断行: " + line)
                continue
            values = [_decode_field(v) for v in line.split("\t")]
            if dropped:
                expanded: list[str] = []
                position = 0
                for name in fields:
                    if name in queried:
                        expanded.append(values[position] if position < len(values) else "")
                        position += 1
                    else:
                        expanded.append("")
                values = expanded
            if self.max_field_bytes:
                limited: list[str] = []
                for value in values:
                    clipped = _truncate_bytes(value, self.max_field_bytes)
                    if clipped != value:
                        truncated += 1
                    limited.append(clipped)
                values = limited
            rows.append(values)
            if self.max_rows and len(rows) >= self.max_rows:
                logger.warn(f"tshark 行数达到上限 {self.max_rows}，后续记录已丢弃")
                break
        if truncated:
            logger.warn(f"tshark 字段长度超过 {self.max_field_bytes} 字节，"
                        f"已截断 {truncated} 个值")
        return rows

    def info(self, pcap: str | Path, display_filter: str = "",
             cancel: threading.Event | None = None) -> list[list[str]]:
        return self.fields(pcap, ["frame.number", "frame.time_relative",
                                  "_ws.col.protocol", "_ws.col.info"],
                           display_filter, cancel=cancel)

    def export_objects(self, pcap: str | Path, protocol: str,
                       directory: str | Path,
                       cancel: threading.Event | None = None) -> tuple[int, str]:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return run([self.path, "-r", str(pcap), "--export-objects",
                    f"{protocol},{directory}"], cancel=cancel, echo=False)


class ToolBox:
    """Resolves and runs the external tools, remembering user overrides."""

    #: tool key -> executable name
    TOOL_NAMES = {
        "tshark": "tshark",
        "wireshark": "wireshark",
        "java": "java",
        "aircrack": "aircrack-ng",
        "hashcat": "hashcat",
        "john": "john",
        "foremost": "foremost",
        "binwalk": "binwalk",
        "pcapfix": "pcapfix",
        "etl2pcapng": "etl2pcapng",
        "pyrdp_player": "pyrdp-player",
        "openssl": "openssl",
    }

    #: Tools whose user override is stored in ``[config]``: the WebUI
    #: (``SETTING_META`` in ``app.js``) saves the path there.  ``[paths]`` is
    #: still accepted as a fallback for older config files.
    CONFIG_OVERRIDE_KEYS = ("tshark",)

    def __init__(self, config: Config) -> None:
        self.config = config

    def configured(self, key: str) -> str:
        """Return the user-configured override for ``key`` (may be empty)."""
        if key in self.CONFIG_OVERRIDE_KEYS:
            return (self.config.get(key, "config").strip()
                    or self.config.get(key, "paths").strip())
        return self.config.get(key, "paths")

    def path(self, key: str) -> str | None:
        name = self.TOOL_NAMES.get(key, key)
        return find_tool(name, self.configured(key))

    def tshark(self) -> TShark | None:
        path = self.path("tshark")
        if not path:
            logger.error("未找到 tshark，请安装 wireshark-cli 或在设置中指定路径")
            return None
        return TShark(
            path,
            cache=self.config.get_bool("tshark_cache", fallback=True),
            retries=max(0, self.config.get_int("tshark_retry", fallback=1)),
            timeout=max(1, self.config.get_int("tshark_timeout", fallback=600)),
            max_field_bytes=max(
                0, self.config.get_int("tshark_max_field_kb", fallback=256) * 1024),
            max_rows=max(
                0, self.config.get_int("tshark_max_rows", fallback=2_000_000)),
            cache_max_bytes=max(
                0, self.config.get_int("tshark_cache_max_mb",
                                       fallback=DEFAULT_CACHE_MAX_MB)) * 1024 * 1024,
            cache_ttl_seconds=max(
                0.0, float(self.config.get_int(
                    "tshark_cache_ttl_days",
                    fallback=DEFAULT_CACHE_TTL_DAYS))) * 86_400,
        )

    def javapath(self) -> str:
        return self.path("java") or "java"

    def availability(self) -> dict[str, bool]:
        return {key: bool(self.path(key)) for key in self.TOOL_NAMES}

    def run_tool(self, key: str, args: list[str], timeout: int = 3600,
                 cancel: threading.Event | None = None) -> tuple[int, str]:
        path = self.path(key)
        if not path:
            return 127, f"未找到 {self.TOOL_NAMES.get(key, key)}"
        return run([path, *args], timeout=timeout, cancel=cancel)


def executable_env_hint() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(TOOLS_DIR) + os.pathsep + env.get("PATH", "")
    return env
