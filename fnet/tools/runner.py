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
_FIELD_CACHE: dict[str, set[str]] = {}


def _exe(name: str) -> str:
    return name + ".exe" if IS_WINDOWS else name


def _candidates(name: str) -> list[Path]:
    exe = _exe(name)
    paths = [
        Path(name),
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
            Path("/snap/bin") / exe,
            Path("/var/lib/flatpak/exports/bin") / exe,
        ]
    return paths


def find_tool(name: str, configured: str = "") -> str | None:
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    for path in _candidates(name):
        if path.is_file():
            return str(path)
    return None


def tool_version(path: str, timeout: int = 10) -> str:
    for flag in ("--version", "-v", "-V"):
        code, out = run([path, flag], timeout=timeout, echo=False)
        if code == 0 and out.strip():
            return out.strip().splitlines()[0]
    return ""


def run(cmd: list[str], timeout: int = 600, stdin: bytes | None = None,
        cancel: threading.Event | None = None, echo: bool = True,
        env: dict[str, str] | None = None) -> tuple[int, str]:
    """Run ``cmd`` and return ``(returncode, combined output)``.

    ``cancel`` is polled while the child runs so long jobs (aircrack-ng,
    hashcat, pyrdp) can be aborted from the WebUI.
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

    timer = threading.Timer(timeout, proc.kill)
    timer.daemon = True
    timer.start()
    try:
        while True:
            try:
                out, _ = proc.communicate(stdin, timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    proc.kill()
                    out, _ = proc.communicate()
                    return 130, _decode(out) + "\n[已取消]"
                if timeout and proc.poll() is None:
                    continue
                out, _ = proc.communicate()
                break
    finally:
        timer.cancel()
    if proc.returncode == -9 and timeout:
        return 124, _decode(out) + "\n[命令执行超时]"
    return proc.returncode or 0, _decode(out)


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


@dataclass
class TShark:
    path: str
    cache: bool = True
    retries: int = 1
    timeout: int = 600
    max_field_bytes: int = 262_144
    max_rows: int = 2_000_000

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
            if path.is_file() and path.stat().st_size >= 0:
                return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return None

    @staticmethod
    def _write_cache(path: Path, text: str) -> None:
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

    def known_fields(self) -> set[str]:
        """Field names this tshark understands (cached, one spawn per run).

        Requesting an unknown ``-e`` field makes tshark abort without any
        output, which used to silently disable a whole analysis.  The field
        list is therefore filtered and the dropped columns are re-inserted as
        empty strings so callers keep positional alignment.
        """
        cached = _FIELD_CACHE.get(self.path)
        if cached is not None:
            return cached
        names: set[str] = set()
        code, out = run([self.path, "-G", "fields"], timeout=120, echo=False)
        if code == 0:
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
        queried = [name for name in fields if not known or name in known]
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
            logger.error(out.strip() or f"tshark 退出码 {code}")
            return []
        rows = []
        truncated = 0
        for line in out.splitlines():
            if not line.strip():
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
                    if len(value.encode("utf-8", "replace")) > self.max_field_bytes:
                        value = value[:self.max_field_bytes] + "…[已截断]"
                        truncated += 1
                    limited.append(value)
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

    def __init__(self, config: Config) -> None:
        self.config = config

    def path(self, key: str) -> str | None:
        name = self.TOOL_NAMES.get(key, key)
        return find_tool(name, self.config.get(key, "paths"))

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
