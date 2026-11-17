"""Live packet capture driven by ``tshark`` (standard library only).

The WebUI exposes this as a small start/stop controller: the capture is
written to ``<cache>/live/live-<timestamp>.pcapng`` and can be submitted to
the normal analysis pipeline as soon as it stops.
"""
from __future__ import annotations

import datetime as _dt
import re
import secrets
import signal
import subprocess
import threading
import time
from pathlib import Path

from fnet.logger import logger
from fnet.paths import CACHE_DIR
from fnet.tools.runner import run

_INTERFACE_RE = re.compile(
    r"^\s*(\d+)\.\s+(.+?)(?:\s+\(([^()]*)\))?\s*$")


def parse_interfaces(output: str) -> list[dict]:
    """Parse ``tshark -D`` into ``[{index, name, description}]``."""
    items: list[dict] = []
    for line in str(output or "").splitlines():
        match = _INTERFACE_RE.match(line)
        if not match:
            continue
        items.append({
            "index": int(match.group(1)),
            "name": match.group(2).strip(),
            "description": (match.group(3) or "").strip(),
        })
    return items


class LiveCapture:
    """One-at-a-time live capture process."""

    def __init__(self, toolbox, config) -> None:
        self.toolbox = toolbox
        self.config = config
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._path: Path | None = None
        self._interface = ""
        self._filter = ""
        self._started = 0.0
        self._output = ""

    # -- interfaces ----------------------------------------------------
    def interfaces(self) -> list[dict]:
        tshark = self.toolbox.path("tshark")
        if not tshark:
            return []
        code, out = run([tshark, "-D"], timeout=30, echo=False)
        if code != 0:
            logger.warn(f"tshark -D 失败: {out[:300]}")
            return []
        return parse_interfaces(out)

    # -- lifecycle -----------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            proc = self._proc
            running = bool(proc is not None and proc.poll() is None)
            path = self._path
            size = 0
            if path is not None and path.is_file():
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
            return {
                "running": running,
                "interface": self._interface,
                "filter": self._filter,
                "path": str(path) if path else "",
                "size": size,
                "elapsed": round(time.time() - self._started, 1)
                if running and self._started else 0,
                "pid": proc.pid if running and proc else 0,
                "output": self._output[-2000:],
            }

    def start(self, interface: str, capture_filter: str = "",
              name: str = "") -> dict:
        interface = str(interface or "").strip()
        capture_filter = str(capture_filter or "").strip()
        name = str(name or "").strip()
        if not interface:
            raise ValueError("请选择抓包网卡")
        if any(ch in interface for ch in "\r\n\x00"):
            raise ValueError("网卡名称非法")
        if any(ch in capture_filter for ch in "\r\n\x00"):
            raise ValueError("抓包过滤器非法")
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise ValueError("已有抓包任务在运行，请先停止")
        tshark = self.toolbox.path("tshark")
        if not tshark:
            raise ValueError("未找到 tshark，无法实时抓包")
        directory = CACHE_DIR / "live"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:40] or "capture"
        target = directory / f"live-{stamp}-{safe}-{secrets.token_hex(3)}.pcapng"
        cmd = [tshark, "-i", interface, "-w", str(target), "-q"]
        if capture_filter:
            cmd += ["-f", capture_filter]
        logger.info("开始实时抓包: " + " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace")
        except OSError as exc:
            raise ValueError(f"无法启动抓包: {exc}") from exc
        # tshark exits immediately when the interface does not exist or the
        # user lacks capture permission; surface its message instead of
        # returning a dead capture.
        time.sleep(0.5)
        if proc.poll() is not None:
            output = ""
            try:
                output = proc.stdout.read() if proc.stdout else ""
            except OSError:
                output = ""
            finally:
                if proc.stdout is not None:
                    proc.stdout.close()
            raise ValueError(output.strip()[-800:] or "抓包进程立即退出")
        with self._lock:
            self._proc = proc
            self._path = target
            self._interface = interface
            self._filter = capture_filter
            self._started = time.time()
            self._output = ""
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            proc = self._proc
            path = self._path
        # ``status()`` takes the same lock, so it must be called after the
        # ``with`` block; otherwise a second ``stop()`` would deadlock.
        if proc is None:
            return self.status()
        if proc.poll() is None:
            logger.info("停止实时抓包…")
            try:
                if hasattr(signal, "SIGINT"):
                    proc.send_signal(signal.SIGINT)
                else:  # pragma: no cover - Windows fallback
                    proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    proc.kill()
        output = ""
        try:
            output = proc.stdout.read() if proc.stdout else ""
        except OSError:
            output = ""
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
        with self._lock:
            self._output = (output or "")[-2000:]
            self._proc = None
            status = {
                "running": False,
                "interface": self._interface,
                "filter": self._filter,
                "path": str(path) if path else "",
                "size": path.stat().st_size
                if path is not None and path.is_file() else 0,
                "elapsed": round(time.time() - self._started, 1)
                if self._started else 0,
                "pid": 0,
                "output": self._output,
            }
            self._started = 0.0
        if status["path"]:
            logger.good(f"实时抓包已保存: {status['path']} "
                        f"({status['size']} 字节)")
        return status

    def shutdown(self) -> None:
        """Best-effort stop used when the HTTP server exits."""
        try:
            if self.status().get("running"):
                self.stop()
        except Exception:  # noqa: BLE001 - shutdown must not raise
            pass
