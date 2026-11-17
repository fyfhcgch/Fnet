"""Thread-safe application logger with in-memory history for the WebUI.

The logger has no GUI dependency: the HTTP layer polls :meth:`records_since`
on the active job, so it works headless as well.
"""
from __future__ import annotations

import datetime as _dt
import threading
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from fnet.paths import LOG_DIR, ensure_dirs

LEVEL_TAGS = {
    "debug": "[DEBUG]",
    "info": "[*]",
    "good": "[+]",
    "warn": "[!]",
    "error": "[-]",
}
VALID_LEVELS = set(LEVEL_TAGS)


@dataclass
class LogRecord:
    seq: int
    time: str
    level: str
    text: str
    tag: str = field(init=False)

    def __post_init__(self) -> None:
        self.tag = LEVEL_TAGS.get(self.level, "[*]")

    @property
    def line(self) -> str:
        return f"{self.time} {self.tag} {self.text}"

    def as_dict(self) -> dict:
        return {"seq": self.seq, "time": self.time, "level": self.level,
                "tag": self.tag, "text": self.text}


class Logger:
    """Writes to ``fnet.log`` and keeps the last 20k records in memory."""

    def __init__(self, path: Path | None = None, echo: bool = False,
                 keep: int = 20000) -> None:
        ensure_dirs()
        self.path = path or LOG_DIR / "fnet.log"
        self.echo = echo
        self._lock = threading.Lock()
        self._seq = 0
        self._records: deque[LogRecord] = deque(maxlen=keep)
        self._listeners: list = []

    # -- writing -------------------------------------------------------
    def log(self, text: str, level: str = "info") -> None:
        level = level if level in VALID_LEVELS else "info"
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            record = LogRecord(self._seq, stamp, level, str(text))
            self._records.append(record)
            try:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(record.line + "\n")
            except OSError:
                pass
            listeners = list(self._listeners)
        if self.echo:
            print(record.line, flush=True)
        for listener in listeners:
            try:
                listener(record)
            except Exception:  # noqa: BLE001 - listeners must never break logging
                continue

    def debug(self, text: str) -> None:
        self.log(text, "debug")

    def info(self, text: str) -> None:
        self.log(text, "info")

    def good(self, text: str) -> None:
        self.log(text, "good")

    def warn(self, text: str) -> None:
        self.log(text, "warn")

    def error(self, text: str) -> None:
        self.log(text, "error")

    # -- reading -------------------------------------------------------
    def records_since(self, seq: int = 0, limit: int = 2000) -> list[LogRecord]:
        with self._lock:
            return [r for r in self._records if r.seq > seq][:limit]

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq

    def history(self, limit: int = 5000) -> list[str]:
        with self._lock:
            return [r.line for r in list(self._records)[-limit:]]

    def tail(self, limit: int = 200) -> list[LogRecord]:
        with self._lock:
            return list(self._records)[-limit:]

    def subscribe(self, listener) -> None:
        with self._lock:
            self._listeners.append(listener)

    def unsubscribe(self, listener) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass

    def extend(self, records: Iterable[LogRecord]) -> None:
        for record in records:
            self.log(record.text, record.level)


class JobLog:
    """Per-job log buffer that also forwards to the global logger."""

    def __init__(self, sink: Logger, prefix: str = "") -> None:
        self.sink = sink
        self.prefix = prefix
        self._lock = threading.Lock()
        self._seq = 0
        self._records: list[LogRecord] = []
        self._keep = 40000

    def log(self, text: str, level: str = "info") -> None:
        level = level if level in VALID_LEVELS else "info"
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            record = LogRecord(self._seq, stamp, level, str(text))
            self._records.append(record)
            if len(self._records) > self._keep:
                del self._records[: len(self._records) - self._keep]
            seq = self._seq
        self.sink.log(f"[job:{self.prefix}] {text}" if self.prefix else text, level)
        record.seq = seq

    def debug(self, text: str) -> None:
        self.log(text, "debug")

    def info(self, text: str) -> None:
        self.log(text, "info")

    def good(self, text: str) -> None:
        self.log(text, "good")

    def warn(self, text: str) -> None:
        self.log(text, "warn")

    def error(self, text: str) -> None:
        self.log(text, "error")

    def records_since(self, seq: int = 0, limit: int = 4000) -> list[LogRecord]:
        with self._lock:
            return [r for r in self._records if r.seq > seq][:limit]

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq


logger = Logger()
