"""Filesystem layout of Fnet (XDG aware on Linux, AppData on Windows).

Static data (word lists, icons, default configuration) lives next to the
package inside the repository; mutable data (logs, user configuration,
downloaded plugins) goes to a per-user directory following the native
conventions of the host system.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

#: Shipped read-only data (word lists, icon set, default config).  It lives
#: inside the package so a normal ``pip install`` ships it in the wheel.
ASSETS_DIR = Path(os.environ.get("FNET_ASSETS", PACKAGE_DIR / "assets"))

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def _xdg(name: str, fallback: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else fallback


if os.environ.get("FNET_HOME"):
    USER_DIR = Path(os.environ["FNET_HOME"]).expanduser()
elif IS_WINDOWS:
    USER_DIR = Path(os.environ.get("APPDATA", Path.home())) / "Fnet"
elif IS_MACOS:
    USER_DIR = Path.home() / "Library" / "Application Support" / "Fnet"
else:
    USER_DIR = _xdg("XDG_CONFIG_HOME", Path.home() / ".config") / "fnet"

if os.environ.get("FNET_HOME"):
    LOG_DIR = USER_DIR / "logs"
    CACHE_DIR = USER_DIR / "cache"
elif IS_WINDOWS or IS_MACOS:
    LOG_DIR = USER_DIR / "logs"
    CACHE_DIR = USER_DIR / "cache"
else:
    LOG_DIR = _xdg("XDG_STATE_HOME", Path.home() / ".local" / "state") / "fnet" / "logs"
    CACHE_DIR = _xdg("XDG_CACHE_HOME", Path.home() / ".cache") / "fnet"

#: Optional directory holding portable helper binaries (tshark, foremost...).
TOOLS_DIR = Path(os.environ.get("FNET_TOOLS", PROJECT_ROOT / "tools")).expanduser()

DEFAULT_CONFIG = ASSETS_DIR / "config.ini"
USER_CONFIG = USER_DIR / "config.ini"

WORDLIST_DIR = ASSETS_DIR / "wordlists"
DEFAULT_WORDLIST = WORDLIST_DIR / "top25000.txt"


def ensure_dirs() -> None:
    for path in (USER_DIR, LOG_DIR, CACHE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def resource(*parts: str) -> Path:
    """Return a path inside the shipped asset tree."""
    return ASSETS_DIR.joinpath(*parts)


def wordlist(name_or_path: str | None) -> Path | None:
    """Resolve a word list reference against the asset tree.

    Accepts absolute paths, paths relative to the project root (the
    historical ``assests/top25000.txt`` style) and bare file names.
    """
    if not name_or_path:
        return DEFAULT_WORDLIST if DEFAULT_WORDLIST.exists() else None
    raw = name_or_path.replace("\\", "/")
    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        return candidate if candidate.is_file() else None
    for base in (PROJECT_ROOT, ASSETS_DIR, WORDLIST_DIR):
        path = base / raw
        if path.is_file():
            return path
    path = WORDLIST_DIR / candidate.name
    return path if path.is_file() else None
