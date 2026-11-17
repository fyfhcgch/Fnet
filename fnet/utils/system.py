"""Small platform-integration helpers so Fnet is native everywhere."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"


def open_path(path: str | Path) -> bool:
    """Open a file or directory with the desktop's default handler."""
    target = str(path)
    if IS_WINDOWS:
        try:
            os.startfile(target)  # type: ignore[attr-defined]
            return True
        except OSError:
            return False
    opener = "open" if IS_MACOS else "xdg-open"
    if shutil.which(opener) is None and opener == "xdg-open":
        opener = "gio"
        args = [opener, "open", target]
    else:
        args = [opener, target]
    try:
        subprocess.Popen(args, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False


def open_url(url: str) -> bool:
    """Open an URL in the user's default browser with the standard library."""
    import webbrowser

    try:
        return bool(webbrowser.open(url))
    except Exception:  # noqa: BLE001 - webbrowser raises various errors
        return False


def reveal(path: str | Path) -> bool:
    """Show a file in the platform file manager (best effort)."""
    target = Path(path)
    if IS_WINDOWS:
        try:
            subprocess.Popen(["explorer", "/select,", str(target)])
            return True
        except OSError:
            return False
    if IS_MACOS:
        try:
            subprocess.Popen(["open", "-R", str(target)])
            return True
        except OSError:
            return False
    # Linux: there is no portable "select", open the parent directory.
    return open_path(target.parent)


def default_mono_font() -> str:
    """Return a monospace family that actually exists on this machine."""
    candidates = ("JetBrains Mono", "Fira Code", "Cascadia Mono", "Consolas",
                  "DejaVu Sans Mono", "Noto Sans Mono", "Liberation Mono",
                  "Menlo", "Monaco", "Ubuntu Mono", "Source Code Pro")
    if IS_WINDOWS or IS_MACOS:
        return candidates[0]
    fc_match = shutil.which("fc-match")
    if fc_match:
        try:
            out = subprocess.run([fc_match, "-f", "%{family}"], capture_output=True,
                                 text=True, timeout=5).stdout
            families = {name.strip() for name in out.split(",")}
            for name in candidates:
                if name in families:
                    return name
        except (OSError, subprocess.SubprocessError):
            pass
    return "monospace"
