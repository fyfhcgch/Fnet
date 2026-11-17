"""Configuration handling (``fnet/assets/config.ini`` + user overrides)."""
from __future__ import annotations

import configparser
import shutil
from pathlib import Path

from fnet.paths import DEFAULT_CONFIG, USER_CONFIG, ensure_dirs

#: Built-in keyword set.  It covers the encodings CTF players expect to be
#: recognised out of the box.
DEFAULT_REGMATCH = (
    r"(flag\{.+?\}|ctfshow\{.+?\}|hgame\{.+?\}|begin\{.+?\}|ctf\{.+?\})"
    ";666c6167\\w+;(Zmxh[\\w+/\\=]+|TVpXR0[\\w+/\\=]+|MZWGCZ[\\w+/\\=]+)"
    ";&#102.+;flag\\W7B.+\\W7D;102 108 52 103( \\d+)+;102 49 97 103( \\d+)+"
    ";10210852103(\\d+)+;10210897103;1024952103;1024997103;103 97 109 101"
    ";10397109101;107 101 121;107101121;112 97 115 115;11297115115;43 54 46"
    ";435446;46 31 34 47;46 31 41 47;46 4C 34 47;46 4C 41 47;46313447"
    ";46314147;464C3447;464C4147;47 41 4D 45;47414D45;4B 45 59;4B4559"
    ";50 41 53 53;50415353;63 74 66;637466;66 31 34 67;66 31 61 67"
    ";66 6C 34 67;66 6C 61 67;66313467;66316167;666C3467;666C6167"
    ";67 61 6D 65;67616D65;6B 65 79;6B6579;70 61 73 73;70617373"
    ";99 116 102;99116102;@IH<;A2V5;AO.MG;ASIS;CGFZC;CNFF;CTF;F#S<;F14G"
    ";F1AG;FL4G;GAME;KEY;MZWGCZ;PASS;PGS;Q0NURG;Q1RG;R0FNR;RJE0R;RJFBR"
    ";RKW0R;RKXBR;RLX;S0VZ;S69T;S6NT;SEC;SY9T;SYNT;TNZR;U.C5EC;UEFTU"
    ";W^7?+;Y3RM;Z2FTZ;ZABAMAWA;ZJE0Z;ZJFHZ;ZMW0Z;ZMXHZ;504b0304;select;flag"
)

DEFAULTS = {
    "config": {
        "regmatch": DEFAULT_REGMATCH,
        "passwddir": "wordlists/top25000.txt",
        "javapath": "java",
        "font": "JetBrains Mono",
        "font_size": "12",
        "theme": "dark",
        "thread_count": "50",
        "tshark": "",
        "wireshark": "",
        "host": "127.0.0.1",
        "port": "8765",
        "open_browser": "1",
        "max_upload_mb": "1024",
        "sql_success": "",
        "sql_time_threshold": "1.0",
        "tshark_cache": "1",
        "tshark_retry": "1",
        "tshark_timeout": "600",
        "tshark_max_field_kb": "256",
        "tshark_max_rows": "2000000",
        "shards": "1",
        "language": "zh",
    },
    "plugins": {"execute_cmd": "{}"},
    "paths": {
        "tls_keylog": "",
        "tls_private_key": "",
        "tls_key_passphrase": "",
        "cobaltstrike_keys": "",
        "rdp_keylog": "",
        "rdp_private_key": "",
        "antsword_rsa_public_key": "",
        "minidump": "",
        "rules_file": "",
        "live_interface": "",
        "hashcat": "",
        "john": "",
        "aircrack": "",
        "foremost": "",
        "pcapfix": "",
        "etl2pcapng": "",
    },
    "recent": {"files": ""},
}


class Config:
    """Small typed wrapper around :class:`configparser.ConfigParser`."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or USER_CONFIG
        self._cp = configparser.ConfigParser(interpolation=None)
        for section, values in DEFAULTS.items():
            self._cp[section] = dict(values)
        self.load()

    # -- persistence ---------------------------------------------------
    def load(self) -> None:
        ensure_dirs()
        if not self.path.exists() and DEFAULT_CONFIG.exists():
            shutil.copy(DEFAULT_CONFIG, self.path)
        if self.path.exists():
            self._cp.read(self.path, encoding="utf-8")

    def save(self) -> None:
        ensure_dirs()
        with self.path.open("w", encoding="utf-8") as fh:
            self._cp.write(fh)

    # -- accessors -----------------------------------------------------
    def get(self, key: str, section: str = "config", fallback: str = "") -> str:
        return self._cp.get(section, key, fallback=fallback)

    def get_int(self, key: str, section: str = "config", fallback: int = 0) -> int:
        try:
            return int(self.get(key, section, str(fallback)))
        except ValueError:
            return fallback

    def get_float(self, key: str, section: str = "config",
                  fallback: float = 0.0) -> float:
        try:
            return float(self.get(key, section, str(fallback)))
        except ValueError:
            return fallback

    def get_bool(self, key: str, section: str = "config",
                 fallback: bool = False) -> bool:
        raw = self.get(key, section, "1" if fallback else "0").strip().lower()
        return raw in ("1", "true", "yes", "on")

    def set(self, key: str, value: str, section: str = "config") -> None:
        if section not in self._cp:
            self._cp[section] = {}
        self._cp[section][key] = str(value)

    def set_many(self, values: dict[str, str], section: str = "config") -> None:
        for key, value in values.items():
            self.set(key, value, section)

    def regmatch(self) -> list[str]:
        """Return the "interesting keyword" patterns used by the scanner."""
        raw = self.get("regmatch")
        return [p for p in raw.split(";") if p]

    def as_dict(self, section: str = "config") -> dict[str, str]:
        if section not in self._cp:
            return {}
        return dict(self._cp[section])

    # -- recent files --------------------------------------------------
    def recent_files(self) -> list[str]:
        raw = self.get("files", "recent")
        return [p for p in raw.split("\n") if p]

    def add_recent(self, path: str) -> None:
        items = [path] + [p for p in self.recent_files() if p != path]
        self.set("files", "\n".join(items[:12]), "recent")


def load_config() -> Config:
    return Config()
