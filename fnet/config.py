"""Configuration handling (``fnet/assets/config.ini`` + user overrides)."""
from __future__ import annotations

import configparser
import os
import shutil
import tempfile
import threading
from pathlib import Path

from fnet.logger import logger
from fnet.paths import DEFAULT_CONFIG, USER_CONFIG, ensure_dirs

#: 序列化 ``Config.save()``：``crack.start`` 等请求线程与 WebUI 主线程会同时
#: 写同一个文件，缺少锁时后写者可能覆盖前写者。
_SAVE_LOCK = threading.Lock()

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
        "hashcat_workload": "3",
        "hashcat_optimized": "1",
        "hashcat_force": "0",
        "hashcat_timeout": "300",
        "hashcat_extra": "",
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
        # tshark 结果缓存上限：512 MB / 14 天，0 表示不限制该项。
        "tshark_cache_max_mb": "512",
        "tshark_cache_ttl_days": "14",
        "tshark_retry": "1",
        "tshark_timeout": "600",
        "tshark_max_field_kb": "256",
        "tshark_max_rows": "2000000",
        "shards": "1",
        "language": "zh",
    },
    "plugins": {"execute_cmd": "{}"},
    # 在线 IOC 情报（默认完全离线；填写 api key 才会发请求）
    "intel": {
        "provider": "",
        "vt_api_key": "",
        "otx_api_key": "",
        "vt_min_malicious": "3",
        "otx_min_pulses": "1",
        "timeout": "10",
        "vt_interval": "15",
    },
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
        self.path = Path(path) if path else USER_CONFIG
        self._cp = configparser.ConfigParser(interpolation=None)
        #: 最近一次 ``load()`` 的中文错误信息（空字符串表示成功）。
        self.load_error = ""
        #: 最近一次 ``save()`` 的中文错误信息（空字符串表示成功）。
        self.save_error = ""
        for section, values in DEFAULTS.items():
            self._cp[section] = dict(values)
        self.load()

    # -- persistence ---------------------------------------------------
    def load(self) -> str:
        """读取配置文件，返回中文错误信息（成功时返回空字符串）。

        调用方（CLI）负责把错误信息打印出来并退出码 2；WebUI 的
        ``reload_config`` 只记录日志，不让异常冒泡成 500。
        """
        self.load_error = ""
        ensure_dirs()
        try:
            if not self.path.exists() and DEFAULT_CONFIG.exists():
                shutil.copy(DEFAULT_CONFIG, self.path)
            if self.path.exists():
                self._cp.read(self.path, encoding="utf-8")
        except OSError as exc:
            self.load_error = (
                f"无法读取配置文件 {self.path}：{exc}"
                "（请检查路径是否存在、是否有读写权限）")
            logger.warn(self.load_error)
        except configparser.Error as exc:
            self.load_error = f"配置文件格式错误 {self.path}：{exc}"
            logger.warn(self.load_error)
        return self.load_error

    def save(self) -> bool:
        """原子写回配置文件（同目录临时文件 + ``os.replace``），失败返回 False。"""
        self.save_error = ""
        ensure_dirs()
        with _SAVE_LOCK:
            name = ""
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                handle, name = tempfile.mkstemp(prefix=self.path.name,
                                               dir=self.path.parent)
                with os.fdopen(handle, "w", encoding="utf-8") as fh:
                    self._cp.write(fh)
                os.replace(name, self.path)
            except OSError as exc:
                try:
                    if name:
                        os.unlink(name)
                except OSError:
                    pass
                self.save_error = f"无法保存配置文件 {self.path}：{exc}"
                logger.warn(self.save_error)
                return False
        return True

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
