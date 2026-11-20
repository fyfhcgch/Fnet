"""User-extensible helper tool registry behind the "工具" menu.

Internal tools are described declaratively so the WebUI can list them and
the backend can run them.  User added tools are persisted in
``config.ini`` under ``[plugins] execute_cmd`` as JSON.
"""
from __future__ import annotations

import json
import os
import shlex
import threading
from dataclasses import dataclass, field
from urllib.parse import quote

from fnet.config import Config
from fnet.logger import logger
from fnet.tools.runner import run
from fnet.utils.system import open_url

#: Built-in "tools" launched from the tools menu.
BUILTIN_TOOLS: list[dict[str, str]] = [
    {"key": "cyberchef", "name": "CyberChef", "kind": "url",
     "target": "https://gchq.github.io/CyberChef/",
     "description": "浏览器中打开的 CyberChef（可离线替换为本地地址）"},
    {"key": "wireshark", "name": "Wireshark", "kind": "tool",
     "target": "wireshark", "description": "用 Wireshark 打开当前流量包"},
    {"key": "foremost", "name": "Foremost", "kind": "tool",
     "target": "foremost", "description": "文件分离 / 数据雕刻"},
    {"key": "pcapfix", "name": "PcapFix", "kind": "tool",
     "target": "pcapfix", "description": "修复损坏的 pcap/pcapng"},
    {"key": "etl2pcapng", "name": "ETL2PCAPNG", "kind": "tool",
     "target": "etl2pcapng", "description": "Windows ETL 转 pcapng"},
    {"key": "hashcat", "name": "Hashcat", "kind": "tool",
     "target": "hashcat", "description": "离线哈希破解"},
    {"key": "john", "name": "John the Ripper", "kind": "tool",
     "target": "john", "description": "离线哈希破解"},
]


@dataclass
class Plugin:
    key: str
    name: str
    command: list[str] = field(default_factory=list)
    description: str = ""

    def as_dict(self) -> dict:
        return {"key": self.key, "name": self.name,
                "command": self.command, "description": self.description}


class PluginManager:
    def __init__(self, config: Config) -> None:
        self.config = config

    # -- user tools ----------------------------------------------------
    def user_tools(self) -> dict[str, list[str]]:
        raw = self.config.get("execute_cmd", "plugins", "{}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        result: dict[str, list[str]] = {}
        if isinstance(data, dict):
            for name, spec in data.items():
                if isinstance(spec, str):
                    result[name] = shlex.split(spec, posix=os.name != "nt")
                elif isinstance(spec, list):
                    result[name] = [str(x) for x in spec]
        return result

    def add(self, name: str, command: str) -> None:
        tools = self.user_tools()
        tools[name] = shlex.split(command, posix=os.name != "nt")
        self.config.set("execute_cmd", json.dumps(tools, ensure_ascii=False),
                        "plugins")
        self.config.save()
        logger.good(f"已添加工具 {name}: {command}")

    def remove(self, name: str) -> bool:
        tools = self.user_tools()
        if name not in tools:
            return False
        del tools[name]
        self.config.set("execute_cmd", json.dumps(tools, ensure_ascii=False),
                        "plugins")
        self.config.save()
        logger.info(f"已移除工具 {name}")
        return True

    def as_list(self) -> list[dict]:
        items = [dict(tool, source="builtin") for tool in BUILTIN_TOOLS]
        for name, command in self.user_tools().items():
            items.append({"key": name, "name": name, "kind": "command",
                          "target": " ".join(command), "source": "user",
                          "description": "用户添加的工具"})
        return items

    # -- execution -----------------------------------------------------
    def run(self, key: str, target: str = "",
            cancel: threading.Event | None = None) -> str:
        if key in ("cyberchef", "cyberchef-local"):
            open_url("https://gchq.github.io/CyberChef/")
            return "已在浏览器中打开 CyberChef"
        tools = self.user_tools()
        command = tools.get(key)
        if command is None:
            return f"未注册的工具: {key}"
        argv = list(command)
        if target:
            argv.append(target)
        code, out = run(argv, cancel=cancel)
        return out if code == 0 else f"[退出码 {code}]\n{out}"


def plugin_url(url: str) -> str:
    """Percent-encode an URL for safe inclusion in JSON/HTML."""
    return quote(url, safe=":/?&=#%+")
