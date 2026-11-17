"""Feature catalogue: maps UI check boxes to analysis handlers."""
from __future__ import annotations

import importlib
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from fnet import findings as findings_mod
from fnet.config import Config
from fnet.logger import Logger
from fnet.tools.runner import TShark


class CancelledError(RuntimeError):
    """Raised inside a handler when the user cancels the job."""


@dataclass
class FeatureContext:
    """Everything a handler needs, injected by the job runner."""

    config: Config
    logger: Logger
    tshark: TShark | None
    pcap: str
    params: dict = field(default_factory=dict)
    progress: Callable[[int], None] | None = None
    cancel: threading.Event | None = None
    output_dir: Path | None = None
    findings: list = field(default_factory=list)
    _findings_capped: bool = field(default=False, repr=False)

    def report(self, text: str, level: str = "info") -> None:
        self.logger.log(text, level)

    def add_finding(self, kind: str, summary: str, *, frame="",
                    detail: str = "", level: str = "info",
                    extra: dict | None = None) -> dict | None:
        """Record one structured result for the WebUI table and reports.

        Handlers should still log the human readable line; findings are the
        machine friendly projection of the same discovery.
        """
        if len(self.findings) >= findings_mod.MAX_FINDINGS:
            if not self._findings_capped:
                self._findings_capped = True
                self.report(
                    f"结构化结果达到上限 {findings_mod.MAX_FINDINGS} 条，后续发现不再记录",
                    "warn")
            return None
        item = findings_mod.make(kind, summary, frame=frame, detail=detail,
                                 level=level, extra=extra)
        self.findings.append(item)
        return item

    def set_progress(self, value: int) -> None:
        if self.progress:
            self.progress(max(0, min(100, int(value))))

    def check_cancel(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise CancelledError("分析已被用户取消")

    def cancelled(self) -> bool:
        return bool(self.cancel is not None and self.cancel.is_set())

    def write_output(self, name: str, data: bytes | str) -> Path:
        base = Path(self.output_dir or ".")
        base.mkdir(parents=True, exist_ok=True)
        path = base / name
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        self.report(f"结果已保存: {path}", "info")
        return path


@dataclass(frozen=True)
class Feature:
    checkbox: str
    title: str
    handler: str
    category: str
    description: str = ""
    default: bool = False
    needs: tuple[str, ...] = ()


#: Order in which categories are displayed in the WebUI sidebar.
CATEGORIES: list[dict[str, str]] = [
    {"key": "text", "name": "文本与关键字"},
    {"key": "http", "name": "HTTP / Web"},
    {"key": "webshell", "name": "Webshell / Shiro"},
    {"key": "sql", "name": "SQL 注入"},
    {"key": "c2", "name": "C2 / 远控"},
    {"key": "auth", "name": "认证与凭据"},
    {"key": "flow", "name": "协议流量"},
    {"key": "ics", "name": "工控协议"},
    {"key": "usb", "name": "USB / 外设"},
    {"key": "wireless", "name": "无线与蓝牙"},
    {"key": "tls", "name": "TLS / 加密"},
    {"key": "misc", "name": "杂项"},
    {"key": "rdp", "name": "RDP 重放"},
]

FEATURES: list[Feature] = [
    Feature("checkBox_10", "关键字检测", "text_scan.keyword_scan", "text",
            "在流量中查找 flag/关键字（支持自定义正则、十六进制、编码关键词）", True),
    Feature("checkBox_30", "HTTP数据提取", "http.extract", "http",
            "提取 HTTP 请求/响应、URI、Host、状态码、Cookie 与认证头", True),
    Feature("checkBox_32", "HTTP下载文件分析", "http.export_files", "http",
            "导出 HTTP 传输的文件，识别文件类型并计算 MD5"),
    Feature("checkBox_42", "shiro流量解密", "webshell.shiro", "webshell",
            "Shiro rememberMe 反序列化流量解密（自动识别密钥 / 手动密钥）"),
    Feature("checkBox_26", "SQL盲注流量分析", "sql.blind", "sql",
            "根据界面上的正则与成功条件还原布尔/时间盲注结果"),
    Feature("checkBox_46", "SQL二分盲注增强", "sql.binary", "sql",
            "二分法盲注的增强还原（按字符区间推断）"),
    Feature("checkBox_34", "SQL盲注日志分析", "sql.log_analysis", "sql",
            "从已保存的盲注日志推断注入内容"),
    Feature("checkBox_15", "Cobalt Strike流量分析", "cs.analyze", "c2",
            "CS beacon 元数据/任务解密（需要 .cobaltstrike.beacon_keys）",
            False, ("cryptography",)),
    Feature("checkBox_43", "WINRM流量解密", "winrm.decrypt", "c2",
            "WinRM 凭据认证流量还原（NTLM hash 或 password）"),
    Feature("checkBox_39", "NTLM HASH提取", "ntlm.extract", "auth",
            "从 NTLMSSP 认证中提取 NetNTLM 哈希（hashcat 格式）"),
    Feature("checkBox_45", "Kerberos解析破解", "kerberos.parse", "auth",
            "提取 AS-REQ/AS-REP/TGS-REP 并生成 hashcat 哈希"),
    Feature("checkBox_20", "ICMP流量分析", "flows.icmp", "flow",
            "ICMP 载荷中的隐藏数据"),
    Feature("checkBox_19", "Telnet流量分析", "flows.telnet", "flow",
            "Telnet 会话内容还原"),
    Feature("checkBox_27", "FTP流量分析", "flows.ftp", "flow",
            "FTP 账号密码、命令与传输文件"),
    Feature("checkBox_37", "MYSQL数据分析", "flows.mysql", "flow",
            "MySQL 查询、登录信息与结果"),
    Feature("checkBox_28", "SMTP流量分析", "flows.smtp", "flow",
            "SMTP 邮件内容提取"),
    Feature("checkBox_23", "DNS流量分析", "flows.dns", "flow",
            "DNS 查询与隐蔽隧道检测"),
    Feature("checkBox_41", "4G/5G通信协议分析", "flows.gtp", "flow",
            "GTP 隧道与错误 TEID 检测"),
    Feature("checkBox_35", "UDP流分析（混乱数据多）", "flows.udp", "flow",
            "UDP 会话与载荷提取"),
    Feature("checkBox_33", "TCP流分析（混乱数据多）", "flows.tcp", "flow",
            "TCP 流重组与内容提取"),
    Feature("checkBox_44", "ARP协议分析", "arp.analyze", "flow",
            "ARP 流量、IP/MAC 冲突与异常字段分析"),
    Feature("checkBox_29", "工控协议mms分析", "ics.summary", "ics",
            "MMS 协议会话概览"),
    Feature("checkBox_11", "工控协议modbus分析", "ics.modbus", "ics",
            "Modbus 功能码、地址与异常帧检测"),
    Feature("checkBox_12", "工控协议iec60870分析", "ics.iecd", "ics",
            "IEC 60870-5-104 类型标识、传送原因与会话概览"),
    Feature("checkBox_13", "工控协议mqtt分析", "ics.mqtt", "ics",
            "MQTT 主题与消息提取"),
    Feature("checkBox_22", "工控协议omron分析", "ics.omron", "ics",
            "OMRON FINS 会话概览"),
    Feature("checkBox_14", "工控协议s7comm分析", "ics.s7comm", "ics",
            "S7comm 读写请求分析"),
    Feature("checkBox_38", "工控协议goose分析", "ics.goose", "ics",
            "GOOSE 报文概览"),
    Feature("checkBox_16", "USB-键盘流量分析", "usb.keyboard", "usb",
            "USB HID 键盘按键还原"),
    Feature("checkBox_17", "USB-鼠标流量分析", "usb.mouse", "usb",
            "USB HID 鼠标轨迹还原"),
    Feature("checkBox_40", "EV3数据提取", "misc.ev3", "usb",
            "LEGO EV3 蓝牙数据还原"),
    Feature("checkBox_21", "蓝牙流量分析", "flows.bluetooth", "wireless",
            "Bluetooth/BTHCI 协议概览"),
    Feature("checkBox_18", "无线流量暴力破解", "wifi.crack", "wireless",
            "WPA/WPA2 握手包字典破解（需要 aircrack-ng）", False, ("aircrack",)),
    Feature("checkBox_24", "TLS流量解密", "tls.decrypt", "tls",
            "解密 TLS/QUIC 流量，提取证书链、KeyUpdate、HTTP/2、"
            "WebSocket、HTTP/3 与明文凭据"),
    Feature("checkBox_47", "RDP流量重放", "rdp.handler", "rdp",
            "用私钥/Key log 解密 RDP 会话并生成重放文件", False,
            ("pyrdp_player",)),
    Feature("checkBox_36", "SCSI传输数据提取", "misc.scsi", "misc",
            "SCSI 读写数据提取"),
    Feature("checkBox_31", "IPID数据分析（通常关闭）", "misc.ipid", "misc",
            "IP ID 字段的隐蔽信道分析"),
]

BY_CHECKBOX = {feature.checkbox: feature for feature in FEATURES}
BY_HANDLER = {feature.handler: feature for feature in FEATURES}


def feature_dict(feature: Feature) -> dict:
    return {
        "checkbox": feature.checkbox,
        "title": feature.title,
        "handler": feature.handler,
        "category": feature.category,
        "description": feature.description,
        "default": feature.default,
        "needs": list(feature.needs),
    }


def resolve(handler: str):
    """Resolve ``"module.function"`` to a callable."""
    module_name, _, func_name = handler.partition(".")
    try:
        module = importlib.import_module(f"fnet.features.{module_name}")
    except ImportError as exc:
        raise AttributeError(f"handler 模块不存在: {handler}") from exc
    func = getattr(module, func_name, None)
    if not callable(func):
        raise AttributeError(f"handler 不存在: {handler}")
    return func


def call_feature(ctx: FeatureContext, handler: str) -> None:
    """Run one handler, logging (not hiding) exceptions."""
    func = resolve(handler)
    func(ctx)
