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
    #: Set when the handler runs on a frame-range shard: original frame
    #: numbers are ``frame + frame_offset`` and output names are prefixed.
    frame_offset: int = 0
    shard: str = ""
    _findings_capped: bool = field(default=False, repr=False)

    def report(self, text: str, level: str = "info") -> None:
        self.logger.log(text, level)

    def original_frame(self, frame):
        """Translate a shard-local frame number back to the whole capture."""
        if not self.frame_offset:
            return frame
        text = str(frame if frame is not None else "").strip()
        if text.isdigit():
            return str(int(text) + int(self.frame_offset))
        return frame

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
        item = findings_mod.make(kind, summary,
                                 frame=self.original_frame(frame),
                                 detail=detail, level=level, extra=extra)
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
        if self.shard:
            safe = "".join(ch if ch.isalnum() or ch in "-_." else "_"
                           for ch in name)[:120]
            name = f"shard_{self.shard}_{safe}"
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
    #: English metadata powers the language switcher while logs and reports
    #: stay in Chinese (see ``docs/WEBUI.md``).
    title_en: str = ""
    description_en: str = ""
    #: Stateless handlers can run on frame-range shards; stateful ones
    #: (stream reassembly, decryption, handshakes) always see the whole file.
    shardable: bool = False


#: Order in which categories are displayed in the WebUI sidebar.
CATEGORIES: list[dict[str, str]] = [
    {"key": "text", "name": "文本与关键字", "name_en": "Text & keywords"},
    {"key": "http", "name": "HTTP / Web", "name_en": "HTTP / Web"},
    {"key": "webshell", "name": "Webshell / Shiro",
     "name_en": "Webshell / Shiro"},
    {"key": "sql", "name": "SQL 注入", "name_en": "SQL injection"},
    {"key": "c2", "name": "C2 / 远控", "name_en": "C2 / remote access"},
    {"key": "auth", "name": "认证与凭据", "name_en": "Auth & credentials"},
    {"key": "flow", "name": "协议流量", "name_en": "Protocol flows"},
    {"key": "ics", "name": "工控协议", "name_en": "Industrial protocols"},
    {"key": "usb", "name": "USB / 外设", "name_en": "USB / peripherals"},
    {"key": "wireless", "name": "无线与蓝牙", "name_en": "Wireless & Bluetooth"},
    {"key": "tls", "name": "TLS / 加密", "name_en": "TLS / encryption"},
    {"key": "misc", "name": "杂项", "name_en": "Miscellaneous"},
    {"key": "rdp", "name": "RDP 重放", "name_en": "RDP replay"},
]

FEATURES: list[Feature] = [
    Feature("checkBox_10", "关键字检测", "text_scan.keyword_scan", "text",
            "在流量中查找 flag/关键字（支持自定义正则、十六进制、编码关键词）", True,
            title_en="Keyword scan",
            description_en="Find flags and keywords (custom regex, hex and "
                           "encoded variants) in the capture",
            shardable=True),
    Feature("checkBox_30", "HTTP数据提取", "http.extract", "http",
            "提取 HTTP 请求/响应、URI、Host、状态码、Cookie 与认证头", True,
            title_en="HTTP extraction",
            description_en="Extract HTTP requests/responses, URIs, hosts, "
                           "status codes, cookies and auth headers",
            shardable=True),
    Feature("checkBox_32", "HTTP下载文件分析", "http.export_files", "http",
            "导出 HTTP 传输的文件，识别文件类型并计算 MD5",
            title_en="HTTP file analysis",
            description_en="Carve files transferred over HTTP, identify their "
                           "type and compute MD5 hashes",
            shardable=True),
    Feature("checkBox_42", "shiro流量解密", "webshell.shiro", "webshell",
            "Shiro rememberMe 反序列化流量解密（自动识别密钥 / 手动密钥）",
            title_en="Shiro decryption",
            description_en="Decrypt Shiro rememberMe deserialization traffic "
                           "with automatic or manual keys"),
    Feature("checkBox_26", "SQL盲注流量分析", "sql.blind", "sql",
            "根据界面上的正则与成功条件还原布尔/时间盲注结果",
            title_en="Blind SQL injection",
            description_en="Reconstruct boolean/time based blind SQL injection "
                           "results from configurable patterns",
            shardable=True),
    Feature("checkBox_46", "SQL二分盲注增强", "sql.binary", "sql",
            "二分法盲注的增强还原（按字符区间推断）",
            title_en="Binary-search blind SQLi",
            description_en="Enhanced reconstruction of binary-search blind SQL "
                           "injection (character range inference)",
            shardable=True),
    Feature("checkBox_34", "SQL盲注日志分析", "sql.log_analysis", "sql",
            "从已保存的盲注日志推断注入内容",
            title_en="Blind SQLi log analysis",
            description_en="Infer injected data from a previously saved blind "
                           "SQL injection log",
            shardable=True),
    Feature("checkBox_15", "Cobalt Strike流量分析", "cs.analyze", "c2",
            "CS beacon 元数据/任务解密（需要 .cobaltstrike.beacon_keys）",
            False, ("cryptography",),
            title_en="Cobalt Strike analysis",
            description_en="Decrypt CS beacon metadata and tasks (requires "
                           ".cobaltstrike.beacon_keys)"),
    Feature("checkBox_43", "WINRM流量解密", "winrm.decrypt", "c2",
            "WinRM 凭据认证流量还原（NTLM hash 或 password）",
            title_en="WinRM decryption",
            description_en="Recover WinRM authentication traffic using an "
                           "NTLM hash or password"),
    Feature("checkBox_39", "NTLM HASH提取", "ntlm.extract", "auth",
            "从 NTLMSSP 认证中提取 NetNTLM 哈希（hashcat 格式）",
            title_en="NTLM hash extraction",
            description_en="Extract NetNTLM hashes from NTLMSSP authentication "
                           "in hashcat format",
            shardable=True),
    Feature("checkBox_45", "Kerberos解析破解", "kerberos.parse", "auth",
            "提取 AS-REQ/AS-REP/TGS-REP 并生成 hashcat 哈希；支持 keytab/密码"
            "解密、AES 19600/19700、PAC 与用户时间线",
            title_en="Kerberos parsing & cracking",
            description_en="Extract AS/TGS messages, emit hashcat hashes, "
                           "decrypt with keytab/password, parse PAC and build "
                           "a user timeline",
            shardable=True),
    Feature("checkBox_20", "ICMP流量分析", "flows.icmp", "flow",
            "ICMP 载荷中的隐藏数据与分块隧道路由",
            title_en="ICMP analysis",
            description_en="Hidden data in ICMP payloads and chunked tunnel "
                           "reassembly",
            shardable=True),
    Feature("checkBox_19", "Telnet流量分析", "flows.telnet", "flow",
            "Telnet 会话内容还原",
            title_en="Telnet analysis",
            description_en="Reconstruct Telnet session contents",
            shardable=True),
    Feature("checkBox_27", "FTP流量分析", "flows.ftp", "flow",
            "FTP 账号密码、命令与传输文件",
            title_en="FTP analysis",
            description_en="FTP credentials, commands and transferred files",
            shardable=True),
    Feature("checkBox_37", "MYSQL数据分析", "flows.mysql", "flow",
            "MySQL 握手认证、查询与结果集、LOAD DATA/LOAD_FILE 文件内容",
            title_en="MySQL analysis",
            description_en="MySQL handshake authentication, queries, result "
                           "sets and LOAD DATA/LOAD_FILE contents",
            shardable=True),
    Feature("checkBox_28", "SMTP流量分析", "flows.smtp", "flow",
            "SMTP MIME 与附件还原、投递链；同时解析 IMAP / POP3 命令与附件",
            title_en="Mail protocol analysis",
            description_en="SMTP MIME/attachment and delivery chain recovery "
                           "plus IMAP/POP3 commands and attachments",
            shardable=True),
    Feature("checkBox_23", "DNS流量分析", "flows.dns", "flow",
            "DNS 查询与隐蔽隧道检测：分块按序重组（base32/base64/hex）、"
            "隧道时间线与解码数据落盘",
            title_en="DNS analysis",
            description_en="DNS queries and covert tunnel detection with "
                           "ordered base32/base64/hex chunk reassembly, "
                           "timeline and decoded output",
            shardable=True),
    Feature("checkBox_41", "4G/5G通信协议分析", "flows.gtp", "flow",
            "GTP 隧道与错误 TEID 检测",
            title_en="4G/5G (GTP) analysis",
            description_en="GTP tunnels and wrong-TEID detection",
            shardable=True),
    Feature("checkBox_35", "UDP流分析（混乱数据多）", "flows.udp", "flow",
            "UDP 会话与载荷提取",
            title_en="UDP flow analysis",
            description_en="UDP conversations and payload extraction"),
    Feature("checkBox_33", "TCP流分析（混乱数据多）", "flows.tcp", "flow",
            "TCP 流重组与内容提取",
            title_en="TCP flow analysis",
            description_en="TCP stream reassembly and content extraction"),
    Feature("checkBox_44", "ARP协议分析", "arp.analyze", "flow",
            "ARP 流量、IP/MAC 冲突与异常字段分析",
            title_en="ARP analysis",
            description_en="ARP traffic, IP/MAC conflicts and anomalous fields",
            shardable=True),
    Feature("checkBox_29", "工控协议mms分析", "ics.summary", "ics",
            "MMS 协议会话概览",
            title_en="MMS analysis",
            description_en="MMS session overview",
            shardable=True),
    Feature("checkBox_11", "工控协议modbus分析", "ics.modbus", "ics",
            "Modbus 功能码、地址与异常帧检测",
            title_en="Modbus analysis",
            description_en="Modbus function codes, addresses and exception "
                           "frames",
            shardable=True),
    Feature("checkBox_12", "工控协议iec60870分析", "ics.iecd", "ics",
            "IEC 60870-5-104 类型标识、传送原因与会话概览",
            title_en="IEC 60870-5-104 analysis",
            description_en="IEC 60870-5-104 type IDs, cause of transmission "
                           "and session overview",
            shardable=True),
    Feature("checkBox_13", "工控协议mqtt分析", "ics.mqtt", "ics",
            "MQTT 主题与消息提取",
            title_en="MQTT analysis",
            description_en="MQTT topics and message extraction",
            shardable=True),
    Feature("checkBox_22", "工控协议omron分析", "ics.omron", "ics",
            "OMRON FINS 会话概览",
            title_en="OMRON FINS analysis",
            description_en="OMRON FINS session overview",
            shardable=True),
    Feature("checkBox_14", "工控协议s7comm分析", "ics.s7comm", "ics",
            "S7comm 读写请求分析",
            title_en="S7comm analysis",
            description_en="S7comm read/write request analysis",
            shardable=True),
    Feature("checkBox_38", "工控协议goose分析", "ics.goose", "ics",
            "GOOSE 报文概览",
            title_en="GOOSE analysis",
            description_en="GOOSE message overview",
            shardable=True),
    Feature("checkBox_16", "USB-键盘流量分析", "usb.keyboard", "usb",
            "USB HID 键盘按键还原",
            title_en="USB keyboard analysis",
            description_en="Reconstruct USB HID keyboard keystrokes",
            shardable=True),
    Feature("checkBox_17", "USB-鼠标流量分析", "usb.mouse", "usb",
            "USB HID 鼠标轨迹还原",
            title_en="USB mouse analysis",
            description_en="Reconstruct USB HID mouse movement",
            shardable=True),
    Feature("checkBox_40", "EV3数据提取", "misc.ev3", "usb",
            "LEGO EV3 蓝牙数据还原",
            title_en="EV3 data extraction",
            description_en="Reconstruct LEGO EV3 Bluetooth data",
            shardable=True),
    Feature("checkBox_21", "蓝牙流量分析", "flows.bluetooth", "wireless",
            "Bluetooth/BTHCI 协议概览",
            title_en="Bluetooth analysis",
            description_en="Bluetooth/BTHCI protocol overview",
            shardable=True),
    Feature("checkBox_18", "无线流量暴力破解", "wifi.crack", "wireless",
            "WPA/WPA2 握手包字典破解（需要 aircrack-ng）；提供 PSK 时可解密"
            "数据帧并把明文交回 HTTP/DNS/凭据分析",
            False, ("aircrack",),
            title_en="Wi-Fi handshake cracking",
            description_en="WPA/WPA2 handshake dictionary cracking (aircrack-ng) "
                           "and, with a PSK, CCMP data-frame decryption feeding "
                           "the HTTP/DNS/credential features"),
    Feature("checkBox_24", "TLS流量解密", "tls.decrypt", "tls",
            "解密 TLS/QUIC 流量，提取证书链、KeyUpdate、HTTP/2、"
            "WebSocket、HTTP/3 与明文凭据",
            title_en="TLS decryption",
            description_en="Decrypt TLS/QUIC traffic and extract certificate "
                           "chains, KeyUpdate, HTTP/2, WebSocket, HTTP/3 and "
                           "plaintext credentials"),
    Feature("checkBox_47", "RDP流量重放", "rdp.handler", "rdp",
            "用私钥/Key log 解密 RDP 会话并生成重放文件", False,
            ("pyrdp_player",),
            title_en="RDP replay",
            description_en="Decrypt RDP sessions with a private key/keylog and "
                           "generate replay files"),
    Feature("checkBox_36", "SCSI传输数据提取", "misc.scsi", "misc",
            "SCSI 读写数据提取",
            title_en="SCSI data extraction",
            description_en="SCSI read/write data extraction",
            shardable=True),
    Feature("checkBox_31", "IPID数据分析（通常关闭）", "misc.ipid", "misc",
            "IP ID 字段的隐蔽信道分析",
            title_en="IP ID analysis (usually off)",
            description_en="Covert channel analysis of the IP ID field"),
]

BY_CHECKBOX = {feature.checkbox: feature for feature in FEATURES}
BY_HANDLER = {feature.handler: feature for feature in FEATURES}


def feature_dict(feature: Feature) -> dict:
    return {
        "checkbox": feature.checkbox,
        "title": feature.title,
        "title_en": feature.title_en or feature.title,
        "handler": feature.handler,
        "category": feature.category,
        "description": feature.description,
        "description_en": feature.description_en or feature.description,
        "default": feature.default,
        "needs": list(feature.needs),
        "shardable": feature.shardable,
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
