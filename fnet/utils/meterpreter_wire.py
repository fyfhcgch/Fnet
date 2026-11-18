"""Meterpreter XOR/staging 线缆协议解析核心（纯标准库，离线）。

本模块是 Fnet 中 Meterpreter 报文解析的**新的可靠核心**，取代
``fnet/utils/c2ext.py`` 里过时的 ``iter_packets`` 实现。参考 Metasploit
``lib/rex/post/meterpreter/packet.rb``（``Rex::Post::Meterpreter::Packet``）：

现代报文（Meterpreter >= 4.11）线缆布局::

    XOR_KEY(4) || obfuscated[ GUID(16) | flags(4) | length(4) | type(4) | body ]

旧版（pre-4.11 / metsvc）报文布局::

    XOR_KEY(4) || obfuscated[ length(4) | type(4) | body ]

* ``XOR_KEY`` 以 4 字节为周期异或后面的**全部**字节（头 + 体）；
* ``length`` 是 TLV 自包含长度：``length = 8 + len(body)``（即包含
  ``length`` 与 ``type`` 两个 DWORD），所以报文总长 ``total = 24 + length``
  （现代）或 ``total = 4 + length``（旧版）；
* ``flags``：0 = 明文，1 = AES-256-CBC，2 = AES-128-CBC；加密时 ``body``
  为 ``IV(16) || ciphertext``，密文是**嵌套 TLV 流**用 PKCS#7 填充后加密；
* 嵌套 TLV 线格式：``length(4, 自包含) | type(4) | value``，大端。

模块不抛异常：所有解析函数对畸形输入都返回 ``None`` / 空列表 / 状态字段。
AES 只走 :func:`fnet.utils.crypto.aes_cbc_decrypt`，无第三方依赖。
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from fnet.utils.codec import find_flags, xor as _xor
from fnet.utils.crypto import aes_cbc_decrypt

# ---------------------------------------------------------------------------
# 常量：与 Metasploit packet.rb / fnet/utils/meterpreter.py 保持一致
# ---------------------------------------------------------------------------
XOR_KEY_SIZE = 4
GUID_SIZE = 16
MODERN_HEADER_SIZE = XOR_KEY_SIZE + GUID_SIZE + 4 + 4 + 4  # 32
LEGACY_HEADER_SIZE = XOR_KEY_SIZE + 4 + 4                 # 12

ENC_FLAG_NONE = 0x0
ENC_FLAG_AES256 = 0x1
ENC_FLAG_AES128 = 0x2

ENCRYPTION_NAMES = {
    ENC_FLAG_NONE: "none",
    ENC_FLAG_AES256: "AES-256-CBC",
    ENC_FLAG_AES128: "AES-128-CBC",
}

PACKET_TYPES = {
    0: "request",
    1: "response",
    2: "config",
    10: "plain_request",
    11: "plain_response",
}

MAX_PACKET_LENGTH = 16 * 1024 * 1024
MAX_TLV_LENGTH = 16 * 1024 * 1024

# TLV meta 位（高位半字）
TLV_META_NONE = 0
TLV_META_STRING = 1 << 16
TLV_META_UINT = 1 << 17
TLV_META_RAW = 1 << 18
TLV_META_BOOL = 1 << 19
TLV_META_QWORD = 1 << 20
TLV_META_COMPRESSED = 1 << 29
TLV_META_GROUP = 1 << 30
TLV_META_COMPLEX = 1 << 31

KNOWN_META_MASK = (TLV_META_STRING | TLV_META_UINT | TLV_META_RAW |
                   TLV_META_BOOL | TLV_META_QWORD | TLV_META_COMPRESSED |
                   TLV_META_GROUP | TLV_META_COMPLEX)

# 名称表优先采用 Metasploit 权威取值，同时兼容 fnet/utils/meterpreter.py
# 里使用的别名（RAW/UINT/BOOL 的旧编号），以便报告里的词汇统一。
TLV_NAMES = {
    (TLV_META_UINT, 1): "COMMAND_ID",
    (TLV_META_STRING, 2): "REQUEST_ID",
    (TLV_META_GROUP, 3): "EXCEPTION",
    (TLV_META_COMPLEX, 3): "EXCEPTION",  # meterpreter.py 旧别名
    (TLV_META_UINT, 4): "RESULT",
    (TLV_META_STRING, 10): "STRING",
    (TLV_META_UINT, 11): "UINT",
    (TLV_META_RAW, 11): "RAW",           # meterpreter.py 旧别名
    (TLV_META_BOOL, 12): "BOOL",
    (TLV_META_UINT, 12): "UINT",         # meterpreter.py 旧别名
    (TLV_META_BOOL, 13): "BOOL",         # meterpreter.py 旧别名
    (TLV_META_UINT, 14): "LENGTH",       # meterpreter.py 旧别名
    (TLV_META_RAW, 15): "MEMORY",        # meterpreter.py 旧别名
    (TLV_META_UINT, 25): "LENGTH",
    (TLV_META_RAW, 26): "DATA",
    (TLV_META_UINT, 50): "CHANNEL_ID",
    (TLV_META_STRING, 51): "CHANNEL_TYPE",
    (TLV_META_RAW, 52): "CHANNEL_DATA",
    (TLV_META_GROUP, 53): "CHANNEL_DATA_GROUP",
    (TLV_META_STRING, 460): "MACHINE_ID",
    (TLV_META_RAW, 461): "UUID",
    (TLV_META_RAW, 462): "SESSION_GUID",
    (TLV_META_RAW, 552): "SYM_KEY",
    (TLV_META_RAW, 553): "ENC_SYM_KEY",
}

# ---------------------------------------------------------------------------
# 数据容器
# ---------------------------------------------------------------------------
@dataclass
class MPacket:
    """一个 Meterpreter 线缆报文（头字段 + TLV 摘要 + 解密状态）。"""

    version: str                       # "modern" / "legacy"
    offset: int                        # 在输入缓冲中的起始位置
    total: int                         # 线上总字节数（含 4 字节 XOR key）
    xor_key: bytes
    session_guid: bytes
    encrypt_flags: int
    length: int                        # 头里的 TLV 自包含长度
    packet_type: int
    kind: str = ""                     # request/response/config/...（post_init 填充）
    encrypted: bool = False
    plaintext: bytes = b""             # 嵌套 TLV 流（解密成功时为明文）
    ciphertext: bytes = b""            # 加密报文的 IV + 密文（或 XOR 后的原始体）
    tlvs: list[dict] = field(default_factory=list)
    command_id: int | None = None
    decrypt_ok: bool = True            # 明文包视为“无需解密”，记 True
    decrypt_reason: str = ""
    header_hex: str = ""

    def __post_init__(self) -> None:
        if not self.kind:
            self.kind = PACKET_TYPES.get(self.packet_type, "unknown")
        if not self.header_hex and self.xor_key:
            self.header_hex = self.xor_key.hex()

    # -- 便捷属性 ---------------------------------------------------------
    @property
    def guid_hex(self) -> str:
        """会话 GUID（旧版报文没有 GUID，返回 ``-``）。"""
        return self.session_guid.hex() if self.session_guid else "-"

    @property
    def command_hex(self) -> str:
        return "-" if self.command_id is None else f"0x{self.command_id:08x}"

    @property
    def encryption_name(self) -> str:
        return ENCRYPTION_NAMES.get(self.encrypt_flags,
                                    f"flags-{self.encrypt_flags}")

    @property
    def tlv_summary(self) -> str:
        names = [str(tlv.get("name", "-")) for tlv in self.tlvs]
        return ",".join(names) if names else "-"


# ---------------------------------------------------------------------------
# TLV 解析
# ---------------------------------------------------------------------------
def _tlv_name(tlv_type: int) -> str:
    meta = tlv_type & KNOWN_META_MASK
    tid = tlv_type & 0xFFFF
    return TLV_NAMES.get((meta, tid), f"0x{tlv_type & 0xFFFFFFFF:08x}")


def _decode_tlv_value(tlv_type: int, value: bytes) -> str:
    """把 TLV 值转成可读文本（与 meterpreter.py 的词汇一致）。"""
    if not value:
        return ""
    meta = tlv_type & KNOWN_META_MASK
    if meta & (TLV_META_STRING | TLV_META_COMPLEX):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    if meta & TLV_META_UINT:
        return str(int.from_bytes(value[:4], "big"))
    if meta & TLV_META_QWORD:
        return str(int.from_bytes(value[:8], "big"))
    if meta & TLV_META_BOOL:
        return "true" if value[:1] not in (b"", b"\x00") else "false"
    return value[:64].hex()


def _walk_tlvs(data: bytes, start: int = 0) -> tuple[list[dict], bool]:
    """顺序解析 TLV；返回 (列表, 是否完整消费到末尾)。不抛异常。"""
    tlvs: list[dict] = []
    offset = start
    size = len(data)
    while offset + 8 <= size:
        length = int.from_bytes(data[offset:offset + 4], "big")
        tlv_type = int.from_bytes(data[offset + 4:offset + 8], "big")
        if length < 8 or length > MAX_TLV_LENGTH or offset + length > size:
            break
        value = data[offset + 8:offset + length]
        tlvs.append({
            "name": _tlv_name(tlv_type),
            "type": tlv_type,
            "value": _decode_tlv_value(tlv_type, value),
            "raw": value,
            "length": length,
            "offset": offset,
        })
        offset += length
    return tlvs, offset == size


def _plausible_tlvs(data: bytes) -> tuple[bool, list[dict]]:
    """判断一段字节是否像合法的嵌套 TLV 流。

    仅靠 12 字节前缀（长度 + 类型）判断旧版报文会产生大量误报；这里要求
    体部能完整走出至少一条 TLV，且第一条 TLV 的 meta 位属于已知集合。
    """
    tlvs, clean = _walk_tlvs(data, 0)
    if not tlvs or not clean:
        return False, tlvs
    first = tlvs[0]["type"] & 0xFFFF0000  # 只校验高位 meta 位，低 16 位是 TLV id
    # meta 高位不能是随机垃圾：只能由已知 meta 位组合而成。
    if first & ~KNOWN_META_MASK:
        return False, tlvs
    return True, tlvs


def _command_from_tlvs(tlvs: list[dict]) -> int | None:
    for tlv in tlvs:
        if tlv["name"] == "COMMAND_ID" and len(tlv["raw"]) >= 4:
            return int.from_bytes(tlv["raw"][:4], "big")
    return None


# ---------------------------------------------------------------------------
# 报文解析
# ---------------------------------------------------------------------------
def _decrypt_body(body: bytes, flags: int, key: bytes) -> tuple[bytes | None, str]:
    """对 ``IV || ciphertext`` 做 AES-CBC 解密，返回 (明文候选, 错误原因)。

    OpenSSL（Metasploit 侧）默认加 PKCS#7 填充；严格去填充失败时仍尝试
    保留完整明文，只要随后能走出合法 TLV 即视为成功。
    """
    if flags == ENC_FLAG_AES256 and len(key) != 32:
        return None, "密钥长度不匹配（AES-256-CBC 需要 32 字节密钥）"
    if flags == ENC_FLAG_AES128 and len(key) != 16:
        return None, "密钥长度不匹配（AES-128-CBC 需要 16 字节密钥）"
    if len(body) < 17 or (len(body) - 16) % 16:
        return None, "密文长度不足（需要 IV + 整块密文）"
    iv, ciphertext = body[:16], body[16:]
    candidates: list[bytes] = []
    try:
        strict = aes_cbc_decrypt(ciphertext, key, iv, unpad=True)
        raw = aes_cbc_decrypt(ciphertext, key, iv, unpad=False)
    except (ValueError, IndexError, TypeError) as exc:  # defensive
        return None, f"AES 解密失败：{exc}"
    for candidate in (strict, raw):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    if not candidates:
        return None, "AES 解密结果为空"
    # 优先选能完整走出 TLV 的候选。
    best: bytes | None = None
    best_count = -1
    for candidate in candidates:
        ok, parsed = _plausible_tlvs(candidate)
        if ok and len(parsed) > best_count:
            best, best_count = candidate, len(parsed)
    if best is not None:
        return best, ""
    return candidates[0], "解密后未发现合法 TLV（密钥可能错误）"


def _decode_at(data: bytes, offset: int, key: bytes | None) -> MPacket | None:
    """在 ``offset`` 处尝试解析一个报文，失败返回 None。"""
    available = len(data) - offset
    if available < LEGACY_HEADER_SIZE:
        return None

    xor_key = data[offset:offset + XOR_KEY_SIZE]
    if not xor_key:
        return None

    # ---- 现代报文：GUID(16) + flags(4) + length(4) + type(4) ----------
    if available >= MODERN_HEADER_SIZE:
        head = _xor(data[offset:offset + MODERN_HEADER_SIZE], xor_key)
        guid = head[XOR_KEY_SIZE:XOR_KEY_SIZE + GUID_SIZE]
        flags = int.from_bytes(head[20:24], "big")
        length = int.from_bytes(head[24:28], "big")
        packet_type = int.from_bytes(head[28:32], "big")
        # length 是 TLV 自包含长度：total = 24 + length（头 32 字节 = 24 + 8）。
        total = 24 + length
        if (flags in (ENC_FLAG_NONE, ENC_FLAG_AES256, ENC_FLAG_AES128)
                and 8 <= length <= MAX_PACKET_LENGTH
                and total <= available
                and packet_type in PACKET_TYPES):
            body = _xor(data[offset + MODERN_HEADER_SIZE:offset + total],
                        xor_key)
            header_hex = data[offset:offset + MODERN_HEADER_SIZE].hex()
            packet = MPacket(
                version="modern", offset=offset, total=total,
                xor_key=xor_key, session_guid=guid, encrypt_flags=flags,
                length=length, packet_type=packet_type,
                encrypted=flags != ENC_FLAG_NONE,
                ciphertext=b"" if flags == ENC_FLAG_NONE else body,
                header_hex=header_hex,
            )
            if flags == ENC_FLAG_NONE:
                ok, tlvs = _plausible_tlvs(body)
                if ok:
                    packet.plaintext = body
                    packet.tlvs = tlvs
                    packet.command_id = _command_from_tlvs(tlvs)
                    return packet
                return None
            # 加密报文：先做结构校验（IV + 16 倍数密文），有密钥再解密。
            if len(body) < 32 or (len(body) - 16) % 16:
                return None
            if not key:
                packet.decrypt_ok = False
                packet.decrypt_reason = "未提供会话密钥，保留密文"
                return packet
            plain, reason = _decrypt_body(body, flags, key)
            if plain is None:
                packet.decrypt_ok = False
                packet.decrypt_reason = reason
                return packet
            packet.plaintext = plain
            packet.decrypt_reason = reason
            packet.decrypt_ok = not reason
            ok, tlvs = _plausible_tlvs(plain)
            if ok:
                packet.tlvs = tlvs
                packet.command_id = _command_from_tlvs(tlvs)
            return packet

    # ---- 旧版报文：length(4) + type(4)，无 GUID / flags ----------------
    head = _xor(data[offset:offset + LEGACY_HEADER_SIZE], xor_key)
    length = int.from_bytes(head[4:8], "big")
    packet_type = int.from_bytes(head[8:12], "big")
    total = XOR_KEY_SIZE + length
    if not (8 <= length <= MAX_PACKET_LENGTH
            and total <= available
            and packet_type in PACKET_TYPES):
        return None
    body = _xor(data[offset + LEGACY_HEADER_SIZE:offset + total], xor_key)
    ok, tlvs = _plausible_tlvs(body)  # 旧版必须有合法 TLV 流，杜绝误报
    if not ok:
        return None
    return MPacket(
        version="legacy", offset=offset, total=total, xor_key=xor_key,
        session_guid=b"", encrypt_flags=ENC_FLAG_NONE, length=length,
        packet_type=packet_type, encrypted=False, plaintext=body,
        tlvs=tlvs, command_id=_command_from_tlvs(tlvs),
        decrypt_ok=True, decrypt_reason="",
        header_hex=data[offset:offset + LEGACY_HEADER_SIZE].hex(),
    )


def iter_packets(data: bytes, key: bytes | None = None, *,
                 scan_limit: int = 4096, max_packets: int = 1000) -> list[MPacket]:
    """扫描并解析连续的 Meterpreter XOR 报文。

    * 最多向前跳过 ``scan_limit`` 字节前导垃圾（staging banner/半包）；
    * 找到首个报文后遇到非法头即停止，避免把自然语言误判为报文；
    * ``key`` 用于 AES 解密（16 字节 = AES-128，32 字节 = AES-256）；
      长度不匹配或密钥错误时保留 ``ciphertext``，``decrypt_ok=False``；
    * ``max_packets`` 防止畸形输入造成无限循环。

    兼容旧调用 ``iter_packets(data, scan_limit)``：若第二参数是 ``int``，
    视为 ``scan_limit``（旧签名），而不是密钥。
    """
    if isinstance(key, int):  # 旧版 c2ext.iter_packets(data, scan_limit)
        scan_limit, key = key, None
    if key is not None:
        try:
            key = bytes(key)
        except (TypeError, ValueError):
            key = None
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return []
    data = bytes(data)

    packets: list[MPacket] = []
    offset = 0
    scanned = 0
    limit = max(0, min(int(scan_limit), len(data)))
    cap = max(0, int(max_packets))
    while offset + LEGACY_HEADER_SIZE <= len(data) and len(packets) < cap:
        packet = _decode_at(data, offset, key)
        if packet is None:
            if packets or scanned >= limit:
                break
            offset += 1
            scanned += 1
            continue
        packets.append(packet)
        offset += packet.total
        scanned = 0
    return packets


def looks_like_xor_meterpreter(data: bytes) -> bool:
    """协议识别回调：存在至少一个可通过严格校验的 XOR 报文即为 True。"""
    if not data or len(data) < LEGACY_HEADER_SIZE:
        return False
    return bool(iter_packets(data, max_packets=1))


def decrypt_packet_body(data: bytes, packet: MPacket,
                        key: bytes) -> bytes | None:
    """兼容旧 API：解密单个报文体，失败返回 None。"""
    if not key or not packet.encrypted:
        return None
    start = (packet.offset + MODERN_HEADER_SIZE if packet.version == "modern"
             else packet.offset + LEGACY_HEADER_SIZE)
    body = _xor(bytes(data)[start:packet.offset + packet.total],
                packet.xor_key)
    plain, reason = _decrypt_body(body, packet.encrypt_flags, bytes(key))
    return plain if plain is not None and not reason else None


# ---------------------------------------------------------------------------
# Staging（checksum URI + metsrv stage）
# ---------------------------------------------------------------------------
URI_CHECKSUM_INITW = 92   # Windows/native（x86）初始 stage
URI_CHECKSUM_INITX64 = 93  # x64 stager
INITM_MARKER = "INITM"


def checksum8(text: str) -> int:
    """Metasploit ``Rex::Text.checksum8``：字节和取低 8 位。"""
    return sum((text or "").encode("latin-1", "ignore")) & 0xFF


def meterpreter_stage_uri(uri: str) -> dict | None:
    """识别 Meterpreter staging 请求 URI（checksum 92/93 或 INITM）。"""
    path = (uri or "").split("?", 1)[0]
    if INITM_MARKER in path.upper():
        return {"checksum": None, "arch": "x86", "reason": "INITM 标记"}
    for offset in (0, 1):  # 兼容带/不带前导斜杠的 checksum 计算
        target = path[offset:] if offset else path
        if not target:
            continue
        value = checksum8(target)
        if value == URI_CHECKSUM_INITW:
            return {"checksum": value, "arch": "x86", "reason": "URI 校验和 92"}
        if value == URI_CHECKSUM_INITX64:
            return {"checksum": value, "arch": "x64", "reason": "URI 校验和 93"}
    return None


def parse_stage_blob(body: bytes) -> dict | None:
    """解析下载的 ``metsrv`` stage（容忍尾部附加数据）。

    返回 ``{"stage", "length_prefixed", "is_pe", "strings", "size"}``。
    """
    if not isinstance(body, (bytes, bytearray, memoryview)):
        return None
    body = bytes(body)
    if len(body) < 8:
        return None
    stage = body
    length_prefixed = False
    declared = int.from_bytes(body[:4], "big")
    if 0 < declared <= len(body) - 4:
        # 反向 TCP staging 总是用 4 字节大端长度前缀；抓包可能带尾部冗余。
        stage = body[4:4 + declared]
        length_prefixed = True
    strings = [match.group().decode("latin-1")
               for match in re.finditer(rb"[\x20-\x7e]{6,}", stage)]
    return {
        "stage": stage,
        "length_prefixed": length_prefixed,
        "is_pe": stage[:2] == b"MZ",
        "strings": strings,
        "size": len(stage),
    }


# ---------------------------------------------------------------------------
# HTTP 体候选 / 报告辅助
# ---------------------------------------------------------------------------
def wire_body_candidates(body: bytes) -> list[tuple[bytes, str]]:
    """返回原始体 + 标准/URL-safe base64 解码候选（去重、限量、不抛异常）。

    Meterpreter HTTP 传输可能直接发 XOR 报文，也可能用 base64（标准或
    URL-safe 字母表）编码；这里把三种候选都交给 :func:`iter_packets`。
    """
    result: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()

    def add(value: bytes, label: str) -> None:
        if value and value not in seen:
            seen.add(value)
            result.append((value, label))

    if not isinstance(body, (bytes, bytearray, memoryview)):
        return result
    raw = bytes(body)
    add(raw, "raw")
    try:
        text = raw.decode("ascii", "ignore")
        compact = re.sub(r"\s+", "", text)
        if compact:
            padded = compact + "=" * (-len(compact) % 4)
            for label, decoder in (("base64", base64.b64decode),
                                   ("base64url", base64.urlsafe_b64decode)):
                for value in (padded, compact):
                    try:
                        add(decoder(value), label)
                        break
                    except (binascii.Error, ValueError):
                        continue
        # 有些 profile 先做百分号编码再 base64。
        try:
            from urllib.parse import unquote_to_bytes
            decoded = unquote_to_bytes(compact)
            if decoded and decoded != raw:
                add(decoded, "url")
        except Exception:  # pragma: no cover - 永不因解码失败抛异常
            pass
    except Exception:  # pragma: no cover
        pass
    return result[:8]


def explain_packet(packet: MPacket) -> dict:
    """生成适合写入 finding detail 的紧凑字典（避免 ``-`` 这种空信息）。"""
    names = [str(tlv.get("name", "-")) for tlv in packet.tlvs]
    return {
        "version": packet.version,
        "encryption": packet.encryption_name,
        "guid": packet.guid_hex,
        "packet_type": packet.packet_type,
        "kind": packet.kind,
        "command_id": packet.command_id if packet.command_id is not None else "-",
        "command_hex": packet.command_hex,
        "tlv_count": len(packet.tlvs),
        "tlvs": names,
        "decrypt_ok": bool(packet.decrypt_ok),
        "decrypt_reason": packet.decrypt_reason,
        "offset": packet.offset,
        "length": packet.length,
    }


def flag_strings(data: bytes) -> list[str]:
    """从报文中提取 CTF flag（调用 codec.find_flags，去重保序）。"""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return []
    raw = bytes(data)
    texts: list[str] = []
    for encoding in ("utf-8", "latin-1"):
        try:
            texts.append(raw.decode(encoding))
        except UnicodeDecodeError:
            continue
    found: list[str] = []
    for text in texts:
        for flag in find_flags(text):
            if flag not in found:
                found.append(flag)
    return found
