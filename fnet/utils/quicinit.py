"""QUIC Initial 取证：无 keylog 时解密 Initial 长包头（纯标准库）。

QUIC 的 Initial 长包头（RFC 9000 §17.2.2）使用一组“公开可推导”的保护密钥：
初始密钥由版本常数（盐）与客户端第一个 Initial 包的目的连接 ID（DCID）
经 HKDF-Extract/Expand 链派生（RFC 9001 §5.2，QUIC v2 的差异见 RFC 9369
§3.3——盐与 HKDF 标签改名，派生输入仍是客户端 DCID），因此任何旁观者
都能：

1. 用版本盐 + DCID 推导 client/server 两侧的 Initial 包保护密钥
   （``quic key``/``quic iv``）与头部保护密钥（``quic hp``）；
2. 用 AES-128-ECB 对保护载荷采样生成掩码，去除头部保护
   （RFC 9001 §5.4.2），恢复首字节与包号；
3. 以头部（含已恢复的包号）为 AAD，用 AES-128-GCM 解密载荷
   （RFC 9001 §5.4.3），得到 CRYPTO 帧；
4. 按 CRYPTO 帧的 offset 重组握手流，解析 ClientHello（SNI/ALPN/版本）。

本模块不依赖任何第三方库：AES-128 与 GCM 使用 ``fnet.utils.crypto`` 的纯
Python 实现；HKDF 基于 ``hmac``/``hashlib``。即使没有 TLS keylog，也能从
QUIC Initial 中提取 SNI、ALPN、协商版本与连接 ID。GCM 解密经
``fnet.utils.accel`` 在调用侧注入可选 CUDA/JIT 加速——加速栈不可用时与
纯 Python 实现逐字节一致，行为不变。

同时支持三类无加密的长包头（RFC 8999/9000）：

* **版本协商**（Version Negotiation，version=0）：列出服务器支持的版本；
* **Retry**：校验 Retry 完整性标签（RFC 9001 §5.8，AEAD_AES_128_GCM 空
  明文 + Retry 伪包头作 AAD），提取 Retry Token；
* **合并包**（coalesced datagram）：一个 UDP 报文里首尾相接的多个长包头
  （Initial/Handshake 的 Length 字段给出包尾）按序逐个处理。

已知限制：只支持 v1/v2（含 draft-29）的 Initial；服务器 Initial 的派生
输入是“原始 DCID”，当服务器改用新 CID 时需要调用方（initial_forensics）
记录的客户端 DCID 旁边本模块才有机会解密；Handshake/0-RTT/1-RTT 包使用
握手/应用密钥，没有 keylog 无法解密。版本协商包的候选版本列表延伸到报文
末尾（RFC 8999 §6），其后 RFC 9000 要求的随机填充无法与版本区分，可能被
当作最后一个候选版本（grease 码点已过滤）。
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from fnet.utils import accel
from fnet.utils.crypto import aes_encrypt_block
from fnet.utils.tlsdeep import QUIC_VERSIONS, parse_client_hello

# ---------------------------------------------------------------------------
# 版本常量
# ---------------------------------------------------------------------------
#: RFC 9000 QUIC v1；RFC 9369 QUIC v2 正式码点与早期 v2 草案码点。
QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
QUIC_V2_DRAFT = 0x709A50C4
DRAFT_29 = 0xFF00001D

#: v2 家族（RFC 9369）：长包头类型位重排，HKDF 标签改为 ``quicv2`` 前缀。
QUIC_V2_VERSIONS = frozenset({QUIC_V2, QUIC_V2_DRAFT})

#: 每个版本的 Initial 盐（RFC 9001 §5.2.1 / RFC 9369 §3.3.1 / draft-29）。
#: 这些常量写死在协议文档里，属于“公开密钥”。
QUIC_INITIAL_SALTS = {
    QUIC_V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    QUIC_V2_DRAFT: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    DRAFT_29: bytes.fromhex("afbfec289943d24c9a5e5fee14bd0efa5dfab56f"),
}

#: Retry 完整性标签的 (key, nonce) 常量（RFC 9001 §5.8 / RFC 9369 §3.3.3）。
#: 原文由某个固定 secret 经 ``quic key``/``quic iv`` 展开而来，直接记录结果。
RETRY_INTEGRITY = {
    QUIC_V1: (bytes.fromhex("be0c690b9f66575a1d766b54e368c84e"),
              bytes.fromhex("461599d35d632bf2239825bb")),
    QUIC_V2: (bytes.fromhex("8fb4b01b56ac48e260fbcbcead7ccc92"),
              bytes.fromhex("d86969bc2d7c6d9990efb04a")),
}


def version_name(version: int) -> str:
    """版本号的人类可读名称，如 ``"QUIC v1 (RFC 9000)"``。"""
    name = QUIC_VERSIONS.get(int(version))
    return f"{name} (0x{int(version):08x})" if name else f"0x{int(version):08x}"


# ---------------------------------------------------------------------------
# HKDF（RFC 8446 §7.1）：初始密钥派生链的全部材料
# ---------------------------------------------------------------------------
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract：以盐为 HMAC-SHA256 的 key 对输入做 PRK。"""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand：逐块 HMAC 计出 ``length`` 字节输出。"""
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: str, length: int,
                      context: bytes = b"") -> bytes:
    """RFC 8446 §7.1 HKDF-Expand-Label。

    结构为 ``struct``(长度) + "tls13 " 前缀 + 标签 + 上下文；QUIC 的
    ``quic key``/``quic iv``/``quic hp``/``client in`` 等标签都经此展开。
    """
    full = ("tls13 " + label).encode("ascii")
    info = (struct.pack("!H", length) + bytes([len(full)]) + full
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length)


def initial_secrets(version: int, dcid: bytes) -> dict[str, dict]:
    """派生一个连接两侧的 Initial 密钥材料（RFC 9001 §5.2）。

    派生输入是**客户端第一个 Initial 的 DCID**（v1/v2 皆然；RFC 9369 只改
    盐与标签名）。返回 ``{"client": {...}, "server": {...}}``，每侧含
    ``secret``（TLS 层密钥）、``key``（16 字节 AEAD 密钥）、``iv``（12 字节
    nonce 基值）与 ``hp``（16 字节头部保护密钥）。
    """
    salt = QUIC_INITIAL_SALTS.get(int(version))
    if salt is None:
        raise ValueError(f"不支持的 QUIC 版本: 0x{int(version):08x}")
    prefix = "quicv2 " if int(version) in QUIC_V2_VERSIONS else "quic "
    initial_secret = hkdf_extract(salt, dcid)
    result: dict[str, dict] = {}
    for role in ("client", "server"):
        secret = hkdf_expand_label(initial_secret, f"{role} in", 32)
        result[role] = {
            "secret": secret,
            "key": hkdf_expand_label(secret, prefix + "key", 16),
            "iv": hkdf_expand_label(secret, prefix + "iv", 12),
            "hp": hkdf_expand_label(secret, prefix + "hp", 16),
        }
    return result


# ---------------------------------------------------------------------------
# 长包头解析（RFC 8999 版本不变量 + RFC 9000 §17.2）
# ---------------------------------------------------------------------------
def _varint(data: bytes, offset: int) -> tuple[int, int]:
    """读取一个 QUIC 变长整数，返回 ``(值, 下一偏移)``。"""
    first = data[offset]
    length = 1 << (first >> 6)          # 前两位决定 1/2/4/8 字节编码
    if offset + length > len(data):
        raise ValueError("截断的 QUIC varint")
    value = first & 0x3F
    for shift in range(1, length):
        value = (value << 8) | data[offset + shift]
    return value, offset + length


#: 长包头类型位（首字节 4-5 位）→ 包类型名。v2（RFC 9369 §3.2）重排：
#: 0=Retry 1=Initial 2=Handshake 3=0-RTT；v1：0=Initial 1=0-RTT 2=Handshake 3=Retry。
_LONG_TYPES_V1 = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
_LONG_TYPES_V2 = {0: "Retry", 1: "Initial", 2: "Handshake", 3: "0-RTT"}


def parse_long_header(packet: bytes) -> dict | None:
    """解析一个长包头（不解密），失败返回 ``None``。

    返回字段：``packet_type``（Initial/0-RTT/Handshake/Retry/Version
    Negotiation）、``version``、``dcid``/``scid``（字节串）、``token``
    （Initial/0-RTT 的地址验证令牌）、``pn_offset``（包号字段起点）、
    ``payload_len``（Length 字段值：包号 + 受保护载荷 + 认证标签）、
    ``packet_end``（本包结束偏移，合并包中下一包从此开始；Retry 与版本
    协商没有 Length 字段，占满整个报文，返回 ``len(packet)``）。
    """
    packet = bytes(packet or b"")
    if len(packet) < 6 or not packet[0] & 0x80:
        return None                                   # 短包头或长度不足
    version = int.from_bytes(packet[1:5], "big")
    try:
        if version == 0:                              # 版本协商（RFC 8999 §6）
            offset = 5
            dcid_len = packet[offset]
            offset += 1
            dcid = packet[offset:offset + dcid_len]
            offset += dcid_len
            scid_len = packet[offset]
            offset += 1
            scid = packet[offset:offset + scid_len]
            offset += scid_len
            return {"packet_type": "Version Negotiation", "version": 0,
                    "dcid": dcid, "scid": scid, "token": b"",
                    "pn_offset": offset, "payload_len": len(packet) - offset,
                    "packet_end": len(packet)}
        type_bits = (packet[0] >> 4) & 0x03
        table = _LONG_TYPES_V2 if version in QUIC_V2_VERSIONS else _LONG_TYPES_V1
        packet_type = table[type_bits]
        offset = 5
        dcid_len = packet[offset]
        offset += 1
        dcid = packet[offset:offset + dcid_len]
        offset += dcid_len
        scid_len = packet[offset]
        offset += 1
        scid = packet[offset:offset + scid_len]
        offset += scid_len
        token = b""
        if packet_type in ("Initial", "0-RTT"):       # 这两类有令牌字段
            token_len, offset = _varint(packet, offset)
            if offset + token_len > len(packet):
                return None
            token = packet[offset:offset + token_len]
            offset += token_len
        if packet_type == "Retry":                    # Retry 无 Length 字段
            if len(packet) < 17:                      # 头部 + 16 字节标签
                return None
            return {"packet_type": "Retry", "version": version,
                    "dcid": dcid, "scid": scid, "token": packet[offset:-16],
                    "pn_offset": offset, "payload_len": len(packet) - offset,
                    "packet_end": len(packet)}
        payload_len, offset = _varint(packet, offset)
        packet_end = offset + payload_len             # 包号 + 载荷 + 标签
        if packet_end > len(packet):
            packet_end = len(packet)
        return {"packet_type": packet_type, "version": version,
                "dcid": dcid, "scid": scid, "token": token,
                "pn_offset": offset, "payload_len": payload_len,
                "packet_end": packet_end}
    except (IndexError, ValueError):
        return None


# ---------------------------------------------------------------------------
# 头部保护去除 + AEAD 解密（RFC 9001 §5.4）
# ---------------------------------------------------------------------------
def _decrypt_payload(packet: bytes, hdr: dict, keys: dict) -> tuple | None:
    """用一组密钥去掉头部保护并解密载荷，失败返回 ``None``。

    返回 ``(明文载荷, 包号)``。头部保护掩码来自保护载荷中 pn_offset+4 起
    的 16 字节样本（与包号长度无关，RFC 9001 §5.4.2）；掩码低 4 位恢复首
    字节（含包号长度），其余位恢复包号本身。AEAD 的 AAD 是去除保护后的
    头部（含明文包号），nonce 为 ``iv XOR 包号``。
    """
    pn_offset = hdr["pn_offset"]
    sample = packet[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16 or pn_offset + 21 > len(packet):
        return None                                   # 样本不足（ RFC 9001 §A.2 要求）
    mask = aes_encrypt_block(sample, keys["hp"])
    first = packet[0] ^ (mask[0] & 0x0F)              # 长包头首字节低 4 位
    pn_len = (first & 0x03) + 1
    if pn_offset + pn_len + 16 > len(packet):
        return None
    pn_raw = bytes(a ^ b for a, b in
                   zip(packet[pn_offset:pn_offset + pn_len],
                       mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_raw, "big")
    nonce = bytes(a ^ b for a, b in
                  zip(keys["iv"], pn.to_bytes(12, "big")))
    aad = bytes([first]) + packet[1:pn_offset] + pn_raw
    # GCM 解密经 accel 注入可选 CUDA/JIT 加速：不可用时与
    # fnet.utils.crypto.aes_gcm_decrypt 的纯 Python 实现逐字节一致。
    plain, ok = accel.aes_gcm_decrypt(packet[pn_offset + pn_len:hdr["packet_end"]],
                                      keys["key"], nonce, aad)
    return (plain, pn) if ok else None


def decrypt_initial(packet, original_dcid: bytes | None = None) -> dict | None:
    """解密一个 Initial 长包头（无需 keylog），失败返回 ``None``（不抛异常）。

    ``original_dcid``：可选的原始 DCID。客户端 Initial 的派生输入就是包头
    DCID；但服务器的 Initial 包 DCID 是它自选的新 CID，派生输入仍是客户端
    原始 DCID（RFC 9001 §5.2），此时需要调用方提供。两种输入都会尝试。

    成功返回::

        {"version", "packet_type": "Initial", "dcid", "scid", "token",
         "key_cid": 派生输入的 DCID, "role": "client"/"server",
         "packet_number", "crypto": [(offset, bytes), ...], "packet_end"}
    """
    try:
        packet = bytes(packet or b"")
        hdr = parse_long_header(packet)
        if not hdr or hdr["packet_type"] != "Initial":
            return None
        version = hdr["version"]
        if version not in QUIC_INITIAL_SALTS:
            return None
        # 派生输入候选：包头 DCID（客户端 Initial）+ 调用方提供的原始 DCID。
        candidates: list[bytes] = [hdr["dcid"]]
        if original_dcid and original_dcid not in candidates:
            candidates.append(bytes(original_dcid))
        for key_cid in candidates:
            if not key_cid and hdr["dcid"]:
                continue                              # 空输入无法派生
            secrets = initial_secrets(version, key_cid)
            for role in ("client", "server"):         # 方向未知，两侧都试
                result = _decrypt_payload(packet, hdr, secrets[role])
                if result is None:
                    continue
                plain, pn = result
                return {
                    "version": version,
                    "packet_type": "Initial",
                    "dcid": hdr["dcid"].hex(),
                    "scid": hdr["scid"].hex(),
                    "token": hdr["token"].hex(),
                    "key_cid": key_cid.hex(),
                    "role": role,
                    "packet_number": pn,
                    "crypto": crypto_frames(plain),
                    "packet_end": hdr["packet_end"],
                }
        return None
    except Exception:                                 # noqa: BLE001 — 解析失败静默跳过
        return None


# ---------------------------------------------------------------------------
# CRYPTO 帧解析与握手流重组
# ---------------------------------------------------------------------------
def crypto_frames(plain: bytes) -> list[tuple[int, bytes]]:
    """提取一个 Initial 明文载荷里的 CRYPTO 帧，``[(offset, data)]``。

    同时跳过 PADDING/PING/ACK/PATH_CHALLENGE/NEW_TOKEN 等帧；遇到未知帧
    类型即停止（Initial 里首个 CRYPTO 帧通常携带 ClientHello）。
    """
    chunks: list[tuple[int, bytes]] = []
    plain = bytes(plain or b"")
    try:
        pos = 0
        while pos < len(plain):
            frame_type, pos = _varint(plain, pos)
            if frame_type in (0x00, 0x01):            # PADDING / PING
                continue
            if frame_type in (0x02, 0x03):            # ACK / ACK_ECN
                _largest, pos = _varint(plain, pos)
                _delay, pos = _varint(plain, pos)
                count, pos = _varint(plain, pos)
                for _ in range(min(count, 64)):
                    _gap, pos = _varint(plain, pos)
                    _range, pos = _varint(plain, pos)
                if frame_type == 0x03:
                    for _ in range(3):
                        _ecn, pos = _varint(plain, pos)
                continue
            if frame_type == 0x04:                    # RETIRE_CONNECTION_ID
                _seq, pos = _varint(plain, pos)
                continue
            if frame_type == 0x07:                    # NEW_TOKEN
                _tlen, pos = _varint(plain, pos)
                pos += _tlen
                continue
            if frame_type == 0x08:                    # PATH_CHALLENGE（8 字节）
                pos += 8
                continue
            if frame_type == 0x06:                    # CRYPTO
                offset, pos = _varint(plain, pos)
                length, pos = _varint(plain, pos)
                if pos + length > len(plain):
                    break                             # 载荷被截断
                chunks.append((offset, plain[pos:pos + length]))
                pos += length
                continue
            break                                     # 未知帧：停止解析
    except (IndexError, ValueError):
        return chunks
    return chunks


def reassemble_crypto(chunks) -> bytes:
    """按 offset 重组 CRYPTO 帧数据为握手流；缺口用 0 填充并继续。"""
    bucket: dict[int, bytes] = {}
    for offset, data in chunks or []:
        bucket[int(offset)] = bytes(data)
    stream = b""
    for offset in sorted(bucket):
        data = bucket[offset]
        if offset + len(data) <= len(stream):
            continue                                  # 重复/已被覆盖的分片
        if offset > len(stream):                      # 缺口：补零（记录性损失）
            stream += b"\x00" * (offset - len(stream))
        stream = stream[:offset] + data
    return stream


def _tls_version_names(supported: list[int]) -> list[str]:
    """supported_versions 扩展里的版本号 → 名称（去重保序）。"""
    names = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
             0x0301: "TLS 1.0"}
    result: list[str] = []
    for value in supported or []:
        name = names.get(int(value))
        if name and name not in result:
            result.append(name)
    return result


# ---------------------------------------------------------------------------
# 版本协商与 Retry（RFC 8999 §6 / RFC 9001 §5.8）
# ---------------------------------------------------------------------------
#: 版本协商中的“抹黄油”保留码点：0x?a?a?a?（每个字节的低半字节都是 0xa，
#: 高半字节任意，RFC 8999 §6）。注意列表后的随机填充不是 4 字节对齐语义，
#: 有被误当版本解析的固有歧义（见模块 docstring 的已知限制）。
def _is_version_grease(version: int) -> bool:
    return (int(version) & 0xFFFFFFFF) & 0x0F0F0F0F == 0x0A0A0A0A


def parse_version_negotiation(packet) -> dict | None:
    """解析版本协商包（RFC 8999 §6），非版本协商返回 ``None``。

    服务器在 DCID/SCID 字段里回填客户端的 SCID/DCID（镜像），随后是 4 字
    节对齐的候选版本列表与随机填充。返回 ``{"dcid", "scid", "versions"}``，
    其中 ``versions`` 已过滤 0x00000000 与 grease 保留码点。
    """
    packet = bytes(packet or b"")
    hdr = parse_long_header(packet)
    if not hdr or hdr["packet_type"] != "Version Negotiation":
        return None
    versions: list[int] = []
    offset = hdr["pn_offset"]
    while offset + 4 <= len(packet):
        value = int.from_bytes(packet[offset:offset + 4], "big")
        offset += 4
        if value and not _is_version_grease(value) and value not in versions:
            versions.append(value)
    return {"dcid": hdr["dcid"].hex(), "scid": hdr["scid"].hex(),
            "versions": versions}


def verify_retry(packet, original_dcid: bytes) -> dict | None:
    """解析并校验 Retry 包（RFC 9001 §5.8），非 Retry 包返回 ``None``。

    Retry 完整性标签 = AEAD_AES_128_GCM(公开常量 key/nonce，空明文，
    AAD = Retry 伪包头)。伪包头 = ``ODCID 长度 + ODCID + Retry 包（去掉
    标签）``，其中 ODCID 是该 Retry 回应的那个客户端 Initial 的 DCID。

    返回 ``{"version", "dcid", "scid", "token", "integrity": bool}``；
    ``integrity`` 为 False 表示标签不匹配（可能被篡改或 ODCID 不对）。
    """
    packet = bytes(packet or b"")
    hdr = parse_long_header(packet)
    if not hdr or hdr["packet_type"] != "Retry":
        return None
    constants = RETRY_INTEGRITY.get(hdr["version"])
    if constants is None:
        return None
    odcid = bytes(original_dcid or b"")
    pseudo = bytes([len(odcid)]) + odcid + packet[:-16]
    key, nonce = constants
    _, ok = accel.aes_gcm_decrypt(packet[-16:], key, nonce, pseudo)
    return {"version": hdr["version"],
            "version_name": version_name(hdr["version"]),
            "dcid": hdr["dcid"].hex(), "scid": hdr["scid"].hex(),
            "token": hdr["token"].hex(), "integrity": ok}


# ---------------------------------------------------------------------------
# 顶层入口：一份抓包的 Initial 取证汇总
# ---------------------------------------------------------------------------
def client_hello_summary(hello: dict | None) -> dict:
    """把 ``parse_client_hello`` 的结果压平成取证要用的摘要字段。"""
    hello = hello or {}
    return {
        "sni": hello.get("sni") or "",
        "alpn": list(hello.get("alpn") or []),
        "tls_versions": _tls_version_names(hello.get("supported_versions")),
        "cipher_suites": list(hello.get("ciphers") or []),
        "extensions": list(hello.get("extensions") or []),
    }


def initial_forensics(packets, *, limit: int = 200) -> dict:
    """汇总一份抓包里全部 QUIC Initial 取证结果（无需 keylog）。

    ``packets``：原始 UDP 载荷的迭代，元素为 ``bytes`` 或 ``(标签, bytes)``
    二元组（标签一般为帧号，仅用于回溯引用）。一个 UDP 报文里合并的多个
    长包头会按 Length 字段逐个处理。

    返回::

        {"connections": [每个连接一条：version/version_name/dcid/scid/
                         sni/alpn/tls_versions/cipher_suites/frames/…],
         "version_negotiations": [版本协商包解析结果],
         "retries": [Retry 包解析结果（含完整性校验）],
         "undecrypted": int,          # 识别为 Initial 但解密失败的包数
         "packets_seen": int}
    """
    connections: dict[tuple[int, str], dict] = {}
    order: list[tuple[int, str]] = []
    negotiations: list[dict] = []
    retries: list[dict] = []
    undecrypted = 0
    seen = 0

    def connection(version: int, dcid: str) -> dict:
        key = (version, dcid)
        item = connections.get(key)
        if item is None:
            item = {"version": version, "version_name": version_name(version),
                    "dcid": dcid, "scid": "", "crypto": [], "frames": []}
            connections[key] = item
            order.append(key)
        return item

    for item in packets or []:
        if isinstance(item, (bytes, bytearray)):
            label, raw = "", bytes(item)
        else:
            label, raw = str(item[0]), bytes(item[1])
        # 逐个处理合并包：Initial/0-RTT/Handshake 的 Length 给出包尾。
        offset = 0
        while offset < len(raw):
            chunk = raw[offset:]
            hdr = parse_long_header(chunk)
            if hdr is None:
                break
            seen += 1
            end = hdr["packet_end"]
            if hdr["packet_type"] == "Version Negotiation":
                parsed = parse_version_negotiation(chunk)
                if parsed:
                    parsed["frames"] = [label] if label else []
                    negotiations.append(parsed)
                offset = len(raw)                 # 版本协商占满整个报文
                continue
            if hdr["packet_type"] == "Retry":
                # 完整性校验需要原始 DCID；依次尝试本抓包已见过的客户端 DCID。
                odcids = [bytes.fromhex(key[1]) for key in order]
                if hdr["dcid"]:
                    odcids.append(hdr["dcid"])
                verified = None
                for odcid in odcids:
                    verified = verify_retry(chunk, odcid)
                    if verified and verified["integrity"]:
                        break
                if verified is None:
                    verified = {"version": hdr["version"],
                                "version_name": version_name(hdr["version"]),
                                "dcid": hdr["dcid"].hex(),
                                "scid": hdr["scid"].hex(),
                                "token": hdr["token"].hex(),
                                "integrity": False}
                verified["frames"] = [label] if label else []
                retries.append(verified)
                offset = len(raw)                 # Retry 占满整个报文
                continue
            if hdr["packet_type"] == "Initial":
                # 派生输入候选：包头 DCID + 已知原始 DCID（服务器改 CID 时）。
                known = [bytes.fromhex(key[1]) for key in order]
                parsed = None
                for candidate in [hdr["dcid"]] + known:
                    parsed = decrypt_initial(chunk, candidate)
                    if parsed:
                        break
                if parsed is None:
                    undecrypted += 1
                else:
                    key = (parsed["version"], parsed["key_cid"])
                    conn = connection(parsed["version"], parsed["key_cid"])
                    if not conn["scid"]:
                        conn["scid"] = parsed["scid"]
                    conn["crypto"].extend(parsed["crypto"])
                    if label and label not in conn["frames"]:
                        conn["frames"].append(label)
            offset += end                         # 合并包中下一包从此开始

    results: list[dict] = []
    for key in order[:limit]:
        conn = connections[key]
        stream = reassemble_crypto(conn["crypto"])
        summary = client_hello_summary(parse_client_hello(stream)
                                       if stream.startswith(b"\x01") else None)
        record = {name: conn[name] for name in
                  ("version", "version_name", "dcid", "scid")}
        record.update(summary)
        record["frames"] = conn["frames"]
        record["crypto_bytes"] = len(stream)
        record["hello_decrypted"] = bool(summary["sni"] or summary["alpn"]
                                         or summary["cipher_suites"])
        results.append(record)
    return {"connections": results, "version_negotiations": negotiations,
            "retries": retries, "undecrypted": undecrypted,
            "packets_seen": seen}
