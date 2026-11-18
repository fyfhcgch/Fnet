"""Sliver C2 会话解密与分析核心（纯标准库）。

背景：把 Sliver 会话数据笼统描述成 "AES-GCM only" 是不准确的。

* Sliver <=1.4：RSA 交换密钥 + AES-GCM-256 会话数据（遗留兼容）。
* Sliver v1.5：8 位 TOTP + SHA256(公钥) + NaCl sealed box 交换密钥；
  会话数据使用 ChaCha20-Poly1305。
* Sliver v1.6：Age/X25519 交换密钥（植入体携带 SHA256(peer public key)）；
  会话数据同样使用 ChaCha20-Poly1305，消息外层可带 74 字节 minisign 签名。

本模块实现 RFC 8439 IETF ChaCha20-Poly1305（12 字节 nonce / 16 字节 tag）、
会话载荷解密（签名前缀跳过 + gzip 透明解压 + AES-GCM 遗留回退）、HTTP/DNS
常见编码器候选解码、protobuf Envelope 解析、密钥交换启发式分类与报告摘要。

所有公开函数对畸形输入都返回 ``None`` / 空值，绝不抛出异常，也不调用外部进程。
"""
from __future__ import annotations

import base64
import gzip
import hmac
import math
import re
import struct
import urllib.parse
import zlib
from collections import Counter

from fnet.utils.codec import find_flags
from fnet.utils.crypto import aes_gcm_decrypt

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
MAX_CANDIDATES = 200            #: ``decode_body_candidates`` 的候选上限
MINISIGN_SIG_LEN = 74           #: Sliver minisign 原始签名长度
_NONCE_LEN = 12
_TAG_LEN = 16
_CHACHA_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
_POLY1305_P = (1 << 130) - 5
_U64_MASK = (1 << 64) - 1
_U128_MASK = (1 << 128) - 1

#: Sliver ``util/encoders/base64.go`` 中构建时使用的自定义字母表。
SLIVER_BASE64_ALPHABET = (
    "a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ"
)
#: Sliver DNS 编码器的变形 Base32 字母表。
SLIVER_BASE32_ALPHABET = "ab1c2d3e4f5g6h7j8k9m0npqrtuvwxyz"
BTC_BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)
_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_STD_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_GZIP_MAGIC = b"\x1f\x8b"


# ---------------------------------------------------------------------------
# RFC 8439 ChaCha20 / Poly1305 / AEAD（内部原语）
# ---------------------------------------------------------------------------
def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """单个 ChaCha20 块（64 字节）。counter 从 0 或 1 开始由调用方决定。"""
    state = list(_CHACHA_CONSTANTS)
    state.extend(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state.extend(struct.unpack("<3I", nonce))
    working = state[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *((word + original) & 0xFFFFFFFF
                  for word, original in zip(working, state))
    )


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        stream = _chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        out.extend(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)


def _poly1305_key(key: bytes, nonce: bytes) -> bytes:
    """用 counter=0 的 ChaCha20 块生成一次性 Poly1305 密钥。"""
    return _chacha20_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    remainder = len(data) & 15
    return b"\x00" * (16 - remainder) if remainder else b""


def _poly1305_mac(message: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset:offset + 16]
        # “在数据字节数之后再补一个 1 位”，短块等价于加 1 << (8 * len)。
        number = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        acc = ((acc + number) * r) % _POLY1305_P
    return ((acc + s) & _U128_MASK).to_bytes(16, "little")


def chacha20_poly1305_decrypt(
    ciphertext: bytes, key: bytes, aad: bytes = b""
) -> tuple[bytes | None, str | None]:
    """RFC 8439 IETF ChaCha20-Poly1305 解密。

    输入布局为 ``nonce(12) || ciphertext || tag(16)``，与 Sliver 的
    ``aead.Seal(nonce, nonce, plaintext, nil)`` 返回值一致。tag 校验失败时
    返回 ``(None, 原因)``；任何畸形输入都不会抛出异常。
    """
    try:
        if not isinstance(key, (bytes, bytearray, memoryview)) or len(key) != 32:
            return None, "invalid key length (need 32)"
        if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
            return None, "invalid ciphertext"
        blob = bytes(ciphertext)
        key_bytes = bytes(key)
        aad_bytes = bytes(aad) if isinstance(aad, (bytes, bytearray, memoryview)) else b""
        if len(blob) < _NONCE_LEN + _TAG_LEN:
            return None, "ciphertext too short"
        nonce, sealed = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
        body, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
        otk = _poly1305_key(key_bytes, nonce)
        mac_data = aad_bytes + _pad16(aad_bytes)
        mac_data += body + _pad16(body)
        mac_data += struct.pack("<Q", len(aad_bytes) & _U64_MASK)
        mac_data += struct.pack("<Q", len(body) & _U64_MASK)
        expected = _poly1305_mac(mac_data, otk)
        if not hmac.compare_digest(expected, tag):
            return None, "tag mismatch"
        return _chacha20_xor(key_bytes, 1, nonce, body), None
    except Exception as exc:  # 防御式：解密核心绝不能把异常抛给调用方
        return None, "decrypt error: %s" % type(exc).__name__


# ---------------------------------------------------------------------------
# 会话载荷
# ---------------------------------------------------------------------------
def _safe_gunzip(data: bytes) -> tuple[bytes, bool]:
    """安全 gzip 解压；截断数据尽量返回已解压的部分。"""
    if not data.startswith(_GZIP_MAGIC):
        return data, False
    try:
        return gzip.decompress(data), True
    except Exception:
        pass
    try:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        partial = inflater.decompress(data)
        try:
            partial += inflater.flush()
        except Exception:
            pass
        if partial:
            return partial, True
    except Exception:
        pass
    return data, False


def decrypt_session(
    blob: bytes,
    key: bytes,
    *,
    allow_signature: bool = True,
    allow_unsigned: bool = True,
) -> dict | None:
    """解密 Sliver 会话载荷。

    先尝试 v1.5/v1.6 的 ChaCha20-Poly1305（可跳过 74 字节 minisign 签名，
    但不做公钥验签——没有提供公钥，只靠 AEAD tag 校验），再回退到 <=1.4 的
    AES-GCM-256。解密成功后透明 gzip 解压。成功返回::

        {"plaintext": bytes, "cipher": "chacha20-poly1305"|"aes-gcm",
         "signature_skipped": bool, "compressed": bool}

    全部失败返回 ``None``。
    """
    try:
        if not isinstance(blob, (bytes, bytearray, memoryview)):
            return None
        if not isinstance(key, (bytes, bytearray, memoryview)):
            return None
        data = bytes(blob)
        key_bytes = bytes(key)

        candidates: list[tuple[bytes, bool]] = []
        if allow_unsigned:
            candidates.append((data, False))
        if allow_signature and len(data) > MINISIGN_SIG_LEN:
            candidates.append((data[MINISIGN_SIG_LEN:], True))
        if not candidates:
            return None

        for candidate, skipped in candidates:
            plaintext, _reason = chacha20_poly1305_decrypt(candidate, key_bytes)
            if plaintext is not None:
                plain, compressed = _safe_gunzip(plaintext)
                return {
                    "plaintext": plain,
                    "cipher": "chacha20-poly1305",
                    "signature_skipped": skipped,
                    "compressed": compressed,
                }

        # 遗留 Sliver <=1.4：12 字节 nonce 前缀 + AES-GCM。
        if len(key_bytes) in (16, 24, 32):
            for candidate, _skipped in candidates:
                if len(candidate) < _NONCE_LEN + _TAG_LEN:
                    continue
                nonce, sealed = candidate[:_NONCE_LEN], candidate[_NONCE_LEN:]
                try:
                    plaintext, valid = aes_gcm_decrypt(sealed, key_bytes, nonce)
                except Exception:
                    continue
                if valid:
                    plain, compressed = _safe_gunzip(plaintext)
                    return {
                        "plaintext": plain,
                        "cipher": "aes-gcm",
                        "signature_skipped": False,
                        "compressed": compressed,
                    }
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 编码器候选解码
# ---------------------------------------------------------------------------
def _b64decode(
    text: str,
    *,
    alphabet: str | None = None,
    urlsafe: bool = False,
) -> bytes | None:
    """严格 base64 解码：要求可规范化回原文本，避免把普通字符串误当编码。"""
    if not text or len(text) < 4:
        return None
    if alphabet:
        standard = text.translate(str.maketrans(alphabet, _STD_B64))
    elif urlsafe:
        standard = text.replace("-", "+").replace("_", "/")
    else:
        standard = text
    standard = re.sub(r"\s+", "", standard).strip()
    if not standard or any(ch not in _STD_B64 + "=" for ch in standard):
        return None
    if "=" in standard.rstrip("="):
        return None
    padded = standard + "=" * (-len(standard) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        return None
    if len(decoded) < 2:
        return None
    # 与原文本比较时必须保持“原字母表”：urlsafe 期望 -/_，自定义字母表期望
    # 自定义字符；``standard`` 已被转换成标准 base64，不能直接拿来比较。
    original = re.sub(r"\s+", "", text).strip().rstrip("=")
    try:
        if alphabet:
            check = base64.b64encode(decoded).decode("ascii").rstrip("=")
            check = check.translate(str.maketrans(_STD_B64, alphabet))
        elif urlsafe:
            check = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        else:
            check = base64.b64encode(decoded).decode("ascii").rstrip("=")
    except Exception:
        return None
    return decoded if check == original else None


def _hexdecode(text: str) -> bytes | None:
    cleaned = re.sub(r"[\s:,-]", "", text)
    if len(cleaned) < 4 or len(cleaned) % 2:
        return None
    if not re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        return None
    try:
        decoded = bytes.fromhex(cleaned)
    except Exception:
        return None
    return decoded if len(decoded) >= 2 and decoded.hex() == cleaned.lower() else None


def _sliver_b32decode(text: str) -> bytes | None:
    lowered = text.lower()
    if len(lowered) < 8 or any(ch not in SLIVER_BASE32_ALPHABET for ch in lowered):
        return None
    standard = lowered.translate(str.maketrans(SLIVER_BASE32_ALPHABET, _STD_B32))
    padded = standard.upper() + "=" * (-len(standard) % 8)
    try:
        decoded = base64.b32decode(padded, casefold=False)
    except Exception:
        return None
    if len(decoded) < 2:
        return None
    check = base64.b32encode(decoded).decode("ascii").rstrip("=")
    check = check.translate(str.maketrans(_STD_B32, SLIVER_BASE32_ALPHABET))
    return decoded if check == lowered.rstrip("=") else None


def _b58encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        chars.append(BTC_BASE58_ALPHABET[remainder])
    return "1" * zeros + "".join(reversed(chars))


def _b58decode(text: str) -> bytes | None:
    if len(text) < 8 or any(ch not in BTC_BASE58_ALPHABET for ch in text):
        return None
    try:
        number = 0
        for ch in text:
            number = number * 58 + BTC_BASE58_ALPHABET.index(ch)
        zeros = len(text) - len(text.lstrip("1"))
        body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        decoded = b"\x00" * zeros + body
    except Exception:
        return None
    return decoded if len(decoded) >= 2 and _b58encode(decoded) == text else None


def decode_body_candidates(body: bytes, uri: str = "") -> list[tuple[bytes, str]]:
    """生成 HTTP/DNS 载荷的解码候选 ``(候选字节, 编码器名)``。

    覆盖 raw / base64 / base64url / Sliver 自定义 base64 / hex / gzip /
    变形 base32 / Bitcoin base58；同时把 URI query（尤其 ``_=``）与
    urlencoded body 中的值当作额外来源。英语词表与图片隐写编码器不做完整
    还原，只在有明确名字提示时以 ``unsupported:<name>`` 标注。
    """
    results: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()

    def add(data: bytes | None, name: str) -> None:
        if not data or len(results) >= MAX_CANDIDATES or data in seen:
            return
        seen.add(data)
        results.append((data, name))

    if body is None:
        return []
    try:
        if isinstance(body, (bytes, bytearray, memoryview)):
            raw = bytes(body)
        elif isinstance(body, str):
            raw = body.encode("utf-8", "replace")
        else:
            return []
    except Exception:
        return []

    sources: list[bytes] = [raw]
    unsupported_labels: list[str] = []
    try:
        query = urllib.parse.urlsplit(uri or "").query
        params = urllib.parse.parse_qs(query, keep_blank_values=False)
        # Sliver HTTP profile 常用 ``_=`` 携带 nonce/载荷；其余参数兜底。
        for key in ("_", "nonce", "n", "d", "data", "q"):
            for value in params.get(key, [])[:4]:
                sources.append(value.encode("utf-8", "replace"))
        for values in params.values():
            for value in values[:2]:
                sources.append(value.encode("utf-8", "replace"))
        for key in ("enc", "encoder", "e"):
            for value in params.get(key, []):
                lowered = value.lower()
                if lowered in ("english", "png", "jpeg", "jpg", "gif",
                               "image", "stego", "steganography"):
                    unsupported_labels.append("unsupported:" + lowered)
    except Exception:
        pass

    # 有明确“不支持的编码器”名字提示时，清楚标注原始载荷，避免被当成已解码。
    add(raw, unsupported_labels[0] if unsupported_labels else "raw")
    if raw.startswith(_GZIP_MAGIC):
        plain, ok = _safe_gunzip(raw)
        if ok:
            add(plain, "gzip")

    try:
        if b"=" in raw and len(raw) < 4096:
            form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"),
                                         keep_blank_values=False)
            for values in form.values():
                for value in values[:2]:
                    sources.append(value.encode("utf-8", "replace"))
    except Exception:
        pass

    decoders = (
        ("base64", lambda text: _b64decode(text)),
        ("base64url", lambda text: _b64decode(text, urlsafe=True)),
        ("custom-base64", lambda text: _b64decode(text, alphabet=SLIVER_BASE64_ALPHABET)),
        ("hex", _hexdecode),
        ("base32-sliver", _sliver_b32decode),
        ("base58", _b58decode),
    )
    for source in sources:
        if len(results) >= MAX_CANDIDATES:
            break
        if not source:
            continue
        if source.startswith(_GZIP_MAGIC):
            plain, ok = _safe_gunzip(source)
            if ok:
                add(plain, "gzip")
        text = source.decode("ascii", "ignore")
        if len(text) < 4:
            continue
        for name, decoder in decoders:
            try:
                decoded = decoder(text)
            except Exception:
                decoded = None
            if decoded:
                add(decoded, name)
    return results


# ---------------------------------------------------------------------------
# protobuf Envelope
# ---------------------------------------------------------------------------
def _read_varint(data: bytes, offset: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return None, offset


def parse_envelope(data: bytes) -> dict | None:
    """解析 Sliver ``Envelope``（ID=1, Type=2, Data=3, Unknown=4）。

    对未知字段与嵌套 protobuf 保持宽容：未知 wire type 0/1/2/5 直接跳过，
    Data 原样保留。没有任何已知字段时返回 ``None``。
    """
    try:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return None
        buf = bytes(data)
        if not buf:
            return None
        envelope = {"id": 0, "type": 0, "data": b"", "unknown": False}
        offset = 0
        known = 0
        while offset < len(buf):
            key, offset = _read_varint(buf, offset)
            if key is None or key == 0:
                break
            field, wire = key >> 3, key & 7
            if wire == 0:
                value, offset = _read_varint(buf, offset)
                if value is None:
                    break
                if field == 1:
                    envelope["id"] = value - (1 << 64) if value >= (1 << 63) else value
                    known += 1
                elif field == 2:
                    envelope["type"] = value & 0xFFFFFFFF
                    known += 1
                elif field == 4:
                    envelope["unknown"] = bool(value)
                    known += 1
            elif wire == 2:
                length, offset = _read_varint(buf, offset)
                if length is None or offset + length > len(buf):
                    break
                value = buf[offset:offset + length]
                offset += length
                if field == 3:
                    envelope["data"] = value
                    known += 1
            elif wire == 1:
                offset += 8
            elif wire == 5:
                offset += 4
            else:
                # group 等不支持的 wire type：停止解析，保留已读字段。
                break
            if offset > len(buf):
                break
        return envelope if known else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 密钥交换分类 / 报告摘要
# ---------------------------------------------------------------------------
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * math.log2(count / total)
                for count in Counter(data).values()) / 8.0


def _age_tail_score(tail: bytes) -> int:
    """Age v1 去掉 ``age-encryption.org/v1\\n-> X25519 `` 前缀后的特征分。"""
    lines = tail.split(b"\n", 4)
    score = 0
    if len(lines) >= 2 and re.fullmatch(rb"[A-Za-z0-9+/]{43}", lines[0].strip()):
        score += 1
    if len(lines) >= 3 and re.fullmatch(rb"[A-Za-z0-9+/]{43}", lines[1].strip()):
        score += 1
    if any(line.startswith(b"--- ") for line in lines[:5]):
        score += 1
    return score


def classify_key_exchange(blob: bytes, uri: str = "") -> dict | None:
    """识别 Sliver 密钥交换载荷（保守启发式）。

    返回 ``{"version", "kind", "confidence", "details"}``；无法识别返回 ``None``。
    """
    try:
        data = bytes(blob) if isinstance(blob, (bytes, bytearray, memoryview)) else b""
    except Exception:
        return None
    if len(data) < 16:
        return None
    details: list[str] = []
    lower_uri = (uri or "").lower()

    def result(version: str, kind: str, confidence: int) -> dict:
        return {
            "version": version,
            "kind": kind,
            "confidence": max(0, min(100, confidence)),
            "details": details,
        }

    # v1.6：Age / X25519（marker 可能被裁掉，只留下 32 字节 hash + age stanza）。
    if data.startswith(b"age-encryption.org/v1"):
        details.append("age-marker: full")
        return result("v1.6", "age-x25519", 95)
    if len(data) > 32:
        tail = data[32:]
        if tail.startswith(b"age-encryption.org/v1"):
            details.append("pubkey-hash: 32 bytes")
            details.append("age-marker: full-after-hash")
            return result("v1.6", "age-x25519", 92)
        if _age_tail_score(tail) >= 2:
            details.append("pubkey-hash: 32 bytes")
            details.append("age-marker: trimmed")
            confidence = 78
            if any(ext in lower_uri for ext in (".html", ".jsp", ".php")):
                confidence += 5
            return result("v1.6", "age-x25519", confidence)

    # v1.5：8 位 ASCII TOTP + 32 字节公钥 hash + NaCl sealed box（>=48 字节）。
    if len(data) >= 8 + 32 + 48 and data[:8].isdigit():
        details.append("totp: 8 ascii digits")
        details.append("pubkey-hash: 32 bytes")
        details.append("sealed-box: >=48 bytes")
        return result("v1.5", "totp-nacl-sealedbox", 90)

    # <=1.4：RSA / X.509 密钥交换。DER/PEM 是强特征；仅凭 RSA 长度则保守给分。
    if data.startswith(b"-----BEGIN") or data.startswith(b"\x30\x82"):
        details.append("rsa/x509 marker: DER/PEM")
        return result("<=1.4", "rsa-key-exchange", 85)
    if len(data) in (128, 192, 256, 384, 512) and _shannon_entropy(data) > 0.75:
        details.append("rsa-sized ciphertext: %d bytes" % len(data))
        confidence = 55
        if ".php" in lower_uri or "exchange" in lower_uri:
            confidence += 10
        return result("<=1.4", "rsa-key-exchange", confidence)
    return None


def _tlv_candidates(data: bytes) -> list[dict]:
    """保守探测 TLV 序列（整段必须被完整解析，至少两条记录）。"""
    best: list[dict] = []
    for tag_len, len_len in ((1, 1), (2, 2), (2, 4)):
        pairs: list[dict] = []
        offset = 0
        complete = True
        while offset + tag_len + len_len <= len(data):
            tag = int.from_bytes(data[offset:offset + tag_len], "big")
            offset += tag_len
            length = int.from_bytes(data[offset:offset + len_len], "big")
            offset += len_len
            if length == 0 or offset + length > len(data):
                complete = False
                break
            pairs.append({"tag": tag, "len": length})
            offset += length
            if len(pairs) >= 32:
                break
        if complete and len(pairs) >= 2 and offset == len(data) and len(pairs) > len(best):
            best = pairs
    return best


def sliver_summary(plaintext: bytes) -> dict:
    """为报告生成纯数据摘要：Envelope、可打印预览、flag 与（必要时）TLV。"""
    summary: dict = {"envelope": None, "text": "", "flags": [], "tlv_like": False}
    try:
        data = bytes(plaintext) if isinstance(plaintext, (bytes, bytearray, memoryview)) \
            else b""
    except Exception:
        return summary
    try:
        envelope = parse_envelope(data)
        summary["envelope"] = envelope
        preview = "".join(
            chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "."
            for byte in data[:512]
        )
        summary["text"] = preview
        flags = find_flags(preview)
        if not flags:
            try:
                flags = find_flags(data.decode("utf-8", "replace")[:4096])
            except Exception:
                flags = []
        summary["flags"] = flags
        if envelope is None:
            pairs = _tlv_candidates(data)
            if pairs:
                summary["tlv_like"] = True
                summary["tlv"] = pairs[:16]
    except Exception:
        return summary
    return summary
