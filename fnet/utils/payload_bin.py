"""提取出的二进制载荷（如 ICMP 隧道 ``icmp_tunnel_*.bin``）的分层分析器。

纯标准库、纯函数为主、全部有界，供 ``flows.icmp`` 等处理器对任意提取出的
二进制载荷做统一分析：

1. **画像**（:func:`profile`）：长度、熵、可打印率、16 字节对齐、文件
   magic 识别（PNG/JPEG/GIF/PDF/ZIP/GZIP/7Z/ELF/PE 等内置小表）；
2. **编码层剥离**（:func:`strip_layers`）：整段 base64/base64url/base32/
   hex/URL + gzip/zlib 解压，逐层尝试（复用
   :func:`fnet.utils.openssl_enc.decode_base64_candidates` 的思路与
   ``MAX_INFLATE_BYTES`` 上限，最多 :data:`MAX_LAYERS` 层），每层记录
   encoding 与产物长度；
3. **加密识别与解密尝试**（:func:`attempt_decryption`）：复用
   :func:`fnet.utils.openssl_enc.decrypt_bytes`，口令候选见
   :func:`default_passwords`（内置常见口令 + 从 ``icmp_tunnel_<src>_<dst>.bin``
   文件名提取的两段 IP + 真实样本相关口令），cipher = aes-128/256 的
   cbc/ctr/ecb，digest = md5/sha256（EVP_BytesToKey 派生，``openssl enc``
   经典 KDF），总尝试硬上限 :data:`MAX_ATTEMPTS`；命中判定 = 明文 ≥60%
   可打印或 :func:`fnet.utils.tunnel.find_flags` 命中；
4. **内容提取**（:func:`extract_content`）：对最终明文跑 flag 扫描、提取
   可打印字符串（前 N 条）、识别 magic（解密后可能是图片/压缩包）。

:func:`analyse_payload` 把四步组合成一个返回结构::

    {"profile": {...}, "layers": [...], "encrypted": bool,
     "decrypt": {命中配方或尝试次数},
     "content": {...明文/类型/flag/strings...}}

设计约束：不依赖第三方库、不调用子进程；对畸形输入永不抛异常，尝试
次数与解压体积全部有界，失败路径返回 ``hit=False`` 与尝试统计而不是
抛错。
"""
from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib

from fnet.utils import openssl_enc
from fnet.utils.tunnel import byte_profile, find_flags, find_flags_loose

#: 编码层剥离的最大层数（base64 → gzip → …）。
MAX_LAYERS = 3
#: 解密尝试硬上限：每个 (cipher, digest) 组合 × 全部口令按轮转展开，
#: 保证排在最后的口令（如文件名提取的 IP）也能试到最常见配方。
MAX_ATTEMPTS = 66
#: 内容提取最多返回多少条可打印字符串。
MAX_STRINGS = 16
#: 可打印字符串的最小/最大长度。
MIN_STRING_LEN = 6
MAX_STRING_LEN = 120
#: 明文文本预览的最大字符数。
MAX_PREVIEW_CHARS = 2000
#: 解压产物上限（与 openssl_enc.MAX_INFLATE_BYTES 保持一致）。
MAX_INFLATE_BYTES = openssl_enc.MAX_INFLATE_BYTES

#: 内置口令候选（按优先级排序；``fetus`` 来自真实样本 fetus_pcap.pcap）。
DEFAULT_PASSWORDS = (
    "", "icmp", "icmp_tunnel", "password", "123456", "admin",
    "toor", "flag", "ctf", "syclover",
)
#: 追加在文件名 IP 之后的样本相关口令。
TAIL_PASSWORDS = ("fetus",)

#: cipher 尝试顺序（常见度优先）。
CIPHERS = ("aes-256-cbc", "aes-128-cbc", "aes-256-ctr", "aes-128-ctr",
           "aes-256-ecb", "aes-128-ecb")
#: digest 尝试顺序（旧版 openssl 默认 md5，1.1.0+ 默认 sha256）。
DIGESTS = ("md5", "sha256")

#: magic 识别小表（顺序即优先级；``BM``/``MZ`` 有长度下限防误报）。
_MAGIC_TABLE = (
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP"),
    (b"\x1f\x8b", "GZIP"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"\x7fELF", "ELF"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"-----BEGIN ", "PEM"),
    (b"BM", "BMP"),
    (b"MZ", "PE"),
)
#: OpenSSL 盐化信封也算一种"类型"，但不能据此跳过解密尝试。
_MAGIC_PASS = ("OpenSSL-Salted",)

#: magic → 建议文件扩展名（解密/解压产物落盘用）。
EXT_BY_MAGIC = {
    "PNG": ".png", "JPEG": ".jpg", "GIF": ".gif", "PDF": ".pdf",
    "ZIP": ".zip", "GZIP": ".gz", "7Z": ".7z", "RAR": ".rar",
    "ELF": ".elf", "PE": ".exe", "BMP": ".bmp", "SQLite": ".db",
    "PEM": ".pem",
}

_B64_STD_RE = re.compile(rb"[A-Za-z0-9+/=]+")
_B64_URL_RE = re.compile(rb"[A-Za-z0-9_\-=]+")
_B32_RE = re.compile(rb"[A-Za-z2-7=]+")
_HEX_RE = re.compile(rb"[0-9a-fA-F]+")
_ZLIB_HEAD = (0x01, 0x5E, 0x9C, 0xDA)


# ---------------------------------------------------------------------------
# 画像
# ---------------------------------------------------------------------------
def detect_magic(data: bytes) -> str:
    """识别常见文件 magic；无法识别返回空串。永不抛异常。"""
    body = bytes(data or b"")
    if not body:
        return ""
    if body.startswith(b"Salted__"):
        return "OpenSSL-Salted"
    for magic, name in _MAGIC_TABLE:
        if not body.startswith(magic):
            continue
        # BM/MZ 只有 2 字节，需要足够长度才可信。
        if name in ("BMP", "PE") and len(body) < 14:
            continue
        return name
    return ""


def profile(data: bytes) -> dict:
    """载荷画像：长度/熵/可打印率/16 字节对齐/magic。"""
    info = byte_profile(bytes(data or b""))
    info["magic"] = detect_magic(data)
    return info


# ---------------------------------------------------------------------------
# 编码层剥离
# ---------------------------------------------------------------------------
def _inflate(data: bytes) -> bytes | None:
    """有界 zlib/gzip/raw-deflate 解压；失败返回 ``None``，永不抛异常。"""
    body = bytes(data or b"")
    if not body:
        return None
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS + 16):
        try:
            dec = zlib.decompressobj(wbits)
            out = dec.decompress(body, MAX_INFLATE_BYTES)
            if out:
                return out
        except (zlib.error, ValueError, TypeError):
            continue
        except Exception:  # noqa: BLE001 - 解压失败只是"不是 zlib"
            continue
    return None


def _try_inflate(data: bytes) -> tuple[str, bytes] | None:
    """按外层 gzip/zlib 魔数尝试解压一层。"""
    body = bytes(data or b"")
    if len(body) >= 2 and body[0] == 0x1F and body[1] == 0x8B:
        out = _inflate(body)
        if out:
            return ("gzip", out)
    if len(body) >= 2 and body[0] == 0x78 and body[1] in _ZLIB_HEAD:
        out = _inflate(body)
        if out:
            return ("zlib", out)
    return None


def _wrapped_body(data: bytes, alphabet: re.Pattern) -> bytes | None:
    """归一化候选编码体：单个连续 token，或 openssl ``-a`` 式等宽换行包裹。

    带有内部空白的普通句子（token 宽度不一）返回 ``None``，避免把
    "just plain text" 这类可读文本误剥成 base64。
    """
    raw = bytes(data or b"").strip()
    if not raw:
        return None
    if not re.search(rb"\s", raw):
        return raw
    tokens = raw.split()
    if len(tokens) < 2:
        return None
    widths = {len(token) for token in tokens[:-1]}
    if len(widths) != 1:
        return None
    width = widths.pop()
    if len(tokens[-1]) > width:
        return None
    if not all(alphabet.fullmatch(token) for token in tokens):
        return None
    return b"".join(tokens)


def _try_base64(data: bytes) -> tuple[str, bytes] | None:
    """结构化 base64/base64url 解码一层；不做可读性过滤（密文也要能剥）。"""
    body = _wrapped_body(bytes(data or b""), _B64_URL_RE)
    if not body or len(body) < 16 or len(body) > openssl_enc.MAX_B64_INPUT:
        return None
    for alphabet, label in ((_B64_STD_RE, "base64"),
                            (_B64_URL_RE, "base64-urlsafe")):
        if not alphabet.fullmatch(body):
            continue
        core = body.rstrip(b"=")
        if len(core) % 4 == 1:
            continue
        try:
            decoded = base64.b64decode(core + b"=" * (-len(core) % 4),
                                       validate=False)
        except (binascii.Error, ValueError, TypeError):
            continue
        except Exception:  # noqa: BLE001 - 解码路径不应把分析打挂
            continue
        if decoded and decoded != body:
            return (label, decoded)
    return None


def _try_base32(data: bytes) -> tuple[str, bytes] | None:
    body = _wrapped_body(bytes(data or b""), _B32_RE)
    if not body or len(body) < 16 or len(body) > openssl_enc.MAX_B64_INPUT:
        return None
    if not _B32_RE.fullmatch(body):
        return None
    core = body.upper().rstrip(b"=")
    if len(core) % 8 == 1:
        return None
    try:
        decoded = base64.b32decode(core + b"=" * (-len(core) % 8))
    except (binascii.Error, ValueError, TypeError):
        return None
    except Exception:  # noqa: BLE001
        return None
    if decoded and decoded != body:
        return ("base32", decoded)
    return None


def _try_hex(data: bytes) -> tuple[str, bytes] | None:
    body = _wrapped_body(bytes(data or b""), _HEX_RE)
    if not body or len(body) < 16 or len(body) % 2 \
            or len(body) > openssl_enc.MAX_B64_INPUT:
        return None
    if not _HEX_RE.fullmatch(body):
        return None
    try:
        decoded = bytes.fromhex(body.decode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None
    if decoded and decoded != body:
        return ("hex", decoded)
    return None


def _try_url(data: bytes) -> tuple[str, bytes] | None:
    body = bytes(data or b"").strip()
    if len(body) < 8 or b"%" not in body:
        return None
    if not re.search(rb"%[0-9A-Fa-f]{2}", body):
        return None
    try:
        decoded = urllib.parse.unquote_to_bytes(
            body.decode("utf-8", "replace"))
    except (UnicodeDecodeError, ValueError):
        return None
    if decoded and decoded != body:
        return ("url", decoded)
    return None


def _next_decode(data: bytes) -> tuple[str, bytes] | None:
    """对当前层尝试一次编码剥离：gzip/zlib → base64 → base32 → hex → URL。"""
    body = bytes(data or b"")
    if not body:
        return None
    magic = detect_magic(body)
    if magic and magic not in ("GZIP", "OpenSSL-Salted"):
        return None  # 已经是真实文件（PNG/ZIP/PDF…），不再剥
    for attempt in (_try_inflate, _try_base64, _try_base32, _try_hex,
                    _try_url):
        result = attempt(body)
        if result is not None:
            return result
    return None


def _looks_encrypted(data: bytes) -> bool:
    """均匀不可读字节判定（与 tunnel 的加密判定同一阈值）：熵 ≥7.5、
    可打印率 <0.5、长度 ≥32。"""
    info = byte_profile(bytes(data or b""))
    return (info["length"] >= 32 and info["printable_ratio"] < 0.5
            and info["entropy"] >= 7.5)


def _has_envelope(data: bytes) -> bool:
    """是否带 OpenSSL ``Salted__``/``U2FsdGVkX1`` 信封。"""
    body = bytes(data or b"")
    if not body:
        return False
    try:
        return (openssl_enc.detect_envelope(body, salt_len=8) is not None
                or openssl_enc.detect_envelope(body, salt_len=16) is not None)
    except Exception:  # noqa: BLE001 - 探测失败按"无信封"处理
        return False


def strip_layers(data: bytes) -> tuple[list[dict], bytes]:
    """逐层剥离编码（最多 :data:`MAX_LAYERS` 层）。

    返回 ``(layers, body)``：``layers`` 每项
    ``{"layer", "encoding", "in_bytes", "out_bytes"}``；``body`` 是剥完
    之后应进入解密尝试/内容提取的最终载荷。遇到均匀密文或真实文件
    （magic）即停止——密文交给解密尝试，文件直接报告类型。
    """
    current = bytes(data or b"")
    layers: list[dict] = []
    for depth in range(MAX_LAYERS):
        if not current or _looks_encrypted(current):
            break
        nxt = _next_decode(current)
        if nxt is None:
            break
        encoding, decoded = nxt
        layers.append({"layer": depth + 1, "encoding": encoding,
                       "in_bytes": len(current), "out_bytes": len(decoded)})
        current = decoded
    return layers, current


# ---------------------------------------------------------------------------
# 口令候选
# ---------------------------------------------------------------------------
def _ips_from_name(name: str) -> list[str]:
    """从 ``icmp_tunnel_<src>_<dst>.bin`` 这类文件名提取两段 IP。"""
    return re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", str(name or ""))


def default_passwords(name: str = "", extra: list[str] | None = None) -> list[str]:
    """口令候选：内置常见口令 + 文件名里的 IP + 样本相关口令（去重保序）。"""
    out: list[str] = []
    for pw in DEFAULT_PASSWORDS:
        if pw not in out:
            out.append(pw)
    for ip in _ips_from_name(name):
        if ip not in out:
            out.append(ip)
    for pw in TAIL_PASSWORDS:
        if pw not in out:
            out.append(pw)
    for pw in extra or []:
        text = str(pw)
        if text not in out:
            out.append(text)
    return out


#: 从流量正文里挖口令的启发式模式（password=xxx / pwd: xxx / key=xxx）。
_PASSWORD_HINT_RE = re.compile(
    r"(?i)(?:pass(?:word|wd)?|pwd|secret|token|key)\s*[=:]\s*"
    r"[\"']?([\x21-\x7e]{3,32})")
#: HTTP Basic 认证头（base64(user:pass)）。
_BASIC_AUTH_RE = re.compile(
    r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})")
#: 口令挖掘只读抓包前 8MB，避免大文件拖慢分析。
MAX_MINE_BYTES = 8 * 1024 * 1024


def mine_passwords(data: bytes, limit: int = 20) -> list[str]:
    """从抓包/文本里挖候选口令（供隧道载荷自动解密复用）。

    只做两件低误报的事：``password=...`` 这类键值对、HTTP Basic 头里
    的明文口令。结果有界且去重，作为 :func:`default_passwords` 之后的
    追加候选。
    """
    text = bytes(data or b"")[:MAX_MINE_BYTES].decode("latin-1", "ignore")
    out: list[str] = []
    for match in _PASSWORD_HINT_RE.finditer(text):
        value = match.group(1).strip("\"'")
        if value and value not in out:
            out.append(value)
        if len(out) >= limit:
            return out
    for match in _BASIC_AUTH_RE.finditer(text):
        token = match.group(1)
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4))
        except (binascii.Error, ValueError):
            continue
        _, _, password = raw.decode("utf-8", "replace").partition(":")
        if password and password not in out:
            out.append(password)
        if len(out) >= limit:
            break
    return out[:limit]


# ---------------------------------------------------------------------------
# 解密尝试
# ---------------------------------------------------------------------------
def _is_hit(plain: bytes) -> bool:
    """命中判定：明文 ≥60% 可打印或 flag 命中。"""
    body = bytes(plain or b"")
    if not body:
        return False
    if find_flags(body) or find_flags_loose(body):
        return True
    return byte_profile(body)["printable_ratio"] >= 0.60


def recipe_text(cipher: str, digest: str, *, salted: bool = True,
                base64_input: bool = False,
                password: str = "<口令>") -> str:
    """生成可直接复制的 ``openssl enc`` 解密命令示例。

    ``base64_input`` 表示载荷本身是 Base64 文本（对应 ``-a -A``）；
    ``salted=False`` 对应 ``-nosalt``（无 ``Salted__`` 头的原始密文）。
    """
    parts = ["openssl enc -d", f"-{cipher}", f"-md {digest}"]
    if not salted:
        parts.append("-nosalt")
    if base64_input:
        parts.append("-a -A")
    parts.append("-in <载荷.bin>")
    parts.append(f"-pass pass:{password}")
    return " ".join(parts)


def attempt_decryption(data: bytes, passwords: list[str],
                       *, base64_input: bool = False) -> dict:
    """有界 ``openssl enc`` 兼容自动解密尝试。

    (cipher, digest) 组合外层 × 口令内层轮转展开，保证列表末尾的口令
    （如文件名提取的 IP）也能试到最常见配方；总次数不超过
    :data:`MAX_ATTEMPTS`。盐值情形：带 ``Salted__`` 头取嵌入 salt
    （saltlen 8 优先、16 兜底），否则按 ``-nosalt``（空 salt）。
    KDF 固定 EVP_BytesToKey（``openssl enc`` 经典行为，与命令示例的
    ``-md`` 语义一致）。

    返回 ``{"hit", "attempts", "exhausted"}``；命中时追加
    ``password/cipher/digest/salted/recipe/plaintext/printable_ratio/
    flags``；未命中时附 ``example_command`` 供上层做可操作指引。
    """
    body = bytes(data or b"")
    result: dict = {"hit": False, "attempts": 0, "exhausted": False,
                    "recipes": len(CIPHERS) * len(DIGESTS),
                    "passwords": len(passwords)}
    if not body:
        result["skipped"] = "空载荷"
        return result

    # 盐值情形：嵌入头优先；无头按 -nosalt 处理。
    envelope = None
    try:
        envelope = (openssl_enc.detect_envelope(body, salt_len=8)
                    or openssl_enc.detect_envelope(body, salt_len=16))
    except Exception:  # noqa: BLE001
        envelope = None
    if envelope is not None and envelope.ciphertext:
        salt_cases = [(envelope.salt, envelope.ciphertext, True)]
    else:
        salt_cases = [(b"", body, False)]
    salted = salt_cases[0][2]

    combos = [(cipher, digest) for cipher in CIPHERS for digest in DIGESTS]
    for cipher, digest in combos:
        info = openssl_enc.parse_cipher(cipher)
        if info["mode"] == "unknown":
            continue
        for password in passwords:
            if result["attempts"] >= MAX_ATTEMPTS:
                result["exhausted"] = True
                result["example_command"] = recipe_text(
                    combos[0][0], combos[0][1], salted=salted,
                    base64_input=base64_input)
                return result
            result["attempts"] += 1
            for salt, ciphertext, with_salt in salt_cases:
                try:
                    key, iv = openssl_enc.derive_key_iv(
                        password, salt, key_len=info["key_len"],
                        iv_len=info["iv_len"], kdf="evp", digest=digest)
                except ValueError:
                    continue
                except Exception:  # noqa: BLE001 - 单条候选失败不影响整体
                    continue
                plain = openssl_enc.decrypt_bytes(
                    ciphertext, key, iv, mode=info["mode"],
                    key_len=info["key_len"])
                if plain is not None and _is_hit(plain):
                    info_prof = byte_profile(plain)
                    result.update(
                        hit=True, password=password, cipher=cipher,
                        digest=digest, salted=with_salt,
                        recipe=recipe_text(cipher, digest, salted=with_salt,
                                           base64_input=base64_input,
                                           password=password),
                        plaintext=plain,
                        printable_ratio=info_prof["printable_ratio"],
                        flags=find_flags(plain))
                    return result
    result["exhausted"] = result["attempts"] >= MAX_ATTEMPTS
    result["example_command"] = recipe_text(
        combos[0][0], combos[0][1], salted=salted, base64_input=base64_input)
    return result


# ---------------------------------------------------------------------------
# 定向解密（WebUI 破解按钮）
# ---------------------------------------------------------------------------
#: 用户指定配方时最多尝试的口令数（防止粘贴超大字典把服务卡住）。
MAX_USER_PASSWORDS = 5000


def _salt_cases(body: bytes, salted: bool | None
                ) -> tuple[list[tuple[bytes, bytes, bool]], str]:
    """按用户的“有盐/无盐/自动”选择返回 (salt, ciphertext, with_salt) 列表。"""
    envelope = None
    try:
        envelope = (openssl_enc.detect_envelope(body, salt_len=8)
                    or openssl_enc.detect_envelope(body, salt_len=16))
    except Exception:  # noqa: BLE001 - 探测失败按无信封处理
        envelope = None
    if salted is True and envelope is None:
        return [], "载荷没有 OpenSSL 盐头（Salted__），请改为自动或勾选无盐（-nosalt）"
    if salted is False:
        return [(b"", body, False)], ""
    if envelope is not None and envelope.ciphertext:
        return [(envelope.salt, envelope.ciphertext, True)], ""
    return [(b"", body, False)], ""


def crack_payload(data: bytes, name: str = "",
                  passwords: list[str] | None = None,
                  cipher: str | None = None, digest: str | None = None,
                  salted: bool | None = None,
                  base64_input: bool = False) -> dict:
    """按用户口令/配方做定向解密（WebUI 结果详情里的“破解”按钮）。

    - 指定 ``cipher`` + ``digest``：只跑该组合，口令列表按顺序尝试（上限
      :data:`MAX_USER_PASSWORDS`），适合“题目给了口令但不知道算法”；
    - 未指定：回落到 :func:`attempt_decryption` 的常见配方电池
      （AES-128/256 × cbc/ctr/ecb × md5/sha256，上限
      :data:`MAX_ATTEMPTS`）。

    返回结构与 :func:`attempt_decryption` 一致，额外带 ``recipe`` /
    ``plaintext`` / ``flags``；失败时带 ``example_command``。
    """
    body = bytes(data or b"")
    candidates = [str(pw) for pw in (passwords or [])][:MAX_USER_PASSWORDS]
    if not candidates:
        candidates = default_passwords(name)
    if not body:
        return {"hit": False, "attempts": 0, "exhausted": False,
                "skipped": "空载荷"}
    if not cipher or not digest:
        return attempt_decryption(body, candidates,
                                  base64_input=base64_input)

    cipher = str(cipher).strip().lower()
    digest = str(digest).strip().lower()
    info = openssl_enc.parse_cipher(cipher)
    result: dict = {"hit": False, "attempts": 0, "exhausted": False,
                    "cipher": cipher, "digest": digest,
                    "passwords": len(candidates)}
    if info["mode"] == "unknown":
        result["error"] = f"不支持的 cipher: {cipher}"
        return result
    salt_cases, error = _salt_cases(body, salted)
    if error:
        result["error"] = error
        return result
    result["salted"] = salt_cases[0][2]
    for password in candidates:
        if result["attempts"] >= MAX_USER_PASSWORDS:
            result["exhausted"] = True
            break
        result["attempts"] += 1
        for salt, ciphertext, with_salt in salt_cases:
            try:
                key, iv = openssl_enc.derive_key_iv(
                    password, salt, key_len=info["key_len"],
                    iv_len=info["iv_len"], kdf="evp", digest=digest)
            except Exception:  # noqa: BLE001 - 单条候选失败不影响整体
                continue
            plain = openssl_enc.decrypt_bytes(
                ciphertext, key, iv, mode=info["mode"],
                key_len=info["key_len"])
            if plain is None or not _is_hit(plain):
                continue
            profile = byte_profile(plain)
            result.update(
                hit=True, password=password, salted=with_salt,
                recipe=recipe_text(cipher, digest, salted=with_salt,
                                   base64_input=base64_input,
                                   password=password),
                plaintext=plain,
                printable_ratio=profile["printable_ratio"],
                flags=find_flags(plain) or find_flags_loose(plain))
            return result
    result["example_command"] = recipe_text(
        cipher, digest, salted=result.get("salted", True),
        base64_input=base64_input)
    return result


# ---------------------------------------------------------------------------
# 内容提取
# ---------------------------------------------------------------------------
def extract_content(data: bytes) -> dict:
    """内容提取：flag / 可打印字符串（前 N 条）/ magic / 文本预览。"""
    body = bytes(data or b"")
    info = byte_profile(body)
    flags: list[str] = []
    for flag in (find_flags(body) or find_flags_loose(body)):
        if flag not in flags:
            flags.append(flag)
    strings: list[str] = []
    for match in re.finditer(rb"[ -~]{%d,}" % MIN_STRING_LEN, body):
        text = match.group(0).decode("ascii", "replace")[:MAX_STRING_LEN]
        if text not in strings and text not in flags:
            strings.append(text)
        if len(strings) >= MAX_STRINGS:
            break
    magic = detect_magic(body)
    text = None
    if info["printable_ratio"] >= 0.60:
        text = body.decode("utf-8", "replace")[:MAX_PREVIEW_CHARS]
    return {
        "size": info["length"],
        "printable_ratio": info["printable_ratio"],
        "entropy": info["entropy"],
        "magic": magic,
        "suggested_ext": EXT_BY_MAGIC.get(magic, ""),
        "flags": flags,
        "strings": strings,
        "text": text,
    }


# ---------------------------------------------------------------------------
# 顶层组合
# ---------------------------------------------------------------------------
def analyse_payload(data: bytes, name: str = "",
                    password_candidates: list[str] | None = None) -> dict:
    """对任意提取出的二进制载荷做分层分析（画像→编码剥离→解密→内容）。

    ``name`` 通常是落盘文件名（如 ``icmp_tunnel_<src>_<dst>.bin``），
    其中的 IP 会并入口令候选。返回结构见模块 docstring；任何输入都
    不会抛异常。
    """
    raw = bytes(data or b"")
    prof = profile(raw)
    layers, body = strip_layers(raw)
    passwords = default_passwords(name, extra=password_candidates)
    # 载荷本身是 Base64 文本时，命令示例需要 -a -A（openssl 自己解码）。
    base64_input = bool(layers) and str(layers[0].get("encoding", "")).startswith("base64")

    body_magic = detect_magic(body)
    is_file = bool(body_magic) and body_magic not in _MAGIC_PASS
    if _has_envelope(body):
        decrypt = attempt_decryption(body, passwords, base64_input=base64_input)
    elif is_file:
        decrypt = {"hit": False, "attempts": 0, "exhausted": False,
                   "skipped": f"已识别文件类型 {body_magic}，无需解密尝试"}
    elif _looks_encrypted(body):
        decrypt = attempt_decryption(body, passwords, base64_input=base64_input)
    else:
        decrypt = {"hit": False, "attempts": 0, "exhausted": False,
                   "skipped": "载荷不是高熵密文"}

    if decrypt.get("hit"):
        final = bytes(decrypt.get("plaintext") or b"")
        encrypted = True
    else:
        final = body
        encrypted = not is_file and (_has_envelope(body)
                                     or _looks_encrypted(body))
    content = extract_content(final)
    return {
        "profile": prof,
        "layers": layers,
        "encrypted": encrypted,
        "decrypt": decrypt,
        "content": content,
    }
