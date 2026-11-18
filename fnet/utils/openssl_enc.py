"""纯标准库实现的 OpenSSL ``enc`` 封装解析与解密核心。

``openssl enc`` 的 "Salted__" 封装只携带 8 字节 ASCII 魔数与 salt，
**不记录** cipher/KDF/摘要/迭代次数；魔数后面就是密文。使用 ``-a/-A`` 时
整个封装会被 Base64 编码（盐的输出总是以 ``U2FsdGVkX1`` 开头）。

关于显式 ``-S`` salt（OpenSSL 官方 enc 文档）：

* OpenSSL 1.1.1 及更早：显式 ``-S`` salt **会**随 ``Salted__`` 头一起写入；
* OpenSSL 3.0 起：显式 ``-S`` salt **不**写入密文，解密时必须再次显式提供。

因此 :func:`detect_envelope` 在带 ``spec``（含 ``salt_hex``/``salt``）时可
在无魔数的原始数据上合成信封；:func:`decrypt_envelope` 同时尝试嵌入头与
显式 salt 两种情形。

默认值（与官方 enc 文档一致）：``-md`` 自 1.1.0 起为 SHA-256（旧 CTF 常为
MD5，故两者都试）；``-saltlen`` 默认 8、最大 16；``-pbkdf2`` 默认 10000 次；
``-a -A`` 表示单行 Base64。真实 CLI 的 ``-z`` 输出可能是
``zlib(Salted__ + salt + AES(...))``，故解析前先做一次有界 inflate。

本模块只提供解析/解密原语，由 feature handler 组合使用：

* :func:`detect_envelope`       —— 识别 raw / Base64 盐化封装；
* :func:`derive_key_iv`         —— EVP_BytesToKey 或 PBKDF2 派生；
* :func:`decrypt_bytes`         —— AES CBC/ECB/CTR 解密（复用 ``crypto.py``）；
* :func:`recipe_candidates`     —— 有界的参数组合（KDF/摘要/迭代/salt 长度/cipher）；
* :func:`classify_payload`      —— 纯启发式判断明文可信度；
* :func:`decrypt_envelope`      —— 顶层一键尝试，返回首个可信明文。

设计约束：不依赖第三方库、不调用子进程；对畸形输入永不抛异常，只在
"程序员错误"（非法 digest/KDF 名称等）时抛 ``ValueError``，由上层捕获。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from dataclasses import asdict, dataclass

from fnet.utils.crypto import (
    aes_cbc_decrypt,
    aes_ctr_crypt,
    aes_ecb_decrypt,
    evp_bytes_to_key,
)

# ---------------------------------------------------------------------------
# 常量 / 数据结构
# ---------------------------------------------------------------------------
ENVELOPE_MAGIC = b"Salted__"
BASE64_MAGIC = "U2FsdGVkX1"

#: 默认的 Base64 输入上限，避免把大型 pcap 落盘文件整个塞进解码器。
MAX_B64_INPUT = 2 * 1024 * 1024
#: ``decode_base64_candidates`` 最多返回多少个候选。
MAX_B64_CANDIDATES = 8
#: ``recipe_candidates`` 默认上限。
MAX_RECIPES = 24

_BASE64_ALPHABET_RE = re.compile(rb"[A-Za-z0-9+/=_-]+")
_WS_RE = re.compile(rb"\s+")


@dataclass
class OpenSslEnvelope:
    """解析后的 OpenSSL ``enc`` 封装。

    ``salt`` 为空且 ``salted=False`` 时表示 ``-nosalt``（调用方合成）。
    ``encoding`` 为 ``raw`` 或 ``base64``；``marker`` 记录识别到的标记
    （``Salted__`` / ``U2FsdGVkX1``）。``trailing`` 保留 Base64 正文之后
    的非 Base64 尾巴（正常文件为空）。
    """

    salt: bytes
    ciphertext: bytes
    salted: bool
    encoding: str
    salt_len: int
    marker: str
    trailing: bytes = b""


# ---------------------------------------------------------------------------
# Base64 候选
# ---------------------------------------------------------------------------
def _decode_one(chunk: bytes, *, urlsafe: bool) -> bytes | None:
    """尽力解码一段 Base64；失败返回 ``None``，绝不抛异常。"""
    if not chunk:
        return None
    try:
        clean = _WS_RE.sub(b"", chunk)
        if urlsafe:
            clean = clean.replace(b"-", b"+").replace(b"_", b"/")
        # 补齐到 4 的倍数；validate=False 容忍非字母字符。
        clean += b"=" * (-len(clean) % 4)
        return base64.b64decode(clean, validate=False)
    except (binascii.Error, ValueError, TypeError):
        return None
    except Exception:  # noqa: BLE001 - 解码路径永远不应把 handler 打挂
        return None


def decode_base64_candidates(data: bytes) -> list[tuple[bytes, str]]:
    """返回 ``(解码字节, 标签)`` 候选列表：原文 + 标准/urlsafe Base64。

    * 去除空白与换行；支持 ``-a``（每 64 字符换行）与 ``-A``（单行）。
    * 若输入中嵌有 ``U2FsdGVkX1``，额外从该偏移开始解码（处理文本里内嵌
      的 Base64 块）。
    * 去重、限量、永不抛异常。
    """
    out: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()

    def add(raw: bytes | None, label: str) -> None:
        if raw and raw not in seen and len(out) < MAX_B64_CANDIDATES:
            seen.add(raw)
            out.append((raw, label))

    if not isinstance(data, (bytes, bytearray)):
        return out
    raw = bytes(data)
    if not raw:
        return out
    add(raw, "raw")
    if len(raw) > MAX_B64_INPUT:
        return out

    cleaned = _WS_RE.sub(b"", raw)
    starts = [0]
    offset = cleaned.find(BASE64_MAGIC.encode("ascii"))
    if offset > 0:
        starts.append(offset)
    run = _BASE64_ALPHABET_RE.match(cleaned)
    run_bytes = run.group(0) if run else b""

    for start in starts:
        chunk = cleaned[start:] if start else cleaned
        add(_decode_one(chunk, urlsafe=False), "base64")
        add(_decode_one(chunk, urlsafe=True), "base64-urlsafe")
    if run_bytes and run_bytes != cleaned:
        add(_decode_one(run_bytes, urlsafe=False), "base64-run")
        add(_decode_one(run_bytes, urlsafe=True), "base64-run-urlsafe")
    return out


# ---------------------------------------------------------------------------
# 有界 zlib inflate（enc -z 的真实 CLI 行为：外层 zlib 包裹整个 Salted__ 信封）
# ---------------------------------------------------------------------------
MAX_INFLATE_BYTES = 8 * 1024 * 1024


def _looks_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    return (data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA)) \
        or data[:2] == b"\x1f\x8b"


def _safe_inflate(data: bytes, limit: int = MAX_INFLATE_BYTES) -> bytes | None:
    """安全解压 zlib/gzip/raw-deflate；失败或超限返回 ``None``，永不抛异常。

    真实 ``openssl enc -z`` 输出可能以 ``78 9c ... 53 61 6c 74 65 64 5f 5f``
    开头（先 zlib 压缩再封装），因此必须在查找 ``Salted__`` 之前尝试 inflate。
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    body = bytes(data)
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS + 16):
        try:
            # 注意：decompressobj.decompress 的第二个参数才是 max_length；
            # zlib.decompress 的第二个参数是 wbits，不要传 limit 给它。
            dec = zlib.decompressobj(wbits)
            out = dec.decompress(body, limit)
            if out:
                return out
        except (zlib.error, ValueError, TypeError):
            continue
        except Exception:  # noqa: BLE001 - 解压失败只是"不是 zlib"
            continue
    return None


# ---------------------------------------------------------------------------
# 封装识别
# ---------------------------------------------------------------------------
def _explicit_salt(values: dict | None) -> bytes | None:
    """从 ``spec`` / recipe 中读取显式 ``-S`` salt（hex 或原始字符串）。"""
    if not isinstance(values, dict):
        return None
    salt_hex = values.get("salt_hex") or ""
    if salt_hex:
        try:
            cleaned = re.sub(r"(?i)0x|[\s:,-]", "", str(salt_hex))
            raw = bytes.fromhex(cleaned) if cleaned else b""
            if raw:
                return raw
        except (ValueError, TypeError):
            pass
    plain = values.get("salt")
    if isinstance(plain, (bytes, bytearray)):
        return bytes(plain) or None
    if isinstance(plain, str) and plain:
        return plain.encode("utf-8")
    return None


def _detect_inner(raw: bytes, salt_len: int,
                  spec: dict | None) -> OpenSslEnvelope | None:
    """在已（可选）inflate 过的数据上查找标记，不含外层 zlib 处理。"""
    # 1) 原始封装
    if raw.startswith(ENVELOPE_MAGIC) and len(raw) >= len(ENVELOPE_MAGIC) + salt_len:
        start = len(ENVELOPE_MAGIC)
        return OpenSslEnvelope(
            salt=raw[start:start + salt_len],
            ciphertext=raw[start + salt_len:],
            salted=True,
            encoding="raw",
            salt_len=salt_len,
            marker=ENVELOPE_MAGIC.decode("ascii"),
        )

    # 2) Base64 封装（魔数被编码为 U2FsdGVkX1）
    for decoded, _label in decode_base64_candidates(raw):
        if not decoded.startswith(ENVELOPE_MAGIC):
            continue
        start = len(ENVELOPE_MAGIC)
        if len(decoded) < start + salt_len:
            continue
        trailing = b""
        cleaned = _WS_RE.sub(b"", raw)
        match = _BASE64_ALPHABET_RE.match(cleaned)
        if match and match.end() < len(cleaned):
            trailing = cleaned[match.end():]
        return OpenSslEnvelope(
            salt=decoded[start:start + salt_len],
            ciphertext=decoded[start + salt_len:],
            salted=True,
            encoding="base64",
            salt_len=salt_len,
            marker=BASE64_MAGIC,
            trailing=trailing,
        )

    # 3) 显式 -S：OpenSSL 3.x 不写魔数，salt 由 spec 提供。
    explicit = _explicit_salt(spec)
    if explicit is not None:
        body, encoding = raw, "raw"
        if isinstance(spec, dict) and spec.get("base64"):
            for decoded, label in decode_base64_candidates(raw):
                if label != "raw" and decoded:
                    body, encoding = decoded, "base64"
                    break
        if body:
            return OpenSslEnvelope(
                salt=explicit,
                ciphertext=body,
                salted=False,  # 没有嵌入的魔数头
                encoding=encoding,
                salt_len=len(explicit),
                marker="explicit-S",
            )
    return None


def detect_envelope(data: bytes, *, salt_len: int = 8,
                    spec: dict | None = None) -> OpenSslEnvelope | None:
    """识别 ``Salted__ + salt + ciphertext``（raw 或 Base64）；无标记返回 ``None``。

    ``-nosalt`` 没有标记，本函数默认不会猜测：调用方通过
    :func:`decrypt_envelope` 的 ``spec['nosalt']`` 显式声明。

    例外：当 ``spec`` 提供 ``salt_hex``/``salt``（显式 ``-S``）时，OpenSSL 3.x
    不写入魔数，此时从原始/Base64 数据合成一个 ``marker="explicit-S"`` 的
    信封，以便 ``decrypt_envelope`` 用同一 salt 解密。

    真实 CLI 的 ``-z`` 还会在整个信封外面再套一层 zlib（解压后才是
    ``Salted__``），因此先做一次**有界** inflate，再查找标记。
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    raw = bytes(data)
    if not raw:
        return None
    try:
        # enc 文档：saltlen 默认 8、最大 16；留一点余量以免畸形输入被误砍。
        salt_len = max(0, min(int(salt_len), 16))
    except (TypeError, ValueError):
        salt_len = 8

    # 先尝试外层 zlib（78 9c ... Salted__），成功则以解压结果为准。
    inflated = _safe_inflate(raw)
    if inflated and inflated != raw:
        env = _detect_inner(inflated, salt_len, spec)
        if env is not None:
            return env
    return _detect_inner(raw, salt_len, spec)


# ---------------------------------------------------------------------------
# cipher 名称 / 密钥派生 / 解密
# ---------------------------------------------------------------------------
def parse_cipher(name: str) -> dict:
    """把 ``aes-256-cbc`` / ``aes128ctr`` / ``-aes-192-ecb`` / ``AES_256_CBC``
    归一化为 ``{"name", "key_len", "mode", "iv_len"}``。

    无法识别（如 DES/3DES/Camellia/GCM）时返回 ``mode="unknown"``、
    ``key_len=0``、``iv_len=0`` 而不抛异常，由调用方明确报告"不支持"。
    ``openssl enc`` 本身不支持 GCM/CCM，这里也不会假装支持。
    """
    text = "" if name is None else str(name)
    lowered = text.lower().lstrip("-").replace("_", "-")
    compact = re.sub(r"[^a-z0-9]", "", lowered)
    result = {"name": lowered or "unknown", "key_len": 0,
              "mode": "unknown", "iv_len": 0}
    if "aes" not in compact:
        return result
    # enc 不支持 GCM/CCM 等 AEAD（也没有认证 tag 的概念），明确报告不支持。
    if any(token in compact for token in (
            "gcm", "ccm", "ocb", "eax", "chacha", "des", "camellia",
            "blowfish", "cast", "idea", "seed", "rc4")):
        return result

    key_len = 32  # 未写明位数时按 OpenSSL 常用 aes-256 处理
    for bits in (128, 192, 256):
        if str(bits) in compact:
            key_len = bits // 8
            break
    mode = "cbc"
    for candidate in ("ctr", "ecb", "cbc"):
        if candidate in compact:
            mode = candidate
            break
    result["name"] = f"aes-{key_len * 8}-{mode}"
    result["key_len"] = key_len
    result["mode"] = mode
    result["iv_len"] = 0 if mode == "ecb" else 16
    return result


def _normalize_digest(digest: str) -> str:
    """``sha-256`` / ``SHA256`` -> ``sha256``，``sha`` -> ``sha1``。"""
    value = (digest or "md5").lower().strip()
    value = value.replace("-", "").replace("_", "")
    return {"sha": "sha1"}.get(value, value) or "md5"


def derive_key_iv(password, salt, *, key_len: int = 32, iv_len: int = 16,
                  kdf: str = "evp", digest: str = "md5",
                  iterations: int = 1) -> tuple[bytes, bytes]:
    """派生 ``(key, iv)``。

    * ``kdf='evp'`` 委托给 :func:`fnet.utils.crypto.evp_bytes_to_key`
      （OpenSSL <=1.0 的传统算法，``enc`` 的 count 固定为 1）。
    * ``kdf='pbkdf2'`` 使用 ``hashlib.pbkdf2_hmac``，覆盖 key+iv 后切分。

    ``password`` 接受 ``str``（按 UTF-8）或 ``bytes``。长度/摘要/KDF 非法时
    抛 ``ValueError``（程序员错误）；上层批量解密会捕获并跳过。
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not isinstance(password, (bytes, bytearray)):
        raise ValueError("password 必须是 str 或 bytes")
    password = bytes(password)
    salt_bytes = b"" if salt is None else bytes(salt)
    key_len, iv_len = int(key_len), int(iv_len)
    if key_len < 0 or iv_len < 0 or key_len + iv_len <= 0:
        raise ValueError("无效的 key_len/iv_len")

    dgst = _normalize_digest(digest)
    kind = (kdf or "evp").lower().replace("_", "-")
    if kind == "evp":
        return evp_bytes_to_key(password, salt_bytes or None,
                                key_len, iv_len, dgst)
    if kind in ("pbkdf2", "pbkdf2-hmac", "pbkdf2_hmac"):
        rounds = int(iterations)
        if rounds < 1:
            raise ValueError("iterations 必须 >= 1")
        material = hashlib.pbkdf2_hmac(dgst, password, salt_bytes, rounds,
                                       key_len + iv_len)
        return material[:key_len], material[key_len:key_len + iv_len]
    raise ValueError(f"不支持的 KDF: {kdf}")


def _strict_unpad(data: bytes, block: int = 16) -> bytes | None:
    """严格 PKCS#7 去填充；填充非法返回 ``None``（不是原样返回）。"""
    if not data:
        return b""
    pad = data[-1]
    if 1 <= pad <= block and len(data) >= pad and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return None


def decrypt_bytes(ciphertext, key, iv, *, mode: str = "cbc",
                  key_len: int = 32, unpad: bool = True) -> bytes | None:
    """AES CBC/ECB/CTR 解密；任何失败返回 ``None``，永不抛异常。

    * CBC/ECB 默认严格校验 PKCS#7；填充错误返回 ``None``。
      ``unpad=False`` 对应显式 ``-nopad``。
    * CTR 把 16 字节 ``iv`` 当作初始 big-endian 计数器（CTR 无需填充）。
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        return None
    body = bytes(ciphertext)
    if not body:
        return b""
    if not isinstance(key, (bytes, bytearray)) or not isinstance(iv, (bytes, bytearray)):
        return None
    key_bytes, iv_bytes = bytes(key), bytes(iv)
    if key_len <= 0 or len(key_bytes) not in (16, 24, 32):
        return None
    try:
        kind = (mode or "cbc").lower()
        if kind == "ctr":
            if len(iv_bytes) != 16:
                return None
            return aes_ctr_crypt(body, key_bytes, iv_bytes)
        if len(body) % 16:
            return None
        if kind == "ecb":
            raw = aes_ecb_decrypt(body, key_bytes, unpad=False)
        elif kind == "cbc":
            if len(iv_bytes) != 16:
                return None
            raw = aes_cbc_decrypt(body, key_bytes, iv_bytes, unpad=False)
        else:
            return None
        if not unpad:
            return raw
        return _strict_unpad(raw, 16)
    except (ValueError, IndexError, TypeError):
        return None
    except Exception:  # noqa: BLE001 - 错误密钥往往在这里炸，静默跳过
        return None


# ---------------------------------------------------------------------------
# 参数组合（recipe）
# ---------------------------------------------------------------------------
DEFAULT_RECIPE: dict = {
    "cipher": "aes-256-cbc",
    "key_len": 32,
    "mode": "cbc",
    "iv_len": 16,
    "kdf": "evp",
    "digest": "md5",
    "iterations": 1,
    "salt_len": 8,
    "nosalt": False,
    "base64": False,
    "zlib": False,
    "nopad": False,
    "key_hex": "",
    "iv_hex": "",
    "salt_hex": "",
    "salt": "",
}

#: 这些字段是"判别维度"，fallback 组合会覆盖它们以保证覆盖面；
#: 其余字段视为全局开关，由显式 spec 覆盖到所有组合上。
_DIMENSIONS = ("cipher", "kdf", "digest", "iterations", "salt_len")


def _finalize_recipe(values: dict) -> dict:
    """规整一个 recipe（cipher 决定 key_len/iv_len/mode）。"""
    out = dict(DEFAULT_RECIPE)
    out.update({k: v for k, v in values.items() if k in DEFAULT_RECIPE})
    info = parse_cipher(str(out["cipher"]))
    if info["mode"] != "unknown":
        out["cipher"] = info["name"]
        out["key_len"] = info["key_len"]
        out["mode"] = info["mode"]
        out["iv_len"] = info["iv_len"]
    else:
        out["cipher"] = str(out["cipher"])
    for key in ("iterations", "salt_len"):
        try:
            out[key] = int(out[key] or 0)
        except (TypeError, ValueError):
            out[key] = 0
    out["iterations"] = max(1, out["iterations"])
    out["salt_len"] = max(0, out["salt_len"])
    for key in ("nosalt", "base64", "zlib", "nopad"):
        out[key] = bool(out[key])
    out["key_hex"] = str(out["key_hex"] or "")
    out["iv_hex"] = str(out["iv_hex"] or "")
    out["salt_hex"] = str(out["salt_hex"] or "")
    if not isinstance(out["salt"], (bytes, bytearray)):
        out["salt"] = str(out["salt"] or "")
    return out


def _default_templates() -> list[dict]:
    """有界组合表：EVP(md5/sha256)、PBKDF2(10000/1000/100000)、
    salt 长度 8/16、aes-256/128 的 cbc/ctr，共 24 条。

    排序保证前 24 条里每种必需维度至少出现一次；低优先级组合只保留
    代表性 cipher，避免 5x2x4=40 组合全量爆破。
    """
    groups = (
        ("evp", "md5", 1, 8, ("aes-256-cbc", "aes-256-ctr",
                              "aes-128-cbc", "aes-128-ctr")),
        ("evp", "sha256", 1, 8, ("aes-256-cbc", "aes-256-ctr",
                                 "aes-128-cbc", "aes-128-ctr")),
        ("pbkdf2", "sha256", 10000, 8, ("aes-256-cbc", "aes-256-ctr",
                                        "aes-128-cbc", "aes-128-ctr")),
        ("pbkdf2", "sha256", 10000, 16, ("aes-256-cbc", "aes-256-ctr")),
        ("pbkdf2", "sha256", 1000, 8, ("aes-256-cbc", "aes-128-cbc")),
        ("pbkdf2", "sha256", 100000, 8, ("aes-256-cbc", "aes-128-cbc")),
        ("evp", "md5", 1, 16, ("aes-256-cbc", "aes-256-ctr")),
        ("evp", "sha256", 1, 16, ("aes-256-cbc", "aes-256-ctr")),
        ("pbkdf2", "sha256", 1000, 16, ("aes-256-cbc",)),
        ("pbkdf2", "sha256", 100000, 16, ("aes-256-cbc",)),
    )
    out: list[dict] = []
    for kdf, digest, iterations, salt_len, ciphers in groups:
        for cipher in ciphers:
            out.append({"cipher": cipher, "kdf": kdf, "digest": digest,
                        "iterations": iterations, "salt_len": salt_len})
    return out


def _recipe_key(recipe: dict) -> tuple:
    return tuple(recipe.get(k) for k in (
        "cipher", "key_len", "mode", "iv_len", "kdf", "digest", "iterations",
        "salt_len", "nosalt", "base64", "zlib", "nopad", "key_hex", "iv_hex",
        "salt_hex", "salt",
    ))


def recipe_candidates(spec: dict | None = None) -> list[dict]:
    """生成尝试顺序：显式 spec 优先，其后是有界常用组合。

    ``spec`` 中出现的字段覆盖默认值；全局开关（``base64/zlib/nopad/
    nosalt/key_hex/iv_hex``）会应用到所有 fallback 组合，而判别维度
    （cipher/kdf/digest/iterations/salt_len）仅用于第一条显式配方，
    fallback 保持多样性以免 spec 写错就全军覆没。总数不超过 24。
    """
    spec = spec if isinstance(spec, dict) else {}
    overrides = {k: v for k, v in spec.items() if k in DEFAULT_RECIPE}
    global_overrides = {k: v for k, v in overrides.items() if k not in _DIMENSIONS}

    recipes: list[dict] = []
    if overrides:
        recipes.append(_finalize_recipe(overrides))
    for template in _default_templates():
        merged = dict(DEFAULT_RECIPE)
        merged.update(template)
        merged.update(global_overrides)
        recipes.append(_finalize_recipe(merged))

    unique: list[dict] = []
    seen: set[tuple] = set()
    for item in recipes:
        key = _recipe_key(item)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        if len(unique) >= MAX_RECIPES:
            break
    return unique


# ---------------------------------------------------------------------------
# 明文可信度
# ---------------------------------------------------------------------------
_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "zip": (b"PK\x03\x04", b"PK\x05\x06"),
    "gzip": (b"\x1f\x8b\x08",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "pdf": (b"%PDF-",),
    "elf": (b"\x7fELF",),
    "sqlite": (b"SQLite format 3\x00",),
    "pem": (b"-----BEGIN ",),
}
_SIG_KEYS = tuple(_SIGNATURES) + ("json", "xml", "utf8_text", "high_printable")
_BINARY_MAGICS = ("zip", "gzip", "png", "pdf", "elf", "sqlite")


def classify_payload(data: bytes) -> dict:
    """纯启发式：已知magic / JSON / XML / UTF-8 文本 / 可打印率 / 噪声 / 分数。

    不导入 entropy 模块、不做子进程；分数仅用于排序与阈值判断。
    """
    body = bytes(data) if isinstance(data, (bytes, bytearray)) else b""
    found: dict[str, bool] = {}
    head = body[:512]
    for name, magics in _SIGNATURES.items():
        found[name] = any(body.startswith(m) or m in head for m in magics)

    try:
        text = body.decode("utf-8")
        utf8_ok = True
    except UnicodeDecodeError:
        text = body.decode("utf-8", "replace")
        utf8_ok = False

    stripped = text.lstrip()[:256].lower()
    found["json"] = bool(utf8_ok and stripped.startswith(("{", "["))
                         and '"' in text[:256])
    found["xml"] = bool(utf8_ok and stripped.startswith("<?xml")
                        or (utf8_ok and stripped.startswith("<")
                            and ">" in text[:256]))

    good = 0
    noise = 0
    for byte in body:
        if 32 <= byte < 127 or byte in (9, 10, 13):
            good += 1
        elif byte > 127 and utf8_ok:
            good += 1
        else:
            noise += 1
    printable_ratio = good / max(len(body), 1)
    found["high_printable"] = bool(body) and printable_ratio >= 0.85
    found["utf8_text"] = bool(utf8_ok and found["high_printable"])

    try:
        from fnet.utils.codec import find_flags
        flags = list(find_flags(text))
    except Exception:  # noqa: BLE001 - flag 扫描失败不应影响解密判定
        flags = []
    found["flag"] = bool(flags)

    score = printable_ratio * 10.0
    if any(found[name] for name in _BINARY_MAGICS):
        score += 60.0
    if found["pem"]:
        score += 25.0
    if found["json"] or found["xml"]:
        score += 20.0
    if flags:
        score += 25.0

    signatures = [name for name in _SIG_KEYS if found.get(name)]
    result = {name: bool(found.get(name, False)) for name in _SIG_KEYS + ("flag",)}
    result.update({
        "signatures": signatures,
        "printable_ratio": round(printable_ratio, 4),
        "ratio": round(printable_ratio, 4),
        "noise": round(noise / max(len(body), 1), 4),
        "flags": flags,
        "score": round(score, 3),
    })
    return result


# ---------------------------------------------------------------------------
# 生成文本噪声抑制
# ---------------------------------------------------------------------------
def looks_like_generated_text(name: str, data: bytes) -> bool:
    """判断是否是 handler 自己生成的辅助文本文件（应从加密告警里排除）。

    命中 ``c2_README.txt`` / ``*_README.txt`` / ``findings.*`` / ``report*.txt``
    / ``job.json`` 等文件名直接返回 True；否则按内容判断：合法 UTF-8、
    高可打印率、且不含 ``Salted__`` / ``U2FsdGVkX1`` 标记。
    """
    raw_name = "" if name is None else str(name)
    base = re.split(r"[\\/]", raw_name)[-1].lower()
    if (base == "job.json" or base.endswith("_readme.txt")
            or base == "readme.txt" or base.startswith("findings.")
            or (base.startswith("report") and base.endswith((".txt", ".md", ".html")))):
        return True

    body = bytes(data) if isinstance(data, (bytes, bytearray)) else b""
    if not body:
        return False
    if ENVELOPE_MAGIC in body or BASE64_MAGIC.encode("ascii") in body:
        return False
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not text.strip():
        return False
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text)
    if printable < 0.85:
        return False
    # 长串纯 Base64/十六进制文本更像密文，而不是说明文档。
    compact = text.strip()
    if len(compact) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return False
    return True


# ---------------------------------------------------------------------------
# 顶层解密
# ---------------------------------------------------------------------------
def _acceptable(plain: bytes, cls: dict, flags: list[str]) -> bool:
    """明文可信阈值：flag 命中 / 已知二进制magic / 低噪声 UTF-8 文本。"""
    if not plain or len(plain) < 4:
        return False
    if flags:
        return True
    if any(cls.get(name) for name in _BINARY_MAGICS + ("pem", "json", "xml")):
        return True
    if cls.get("utf8_text") and cls.get("printable_ratio", 0) >= 0.9 \
            and cls.get("noise", 1) <= 0.05 and len(plain) >= 8:
        return True
    return False


def _variants(data: bytes, recipe: dict, spec: dict, salt_len: int,
              explicit_salt: bytes | None
              ) -> list[tuple[bytes, str, int, bytes | None]]:
    """返回 ``(密文, encoding, salt_len, salt_override)`` 候选，只解析不解密。

    ``salt_override`` 非 ``None`` 表示使用显式 ``-S`` salt（OpenSSL 3.x
    不写魔数）而不是嵌入头里的 salt；1.1.1 的嵌入头情形两种都试。
    """
    variants: list[tuple[bytes, str, int, bytes | None]] = []

    def add(env: OpenSslEnvelope | None) -> None:
        if env is None or not env.ciphertext:
            return
        variants.append((env.ciphertext, env.encoding, env.salt_len, None))
        if explicit_salt is not None:
            variants.append((env.ciphertext, env.encoding, len(explicit_salt),
                             explicit_salt))

    add(detect_envelope(data, salt_len=salt_len, spec=spec))
    # 未显式指定 salt_len 时 8/16 都试一遍（封装不记录 saltlen，文档默认 8、最大 16）。
    if "salt_len" not in spec and salt_len in (8, 16):
        other = 16 if salt_len == 8 else 8
        add(detect_envelope(data, salt_len=other, spec=spec))

    # 没有魔数头：显式 -S（OpenSSL 3.x）或 -nosalt。
    if not variants:
        bodies: list[tuple[bytes, str]] = [(data, "raw")]
        if recipe["base64"]:
            for decoded, label in decode_base64_candidates(data):
                if label != "raw" and decoded:
                    bodies.append((decoded, "base64"))
        for body, encoding in bodies:
            variants.append((body, encoding,
                             len(explicit_salt) if explicit_salt else 0,
                             explicit_salt))
    return variants


def _to_bytes_hex(value: str) -> bytes | None:
    if not value:
        return None
    try:
        cleaned = re.sub(r"(?i)0x|[\s:,-]", "", str(value))
        return bytes.fromhex(cleaned) if cleaned else None
    except (ValueError, TypeError):
        return None


def decrypt_envelope(data: bytes, password, *, spec: dict | None = None,
                     max_recipes: int = 24) -> dict | None:
    """依次尝试各 recipe 解密 ``data``，返回首个可信结果，否则 ``None``。

    返回字典含 ``plaintext/recipe/envelope/score/flags/signatures``。
    对无 ``Salted__``/``U2FsdGVkX1`` 标记且未声明 ``nosalt`` 的输入直接返回
    ``None``，避免对每个文件都跑 100000 次 PBKDF2。永不抛异常。
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    blob = bytes(data)
    if not blob:
        return None
    spec = spec if isinstance(spec, dict) else {}
    try:
        limit = max(1, min(int(max_recipes), 64))
    except (TypeError, ValueError):
        limit = MAX_RECIPES

    nosalt = bool(spec.get("nosalt"))
    explicit_salt = _explicit_salt(spec)
    # 真实 CLI 的 -z 可能把整个信封包在 zlib 里；先解外层再解析标记。
    inflated = _safe_inflate(blob)
    source = inflated if inflated else blob
    if not nosalt and detect_envelope(source, salt_len=8, spec=spec) is None \
            and detect_envelope(source, salt_len=16, spec=spec) is None:
        # 原始 blob 本身也再查一次（极端情况下 inflate 结果与 raw 不同源）。
        if detect_envelope(blob, salt_len=8, spec=spec) is None \
                and detect_envelope(blob, salt_len=16, spec=spec) is None:
            return None
        source = blob

    for recipe in recipe_candidates(spec)[:limit]:
        try:
            salt_len = recipe["salt_len"] or 8
            # 显式 raw key/iv 绕过 KDF（对应 -K/-iv）。
            explicit_key = _to_bytes_hex(recipe["key_hex"])
            explicit_iv = _to_bytes_hex(recipe["iv_hex"])

            for ciphertext, _encoding, actual_salt_len, salt_override in _variants(
                    source, recipe, spec, salt_len, explicit_salt):
                try:
                    if explicit_key is not None:
                        key = explicit_key
                        iv = explicit_iv or b""
                    else:
                        if salt_override is not None:
                            salt = salt_override
                        else:
                            env = detect_envelope(source, salt_len=actual_salt_len,
                                                  spec=spec)
                            salt = env.salt if env is not None else b""
                        key, iv = derive_key_iv(
                            password, salt, key_len=recipe["key_len"],
                            iv_len=recipe["iv_len"], kdf=recipe["kdf"],
                            digest=recipe["digest"],
                            iterations=recipe["iterations"])
                    if recipe["mode"] == "ecb":
                        iv = b""  # ECB 忽略 IV
                    plain = decrypt_bytes(
                        ciphertext, key, iv, mode=recipe["mode"],
                        key_len=recipe["key_len"],
                        unpad=not recipe["nopad"])
                    if plain is None or not plain:
                        continue
                    # -z 的两种位置都支持：外层（上面已 inflate）与内层
                    # （AES 解密后的明文才是 zlib 流）。
                    if recipe["zlib"] or _looks_zlib(plain):
                        expanded = _safe_inflate(plain)
                        if expanded:
                            plain = expanded
                        # 若 zlib 层在信封外（真实 CLI 常见形状），上面已经
                        # inflate 过，此处拿到的就是明文，解压失败不算错误。

                    cls = classify_payload(plain)
                    flags = list(cls.get("flags") or [])
                    try:
                        from fnet.utils.codec import find_flags as _find_flags
                        for flag in _find_flags(plain.decode("utf-8", "replace")):
                            if flag not in flags:
                                flags.append(flag)
                    except Exception:  # noqa: BLE001
                        pass
                    if not _acceptable(plain, cls, flags):
                        continue

                    envelope = detect_envelope(source, salt_len=actual_salt_len,
                                               spec=spec)
                    if envelope is not None and (salt_override is None
                                                 or envelope.marker != "explicit-S"):
                        env_dict = asdict(envelope)
                    else:
                        env_dict = asdict(OpenSslEnvelope(
                            salt=salt_override if salt_override is not None else b"",
                            ciphertext=ciphertext, salted=False,
                            encoding=_encoding, salt_len=actual_salt_len,
                            marker="explicit-S" if salt_override is not None
                            else "nosalt"))
                    return {
                        "plaintext": plain,
                        "recipe": dict(recipe),
                        "envelope": env_dict,
                        "score": float(cls["score"]) + (25.0 if flags else 0.0),
                        "flags": flags,
                        "signatures": cls["signatures"],
                    }
                except Exception:  # noqa: BLE001 - 单条候选失败不影响整体
                    continue
        except Exception:  # noqa: BLE001 - 畸形 spec/口令不得向外抛
            continue
    return None
