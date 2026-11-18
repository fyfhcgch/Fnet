"""NetNTLMv2 离线密码验证/枚举回退引擎（纯标准库）。

本模块是 hashcat 的**离线回退**：当环境中没有 hashcat 时，可从捕获的
NTLM 挑战/响应（NetNTLM）直接验证候选密码或做受控的短口令枚举。
主要目标是 NTLMv2（hashcat -m 5600）；NTLMv1 涉及 ES-DES，纯 Python
实现不现实，仅提供 best-effort 提示。所有函数对畸形输入返回安全默认值，
绝不抛异常。
"""
from __future__ import annotations

import itertools
import string
from typing import Callable, Iterator

from fnet.utils.crypto import hmac_md5, md4

__all__ = [
    "verify_ntlmv2",
    "verify_ntlmv1",
    "verify_password",
    "generate_candidates",
    "brute_force_ntlmv2",
    "nt_hash_from_password",
    "nt_hash_from_hex",
    "normalize_account",
]

_ALPHABETS = {
    "ascii_letters": string.ascii_letters,
    "letters": string.ascii_letters,
    "ascii_lowercase": string.ascii_lowercase,
    "lower": string.ascii_lowercase,
    "ascii_uppercase": string.ascii_uppercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "hexdigits": string.hexdigits,
    "punctuation": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}


def _as_bytes(value, encoding: str = "utf-16le") -> bytes:
    """把 str 稳定编码；bytes 原样返回；其他类型给空字节。"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(encoding)
    return b""


def normalize_account(user) -> str:
    """归一化账号名：剥离 ``DOMAIN\\user`` 与 ``user@domain`` 前缀。

    NTLMv2 的 ResponseKeyNT 使用的是**去掉域前缀的用户名**，且大写。
    """
    if not isinstance(user, str):
        user = str(user or "")
    # ``DOMAIN\user`` -> user
    if "\\" in user:
        user = user.rsplit("\\", 1)[-1]
    # ``user@domain`` -> user
    if "@" in user:
        user = user.split("@", 1)[0]
    return user.strip().upper()


def nt_hash_from_password(password) -> bytes:
    """由明文密码推导 NT 哈希 ``MD4(utf16le(password))``。"""
    if not isinstance(password, str):
        password = str(password or "")
    return md4(password.encode("utf-16le"))


def nt_hash_from_hex(value) -> bytes:
    """解析 32 位十六进制字符串为 NT 哈希；非法则返回空。"""
    if not isinstance(value, str):
        value = str(value or "")
    value = "".join(ch for ch in value.strip() if ch in string.hexdigits)
    if len(value) != 32:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def _response_key(nt_hash: bytes, user: bytes) -> bytes:
    return hmac_md5(nt_hash, user)


def verify_ntlmv2(nt_hash: bytes, challenge: bytes, nt_response: bytes,
                  user, domain=None) -> bool:
    """验证一条 NTLMv2 响应是否由给定 NT 哈希生成。

    前 16 字节是 NTLMv2_HMAC，其后为 blob（temp）。按协议重算
    ``HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)`` 并比对其余
    响应前 16 字节。
    """
    if not isinstance(nt_hash, bytes) or len(nt_hash) != 16:
        return False  # 自带的 candidate 短口令理论上可行，但 16 字节哈希必须
    if not isinstance(nt_response, bytes) or len(nt_response) <= 24:
        return False
    if not isinstance(challenge, bytes) or len(challenge) != 8:
        return False
    proof = nt_response[:16]
    blob = nt_response[16:]
    user_buf = _as_bytes(normalize_account(user))
    domain_buf = _as_bytes(str(domain or "").strip().upper())
    response_key = _response_key(nt_hash, user_buf + domain_buf)
    expected = hmac_md5(response_key, challenge + blob)
    return expected == proof


def verify_ntlmv1(nt_hash: bytes, challenge: bytes, nt_response: bytes) -> bool:
    """NTLMv1 的 best-effort。

    纯 NTLMv1 用 DES 派生 24 字节响应（LM/NT 各 3 个 DES 块），纯 Python
    精度难以保证。这里仅做文档化提示：长度合法时返回 ``False`` 并建议改用
    hashcat -m 5500；主要目标请走 ``verify_ntlmv2``。绝不抛异常。
    """
    if (isinstance(nt_hash, bytes) and len(nt_hash) == 16
            and isinstance(nt_response, bytes) and isinstance(challenge, bytes)):
        # 无法在 v1 分支数学上可靠判定；始终返回 False。
        return False
    return False


def verify_password(password, challenge: bytes, nt_response: bytes,
                    user, domain=None, nt_hash: bytes | None = None) -> bool:
    """从明文密码派生 NT 哈希并走 NTLMv2 验证。"""
    if nt_hash is None:
        nt_hash = nt_hash_from_password(password)
    if not nt_hash or not isinstance(nt_hash, bytes):
        return False
    return verify_ntlmv2(nt_hash, challenge, nt_response, user, domain)


def _resolve_alphabet(alphabet) -> str:
    name = (alphabet or "").strip() if isinstance(alphabet, str) else ""
    if not name:
        return string.ascii_letters + string.digits
    if name in _ALPHABETS:
        return _ALPHABETS[name]
    # 允许 ``ascii_letters+digits`` 这样的组合写法
    combined = ""
    for part in name.split("+"):
        combined += _ALPHABETS.get(part.strip(), part)
    return combined or string.ascii_letters + string.digits


def generate_candidates(*, min_len: int = 6, max_len: int | None = None,
                        alphabet: str = "ascii_letters+digits",
                        max_count: int | None = None,
                        cancel: Callable[[], bool] | None = None) -> Iterator[str]:
    """按字母表生成候选口令（小写->大写->数字全覆盖）。

    默认最高 6 位：纯暴力在 62^6 数量级极不现实，交互请用
    ``max_count`` 或 ``cancel`` 收敛。7 位以上应改用 hashcat。
    """
    if max_len is None:
        max_len = min_len
    try:
        lo = max(1, int(min_len))
        hi = max(lo, int(max_len))
    except (TypeError, ValueError):
        lo = hi = 6
    chars = _resolve_alphabet(alphabet)
    if not chars:
        return
    count = 0
    for length in range(lo, hi + 1):
        for combo in itertools.product(chars, repeat=length):
            count += 1
            if cancel is not None:
                try:
                    keep_going = cancel()
                except Exception:  # noqa: BLE001
                    keep_going = False
                if not keep_going:
                    return
            if max_count is not None and count > max_count:
                return
            yield "".join(combo)


def brute_force_ntlmv2(challenge, nt_response, user, domain=None, *,
                       candidates=None, nt_hash: bytes | None = None,
                       max_attempts: int = 500_000,
                       cancel: Callable[[], bool] | None = None):
    """逐个验证候选密码，返回命中的明文密码；未命中返回 ``None``。

    ``candidates`` 为明文口令列表（可传递 ``generate_candidates`` 的产出来做
    受控枚举）。提供 ``nt_hash`` 可跳过每次 ``MD4`` 派生以提升速度，但
    ``candidates`` 仍是明文口令。最多尝试 ``max_attempts`` 次。
    """
    if not isinstance(challenge, bytes) and isinstance(challenge, str):
        challenge = nt_hash_from_hex(challenge) or _as_bytes(challenge, "latin-1")
    if not isinstance(nt_response, bytes):
        nt_response = b""
    if not isinstance(candidates, (list, tuple, set)) or not candidates:
        return None

    def should_stop() -> bool:
        if cancel is not None:
            try:
                return not cancel()
            except Exception:  # noqa: BLE001
                return True
        return False

    attempts = 0
    for candidate in candidates:
        if attempts >= max_attempts or should_stop():
            break
        attempts += 1
        try:
            if verify_password(candidate, challenge, nt_response, user,
                               domain, nt_hash=nt_hash):
                return str(candidate)
        except Exception:  # noqa: BLE001
            continue
    return None