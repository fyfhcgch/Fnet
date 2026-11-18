"""Byte-level Shannon entropy analysis for the "suspected encrypted file"
detection used by the OpenSSL file handler.

Pure standard library (``collections``/``math`` only). We deliberately treat
all empty inputs as safe (entropy 0, "普通/空文件") so callers never need to
guard against ``math.log2(0)``.
"""
from __future__ import annotations

from collections import Counter
import math

#: Entropy (bits/byte) above which a file is judged likely encrypted/compressed.
HIGH_ENTROPY = 7.2
#: Printable ASCII byte set (space .. ~) plus common whitespace.
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8) for a bytes object.

    Empty input returns ``0.0``. Uses the ``-sum p*log2(p)`` definition.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def entropy_ratio(data: bytes) -> float:
    """Entropy normalised to the 0..1 range (8.0 bits/byte == 1.0)."""
    return shannon_entropy(data) / 8.0


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if b in _PRINTABLE)
    return good / len(data)


def classify(data: bytes) -> dict:
    """Classify ``data`` and return a dict describing suspicion.

    Returns ``{"entropy": float, "ratio": float, "am_i_encrypted": bool,
    "hint": str}``.  A file is "疑似加密/压缩" when its entropy is high and
    most bytes are not printable ASCII; otherwise it is treated as plaintext.
    """
    if not data:
        return {"entropy": 0.0, "ratio": 0.0,
                "am_i_encrypted": False, "hint": "空文件，无可分析内容"}
    entropy = shannon_entropy(data)
    ratio = entropy / 8.0
    printable = _printable_ratio(data)
    # High entropy + non-printable => likely encrypted/compressed.
    if entropy > HIGH_ENTROPY and printable < 0.60:
        am_i = True
        hint = ("高熵，疑似加密/压缩，可尝试 AES-CTR 解密"
                "（提供 password/cipher 参数）")
    elif entropy > HIGH_ENTROPY:
        am_i = True
        hint = "高熵，可能为加密/压缩数据（含较多随机可打印字节）"
    elif entropy < 5.0 and printable > 0.70:
        am_i = False
        hint = "低熵且多为可打印文本，疑似明文"
    else:
        am_i = entropy > 6.0
        hint = "熵值中等，结合上下文判断是否为加密数据"
    return {"entropy": round(entropy, 4), "ratio": round(ratio, 4),
            "am_i_encrypted": am_i, "hint": hint}