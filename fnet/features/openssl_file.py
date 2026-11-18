"""OpenSSL encrypted-file detection and decryption (with entropy analysis).

CTF scenario: ``openssl enc -aes-256-ctr -d -nosalt -in flag -out out.bin
-pass pass:haha``.  We (a) rank on-disk recovered/parameter files by byte
entropy to flag "疑似加密文件", then (b) decrypt with
``EVP_BytesToKey``-derived keys in CTR/CBC/ECB and scan the plaintext for
flags via :func:`fnet.utils.tunnel.find_flags`.
"""
from __future__ import annotations

from pathlib import Path

from fnet.features.registry import FeatureContext
from fnet.utils.entropy import classify, entropy_ratio, shannon_entropy
from fnet.utils.crypto import (
    aes_cbc_decrypt, aes_ctr_decrypt, aes_ecb_decrypt, evp_bytes_to_key,
)

#: Files smaller than this are too small to judge by entropy alone.
MIN_ENTROPY_SIZE = 32
_SALTED_MAGIC = b"Salted__"


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (OSError, ValueError, IsADirectoryError):
        return None


def _parse_salt(raw: bytes, nosalt: bool, salt_hex: str | None,
                plain_salt: str | None) -> tuple[bytes, bytes]:
    """Return ``(salt, ciphertext)`` from the OpenSSL header rules.

    ``nosalt`` files are not prefixed; ``salting`` files carry an 8-byte salt
    after ``Salted__`` unless an explicit ``salt``/``salt_hex`` overrides it.
    """
    salt = b""
    data = raw
    if salt_hex:
        try:
            salt = bytes.fromhex(salt_hex.replace(" ", "").replace(":", ""))
        except ValueError:
            salt = b""
    elif plain_salt:
        salt = bytes(plain_salt, "utf-8")
    elif not nosalt and raw.startswith(_SALTED_MAGIC) and len(raw) >= 16:
        salt = raw[8:16]
        data = raw[16:]
    return salt, data


def _parse_cipher(cipher: str) -> tuple[int, str]:
    """Normalise a cipher name like ``aes-256-cbc`` -> ``(key_bytes, mode)``."""
    name = (cipher or "aes-256-ctr").lower().replace("_", "-")
    hits = [key for key in (128, 192, 256) if str(key) in name]
    key_bits = hits[-1] if hits else 256
    mode = "cbc"
    for m in ("ctr", "ecb", "cbc"):
        if m in name:
            mode = m
            break
    return key_bits // 8, mode


def _decrypt_one(ctx: FeatureContext, raw: bytes, password: str,
                 salt: bytes | None, key_bytes: int, mode: str,
                 iv: bytes) -> bytes:
    """Decrypt ``raw`` with an EVP_BytesToKey-derived key.

    May raise (bad padding for CBC/ECB) or return ``b''`` for a wrong key;
    callers decide success via entropy collapse / flag hits.
    """
    key, _ = evp_bytes_to_key(password, salt or None,
                              key_len=key_bytes, iv_len=16)
    if mode == "ctr":
        return aes_ctr_decrypt(raw, key, iv)
    if mode == "ecb":
        return aes_ecb_decrypt(raw, key, unpad=False)
    return aes_cbc_decrypt(raw, key, iv, unpad=False)


def _entropy_report(ctx: FeatureContext, candidates: list[tuple[str, bytes]]) -> None:
    """Rank candidates by entropy (highest first) and record findings."""
    scored = []
    for name, data in candidates:
        if len(data) <= MIN_ENTROPY_SIZE or not data:
            continue
        cls = classify(data)
        scored.append((cls["entropy"], name, len(data), cls))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored:
        ctx.report("没有足够大的二进制文件可进行熵值分析", "warn")
        return

    ctx.report("===== 疑似加密文件熵值排行（最高熵在前）=====", "good")
    for entropy, name, size, cls in scored:
        ctx.report(f"{name} (size={size}) 熵={entropy:.4f} "
                   f"ratio={cls['ratio']:.2f} -> {cls['hint']}",
                   "warn" if cls["am_i_encrypted"] else "info")
        if cls["am_i_encrypted"]:
            ctx.add_finding(
                "file",
                f"疑似加密文件 {name}",
                detail=f"熵 {entropy:.4f}（ratio {cls['ratio']:.2f}） {cls['hint']}",
                extra={"path": name, "size": size,
                       "entropy": cls["entropy"],
                       "ratio": cls["ratio"]},
            )
    ctx.report("若需解密，请提供 password（及可选 path/cipher/salt 参数）", "info")


def _try_decrypt(ctx: FeatureContext, name: str, raw: bytes, params: dict,
                 key_bytes: int, mode: str, iv: bytes,
                 salt: bytes | None) -> bool:
    """Attempt one-file decryption; returns True on success."""
    close_ratio = entropy_ratio(raw)
    try:
        plain = _decrypt_one(ctx, raw, params.get("password", ""), salt,
                             key_bytes, mode, iv)
    except Exception:  # noqa: BLE001 - wrong key/iv often breaks padding
        return False
    if not plain:
        return False
    flags = _find_flags(ctx, plain)
    # Success: a flag hit, or a large entropy collapse towards plaintext.
    if flags or (close_ratio > 0.9 and entropy_ratio(plain) < close_ratio - 0.35):
        ctx.report(f"解密成功: {name}，熵 {shannon_entropy(raw):.2f} -> "
                   f"{shannon_entropy(plain):.2f}，命中 flag: {flags}",
                   "good")
        ctx.write_output("decrypted.bin", plain)
        ctx.add_finding("file",
                        f"OpenSSL 解密成功 {name}",
                        detail=f"命中 flag: {flags}，cipher={mode}，口令已脱敏",
                        extra={"path": name, "cipher": mode, "flags": flags})
        return True
    return False


def _find_flags(ctx: FeatureContext, data: bytes) -> list[str]:
    """Run flag scanning with ``find_flags`` (imported lazily to avoid cycles)."""
    from fnet.utils.tunnel import find_flags
    return list(find_flags(data))


def _file_candidates(ctx: FeatureContext) -> list[tuple[str, bytes]]:
    """Collect on-disk binaries: ``ctx.output_dir`` recovered files plus the
    ``path`` parameter if provided."""
    candidates: list[tuple[str, bytes]] = []
    out_dir = ctx.output_dir
    if out_dir is not None and out_dir.is_dir():
        for path in sorted(out_dir.iterdir()):
            if path.is_file():
                data = _read_bytes(path)
                if data:
                    candidates.append((path.name, data))
    path_param = ctx.params.get("path")
    if path_param:
        p = Path(str(path_param))
        if p.is_file():
            data = _read_bytes(p)
            if data:
                candidates.append((p.name, data))
    return candidates


def detect_encrypted_files(ctx: FeatureContext) -> None:
    """Detect suspected encrypted files by entropy and optionally decrypt."""
    ctx.set_progress(5)
    params = ctx.params or {}
    ctx.check_cancel()

    candidates = _file_candidates(ctx)
    if not candidates:
        ctx.report("未找到可分析的二进制文件（请用 path 参数指定文件）", "warn")
        return

    ctx.set_progress(20)
    # 1) Entropy ranking of every on-disk candidate.
    _entropy_report(ctx, candidates)
    ctx.check_cancel()
    ctx.set_progress(55)

    password = params.get("password")
    if not password:
        ctx.report("未提供 password 参数，仅执行熵值分析", "info")
        ctx.report("若已知口令可尝试解密（解密需 password/path，cipher 默认 "
                   "aes-256-ctr）", "info")
        ctx.set_progress(100)
        return

    # 2) Decryption. target = explicit path (if given and found), else all.
    key_bytes, mode = _parse_cipher(params.get("cipher", "aes-256-ctr"))
    salt_hex = params.get("salt_hex")
    plain_salt = params.get("salt")
    nosalt = bool(params.get("nosalt")) if "nosalt" in params else False
    iv = b"\x00" * 16

    ctx.report(f"尝试用 OpenSSL 解密（cipher={mode}, key={key_bytes*8}bit, "
               f"nosalt={nosalt}）", "info")

    target_path = params.get("path")
    targets = [t for t in candidates if t[0] == (target_path.split("/")[-1]
                                                 if target_path else "")] \
        if target_path else candidates
    if not targets and target_path:
        ctx.report(f"未找到指定文件: {target_path}，将遍历所有落盘文件尝试", "warn")
        targets = candidates

    success = False
    total = len(targets)
    for index, (name, raw) in enumerate(targets, start=1):
        ctx.check_cancel()
        salt, data = _parse_salt(raw, nosalt, salt_hex, plain_salt)
        ctx.report(f"[{index}/{total}] 尝试解密: {name} "
                   f"(salt={salt.hex() if salt else '无'})", "info")
        try:
            if _try_decrypt(ctx, name, data, params, key_bytes, mode, iv, salt):
                success = True
                break
        except Exception as exc:  # noqa: BLE001 - a single cipher must not abort
            ctx.report(f"解密 {name} 失败: {exc}", "debug")
        ctx.set_progress(55 + int(40 * index / total))

    if not success:
        ctx.report("未能成功解密（口令可能不正确，或 cipher/salt 参数不符）。"
                   "若为 CTF：可尝试 generate_candidates/hashcat 生成口令字典，"
                   "不必在此死磕", "warn")
    ctx.set_progress(100)


#: Handler alias, usable interchangeably with ``detect_encrypted_files``.
analyze = detect_encrypted_files