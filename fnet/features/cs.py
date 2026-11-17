"""Cobalt Strike beacon metadata / task output decryption.

Works with the classic ``.cobaltstrike.beacon_keys`` file (Java serialized or
PEM/DER RSA private key).  The parser accepts both HTTP(S) profiles and raw
TCP beacons and falls back to saving candidate blobs when no key is set.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.crypto import (
    aes_cbc_decrypt, aes_ecb_decrypt, load_rsa_private_key,
    rsa_decrypt_pkcs1v15,
)
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio

MAGIC = b"\x00\x00\xbe\xef"
B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
HTTP_FIELDS = ["frame.number", "tcp.stream", "http.request.method",
               "http.request.full_uri", "http.request.uri", "http.cookie",
               "http.file_data", "http.response_in"]
RESP_FIELDS = ["frame.number", "tcp.stream", "http.file_data",
               "http.content_type"]
TCP_FIELDS = ["frame.number", "tcp.stream", "tcp.payload"]


def _b64(value: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", value or "")
    if len(cleaned) < 12:
        return None
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception:  # noqa: BLE001
        return None


def _load_key(ctx: FeatureContext):
    path = str(ctx.params.get("cobaltstrike_keys") or "").strip()
    if not path:
        return None
    target = Path(path).expanduser()
    if not target.is_file():
        ctx.report(f"CS 密钥文件不存在: {target}", "error")
        return None
    try:
        key = load_rsa_private_key(target.read_bytes())
    except OSError as exc:
        ctx.report(f"读取 CS 密钥失败: {exc}", "error")
        return None
    if key is None:
        ctx.report("无法从密钥文件中解析 RSA 私钥", "error")
    else:
        ctx.report(f"已加载 RSA 私钥 ({key.n.bit_length()} bit)", "good")
    return key


def _metadata_from_blob(blob: bytes, key) -> bytes | None:
    """Try common length-prefixed RSA layouts."""
    if key is None:
        return None
    candidates = [blob]
    for endian in ("little", "big"):
        for offset in range(0, min(len(blob) - 4, 64)):
            size = int.from_bytes(blob[offset:offset + 4], endian)
            if 32 <= size <= len(blob) - offset - 4:
                candidates.append(blob[offset + 4:offset + 4 + size])
    size_bytes = (key.n.bit_length() + 7) // 8
    for candidate in candidates:
        for start in (0, max(0, len(candidate) - size_bytes)):
            cipher = candidate[start:start + size_bytes]
            if len(cipher) < size_bytes:
                continue
            plain = rsa_decrypt_pkcs1v15(cipher, key)
            if plain and plain.startswith(MAGIC[:2]):
                return plain
            if plain and MAGIC in plain[:16]:
                return plain[plain.find(MAGIC):]
    return None


def _decode_metadata(plain: bytes) -> dict:
    info: dict = {"magic": plain[:4].hex(), "raw": plain}
    def u32(offset: int) -> int:
        return int.from_bytes(plain[offset:offset + 4], "little")

    if len(plain) >= 12:
        info["pid"] = u32(4)
        info["port"] = int.from_bytes(plain[8:10], "little")
        info["flags"] = plain[10]
        info["version"] = plain[11]
    # The keys are the two 16 byte high-entropy runs after the header.
    if len(plain) >= 56:
        info["aes_key"] = plain[24:40]
        info["hmac_key"] = plain[40:56]
    else:
        info["aes_key"] = plain[16:32]
        info["hmac_key"] = plain[32:48]
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", plain):
        text = match.group().decode("latin-1")
        if not text.startswith(("MZ", "http")):
            strings.append(text)
    info["strings"] = strings
    return info


def _try_decrypt_output(data: bytes, key: bytes) -> tuple[str, bytes] | None:
    if len(data) < 32:
        return None
    candidates = []
    candidates.append(("CBC(IV=前16字节)", aes_cbc_decrypt(data[16:], key, data[:16])))
    candidates.append(("CBC(IV=key)", aes_cbc_decrypt(data, key, key[:16])))
    if len(data) % 16 == 0:
        candidates.append(("ECB", aes_ecb_decrypt(data, key)))
    # Some profiles append an HMAC-SHA256 (32 bytes).
    if len(data) > 64:
        trimmed = data[:-32]
        candidates.append(("CBC(IV=前16字节, 去HMAC)",
                           aes_cbc_decrypt(trimmed[16:], key, trimmed[:16])))
    best = max(candidates, key=lambda item: printable_ratio(item[1])
               + (20 if b"<" in item[1] or b"cmd" in item[1] else 0))
    # 任务输出必然是可读文本：可读率与结构标记两者取严，避免错误密钥解出的
    # 乱码（例如只含一个 '<' 的伪随机字节）被误判为“解密成功”并落盘。
    markers = (b"cmd", b"powershell", b"<", b"{", b"\n")
    if (printable_ratio(best[1]) >= 0.6
            and any(marker in best[1] for marker in markers)):
        return best
    return None


def _candidate_blobs(text: str) -> list[bytes]:
    blobs = []
    for match in B64_RE.finditer(text or ""):
        raw = _b64(match.group(0))
        if raw and len(raw) >= 64:
            blobs.append(raw)
    for match in re.finditer(r"(?i)\b(?:[0-9a-f]{2}){32,}\b", text or ""):
        raw = hex_to_bytes(match.group(0))
        if raw:
            blobs.append(raw)
    return blobs


def analyze(ctx: FeatureContext) -> None:
    key = _load_key(ctx)
    reqs = tshark_rows(ctx, HTTP_FIELDS, "http.request", limit=100_000)
    resps = {}
    for raw in tshark_rows(ctx, RESP_FIELDS, "http.response", limit=100_000):
        row = raw + [""] * (len(RESP_FIELDS) - len(raw))
        item = dict(zip(RESP_FIELDS, row))
        resps[item["frame.number"]] = item

    metadata: list[dict] = []
    outputs = 0
    saved = 0
    for index, raw in enumerate(reqs):
        if index % 100 == 0:
            ctx.set_progress(int(index / max(len(reqs), 1) * 60))
            ctx.check_cancel()
        row = raw + [""] * (len(HTTP_FIELDS) - len(raw))
        item = dict(zip(HTTP_FIELDS, row))
        text = " ".join(item.get("http.request.full_uri", "").split("?", 1)[-1:]
                        + [item.get("http.cookie", "")])
        blobs = _candidate_blobs(text)
        if not blobs:
            continue
        ctx.report(f"帧 {item['frame.number']} 发现 {len(blobs)} 个候选元数据块",
                   "debug")
        for blob in blobs:
            plain = _metadata_from_blob(blob, key)
            if plain is None:
                if key is None:
                    saved += 1
                    ctx.write_output(f"cs_metadata_{item['frame.number']}_{saved}.bin", blob)
                continue
            info = _decode_metadata(plain)
            metadata.append(info)
            ctx.report(f"===== 帧 {item['frame.number']} 元数据解密成功 =====", "good")
            for name in ("pid", "port", "flags", "version"):
                if name in info:
                    ctx.report(f"{name}: {info[name]}", "info")
            ctx.report(f"AES key: {info['aes_key'].hex()}", "good")
            ctx.report(f"HMAC key: {info['hmac_key'].hex()}", "good")
            if info["strings"]:
                ctx.report("明文字符串: " + ", ".join(info["strings"][:20]), "info")
            ctx.write_output(f"cs_metadata_{item['frame.number']}.bin", plain)

    # Decrypt server task output with every recovered AES key.
    aes_keys = [info["aes_key"] for info in metadata if len(info.get("aes_key", b"")) == 16]
    aes_keys = list(dict.fromkeys(aes_keys))
    for resp in resps.values():
        if not resp["http.file_data"]:
            continue
        body = payload_text(hex_to_bytes(resp["http.file_data"]))
        for blob in _candidate_blobs(body):
            for aes_key in aes_keys:
                result = _try_decrypt_output(blob, aes_key)
                if result is None:
                    continue
                variant, plain = result
                outputs += 1
                ctx.report(f"===== 帧 {resp['frame.number']} 任务输出解密 ({variant}) =====",
                           "good")
                decoded = payload_text(plain)
                for line in decoded.splitlines()[:80]:
                    if line.strip():
                        ctx.report("  " + clean_cell(line, 260), "info")
                ctx.write_output(f"cs_output_{resp['frame.number']}_{outputs}.txt", plain)
                for flag in codec.find_flags(decoded):
                    ctx.report(f"发现 flag: {flag}", "good")
                break

    # Raw TCP beacons (no HTTP profile).
    if not reqs:
        ctx.report("没有 HTTP 请求，尝试原始 TCP beacon 载荷", "info")
        rows = tshark_rows(ctx, TCP_FIELDS, "tcp", limit=50_000)
        for raw in rows:
            row = raw + [""] * (3 - len(raw))
            data = hex_to_bytes(row[2])
            if not data:
                continue
            plain = _metadata_from_blob(data, key)
            if plain:
                info = _decode_metadata(plain)
                metadata.append(info)
                ctx.report(f"帧 {row[0]} TCP 元数据解密成功 AES={info['aes_key'].hex()}",
                           "good")
                ctx.write_output(f"cs_tcp_metadata_{row[0]}.bin", plain)

    if metadata:
        ctx.report(f"共恢复 {len(metadata)} 份 beacon 元数据，{outputs} 份任务输出", "good")
    elif key is None:
        ctx.report("未配置 .cobaltstrike.beacon_keys，已保存候选密文；"
                   "请在设置中指定密钥后重新分析", "warn")
        if saved:
            ctx.write_output("cs_README.txt",
                             "这些文件是疑似 Cobalt Strike 元数据密文。\n"
                             "在“设置 → CS 密钥”中指定 .cobaltstrike.beacon_keys 后可解密。\n")
    else:
        ctx.report("未识别到可解密的 Cobalt Strike 元数据", "warn")
    ctx.set_progress(100)
