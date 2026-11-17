"""WinRM (5985/5986) authentication and message decryption.

WinRM uses NTLMSSP + NTLM sealing (RC4/HMAC-MD5) over HTTP.  This module
extracts the NTLM exchange, derives the exported session key from a supplied
password or NT hash and attempts to unseal WinRM envelopes.  When the
deployment uses HTTPS with a different key exchange, the derived key and
credentials are still reported.
"""
from __future__ import annotations

import base64
import re

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.ntlm import _extract_messages, parse_type2, parse_type3
from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.crypto import (
    aes_cbc_decrypt, hmac_md5, nt_hash, rc4,
)
from fnet.utils.pcap import hex_to_bytes, payload_text

FIELDS = [
    "frame.number",
    "tcp.stream",
    "http.request.method",
    "http.request.uri",
    "http.authorization",
    "http.www_authenticate",
    "http.content_type",
    "http.file_data",
]


def _derive_session_key(password: str, nthash_hex: str, user: str, domain: str,
                        challenge: bytes, nt_response: bytes) -> tuple[bytes | None, str]:
    if nthash_hex:
        try:
            nthash = bytes.fromhex(re.sub(r"(?i)[^0-9a-f]", "", nthash_hex))
        except ValueError:
            return None, "NTLM HASH 格式无效"
        if len(nthash) != 16:
            return None, "NTLM HASH 必须是 32 位十六进制（16 字节）"
        source = "NTLM HASH"
    elif password:
        nthash = nt_hash(password)
        source = "password"
    else:
        return None, "需要 NTLM HASH 或 password"
    identity = (user.upper() + domain).encode("utf-16le")
    response_key = hmac_md5(nthash, identity)
    proof = nt_response[:16]
    if len(proof) < 16:
        return None, "NTResponse 太短"
    session_base = hmac_md5(proof, response_key)
    return session_base, source


def _sealing_keys(exported: bytes) -> list[tuple[str, bytes]]:
    """Candidate RC4 sealing keys (MS-NLMP variants + common implementations)."""
    keys = [("RC4(exported)", exported)]
    try:
        keys.append(("RC4(exported, 0)", rc4(exported, b"\x00\x00\x00\x00")))
        keys.append(("RC4(exported, 0xffffffff)", rc4(exported, b"\xff\xff\xff\xff")))
        keys.append(("RC4(exported, 0xaaaaaaaa)", rc4(exported, b"\xaa\xaa\xaa\xaa")))
    except Exception:  # noqa: BLE001
        pass
    return keys


def _try_unseal(payload: bytes, keys: list[tuple[str, bytes]]) -> tuple[str, bytes] | None:
    """Attempt RC4/AES unsealing of a WinRM encrypted fragment."""
    for label, key in keys:
        for offset in (0, 4, 16):
            data = payload[offset:]
            if len(data) < 16:
                continue
            for strip in (0, 16):
                body = data[strip:]
                if len(body) < 8:
                    continue
                try:
                    plain = rc4(key, body)
                except Exception:  # noqa: BLE001
                    continue
                if _looks_xml(plain):
                    return f"{label}, offset={offset}, strip={strip}", plain
                # WinRM may prepend the RC4 stream position / signature.
                if _looks_xml(plain[16:]):
                    return f"{label}, offset={offset}, strip={strip}, 跳过16字节", plain[16:]
        # Some gateways use AES-CBC with the exported key.
        for key_len in (16, 24, 32):
            if len(key) >= key_len:
                for offset in (0, 16):
                    data = payload[offset:]
                    if len(data) >= 32 and len(data) % 16 == 0:
                        try:
                            plain = aes_cbc_decrypt(data, key[:key_len], data[:16])
                        except Exception:  # noqa: BLE001
                            continue
                        if _looks_xml(plain):
                            return f"AES-CBC({key_len * 8}) offset={offset}", plain
    return None


def _looks_xml(data: bytes) -> bool:
    head = data[:400].lower()
    return b"<s:envelope" in head or b"<?xml" in head or b"<soap" in head


def _extract_ciphertexts(ctx: FeatureContext, body: str, ctype: str) -> list[bytes]:
    blobs: list[bytes] = []
    if "encrypted" in (ctype or "").lower() or "encrypted" in body.lower():
        for match in re.finditer(r"<(?:\w+:)?CipherValue[^>]*>(.*?)</(?:\w+:)?CipherValue>",
                                 body, re.S | re.I):
            raw = _b64(match.group(1))
            if raw:
                blobs.append(raw)
    # multipart/encrypted: binary octet stream is not representable in text,
    # but tshark may hand us a base64/hex rendering.
    for match in re.finditer(r"[A-Za-z0-9+/]{80,}={0,2}", body):
        raw = _b64(match.group(0))
        if raw and len(raw) > 48:
            blobs.append(raw)
    return blobs


def _b64(value: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", value or "")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception:  # noqa: BLE001
        return None


def decrypt(ctx: FeatureContext) -> None:
    rows = tshark_rows(ctx, FIELDS, "http", limit=100_000)
    if not rows:
        ctx.report("没有发现 HTTP/WinRM 流量", "warn")
        return

    challenge = b""
    auth_info: dict = {}
    bodies: list[dict] = []
    for raw in rows:
        row = raw + [""] * (len(FIELDS) - len(raw))
        item = dict(zip(FIELDS, row))
        for column in ("http.authorization", "http.www_authenticate"):
            for message in _extract_messages(item.get(column, "")):
                if len(message) < 12:
                    continue
                msg_type = int.from_bytes(message[8:12], "little")
                if msg_type == 2:
                    challenge = parse_type2(message)["challenge"]
                elif msg_type == 3:
                    auth_info = parse_type3(message)
                    auth_info["frame"] = item["frame.number"]
        if item["http.file_data"]:
            bodies.append({"frame": item["frame.number"],
                           "body": payload_text(hex_to_bytes(item["http.file_data"])),
                           "ctype": item["http.content_type"],
                           "uri": item["http.request.uri"]})

    if not auth_info:
        ctx.report("未发现 WinRM NTLM 认证信息", "warn")
        return
    user = auth_info.get("user", "")
    domain = auth_info.get("domain", "")
    nt_response = auth_info.get("nt", b"")
    ctx.report(f"WinRM 账号: {domain}\\{user} (帧 {auth_info.get('frame')})", "good")

    auth_mode = str(ctx.params.get("winrm_auth") or "hash")
    password = str(ctx.params.get("winrm_password") or "")
    nthash_hex = str(ctx.params.get("winrm_ntlm") or "")
    session_base, source = _derive_session_key(
        password if auth_mode == "password" else "",
        nthash_hex if auth_mode != "password" else "",
        user, domain, challenge, nt_response)
    if session_base is None:
        ctx.report(f"无法派生会话密钥: {source}", "warn")
        ctx.report("仍可先用 NTLM HASH 提取/离线破解得到密码", "info")
        return
    ctx.report(f"使用 {source} 派生 NTLM SessionBaseKey: {session_base.hex()}", "good")

    encrypted_key = auth_info.get("session_key", b"")
    exported = session_base
    if encrypted_key:
        exported = rc4(session_base, encrypted_key)
        ctx.report(f"导出会话密钥 (ExportedSessionKey): {exported.hex()}", "good")
    keys = _sealing_keys(exported)

    decrypted = 0
    for body in bodies:
        ctx.check_cancel()
        for cipher in _extract_ciphertexts(ctx, body["body"], body["ctype"]):
            result = _try_unseal(cipher, keys)
            if result is None:
                continue
            variant, plain = result
            decrypted += 1
            ctx.report(f"===== 帧 {body['frame']} WinRM 解密成功 ({variant}) =====",
                       "good")
            text = payload_text(plain)
            for line in text.splitlines()[:100]:
                if line.strip():
                    ctx.report("  " + clean_cell(line, 300), "info")
            ctx.write_output(f"winrm_{body['frame']}.xml", plain)
            for flag in codec.find_flags(text):
                ctx.report(f"发现 flag: {flag}", "good")

    if not decrypted:
        ctx.report("未能解密 WinRM 消息体。", "warn")
        ctx.report("可能原因：使用 HTTPS（需要 TLS keylog）、消息使用 Kerberos、"
                   "或该抓包未包含完整的认证会话。", "info")
        ctx.report("已成功提取认证信息与会话密钥，可用于进一步分析。", "info")
    else:
        ctx.report(f"共解密 {decrypted} 个 WinRM 消息", "good")
    ctx.set_progress(100)
