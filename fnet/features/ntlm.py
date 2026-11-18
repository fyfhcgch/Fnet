"""NTLMSSP parsing and NetNTLM hash extraction (SMB, HTTP, LDAP, RDP...)."""
from __future__ import annotations

import base64
import re
from fnet.features.common import normalize_hex, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils.pcap import hex_to_bytes

SIGNATURE = b"NTLMSSP\x00"
TYPE2 = 2
TYPE3 = 3

FIELDS = [
    "frame.number",
    "tcp.stream",
    "ntlmssp.ntlmauthenticate",
    "ntlmssp.ntlmchallenge",
    "ntlmssp.auth.username",
    "ntlmssp.auth.domain",
    "ntlmssp.auth.hostname",
    "ntlmssp.ntlmserverchallenge",
    "ntlmssp.ntlmv2_response.ntproofstr",
    "ntlmssp.ntlmv2_response",
    "ntlmssp.auth.ntresponse",
    "ntlmssp.auth.lmresponse",
    "ntlmssp.negotiateflags",
    "http.authorization",
    "http.www_authenticate",
]


def _decode_utf16(value: bytes) -> str:
    try:
        return value.decode("utf-16le", "ignore")
    except Exception:  # noqa: BLE001
        return value.decode("latin-1", "ignore")


def _to_int(value, default: int = 0) -> int:
    """Parse a tshark numeric cell.

    ``ntlmssp.negotiateflags`` is a FLAGS field, so tshark prints it as
    ``0x62088235`` (and repeats it comma-separated when a frame carries more
    than one message).  Plain decimal cells still work.
    """
    if isinstance(value, int):
        return value
    text = str(value or "").strip().split(",", 1)[0].strip()
    if not text:
        return default
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return default


def _read(msg: bytes, length_at: int, offset_at: int) -> bytes:
    length = int.from_bytes(msg[length_at:length_at + 2], "little")
    offset = int.from_bytes(msg[offset_at:offset_at + 4], "little")
    if length <= 0 or offset <= 0 or offset + length > len(msg):
        return b""
    return msg[offset:offset + length]


def parse_type2(msg: bytes) -> dict:
    challenge = msg[24:32] if len(msg) >= 32 else b""
    flags = int.from_bytes(msg[20:24], "little") if len(msg) >= 24 else 0
    return {"challenge": challenge, "flags": flags}


def parse_type3(msg: bytes) -> dict:
    if len(msg) < 64:
        return {}
    flags = int.from_bytes(msg[60:64], "little")
    return {
        "lm": _read(msg, 12, 16),
        "nt": _read(msg, 20, 24),
        "domain": _decode_utf16(_read(msg, 28, 32)),
        "user": _decode_utf16(_read(msg, 36, 40)),
        "workstation": _decode_utf16(_read(msg, 44, 48)),
        "session_key": _read(msg, 52, 56),
        "flags": flags,
    }


def _extract_messages(raw: str) -> list[bytes]:
    """Find NTLMSSP messages inside a hex/base64 tshark field."""
    messages: list[bytes] = []
    if not raw:
        return messages
    data = hex_to_bytes(raw) if re.search(r"(?i)[0-9a-f]{2}:", raw) else b""
    if not data or SIGNATURE not in data:
        for match in re.finditer(r"[A-Za-z0-9+/=]{20,}", raw):
            decoded = _b64(match.group(0))
            if decoded and SIGNATURE in decoded:
                data = decoded
                break
    pos = data.find(SIGNATURE)
    while pos != -1:
        message = bytearray(data[pos:])
        # Trim trailing bytes that belong to the next protocol layer.
        if len(message) >= 12:
            msg_type = int.from_bytes(message[8:12], "little")
            if msg_type == TYPE3 and len(message) >= 64:
                ends = []
                for length_at, offset_at in ((12, 16), (20, 24), (28, 32),
                                             (36, 40), (44, 48), (52, 56)):
                    length = int.from_bytes(message[length_at:length_at + 2], "little")
                    offset = int.from_bytes(message[offset_at:offset_at + 4], "little")
                    if offset and length:
                        ends.append(offset + length)
                if ends:
                    del message[max(ends):]
        messages.append(bytes(message))
        pos = data.find(SIGNATURE, pos + 8)
    return messages


def _b64(value: str) -> bytes | None:
    value = re.sub(r"\s+", "", value)
    value += "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value, validate=False)
    except Exception:  # noqa: BLE001
        return None


def _collect(ctx: FeatureContext) -> list[dict]:
    rows = tshark_rows(ctx, FIELDS, "ntlmssp or http.authorization or smb2",
                       limit=200_000)
    events: list[dict] = []
    for raw in rows:
        row = raw + [""] * (len(FIELDS) - len(raw))
        item = dict(zip(FIELDS, row))
        stream = item["tcp.stream"]
        frame = item["frame.number"]
        for column in ("ntlmssp.ntlmauthenticate", "ntlmssp.ntlmchallenge",
                       "http.authorization", "http.www_authenticate"):
            for message in _extract_messages(item.get(column, "")):
                if len(message) < 12:
                    continue
                msg_type = int.from_bytes(message[8:12], "little")
                event = {"frame": frame, "stream": stream, "type": msg_type,
                         "raw": message, "source": column,
                         "item": item}
                if msg_type == TYPE2:
                    event.update(parse_type2(message))
                elif msg_type == TYPE3:
                    event.update(parse_type3(message))
                events.append(event)
        # Structured fallback (newer tshark exposes decoded fields directly).
        # ``ntlmssp.ntlmauthenticate`` / ``ntlmssp.ntlmchallenge`` only exist in
        # old tshark builds; SMB/LDAP/RDP sessions expose the same data through
        # these decoded fields (the server challenge lives on its own frame).
        challenge = normalize_hex(item.get("ntlmssp.ntlmserverchallenge", ""))
        ntproof = normalize_hex(item.get("ntlmssp.ntlmv2_response.ntproofstr", ""))
        ntresponse = normalize_hex(item.get("ntlmssp.auth.ntresponse", ""))
        username = item.get("ntlmssp.auth.username", "")
        if challenge and not username:
            events.append({
                "frame": frame, "stream": stream, "type": TYPE2,
                "challenge": bytes.fromhex(challenge),
                "source": "structured", "item": item,
            })
        if (challenge or ntproof) and username:
            events.append({
                "frame": frame, "stream": stream, "type": TYPE3,
                "user": username,
                "domain": item.get("ntlmssp.auth.domain", ""),
                "challenge": bytes.fromhex(challenge) if challenge else b"",
                "ntproof": bytes.fromhex(ntproof) if ntproof else b"",
                "nt": bytes.fromhex(ntresponse) if ntresponse else b"",
                "source": "structured", "item": item,
            })
    events.sort(key=lambda e: int(e["frame"] or 0))
    return events


def extract(ctx: FeatureContext) -> None:
    events = _collect(ctx)
    if not events:
        ctx.report("没有发现 NTLMSSP 认证流量", "warn")
        return

    challenge_by_stream: dict[str, bytes] = {}
    reported_challenges: set[tuple[str, str]] = set()
    hashes: list[str] = []
    seen: set[str] = set()
    users: set[str] = set()

    for event in events:
        ctx.check_cancel()
        stream = event["stream"]
        if event["type"] == TYPE2:
            challenge = event.get("challenge") or event.get("challenge", b"")
            if challenge:
                challenge_by_stream[stream] = challenge
                key = (stream, challenge.hex())
                if key not in reported_challenges:
                    reported_challenges.add(key)
                    ctx.report(
                        f"帧 {event['frame']} NTLM CHALLENGE: {challenge.hex()}",
                        "info")
            continue
        if event["type"] != TYPE3:
            continue
        item = event.get("item", {})
        user = event.get("user") or item.get("ntlmssp.auth.username", "")
        domain = event.get("domain") or item.get("ntlmssp.auth.domain", "")
        host = item.get("ntlmssp.auth.hostname", "")
        challenge = (event.get("challenge")
                     or challenge_by_stream.get(stream)
                     or bytes.fromhex(normalize_hex(item.get("ntlmssp.ntlmserverchallenge", ""))))
        nt = event.get("nt") or bytes.fromhex(normalize_hex(item.get("ntlmssp.auth.ntresponse", "")))
        lm = event.get("lm", b"")
        ntproof = event.get("ntproof") or bytes.fromhex(
            normalize_hex(item.get("ntlmssp.ntlmv2_response.ntproofstr", "")))
        identity = f"{domain}\\{user}"
        users.add(identity)
        ctx.report(f"===== 帧 {event['frame']} NTLM AUTHENTICATE =====", "good")
        ctx.report(f"账号: {identity or '(空)'}  主机: {host or '-'}", "good")
        if event.get("workstation"):
            ctx.report(f"工作站: {event['workstation']}", "info")

        line = ""
        if len(nt) > 24 or ntproof:
            proof = ntproof or nt[:16]
            blob = nt[16:] if len(nt) > 16 else b""
            if challenge and proof and blob:
                line = (f"{user}::{domain}:{challenge.hex()}:{proof.hex()}:{blob.hex()}")
                ctx.report("NetNTLMv2 (hashcat -m 5600):", "good")
                ctx.report(line, "good")
        elif nt and challenge:
            line = f"{user}::{domain}:{lm.hex()}:{nt.hex()}:{challenge.hex()}"
            ctx.report("NetNTLMv1 (hashcat -m 5500):", "good")
            ctx.report(line, "good")
        if line and line not in seen:
            seen.add(line)
            hashes.append(line)
            is_v2 = bool(len(nt) > 24 or ntproof)
            ctx.add_finding(
                "hash", f"{identity} {('NetNTLMv2' if is_v2 else 'NetNTLMv1')}",
                frame=event["frame"], level="good", detail=line,
                extra={"protocol": "ntlm", "account": identity,
                       "domain": domain, "hash": line,
                       "mode": "5600" if is_v2 else "5500"})

        flags = event.get("flags")
        if not flags:
            flags = _to_int(item.get("ntlmssp.negotiateflags"))
        if flags:
            ctx.report(f"协商标志: 0x{flags:08x}", "info")
        session_key = event.get("session_key", b"")
        if session_key:
            ctx.report("加密会话密钥存在（WinRM/RDP 解密可用）", "info")

    ctx.report(f"共识别 {len(users)} 个账号，{len(hashes)} 条哈希", "good")
    if hashes:
        ctx.write_output("ntlm_hashes.txt", "\n".join(hashes) + "\n")
        ctx.report("可直接用于 hashcat：", "info")
        ctx.report("  NetNTLMv2: hashcat -m 5600 ntlm_hashes.txt wordlist.txt", "info")
        ctx.report("  NetNTLMv1: hashcat -m 5500 ntlm_hashes.txt wordlist.txt", "info")
    ctx.set_progress(100)
