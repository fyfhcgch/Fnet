"""Kerberos AS-REQ / AS-REP / TGS-REP extraction for offline cracking."""
from __future__ import annotations

import re

from fnet.features.common import tshark_rows
from fnet.features.registry import FeatureContext

FIELDS = [
    "frame.number",
    "tcp.stream",
    "kerberos.msg_type",
    "kerberos.cname_string",
    "kerberos.realm",
    "kerberos.etype",
    "kerberos.cipher",
    "kerberos.sname_string",
    "kerberos.padata_type",
    "kerberos.padata_value",
    "kerberos.error_code",
    "kerberos.checksum",
]
MSG_NAMES = {
    10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
    30: "KRB-ERROR",
}
ETYPE_NAMES = {1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 17: "AES128-CTS",
               18: "AES256-CTS", 23: "RC4-HMAC", 24: "RC4-HMAC-EXP"}


def _first(value: str) -> str:
    return re.split(r"[,\s]+", value or "")[0] if value else ""


def _clean_hex(value: str) -> str:
    return re.sub(r"(?i)[^0-9a-f]", "", value or "")


def _split_elements(value: str) -> list[str]:
    return [item for item in re.split(r"[,\s]+", value or "") if item]


def parse(ctx: FeatureContext) -> None:
    rows = tshark_rows(ctx, FIELDS, "kerberos", limit=200_000)
    if not rows:
        ctx.report("没有发现 Kerberos 流量", "warn")
        return

    hashes: list[str] = []
    seen: set[str] = set()
    counts: dict[str, int] = {}
    for index, raw in enumerate(rows):
        if index % 100 == 0:
            ctx.set_progress(int(index / len(rows) * 90))
            ctx.check_cancel()
        row = raw + [""] * (len(FIELDS) - len(raw))
        item = dict(zip(FIELDS, row))
        try:
            msg_type = int(item["kerberos.msg_type"] or 0)
        except ValueError:
            msg_type = 0
        name = MSG_NAMES.get(msg_type, f"type={msg_type}")
        counts[name] = counts.get(name, 0) + 1
        user = _first(item["kerberos.cname_string"]) or "unknown"
        realm = _first(item["kerberos.realm"]).upper() or "UNKNOWN.REALM"
        etypes = []
        for value in _split_elements(item["kerberos.etype"]):
            try:
                etypes.append(int(value))
            except ValueError:
                continue
        cipher = _clean_hex(item["kerberos.cipher"])
        spn = ".".join(_split_elements(item["kerberos.sname_string"]))
        error = item["kerberos.error_code"]

        if msg_type == 30:
            ctx.report(f"帧 {item['frame.number']} KRB-ERROR 代码 {error}", "warn")
            continue
        if not etypes:
            continue
        summary = ", ".join(ETYPE_NAMES.get(e, str(e)) for e in etypes)
        ctx.report(f"帧 {item['frame.number']} {name}: {user}@{realm} [{summary}]"
                   + (f" SN={spn}" if spn else ""), "debug")

        for etype in etypes:
            if etype != 23:
                if etype in (17, 18):
                    ctx.report(
                        f"帧 {item['frame.number']} 使用 AES etype {etype}，"
                        "需要 hashcat -m 19600/19700 且需构造 asrep/tgs 格式", "info")
                continue
            if not cipher or len(cipher) < 64:
                continue
            checksum, edata = cipher[-32:], cipher[:-32]
            if msg_type == 11:
                line = f"$krb5asrep$23${user}@{realm}:{checksum}${edata}"
                label = "AS-REP etype23 (hashcat -m 18200)"
            elif msg_type == 13:
                service = spn or "unknown"
                line = f"$krb5tgs$23$*{user}${realm}${service}*${checksum}${edata}"
                label = "TGS-REP etype23 (hashcat -m 13100)"
            elif msg_type == 10:
                # PA-ENC-TIMESTAMP pre-auth blob.
                line = f"$krb5pa$23${user}${realm}${edata}{checksum}"
                label = "AS-REQ pre-auth etype23 (hashcat -m 7500, 请核对格式)"
            else:
                continue
            if line in seen:
                continue
            seen.add(line)
            hashes.append(line)
            ctx.report(f"===== {label} =====", "good")
            ctx.report(line, "good")
            ctx.add_finding("hash", f"{user}@{realm} {label}",
                            frame=item["frame.number"], level="good",
                            detail=line,
                            extra={"protocol": "kerberos",
                                   "account": f"{user}@{realm}",
                                   "hash": line})

    ctx.report("消息统计: " + ", ".join(f"{k}={v}" for k, v in counts.items()), "info")
    if hashes:
        ctx.write_output("kerberos_hashes.txt", "\n".join(hashes) + "\n")
        ctx.report("哈希已保存，可直接尝试 hashcat/ john 离线破解", "good")
    else:
        ctx.report("没有生成可破解的 RC4-HMAC 哈希（可能只包含 AES 或加密数据字段为空）",
                   "warn")
    ctx.set_progress(100)
