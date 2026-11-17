"""Kerberos AS-REQ / AS-REP / TGS-REP extraction, decryption and PAC parsing.

The handler keeps the original tshark field extraction (so it works on any
capture Wireshark can dissect) and hands the crypto to
:mod:`fnet.utils.kerberos`:

* AS-REP / TGS-REP encrypted parts become hashcat lines (18200/13100 for
  RC4, 19800/19900 and 19600/19700 for AES);
* with ``kerberos_key``, ``kerberos_password`` or a keytab
  (``kerberos_keytab``) the encrypted part is decrypted, so an embedded PAC
  and its NTLM hash become visible;
* every message feeds a per-user timeline.
"""
from __future__ import annotations

import re
from pathlib import Path

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext

FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "kerberos.msg_type",
    "kerberos.cname_string",
    "kerberos.realm",
    "kerberos.etype",
    "kerberos.cipher",
    "kerberos.sname_string",
    "kerberos.salt",
    "kerberos.padata_type",
    "kerberos.padata_value",
    "kerberos.error_code",
]
MSG_NAMES = {
    10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
    30: "KRB-ERROR",
}
ETYPE_NAMES = {1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 17: "AES128-CTS",
               18: "AES256-CTS", 23: "RC4-HMAC", 24: "RC4-HMAC-EXP"}
#: Key usage numbers for the encrypted part of each reply type.
REPLY_USAGE = {11: (3,), 13: (8, 9), 10: (1,)}
MAX_DECRYPT = 200


def _first(value: str) -> str:
    return re.split(r"[,\s]+", value or "")[0] if value else ""


def _clean_hex(value: str) -> str:
    return re.sub(r"(?i)[^0-9a-f]", "", value or "")


def _split_elements(value: str) -> list[str]:
    return [item for item in re.split(r"[,\s]+", value or "") if item]


def _int_values(value: str) -> list[int]:
    out: list[int] = []
    for item in _split_elements(value):
        try:
            out.append(int(item))
        except ValueError:
            continue
    return out


def _keytab_keys(ctx: FeatureContext) -> dict[str, dict[int, bytes]]:
    """Load and cache ``principal -> {etype: key}`` from the configured keytab."""
    cache = ctx.__dict__.setdefault("_keytab_cache", {})
    path = str(ctx.params.get("kerberos_keytab") or "").strip()
    if not path:
        return {}
    if path in cache:
        return cache[path]
    from fnet.utils import kerberos as krb

    try:
        data = Path(path).expanduser().read_bytes()
    except OSError as exc:
        ctx.report(f"无法读取 keytab {path}: {exc}", "error")
        cache[path] = {}
        return {}
    keys = krb.keytab_keys(data)
    if keys:
        ctx.report(f"keytab 载入 {path}，包含 {len(keys)} 个主体", "info")
    else:
        ctx.report(f"keytab 中没有可用密钥: {path}", "warn")
    cache[path] = keys
    return keys


def _candidate_keys(ctx: FeatureContext, user: str, realm: str,
                    etype: int, salt: str) -> list[bytes]:
    """Keys to try for one principal/etype, from keytab, password or raw key."""
    from fnet.utils import kerberos as krb

    keys: list[bytes] = []
    raw = _clean_hex(str(ctx.params.get("kerberos_key") or ""))
    if raw:
        try:
            keys.append(bytes.fromhex(raw))
        except ValueError:
            pass
    password = str(ctx.params.get("kerberos_password") or "")
    if password:
        use_salt = salt or krb.password_salt(realm, user)
        try:
            keys.append(krb.string_to_key(password, use_salt, etype))
        except (ValueError, UnicodeError):
            pass
    keytab = _keytab_keys(ctx)
    if keytab:
        candidates = [f"{user}@{realm}", user]
        candidates += [name for name in keytab
                       if name and name.split("$")[0].lower() == user.lower()]
        for name in candidates:
            entry = keytab.get(name) or keytab.get(name.upper())
            if not entry:
                continue
            key = entry.get(etype)
            if key and key not in keys:
                keys.append(key)
    return keys[:8]


def _decrypt(ctx: FeatureContext, item: dict, user: str, realm: str,
             etype: int, cipher: bytes) -> dict | None:
    from fnet.utils import kerberos as krb

    try:
        msg_type = int(item["kerberos.msg_type"] or 0)
    except ValueError:
        return None
    salt = _first(item.get("kerberos.salt") or "")
    keys = _candidate_keys(ctx, user, realm, etype, salt)
    if not keys:
        return None
    for usage in REPLY_USAGE.get(msg_type, ()):
        for key in keys:
            result = krb.decrypt_encrypted_part(
                {"etype": etype, "cipher": cipher}, key, usage)
            if result.get("ok"):
                result["usage"] = usage
                return result
    return None


def _report_pac(ctx: FeatureContext, plaintext: bytes, user: str,
                realm: str, frame: str) -> None:
    from fnet.utils import kerberos as krb

    pac, offset = krb.find_pac(plaintext)
    if not pac:
        return
    lines = [f"frame={frame} user={user}@{realm} offset={offset}"]
    for key in ("user", "domain", "ntlm_hash", "lm_hash"):
        if pac.get(key):
            lines.append(f"{key}: {pac[key]}")
    logon = pac.get("logon_info") or {}
    for key in ("full_name", "logon_server", "logon_count",
                "bad_password_count"):
        if logon.get(key) not in (None, "", 0):
            lines.append(f"{key}: {logon[key]}")
    if pac.get("sids"):
        lines.append("sids: " + ", ".join(pac["sids"][:20]))
    text = "\n".join(lines)
    ctx.report("===== 解密后 PAC =====", "good")
    for line in lines[1:]:
        ctx.report("  " + clean_cell(line, 300), "good")
    ctx.write_output(f"kerberos_pac_{frame or 'frame'}.txt", text)
    account = pac.get("user") or user
    ctx.add_finding("protocol", f"PAC 用户 {account}@{pac.get('domain') or realm}",
                    frame=frame, level="good", detail=text,
                    extra={"protocol": "kerberos", "account": account})
    if pac.get("ntlm_hash"):
        ctx.report(f"  NTLM 哈希: {pac['ntlm_hash']}", "good")
        ctx.add_finding("hash", f"NTLM {account}", frame=frame, level="good",
                        detail=pac["ntlm_hash"],
                        extra={"protocol": "kerberos", "account": account,
                               "hash": pac["ntlm_hash"]})


def parse(ctx: FeatureContext) -> None:
    from fnet.utils import kerberos as krb

    rows = tshark_rows(ctx, FIELDS, "kerberos", limit=200_000)
    if not rows:
        ctx.report("没有发现 Kerberos 流量", "warn")
        return

    hashes: list[str] = []
    seen_hashes: set[str] = set()
    counts: dict[str, int] = {}
    events: list[dict] = []
    decrypted = 0
    preauth = 0

    for index, raw in enumerate(rows):
        if index % 100 == 0:
            ctx.set_progress(int(index / len(rows) * 85))
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
        etypes = _int_values(item["kerberos.etype"])
        cipher = _clean_hex(item["kerberos.cipher"])
        spn = ".".join(_split_elements(item["kerberos.sname_string"]))
        error = item["kerberos.error_code"]
        try:
            timestamp = float(item["frame.time_epoch"] or 0)
        except ValueError:
            timestamp = 0.0

        events.append({
            "time": timestamp,
            "frame": item["frame.number"],
            "msg_type": msg_type,
            "user": user,
            "realm": realm,
            "spn": spn,
            "etype": etypes[0] if etypes else None,
            "error": error or None,
        })

        if msg_type == 30:
            ctx.report(f"帧 {item['frame.number']} KRB-ERROR 代码 {error}", "warn")
            continue
        if not etypes:
            continue
        summary = ", ".join(ETYPE_NAMES.get(e, str(e)) for e in etypes)
        ctx.report(f"帧 {item['frame.number']} {name}: {user}@{realm} [{summary}]"
                   + (f" SN={spn}" if spn else ""), "debug")

        if msg_type == 10 and ("2" in _split_elements(item["kerberos.padata_type"])
                               or item["kerberos.padata_value"]):
            preauth += 1

        if not cipher:
            continue
        blob = bytes.fromhex(cipher) if len(cipher) % 2 == 0 else b""
        for etype in etypes:
            modes = krb.hashcat_modes(msg_type, etype)
            if not modes:
                continue
            lines = krb.hashcat_lines(msg_type, user, realm, spn, etype, blob)
            for line in lines:
                if line in seen_hashes:
                    continue
                seen_hashes.add(line)
                hashes.append(line)
                label = f"{name} etype{etype} (hashcat -m {modes[0]})"
                ctx.report(f"===== {label} =====", "good")
                ctx.report(line, "good")
                ctx.add_finding("hash", f"{user}@{realm} {label}",
                                frame=item["frame.number"], level="good",
                                detail=line,
                                extra={"protocol": "kerberos",
                                       "account": f"{user}@{realm}",
                                       "hash": line,
                                       "mode": modes[0]})

        decrypted_here = False
        ordered = [etype for etype in (18, 23, 17) if etype in etypes]
        for etype in ordered:
            if decrypted >= MAX_DECRYPT:
                break
            result = _decrypt(ctx, item, user, realm, etype, blob)
            if not result:
                continue
            decrypted += 1
            decrypted_here = True
            plaintext = result.get("plaintext") or b""
            ctx.report(
                f"帧 {item['frame.number']} {name} 解密成功 "
                f"(etype {etype}, usage {result.get('usage')}, "
                f"{len(plaintext)} 字节)", "good")
            ctx.add_finding("protocol", f"{name} 解密 {user}@{realm}",
                            frame=item["frame.number"], level="good",
                            extra={"protocol": "kerberos", "etype": etype,
                                   "usage": result.get("usage")})
            _report_pac(ctx, plaintext, user, realm, item["frame.number"])
            break
        if decrypted_here:
            continue

    ctx.report("消息统计: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
               "info")
    if hashes:
        ctx.write_output("kerberos_hashes.txt", "\n".join(hashes) + "\n")
        ctx.report("哈希已保存，可直接尝试 hashcat/ john 离线破解", "good")
    else:
        ctx.report("没有生成可破解的哈希（可能只包含 AS-REQ 或加密数据为空）",
                   "warn")
    if preauth:
        ctx.report(f"发现 {preauth} 条带 pre-auth 的 AS-REQ；"
                   "若未配置密码/密钥，需先抓取 AS-REP 才能生成 18200 哈希",
                   "info")

    timeline = krb.build_timeline(events)
    if timeline:
        summary = krb.summarise_timeline(events)
        ctx.report(
            f"===== Kerberos 时间线 ({summary['count']} 条, "
            f"{summary.get('duration', 0):.1f}s) =====", "good")
        for item in timeline[:100]:
            stamp = item.get("time") or 0
            line = (f"{stamp:.3f}s 帧 {item.get('frame')} "
                    f"{item.get('message')} {item.get('user') or ''}"
                    f"@{item.get('realm') or ''}")
            if item.get("spn"):
                line += f" SN={item['spn']}"
            if item.get("error") is not None:
                line += f" 错误={item['error']}"
            ctx.report("  " + clean_cell(line, 250), "info")
        if summary.get("users"):
            ctx.report("用户统计: " + ", ".join(
                f"{name}={count}" for name, count
                in sorted(summary["users"].items(),
                          key=lambda pair: -pair[1])[:20]), "info")
        lines = [f"{item.get('time', 0):.6f}\t{item.get('message')}\t"
                 f"{item.get('user')}@{item.get('realm')}\t"
                 f"{item.get('spn') or ''}\t{item.get('frame')}"
                 for item in timeline]
        ctx.write_output("kerberos_timeline.txt", "\n".join(lines) + "\n")
    ctx.set_progress(100)
