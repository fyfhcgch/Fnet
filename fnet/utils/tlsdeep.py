"""TLS helpers that do not depend on Wireshark: PEM/DER, keylog and QUIC.

The TLS feature uses these helpers to

* recognise PEM blocks and encrypted private keys, decrypting them with
  ``openssl`` when the user supplies a passphrase;
* compare a private key with the certificate chain seen in the capture so the
  key is only offered to the endpoint it actually belongs to;
* summarise NSS keylog coverage and TLS 1.3 ``KeyUpdate`` messages;
* name QUIC versions and fold the per-packet QUIC rows into connections.

Everything is standard library only.  The optional ``openssl`` CLI is used
because it understands every key/certificate format; RSA keys fall back to a
small pure-Python DER parser when it is missing.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import os
import re
import tempfile
from collections import Counter
from pathlib import Path

from fnet.tools.runner import find_tool, run

PEM_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----\r?\n(.*?)-----END \1-----", re.S)
PEM_HEADERS_RE = re.compile(r"^([A-Za-z-]+):\s*(.*)$", re.M)
ENCRYPTED_LABELS = ("ENCRYPTED PRIVATE KEY",)
OID_RSA = bytes.fromhex("06092a864886f70d010101")
OID_CN = b"\x55\x04\x03"
OID_SAN = b"\x55\x1d\x11"
KEYLOG_LABELS = (
    "CLIENT_RANDOM", "RSA", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0", "EARLY_EXPORTER_SECRET", "EXPORTER_SECRET",
    "RESUMPTION_MASTER_SECRET", "CLIENT_EARLY_TRAFFIC_SECRET",
)

#: QUIC version registry (RFC 9000 / 9369 plus common drafts).
QUIC_VERSIONS = {
    0x00000001: "QUIC v1 (RFC 9000)",
    0x6B3343CF: "QUIC v2 (RFC 9369)",
    0x709A50C4: "QUIC v2 draft",
    0xFF00001D: "draft-29",
    0xFF00001C: "draft-28",
    0xFF00001B: "draft-27",
    0xFF00001A: "draft-26",
    0xFF000019: "draft-25",
    0xFF000018: "draft-24",
    0xFF000017: "draft-23",
    0xFF000016: "draft-22",
    0xFF000015: "draft-21",
    0x51303530: "QUIC v2 (draft-00)",
    0x00000000: "version negotiation",
}

PACKET_TYPES = {
    "0": "Initial", "1": "0-RTT", "2": "Handshake", "3": "Retry",
    "4": "1-RTT", "5": "Version Negotiation", "6": "Stateless Reset",
}
# QUIC v2 (RFC 9369) renumbers the long-header packet types:
# 0=Retry, 1=Initial, 2=Handshake, 3=0-RTT.
PACKET_TYPES_V2 = {
    "0": "Retry", "1": "Initial", "2": "Handshake", "3": "0-RTT",
}
QUIC_V2_VERSIONS = {0x6B3343CF, 0x709A50C4}


# ---------------------------------------------------------------------------
# PEM / DER
# ---------------------------------------------------------------------------
def pem_blocks(text: str) -> list[dict]:
    """Split a PEM file into blocks with decoded DER and PEM headers."""
    blocks: list[dict] = []
    for match in PEM_RE.finditer(text or ""):
        label = match.group(1).strip()
        body = match.group(2)
        headers = dict(PEM_HEADERS_RE.findall(body))
        try:
            der = base64.b64decode("".join(body.split()), validate=False)
        except (binascii.Error, ValueError):
            continue
        encrypted = (label in ENCRYPTED_LABELS
                     or headers.get("Proc-Type", "").upper().endswith("ENCRYPTED")
                     or "DEK-Info" in headers)
        blocks.append({"label": label, "der": der, "headers": headers,
                       "encrypted": encrypted})
    return blocks


def is_encrypted_pem(text: str) -> bool:
    return any(block["encrypted"] for block in pem_blocks(text))


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("截断的 DER 长度")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or offset + count > len(data):
        raise ValueError("非法的 DER 长度")
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def _tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Return ``(tag, content, next_offset)`` for one DER TLV."""
    if offset >= len(data):
        raise ValueError("截断的 DER 数据")
    tag = data[offset]
    length, start = _read_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise ValueError("截断的 DER 内容")
    return tag, data[start:end], end


def _children(content: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, offset = _tlv(content, offset)
        items.append((tag, value))
    return items


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _der(0x02, raw)


def _find_oid_value(content: bytes, oid: bytes) -> bytes | None:
    """Depth-first search for an OID, returning the next sibling's content."""
    items = _children(content)
    for index, (tag, value) in enumerate(items):
        if tag == 0x06 and value == oid and index + 1 < len(items):
            return items[index + 1][1]
        if tag & 0x20 or tag in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3):
            found = _find_oid_value(value, oid)
            if found is not None:
                return found
    return None


def _name_text(content: bytes) -> str:
    raw = _find_oid_value(content, OID_CN)
    if raw is None:
        return ""
    try:
        return raw.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _asn1_time(tag: int, value: bytes) -> str:
    text = value.decode("ascii", "replace")
    if tag == 0x17 and len(text) >= 10:      # UTCTime YYMMDDHHMMSSZ
        year = int(text[:2])
        year += 2000 if year < 50 else 1900
        return f"{year:04d}-{text[2:4]}-{text[4:6]}"
    if tag == 0x18 and len(text) >= 8:       # GeneralizedTime YYYYMMDD...
        return f"{text[:4]}-{text[4:6]}-{text[6:8]}"
    return text[:20]


def _san_names(content: bytes) -> list[str]:
    """Decode the subjectAltName payload (the DER of ``GeneralNames``)."""
    try:
        tag, inner, _ = _tlv(content)
        if tag == 0x04:          # tolerate a full OCTET STRING wrapper
            tag, inner, _ = _tlv(inner)
        if tag != 0x30:
            return []
        names: list[str] = []
        for gtag, gvalue in _children(inner):
            if gtag == 0x82:
                names.append(gvalue.decode("utf-8", "replace"))
            elif gtag == 0x87 and len(gvalue) in (4, 16):
                names.append(str(ipaddress.ip_address(gvalue)))
        return names
    except ValueError:
        return []


def certificate_spki(der: bytes) -> bytes | None:
    """Return the ``SubjectPublicKeyInfo`` DER of an X.509 certificate."""
    try:
        _tag, body, _ = _tlv(der)
        _tag, tbs, _ = _tlv(body)
        items = _children(tbs)
        index = 1 if items and items[0][0] == 0xA0 else 0
        # serial, signature, issuer, validity, subject -> spki
        if len(items) < index + 6:
            return None
        tag, value = items[index + 5]
        if tag != 0x30:
            return None
        return _der(tag, value)
    except (ValueError, IndexError):
        return None


def certificate_info(der: bytes) -> dict:
    """Best-effort X.509 summary used in logs and CSV output."""
    info = {"subject": "", "issuer": "", "san": [], "not_before": "",
            "not_after": "", "serial": "", "spki": b""}
    try:
        _tag, body, _ = _tlv(der)
        _tag, tbs, _ = _tlv(body)
        items = _children(tbs)
        index = 1 if items and items[0][0] == 0xA0 else 0
        serial = items[index][1]
        info["serial"] = binascii.hexlify(serial).decode().upper()
        issuer = items[index + 2][1]
        validity = items[index + 3][1]
        subject = items[index + 4][1]
        info["subject"] = _name_text(subject)
        info["issuer"] = _name_text(issuer)
        times = _children(validity)
        if len(times) >= 2:
            info["not_before"] = _asn1_time(*times[0])
            info["not_after"] = _asn1_time(*times[1])
        san = _find_oid_value(tbs, OID_SAN)
        if san:
            info["san"] = _san_names(san)
        spki = certificate_spki(der)
        if spki:
            info["spki"] = spki
    except (ValueError, IndexError):
        pass
    return info


def _rsa_spki(der: bytes) -> bytes | None:
    """Build SPKI DER from a PKCS#1 ``RSAPrivateKey``."""
    try:
        _tag, body, _ = _tlv(der)
        items = _children(body)
        if len(items) < 3:
            return None
        modulus, exponent = items[1][1], items[2][1]
        public = _der(0x02, modulus) + _der(0x02, exponent)
        algorithm = _der(0x30, OID_RSA + b"\x05\x00")
        return _der(0x30, algorithm + _der(0x03, b"\x00" + _der(0x30, public)))
    except (ValueError, IndexError):
        return None


def private_key_spki_from_pem(text: str) -> bytes | None:
    """Pure-Python SPKI for unencrypted RSA keys (PKCS#1 or PKCS#8)."""
    for block in pem_blocks(text):
        if block["encrypted"]:
            continue
        if block["label"] == "RSA PRIVATE KEY":
            spki = _rsa_spki(block["der"])
            if spki:
                return spki
        if block["label"] == "PRIVATE KEY":
            try:
                _tag, body, _ = _tlv(block["der"])
                items = _children(body)
                if len(items) >= 3 and items[0][1] in (b"\x00", b"\x01"):
                    inner = items[2][1]
                    if inner.startswith(b"\x30"):
                        spki = _rsa_spki(inner)
                        if spki:
                            return spki
            except (ValueError, IndexError):
                continue
    return None


# ---------------------------------------------------------------------------
# Private keys via openssl
# ---------------------------------------------------------------------------
def openssl_path() -> str | None:
    return find_tool("openssl")


_RSA_SUPPORT: dict[str, bool] = {}


def rsa_keylist_supported(tshark_path: str) -> bool:
    """Whether this tshark still accepts the ``tls.keys_list`` preference.

    Wireshark 4.7 removed the RSA private-key list (TLS 1.3/keylog only), so
    Fnet reports that clearly instead of failing with "obsolete preference".
    """
    if not tshark_path:
        return False
    cached = _RSA_SUPPORT.get(tshark_path)
    if cached is not None:
        return cached
    code, out = run([tshark_path, "-G", "currentprefs"], timeout=60, echo=False)
    supported = code == 0 and "tls.keys_list" in out
    _RSA_SUPPORT[tshark_path] = supported
    return supported


def encrypt_marker(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:8000]
    except OSError:
        return False
    return is_encrypted_pem(head)


def decrypt_private_key(path: Path, passphrase: str,
                        destination: Path | None = None,
                        openssl: str | None = None) -> tuple[Path | None, str]:
    """Decrypt one encrypted PEM key into ``destination``.

    The passphrase is passed through the environment (``-passin
    env:FNET_TLS_KEY_PASS``) so it never shows up in the process list or logs.
    Returns ``(path, message)``; ``path`` is ``None`` when decryption failed.
    """
    source = Path(path)
    if not encrypt_marker(source):
        return source, ""
    if not passphrase:
        return None, "私钥已加密，需要通过 tls_key_passphrase 或配置提供口令"
    tool = openssl or openssl_path()
    if not tool:
        return None, "私钥已加密且未找到 openssl，无法解密（可安装 openssl 或提供明文私钥）"
    if destination is None:
        destination = source.with_suffix(".decrypted.pem")
    target = Path(destination)
    if target.is_file() and target.stat().st_size > 0:
        return target, f"使用已解密的私钥 {target.name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    code, out = run(
        [tool, "pkey", "-in", str(source), "-passin", "env:FNET_TLS_KEY_PASS",
         "-out", str(target)],
        timeout=60, echo=False, env={"FNET_TLS_KEY_PASS": passphrase})
    if code != 0 or not target.is_file() or target.stat().st_size == 0:
        try:
            target.unlink()
        except OSError:
            pass
        hint = out.strip().splitlines()[-1] if out.strip() else f"退出码 {code}"
        return None, f"私钥口令错误或格式不支持: {hint[:240]}"
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target, f"已解密私钥 {source.name}（口令仅通过环境变量传递）"


def spki_from_private_key(path: Path, passphrase: str = "",
                          openssl: str | None = None) -> bytes | None:
    """Public SPKI of a private key, using pure DER for RSA then openssl."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if not is_encrypted_pem(text):
        spki = private_key_spki_from_pem(text)
        if spki:
            return spki
    tool = openssl or openssl_path()
    if not tool:
        return None
    env = {"FNET_TLS_KEY_PASS": passphrase} if passphrase else None
    with tempfile.TemporaryDirectory(prefix="fnet-spki-") as tmp:
        target = Path(tmp) / "key.der"
        cmd = [tool, "pkey", "-in", str(path), "-pubout", "-outform", "DER",
               "-out", str(target)]
        if passphrase:
            cmd += ["-passin", "env:FNET_TLS_KEY_PASS"]
        code, _out = run(cmd, timeout=30, echo=False, env=env)
        if code != 0 or not target.is_file():
            return None
        return target.read_bytes()


def key_fingerprint(spki: bytes | None) -> str:
    if not spki:
        return ""
    return hashlib.sha256(spki).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Keylog coverage and TLS 1.3 KeyUpdate
# ---------------------------------------------------------------------------
def keylog_entries(paths: list[Path]) -> dict:
    """Parse NSS keylog files into labels, client randoms and unique lines."""
    labels: Counter = Counter()
    randoms: list[str] = []
    seen: set[str] = set()
    lines = 0
    for path in paths or []:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) < 2 or parts[0] not in KEYLOG_LABELS:
                continue
            if line.strip() in seen:
                continue
            seen.add(line.strip())
            labels[parts[0]] += 1
            lines += 1
            random = parts[1].lower()
            if random not in randoms:
                randoms.append(random)
    return {"lines": lines, "labels": dict(labels), "randoms": randoms}


def keylog_coverage(entries: dict, client_randoms: list[str]) -> dict:
    """How many Client Hello random values have a usable keylog secret."""
    have = {item.lower() for item in (entries or {}).get("randoms") or []}
    wanted = [item.lower() for item in client_randoms or [] if item]
    covered = [item for item in wanted if item in have]
    missing = [item for item in wanted if item not in have]
    return {"total": len(wanted), "covered": len(covered),
            "missing": missing, "percent": (100.0 * len(covered) / len(wanted)
                                            if wanted else 0.0)}


def key_update_rows(rows) -> list[dict]:
    """Fold tshark KeyUpdate rows into per-endpoint records."""
    grouped: dict[tuple[str, str], dict] = {}
    for raw in rows or []:
        row = list(raw) + [""] * (5 - len(raw))
        frame, src, sport, dst, dport = (str(item) for item in row[:5])
        endpoint = f"{src}:{sport} -> {dst}:{dport}"
        item = grouped.setdefault(endpoint, {
            "endpoint": endpoint, "frames": [], "count": 0})
        item["count"] += 1
        if frame and frame not in item["frames"]:
            item["frames"].append(frame)
    return list(grouped.values())


# ---------------------------------------------------------------------------
# QUIC
# ---------------------------------------------------------------------------
def quic_version_name(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        number = int(text, 16) if text.startswith("0x") else int(text, 0)
    except ValueError:
        return str(value)
    name = QUIC_VERSIONS.get(number)
    return f"{name} (0x{number:08x})" if name else f"0x{number:08x}"


def _is_quic_v2(value) -> bool:
    text = str(value or "").strip().lower()
    try:
        number = int(text, 16) if text.startswith("0x") else int(text, 0)
    except ValueError:
        return False
    return number in QUIC_V2_VERSIONS


def packet_type_name(value, version=None) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        try:
            text = str(int(text, 16))
        except ValueError:
            return str(value)
    table = PACKET_TYPES_V2 if _is_quic_v2(version) else PACKET_TYPES
    return table.get(text) or PACKET_TYPES.get(text, str(value or ""))


def _split_list(value: str) -> list[str]:
    return [part for part in str(value or "").replace(",", " ").split() if part]


def quic_connections(rows, *, limit: int = 400) -> list[dict]:
    """Aggregate QUIC field rows into connection records.

    Rows are ``(frame, time, src, sport, dst, dport, version, dcid, scid,
    packet type, [packet type v2,] server name, alpn, connection number,
    frame length)`` as produced by ``Tshark.fields``.  The optional v2 column
    is inserted at index 10; 14-column rows are still accepted.  The
    connection number (when tshark exposes it) folds both directions of a flow
    into one record.
    """
    connections: dict[str, dict] = {}
    for raw in rows or []:
        row = list(raw)
        if len(row) == 14:
            row.insert(10, "")
        elif len(row) < 14:
            row += [""] * (14 - len(row))
            row.insert(10, "")
        (frame, stamp, src, sport, dst, dport, version, dcid, scid,
         ptype, ptype_v2, sni, alpn, conn, length) = (
             str(item) for item in row[:15])
        key = conn or dcid or f"{src}:{sport}-{dst}:{dport}"
        item = connections.get(key)
        if item is None:
            item = {
                "id": key, "frames": 0, "bytes": 0, "versions": [],
                "packet_types": {}, "sni": [], "alpn": [],
                "client": "", "server": "", "first": stamp, "last": stamp,
                "frames_list": [],
            }
            connections[key] = item
        item["frames"] += 1
        try:
            item["bytes"] += int(float(length))
        except (TypeError, ValueError):
            pass
        if len(item["frames_list"]) < 12:
            item["frames_list"].append(frame)
        if stamp:
            item["last"] = stamp
            if not item["first"]:
                item["first"] = stamp
        # The client is the first sender of this connection ID.
        if not item["client"]:
            item["client"] = f"{src}:{sport}"
            item["server"] = f"{dst}:{dport}"
        for value, bucket in ((version, "versions"), (sni, "sni"),
                              (alpn, "alpn")):
            for part in _split_list(value):
                if part not in item[bucket]:
                    item[bucket].append(part)
        type_value = ptype
        if ptype_v2 and (_is_quic_v2(version) or not ptype):
            type_value = ptype_v2
        for part in _split_list(type_value):
            name = packet_type_name(part, version)
            item["packet_types"][name] = item["packet_types"].get(name, 0) + 1
    result = sorted(connections.values(),
                    key=lambda item: item["frames"], reverse=True)
    return result[:limit]
