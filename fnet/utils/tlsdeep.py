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
import hmac
import ipaddress
import os
import re
import struct
import tempfile
from collections import Counter
from pathlib import Path

from fnet.tools.runner import find_tool, run
from fnet.utils.crypto import aes_encrypt_block, aes_gcm_decrypt

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


# ---------------------------------------------------------------------------
# QUIC Initial packets without a keylog (RFC 8446 §7.1, RFC 9001 §5.2/§5.4)
# ---------------------------------------------------------------------------
#: Per-version Initial salts.  Every QUIC Initial uses these public constants,
#: so the CRYPTO frames (and therefore the Client Hello) can be recovered
#: without any keylog.  draft-29 predates QUIC v2 but shares the v1 scheme.
QUIC_INITIAL_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    0x709A50C4: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    0xFF00001D: bytes.fromhex("afbfec289943d24c9a5e5fee14bd0efa5dfab56f"),
}
#: HKDF label variants per family: ``(label prefix, key prefix)``.  RFC 9369
#: renames the QUIC v2 labels to the ``tls13quicv2 `` prefix; some early
#: implementations (and Fnet's own sample generator) instead used
#: ``tls13 `` + ``quicv2…``, so both are tried and the AEAD tag decides.
QUIC_LABEL_VARIANTS = {
    "v1": (("tls13 ", "quic"),),
    "v2": (("tls13quicv2 ", "quic"), ("tls13 ", "quicv2")),
}


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: bytes, length: int,
                      context: bytes = b"") -> bytes:
    """RFC 8446 §7.1 HKDF-Expand-Label; ``label`` already carries its prefix."""
    info = (struct.pack("!H", length) + bytes([len(label)]) + label
            + bytes([len(context)]) + context)
    return hkdf_expand(secret, info, length)


def _quic_varint(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    length = 1 << (first >> 6)
    if offset + length > len(data):
        raise ValueError("截断的 QUIC varint")
    value = first & 0x3F
    for shift in range(1, length):
        value = (value << 8) | data[offset + shift]
    return value, offset + length


def _unprotect_quic_initial(packet: bytes, pn_offset: int,
                            keys: dict) -> bytes | None:
    """Remove header protection and decrypt one Initial payload (AES-GCM)."""
    # The mask sample starts at pn_offset + 4 regardless of the PN length
    # (RFC 9001 §5.4.2); the packet number length is recovered from the
    # unmasked first byte.
    sample = packet[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return None
    mask = aes_encrypt_block(sample, keys["hp"])
    first = packet[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    if pn_offset + pn_len + 16 > len(packet):
        return None
    pn_raw = bytes(a ^ b for a, b in
                   zip(packet[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    pn = int.from_bytes(pn_raw, "big")
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    aad = bytes([first]) + packet[1:pn_offset] + pn_raw
    plain, ok = aes_gcm_decrypt(packet[pn_offset + pn_len:], keys["key"],
                                nonce, aad)
    return plain if ok else None


def _quic_crypto_frames(plain: bytes) -> list[tuple[int, bytes]]:
    """``[(offset, data)]`` for the CRYPTO frames in one decrypted payload."""
    chunks: list[tuple[int, bytes]] = []
    try:
        pos = 0
        while pos < len(plain):
            frame_type, pos = _quic_varint(plain, pos)
            if frame_type in (0x00, 0x01):          # PADDING / PING
                continue
            if frame_type in (0x02, 0x03):          # ACK / ACK_ECN
                _largest, pos = _quic_varint(plain, pos)
                _delay, pos = _quic_varint(plain, pos)
                count, pos = _quic_varint(plain, pos)
                for _ in range(min(count, 64)):
                    _gap, pos = _quic_varint(plain, pos)
                    _range, pos = _quic_varint(plain, pos)
                if frame_type == 0x03:
                    for _ in range(3):
                        _ecn, pos = _quic_varint(plain, pos)
                continue
            if frame_type == 0x06:                  # CRYPTO
                offset, pos = _quic_varint(plain, pos)
                length, pos = _quic_varint(plain, pos)
                if pos + length > len(plain):
                    break
                chunks.append((offset, plain[pos:pos + length]))
                pos += length
                continue
            break                                   # unknown frame: stop
    except (ValueError, IndexError):
        return chunks
    return chunks


def quic_initial_crypto(packet) -> dict | None:
    """Decrypt one QUIC long-header Initial packet without a keylog.

    Derives the RFC 9001 Initial protection keys from the DCID (HKDF-Extract
    with the version's known salt, then ``client in``/``server in`` and
    ``quic key``/``quic iv``/``quic hp``), strips header protection and
    AES-GCM-decrypts the payload.  Returns ``{"version", "dcid", "scid",
    "crypto": [(offset, bytes)]}`` or ``None`` for Retry/version-negotiation/
    unsupported versions/decryption failures (never raises).
    """
    try:
        return _quic_initial_crypto(bytes(packet or b""))
    except Exception:  # noqa: BLE001
        return None


def _quic_initial_crypto(packet: bytes) -> dict | None:
    if len(packet) < 6 or not packet[0] & 0x80 or not packet[0] & 0x40:
        return None                                  # short/short-header
    version = int.from_bytes(packet[1:5], "big")
    if version == 0:                                 # version negotiation
        return None
    salt = QUIC_INITIAL_SALTS.get(version)
    if salt is None:
        return None
    # v1 Initial is 0b00 and Retry 0b11; RFC 9369 swaps them (Initial 0b01).
    initial_type = 1 if version in QUIC_V2_VERSIONS else 0
    if (packet[0] >> 4) & 0x03 != initial_type:
        return None                                  # Retry/0-RTT/Handshake
    offset = 5
    dcid_len = packet[offset]
    offset += 1
    dcid = packet[offset:offset + dcid_len]
    offset += dcid_len
    scid_len = packet[offset]
    offset += 1
    scid = packet[offset:offset + scid_len]
    offset += scid_len
    token_len, offset = _quic_varint(packet, offset)
    offset += token_len
    payload_len, offset = _quic_varint(packet, offset)
    pn_offset = offset
    if pn_offset + 21 > len(packet):
        return None
    end = min(pn_offset + payload_len, len(packet))
    initial_secret = hkdf_extract(salt, dcid)
    family = "v2" if version in QUIC_V2_VERSIONS else "v1"
    for label_prefix, key_prefix in QUIC_LABEL_VARIANTS[family]:
        for role in ("client", "server"):
            secret = hkdf_expand_label(
                initial_secret, (label_prefix + role + " in").encode("ascii"), 32)
            keys = {
                "key": hkdf_expand_label(
                    secret,
                    (label_prefix + key_prefix + " key").encode("ascii"), 16),
                "iv": hkdf_expand_label(
                    secret,
                    (label_prefix + key_prefix + " iv").encode("ascii"), 12),
                "hp": hkdf_expand_label(
                    secret,
                    (label_prefix + key_prefix + " hp").encode("ascii"), 16),
            }
            plain = _unprotect_quic_initial(packet[:end], pn_offset, keys)
            if plain is None:
                continue
            return {
                "version": version,
                "dcid": dcid.hex(),
                "scid": scid.hex(),
                "crypto": _quic_crypto_frames(plain),
            }
    return None


def quic_initial_fingerprints(packets, *, protocol: str = "q") -> list[dict]:
    """Recover Client Hellos from raw QUIC Initial datagrams (no keylog).

    ``packets`` holds raw UDP payloads, optionally as ``(label, bytes)`` tuples
    where ``label`` is e.g. the frame number.  CRYPTO frame data is aggregated
    per ``(version, dcid)``; the reassembled handshake stream is parsed with
    :func:`parse_client_hello` and fingerprinted (JA3/JA4, ``q`` prefix per the
    JA4+ spec for QUIC).  Only connections whose Client Hello could be
    reassembled are returned; everything else is silently skipped.
    """
    streams: dict[tuple[int, str], dict[int, bytes]] = {}
    labels: dict[tuple[int, str], list[str]] = {}
    scids: dict[tuple[int, str], str] = {}
    for item in packets or []:
        if isinstance(item, (bytes, bytearray)):
            label, raw = "", bytes(item)
        else:
            label, raw = str(item[0]), bytes(item[1])
        parsed = quic_initial_crypto(raw)
        if not parsed:
            continue
        key = (parsed["version"], parsed["dcid"])
        bucket = streams.setdefault(key, {})
        for offset, data in parsed["crypto"]:
            bucket[offset] = data
        scids.setdefault(key, parsed["scid"])
        if label:
            names = labels.setdefault(key, [])
            if label not in names:
                names.append(label)
    results: list[dict] = []
    for (version, dcid), bucket in streams.items():
        stream = b""
        for offset in sorted(bucket):
            data = bucket[offset]
            if offset + len(data) <= len(stream):
                continue                    # duplicate / already covered
            if offset > len(stream):        # gap: pad and keep going
                stream += b"\x00" * (offset - len(stream))
                stream += data
            else:
                stream = stream[:offset] + data
        if not stream.startswith(b"\x01"):  # handshake must start with CH
            continue
        hello = parse_client_hello(stream)
        if not hello:
            continue
        fp = fingerprints(hello, protocol=protocol)
        key = (version, dcid)
        results.append({
            "version": version,
            "version_name": quic_version_name(version),
            "dcid": dcid,
            "scid": scids.get(key, ""),
            "frames": labels.get(key, []),
            "sni": fp["sni"],
            "alpn": hello.get("alpn") or [],
            "ja3": fp["ja3"],
            "ja4": fp["ja4"],
            "hello": hello,
        })
    return results


# ---------------------------------------------------------------------------
# TLS fingerprinting: JA3 / JA3S / JA4 / JA4S
# ---------------------------------------------------------------------------
# JA3 follows the Salesforce definition (MD5 over "TLSVersion,Ciphers,
# Extensions,EllipticCurves,EllipticCurvePointFormats"); JA4/JA4S follow the
# FoxIO JA4+ specification (https://github.com/FoxIO-LLC/ja4).  Everything is
# computed from plain dictionaries so callers can feed either the byte-level
# parsers below or tshark field values.

#: GREASE values (RFC 8701) that JA4 ignores wherever it sees them.
GREASE_VALUES = frozenset(((value << 4) | 0xA) * 0x101 for value in range(16))
#: JA4 short version codes for known protocol versions.
JA4_VERSIONS = {
    0x0002: "s2", 0x0300: "s3", 0x0301: "10", 0x0302: "11",
    0x0303: "12", 0x0304: "13",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
_EMPTY_HASH = "000000000000"
_RECORD_CONTENTS = (0x14, 0x15, 0x16, 0x17)
_DTLS_VERSIONS = (0xFEFF, 0xFEFD, 0xFEFC)


def _hex4(value: int) -> str:
    return f"{value & 0xFFFF:04x}"


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _alnum_byte(value: int) -> bool:
    return (0x30 <= value <= 0x39) or (0x41 <= value <= 0x5A) \
        or (0x61 <= value <= 0x7A)


def _alpn_tag(value) -> str:
    """JA4 ALPN tag: first/last alphanumeric char, hex fallback, or ``00``."""
    raw = bytes(value) if isinstance(value, (bytes, bytearray)) else \
        str(value or "").encode("latin-1", "replace")
    if not raw:
        return "00"
    if _alnum_byte(raw[0]) and _alnum_byte(raw[-1]):
        return raw[:1].decode("ascii") + raw[-1:].decode("ascii")
    hexs = raw.hex()
    return hexs[0] + hexs[-1] if hexs else "00"


def _ja4_version(hello: dict) -> str:
    """JA4 version: highest non-GREASE supported_versions, else the hello one."""
    supported = [value for value in (hello.get("supported_versions") or [])
                 if value and value not in GREASE_VALUES]
    version = max(supported) if supported else (hello.get("version") or 0)
    return JA4_VERSIONS.get(version, "00")


def _split_record(data: bytes) -> bytes:
    """Return the handshake payload of a TLS/DTLS record (or bare input)."""
    data = bytes(data or b"")
    if len(data) >= 13 and data[0] == 0x16 and \
            int.from_bytes(data[1:3], "big") in _DTLS_VERSIONS:
        return data[13:13 + int.from_bytes(data[11:13], "big")]
    if len(data) >= 5 and data[0] in _RECORD_CONTENTS:
        return data[5:5 + int.from_bytes(data[3:5], "big")]
    return data


def _first_handshake(body: bytes, handshake_type: int) -> bytes | None:
    """First handshake message of ``handshake_type`` inside a record payload."""
    offset = 0
    while offset + 4 <= len(body):
        kind = body[offset]
        length = int.from_bytes(body[offset + 1:offset + 4], "big")
        start, end = offset + 4, offset + 4 + length
        if kind == handshake_type:
            return body[start:end if end <= len(body) else len(body)]
        if end > len(body):
            return None
        offset = end
    return None


def _parse_extensions(body: bytes, offset: int, total: int) -> list[tuple]:
    """``[(type, payload), ...]`` from an extension block, best effort."""
    extensions: list[tuple] = []
    end = min(offset + total, len(body))
    pos = offset
    while pos + 4 <= end:
        etype = int.from_bytes(body[pos:pos + 2], "big")
        length = int.from_bytes(body[pos + 2:pos + 4], "big")
        extensions.append((etype, body[pos + 4:pos + 4 + length]))
        pos += 4 + length
    return extensions


def _numbers(payload: bytes, width: int) -> list[int]:
    values = []
    for pos in range(0, len(payload) - width + 1, width):
        values.append(int.from_bytes(payload[pos:pos + width], "big"))
    return values


def _from_extensions(extensions: list[tuple]) -> dict:
    """Decode the fingerprint-relevant extensions into hello dict fields."""
    hello: dict = {"sni": "", "alpn": [], "curves": [], "formats": [],
                   "sig_algs": [], "supported_versions": []}
    for etype, payload in extensions:
        try:
            if etype == 0:                       # server_name
                names = int.from_bytes(payload[0:2], "big")
                pos, end = 2, min(2 + names, len(payload))
                while pos + 3 <= end:
                    name_type = payload[pos]
                    length = int.from_bytes(payload[pos + 1:pos + 3], "big")
                    if name_type == 0:
                        hello["sni"] = payload[pos + 3:pos + 3 + length] \
                            .decode("utf-8", "replace")
                    pos += 3 + length
            elif etype == 10:                    # supported_groups
                hello["curves"] = _numbers(payload[2:], 2)
            elif etype == 11:                    # ec_point_formats
                hello["formats"] = list(payload[1:1 + payload[0]]) \
                    if payload else []
            elif etype == 13:                    # signature_algorithms
                hello["sig_algs"] = _numbers(payload[2:], 2)
            elif etype == 16:                    # application_layer_protocol_negotiation
                names = int.from_bytes(payload[0:2], "big")
                pos, end = 2, min(2 + names, len(payload))
                while pos + 1 <= end:
                    length = payload[pos]
                    hello["alpn"].append(
                        payload[pos + 1:pos + 1 + length].decode("latin-1"))
                    pos += 1 + length
            elif etype == 43:                    # supported_versions (client)
                hello["supported_versions"] = _numbers(payload[1:], 2)
        except (IndexError, ValueError):
            continue
    return hello


def parse_client_hello(data: bytes) -> dict | None:
    """Minimal Client Hello parser (record or handshake message as input).

    Returns ``{"version", "ciphers", "extensions", "curves", "formats",
    "sig_algs", "supported_versions", "sni", "alpn"}`` or ``None`` when the
    bytes are not a usable Client Hello.
    """
    body = _split_record(data)
    hello_body = _first_handshake(body, 1) if body else None
    if not hello_body or len(hello_body) < 34:
        return None
    try:
        version = int.from_bytes(hello_body[0:2], "big")
        offset = 34
        offset += 1 + hello_body[offset]              # legacy_session_id
        if offset + 2 > len(hello_body):
            return None
        cipher_len = int.from_bytes(hello_body[offset:offset + 2], "big")
        offset += 2
        ciphers = _numbers(hello_body[offset:offset + cipher_len], 2)
        offset += cipher_len
        if offset >= len(hello_body):
            return None
        offset += 1 + hello_body[offset]              # compression methods
        extensions: list[tuple] = []
        if offset + 2 <= len(hello_body):
            extensions = _parse_extensions(
                hello_body, offset + 2,
                int.from_bytes(hello_body[offset:offset + 2], "big"))
    except (IndexError, ValueError):
        return None
    hello = {"version": version, "ciphers": ciphers,
             "extensions": [etype for etype, _payload in extensions]}
    hello.update(_from_extensions(extensions))
    return hello


def parse_server_hello(data: bytes) -> dict | None:
    """Minimal Server Hello parser returning the JA3S/JA4S relevant fields."""
    body = _split_record(data)
    hello_body = _first_handshake(body, 2) if body else None
    if not hello_body or len(hello_body) < 39:
        return None
    try:
        version = int.from_bytes(hello_body[0:2], "big")
        offset = 34
        offset += 1 + hello_body[offset]              # legacy_session_id_echo
        if offset + 3 > len(hello_body):
            return None
        cipher = int.from_bytes(hello_body[offset:offset + 2], "big")
        offset += 2
        if offset >= len(hello_body):
            return None
        offset += 1 + hello_body[offset]              # compression methods
        extensions: list[tuple] = []
        if offset + 2 <= len(hello_body):
            extensions = _parse_extensions(
                hello_body, offset + 2,
                int.from_bytes(hello_body[offset:offset + 2], "big"))
    except (IndexError, ValueError):
        return None
    hello = {"version": version, "ciphers": [cipher] if cipher else [],
             "extensions": [etype for etype, _payload in extensions],
             "sni": ""}
    decoded = _from_extensions(extensions)
    for etype, payload in extensions:
        if etype == 16 and payload:                    # server picks one ALPN
            decoded["alpn"] = [payload[1:1 + payload[0]].decode("latin-1")]
        elif etype == 43 and len(payload) == 2:        # negotiated version
            decoded["supported_versions"] = [int.from_bytes(payload, "big")]
    hello["alpn"] = decoded.pop("alpn", [])
    hello["supported_versions"] = decoded.pop("supported_versions", [])
    return hello


def ja3_string(client_hello: dict) -> str:
    """ JA3 string: ``TLSVersion,Ciphers,Extensions,Curves,PointFormats``."""
    hello = client_hello or {}

    def dash(values) -> str:
        return "-".join(str(value) for value in values or [])

    return ",".join([
        str(hello.get("version") or 0),
        dash(hello.get("ciphers")),
        dash(hello.get("extensions")),
        dash(hello.get("curves")),
        dash(hello.get("formats")),
    ])


def ja3(client_hello: dict) -> str:
    return hashlib.md5(ja3_string(client_hello).encode("utf-8")).hexdigest()


def ja3s(server_hello: dict) -> str:
    """JA3S: MD5 over ``version,cipher,extensions`` of the Server Hello."""
    hello = server_hello or {}
    extensions = "-".join(str(value) for value in hello.get("extensions") or [])
    text = f"{hello.get('version') or 0},{(hello.get('ciphers') or [0])[0]},{extensions}"
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def ja4(client_hello: dict, *, protocol: str = "t") -> str:
    """JA4 per the FoxIO JA4+ spec, e.g. ``t13d1516h2_8daaf6152771_b0…``."""
    hello = client_hello or {}
    ciphers = [value for value in hello.get("ciphers") or []
               if value not in GREASE_VALUES]
    extensions = [value for value in hello.get("extensions") or []
                  if value not in GREASE_VALUES]
    if ciphers:
        cipher_hash = _sha12(",".join(sorted(_hex4(value) for value in ciphers)))
        cipher_len = f"{min(len(ciphers), 99):02d}"
    else:
        cipher_hash, cipher_len = _EMPTY_HASH, "00"
    if extensions:
        codes = sorted(_hex4(value) for value in extensions
                       if value not in (0x0000, 0x0010))
        joined = ",".join(codes)
        if 13 in extensions:                           # signature_algorithms
            sigs = [_hex4(value) for value in hello.get("sig_algs") or []
                    if value not in GREASE_VALUES]
            joined = f"{joined}_{','.join(sigs)}"
        ext_hash = _sha12(joined) if joined else _EMPTY_HASH
        ext_len = f"{min(len(extensions), 99):02d}"
    else:
        ext_hash, ext_len = _EMPTY_HASH, "00"
    alpns = hello.get("alpn") or [""]
    sni = "d" if hello.get("sni") else "i"
    return (f"{protocol}{_ja4_version(hello)}{sni}{cipher_len}{ext_len}"
            f"{_alpn_tag(alpns[0])}_{cipher_hash}_{ext_hash}")


def ja4s(server_hello: dict, *, protocol: str = "t") -> str:
    """JA4S per the FoxIO JA4+ spec, e.g. ``t120400_c030_4e8089b08790``."""
    hello = server_hello or {}
    codes = [_hex4(value) for value in hello.get("extensions") or []]
    ext_hash = _sha12(",".join(codes)) if codes else _EMPTY_HASH
    cipher = _hex4((hello.get("ciphers") or [0])[0])
    alpns = hello.get("alpn") or [""]
    return (f"{protocol}{_ja4_version(hello)}"
            f"{min(len(codes), 99):02d}{_alpn_tag(alpns[0])}"
            f"_{cipher}_{ext_hash}")


def fingerprints(client_hello: dict, server_hello: dict | None = None,
                 *, protocol: str = "t") -> dict:
    """Bundle all fingerprints of one handshake for logs, CSV and findings."""
    hello = client_hello or {}
    result = {
        "sni": hello.get("sni") or "",
        "ja3": ja3(hello),
        "ja3_string": ja3_string(hello),
        "ja4": ja4(hello, protocol=protocol),
    }
    if server_hello:
        result["ja3s"] = ja3s(server_hello)
        result["ja4s"] = ja4s(server_hello, protocol=protocol)
    return result
