"""Pure-Python Kerberos helpers for capture analysis.

Wireshark dissects Kerberos, but a pcap-only CTF workflow often needs the raw
application payload decoded: pre-auth blobs, RC4/AES keys, PAC contents and
keytab keys.  This module provides a tiny DER reader, Kerberos message
extraction, the RC4-HMAC and AES-CTS crypto profiles, keytab/PAC parsers and
hashcat-friendly output.

Everything is built on :mod:`fnet.utils.crypto`; no third-party crypto package
is imported.  Public parsers are defensive: truncated or hostile input returns
``None`` (or a partial dict) instead of raising.

References: RFC 4120 (Kerberos V5), RFC 3962 (AES), RFC 4757 (RC4-HMAC),
MS-PAC, MS-KILE and the MIT keytab file format.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any, Iterable

from fnet.utils import crypto

# ---------------------------------------------------------------------------
# Names and limits
# ---------------------------------------------------------------------------
ETYPE_NAMES = {
    1: "DES-CBC-CRC",
    2: "DES-CBC-MD4",
    3: "DES-CBC-MD5",
    16: "DES3-CBC-SHA1",
    17: "AES128-CTS-HMAC-SHA1-96",
    18: "AES256-CTS-HMAC-SHA1-96",
    23: "RC4-HMAC",
    24: "RC4-HMAC-EXP",
}

MSG_NAMES = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    30: "KRB-ERROR",
}

PADATA_NAMES = {
    1: "PA-TGS-REQ",
    2: "PA-ENC-TIMESTAMP",
    3: "PA-PW-SALT",
    16: "PA-PAC-REQUEST",
    19: "PA-ETYPE-INFO2",
    128: "PA-FX-FAST",
    129: "PA-FX-FAST-OPTIONS",
    130: "PA-FX-FAST-ENCRYPTED-CHALLENGE",
    131: "PA-FX-COOKIE",
}

ERROR_NAMES = {
    0: "KDC_ERR_NONE",
    1: "KDC_ERR_NAME_EXP",
    2: "KDC_ERR_SERVICE_EXP",
    3: "KDC_ERR_BAD_PVNO",
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    12: "KDC_ERR_POLICY",
    18: "KDC_ERR_CLIENT_REVOKED",
    23: "KDC_ERR_PREAUTH_FAILED",
    24: "KDC_ERR_PREAUTH_REQUIRED",
    25: "KDC_ERR_BADOPTION",
    31: "KRB_AP_ERR_BAD_INTEGRITY",
    52: "KRB_ERR_RESPONSE_TOO_BIG",
    60: "KRB_ERR_GENERIC",
}

APP_TAGS = {10: 0x6A, 11: 0x6B, 12: 0x6C, 13: 0x6D, 30: 0x7E}

PAC_TYPE_NAMES = {
    1: "LOGON_INFO",
    2: "CREDENTIAL_INFO",
    3: "PAC_CREDENTIAL_INFO",
    6: "SERVER_CHECKSUM",
    7: "PRIVSVR_CHECKSUM",
    10: "CLIENT_INFO",
    11: "DEVICE_INFO",
    12: "DEVICE_INFO_2",
    17: "ATTRIBUTES_INFO",
    19: "REQUESTOR_SID",
}

MAX_PAC = 4 * 1024 * 1024
MAX_PAC_BUFFER = 64 * 1024
MAX_PAC_BUFFERS = 64
MAX_KEYTAB_ENTRIES = 4096
MAX_STRING_BYTES = 4096

# ---------------------------------------------------------------------------
# Minimal DER decoder
# ---------------------------------------------------------------------------
def read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one DER TLV and return ``(tag, value, next_pos)``."""
    if pos < 0 or pos >= len(data):
        raise ValueError("truncated DER tag")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise ValueError("truncated DER length")
    first = data[pos]
    pos += 1
    if first == 0x80:
        raise ValueError("indefinite DER length is not supported")
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 8 or pos + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise ValueError("DER value out of range")
    return tag, data[pos:pos + length], pos + length


def parse_sequence(data: bytes, pos: int = 0) -> bytes:
    """Return the contents of the DER SEQUENCE at ``pos``."""
    tag, value, _ = read_tlv(data, pos)
    if tag != 0x30:
        raise ValueError("expected DER SEQUENCE")
    return value


def parse_int(data: bytes, pos: int = 0) -> int:
    """Decode a DER INTEGER (or ENUMERATED) TLV."""
    tag, value, _ = read_tlv(data, pos)
    if tag not in (0x02, 0x0A):
        raise ValueError("expected DER INTEGER")
    return int.from_bytes(value, "big", signed=True)


def parse_octet_string(data: bytes, pos: int = 0) -> bytes:
    """Decode a DER OCTET STRING TLV."""
    tag, value, _ = read_tlv(data, pos)
    if tag != 0x04:
        raise ValueError("expected DER OCTET STRING")
    return value


def parse_bit_string(data: bytes, pos: int = 0) -> bytes:
    """Decode a DER BIT STRING TLV (unused-bits octet stripped)."""
    tag, value, _ = read_tlv(data, pos)
    if tag != 0x03:
        raise ValueError("expected DER BIT STRING")
    if not value:
        return b""
    return value[1:]


def parse_general_string(data: bytes, pos: int = 0) -> str:
    """Decode a DER GeneralString (also accepts the usual text tags)."""
    tag, value, _ = read_tlv(data, pos)
    if tag not in (0x1B, 0x16, 0x0C, 0x13):
        raise ValueError("expected DER string")
    return value.decode("utf-8", "replace")


def find_context(seq_bytes: bytes, tag_number: int) -> bytes | None:
    """Find a context-tagged field inside SEQUENCE contents."""
    pos = 0
    while pos < len(seq_bytes):
        tag, value, pos = read_tlv(seq_bytes, pos)
        if tag in (0x80 + tag_number, 0xA0 + tag_number):
            return value
    return None


def _find(seq_bytes: bytes, tag_number: int) -> bytes | None:
    try:
        return find_context(seq_bytes, tag_number)
    except (ValueError, IndexError):
        return None


def _ctx_int(seq_bytes: bytes, tag_number: int) -> int | None:
    raw = _find(seq_bytes, tag_number)
    if raw is None:
        return None
    try:
        return parse_int(raw)
    except (ValueError, IndexError):
        return None


def _octets_value(raw: bytes | None) -> bytes:
    if not raw:
        return b""
    if raw[0] == 0x04:
        try:
            tag, value, _ = read_tlv(raw, 0)
            if tag == 0x04:
                return value
        except (ValueError, IndexError):
            pass
    return raw


def _decode_string(raw: bytes | None) -> str:
    if not raw:
        return ""
    try:
        tag, value, _ = read_tlv(raw, 0)
        if tag in (0x1B, 0x16, 0x0C, 0x13):
            return value.decode("utf-8", "replace")
    except (ValueError, IndexError):
        pass
    return raw.decode("utf-8", "replace")


def _string_list(raw: bytes | None) -> list[str]:
    out: list[str] = []
    if not raw:
        return out
    try:
        if raw[0] == 0x30:
            _, raw, _ = read_tlv(raw, 0)
        pos = 0
        while pos < len(raw):
            tag, value, pos = read_tlv(raw, pos)
            if tag in (0x1B, 0x16, 0x0C, 0x13):
                out.append(value.decode("utf-8", "replace"))
    except (ValueError, IndexError):
        pass
    return out


def _int_list(raw: bytes | None) -> list[int]:
    out: list[int] = []
    if not raw:
        return out
    try:
        if raw[0] == 0x30:
            _, raw, _ = read_tlv(raw, 0)
        pos = 0
        while pos < len(raw):
            tag, value, pos = read_tlv(raw, pos)
            if tag == 0x02:
                out.append(int.from_bytes(value, "big", signed=True))
    except (ValueError, IndexError):
        pass
    return out


def _principal(raw: bytes | None) -> dict[str, Any]:
    result: dict[str, Any] = {"name_type": None, "components": [], "name": ""}
    if not raw:
        return result
    try:
        if raw[0] == 0x30:
            _, raw, _ = read_tlv(raw, 0)
    except (ValueError, IndexError):
        return result
    result["name_type"] = _ctx_int(raw, 0)
    result["components"] = _string_list(_find(raw, 1))
    result["name"] = "/".join(result["components"])
    return result


def _padata_items(raw: bytes | None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if not raw:
        return items
    try:
        if raw[0] == 0x30:
            _, raw, _ = read_tlv(raw, 0)
        pos = 0
        while pos < len(raw):
            tag, item, pos = read_tlv(raw, pos)
            if tag != 0x30:
                continue
            ptype = _ctx_int(item, 1)
            value = _octets_value(_find(item, 2))
            items.append({
                "type": ptype,
                "name": PADATA_NAMES.get(ptype, f"PA-{ptype}"),
                "value": value,
                "hex": value.hex(),
            })
    except (ValueError, IndexError):
        pass
    return items


def _encrypted_seq(seq_bytes: bytes) -> dict[str, Any]:
    etype = _ctx_int(seq_bytes, 0)
    cipher = _octets_value(_find(seq_bytes, 2))
    return {
        "etype": etype,
        "etype_name": ETYPE_NAMES.get(etype, f"etype={etype}"),
        "kvno": _ctx_int(seq_bytes, 1),
        "cipher": cipher,
        "cipher_len": len(cipher),
    }


def parse_encrypted_part(der: bytes) -> dict[str, Any]:
    """Parse a DER ``EncryptedData`` sequence."""
    tag, value, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("EncryptedData must be a SEQUENCE")
    return _encrypted_seq(value)


def _ticket(raw: bytes | None) -> dict[str, Any]:
    info: dict[str, Any] = {"realm": "", "sname": "", "sname_components": []}
    if not raw or not raw.startswith(b"\x30"):
        return info
    try:
        _, seqb, _ = read_tlv(raw, 0)
    except (ValueError, IndexError):
        return info
    info["realm"] = _decode_string(_find(seqb, 1))
    sname = _principal(_find(seqb, 2))
    info["sname"] = sname["name"]
    info["sname_components"] = sname["components"]
    return info


def _parse_error(body: bytes) -> dict[str, Any]:
    seqb = body
    try:
        if body and body[0] == 0x30:
            _, seqb, _ = read_tlv(body, 0)
    except (ValueError, IndexError):
        pass
    code = _ctx_int(seqb, 6)
    cname = _principal(_find(seqb, 10))
    return {
        "pvno": _ctx_int(seqb, 0),
        "msg_type": _ctx_int(seqb, 1),
        "error_code": code,
        "error": ERROR_NAMES.get(code, f"KRB-ERROR {code}"),
        "error_text": _decode_string(_find(seqb, 11)),
        "realm": _decode_string(_find(seqb, 9)),
        "cname": cname["name"],
        "cname_components": cname["components"],
        "sname": "",
        "sname_components": [],
        "etypes": [],
        "padata": [],
        "enc_part": None,
    }


def _parse_reply(der: bytes, msg_type: int) -> dict[str, Any]:
    tag, body, _ = read_tlv(der, 0)
    if tag == APP_TAGS[30]:
        return _parse_error(body)
    if tag != APP_TAGS[msg_type]:
        raise ValueError("unexpected Kerberos application tag")
    seqb = parse_sequence(body)

    padata = _padata_items(_find(seqb, 2))
    cname = _principal(_find(seqb, 4))
    ticket = _ticket(_find(seqb, 5))
    enc_part = None
    enc_raw = _find(seqb, 6)
    if enc_raw:
        try:
            enc_part = _encrypted_seq(parse_sequence(enc_raw))
        except (ValueError, IndexError):
            enc_part = None
    etype = enc_part.get("etype") if enc_part else None

    realm = _decode_string(_find(seqb, 3)) or ticket["realm"]
    return {
        "pvno": _ctx_int(seqb, 0),
        "msg_type": msg_type,
        "msg_name": MSG_NAMES.get(msg_type, f"type={msg_type}"),
        "realm": realm,
        "crealm": realm,
        "cname": cname["name"],
        "cname_components": cname["components"],
        "sname": ticket["sname"],
        "sname_components": ticket["sname_components"],
        "ticket_realm": ticket["realm"],
        "etypes": [etype] if etype is not None else [],
        "etype": etype,
        "padata": padata,
        "enc_part": enc_part,
        "error_code": None,
    }


def parse_as_rep(der: bytes) -> dict[str, Any] | None:
    """Parse an application-tagged AS-REP (or KRB-ERROR) message."""
    try:
        return _parse_reply(der, 11)
    except (ValueError, IndexError, TypeError):
        return None


def parse_tgs_rep(der: bytes) -> dict[str, Any] | None:
    """Parse an application-tagged TGS-REP (or KRB-ERROR) message."""
    try:
        return _parse_reply(der, 13)
    except (ValueError, IndexError, TypeError):
        return None


def _parse_request(der: bytes, msg_type: int) -> dict[str, Any]:
    tag, body, _ = read_tlv(der, 0)
    if tag == APP_TAGS[30]:
        return _parse_error(body)
    if tag != APP_TAGS[msg_type]:
        raise ValueError("unexpected Kerberos application tag")
    seqb = parse_sequence(body)

    padata = _padata_items(_find(seqb, 3))
    enc_part = None
    for item in padata:
        if item["type"] == 2 and item["value"]:
            try:
                enc_part = parse_encrypted_part(item["value"])
                break
            except (ValueError, IndexError):
                continue

    result: dict[str, Any] = {
        "pvno": _ctx_int(seqb, 1),
        "msg_type": msg_type,
        "msg_name": MSG_NAMES.get(msg_type, f"type={msg_type}"),
        "realm": "",
        "cname": "",
        "cname_components": [],
        "sname": "",
        "sname_components": [],
        "etypes": [],
        "etype": None,
        "nonce": None,
        "padata": padata,
        "enc_part": enc_part,
        "error_code": None,
    }
    body_raw = _find(seqb, 4)
    if not body_raw:
        return result
    try:
        kdc = parse_sequence(body_raw)
    except (ValueError, IndexError):
        return result
    cname = _principal(_find(kdc, 1))
    sname = _principal(_find(kdc, 3))
    result.update({
        "realm": _decode_string(_find(kdc, 2)),
        "cname": cname["name"],
        "cname_components": cname["components"],
        "sname": sname["name"],
        "sname_components": sname["components"],
        "nonce": _ctx_int(kdc, 6),
        "etypes": _int_list(_find(kdc, 7)),
    })
    etype = enc_part.get("etype") if enc_part else None
    result["etype"] = etype
    if not result["etypes"] and etype is not None:
        result["etypes"] = [etype]
    return result


def parse_as_req(der: bytes) -> dict[str, Any] | None:
    """Parse an application-tagged AS-REQ (or KRB-ERROR) message."""
    try:
        return _parse_request(der, 10)
    except (ValueError, IndexError, TypeError):
        return None


def parse_tgs_req(der: bytes) -> dict[str, Any] | None:
    """Parse an application-tagged TGS-REQ (or KRB-ERROR) message."""
    try:
        return _parse_request(der, 12)
    except (ValueError, IndexError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Crypto profiles
# ---------------------------------------------------------------------------
def _usage_le(usage: int) -> bytes:
    return struct.pack("<I", int(usage) & 0xFFFFFFFF)


def _rc4_checksum_key(key: bytes, usage: int) -> bytes:
    k1 = crypto.hmac_md5(key, _usage_le(usage))
    return crypto.hmac_md5(key, k1)


def rc4_hmac_decrypt(key: bytes, cipher: bytes, usage: int) -> bytes | None:
    """Decrypt an RC4-HMAC blob and verify its leading 16-byte checksum."""
    if len(cipher) < 17:
        return None
    checksum, body = bytes(cipher[:16]), bytes(cipher[16:])
    plaintext = crypto.rc4(key, body)
    expected = crypto.hmac_md5(_rc4_checksum_key(key, usage), plaintext)
    if not hmac.compare_digest(checksum, expected):
        return None
    return plaintext


def _rc4_hmac_encrypt(plaintext: bytes, key: bytes, usage: int,
                      confounder: bytes | None = None) -> bytes:
    confounder = confounder if confounder is not None else b"\x00" * 8
    basic = bytes(confounder) + bytes(plaintext)
    checksum = crypto.hmac_md5(_rc4_checksum_key(key, usage), basic)[:16]
    return checksum + crypto.rc4(key, basic)


def aes_cts_encrypt(data: bytes, key: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """AES-CBC-CS3 ciphertext stealing encryption (RFC 3962)."""
    if len(data) < 16:
        raise ValueError("CTS needs at least one block")
    if len(data) == 16:
        return crypto.aes_cbc_encrypt(data, key, iv, pad=False)
    m = (len(data) + 15) // 16
    padded = bytes(data) + b"\x00" * (16 * m - len(data))
    blocks = crypto.aes_cbc_encrypt(padded, key, iv, pad=False)
    if len(data) % 16 == 0:
        return blocks
    r = len(data) % 16
    return (blocks[:16 * (m - 2)]
            + blocks[16 * (m - 1):16 * m]
            + blocks[16 * (m - 2):16 * (m - 2) + r])


def aes_cts_decrypt(data: bytes, key: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """AES-CBC-CS3 ciphertext stealing decryption (RFC 3962)."""
    n = len(data)
    if n < 16:
        raise ValueError("CTS needs at least one block")
    if n == 16:
        return crypto.aes_cbc_decrypt(data, key, iv, unpad=False)
    if n % 16 == 0:
        return crypto.aes_cbc_decrypt(data, key, iv, unpad=False)
    m = (n + 15) // 16
    r = n % 16
    prefix = bytes(data[:16 * (m - 2)])
    last_block = bytes(data[16 * (m - 2):16 * (m - 1)])
    partial = bytes(data[16 * (m - 1):])
    dm = crypto.aes_decrypt_block(last_block, key)
    penultimate = partial + dm[r:]
    plain_prefix = crypto.aes_cbc_decrypt(prefix + penultimate, key, iv,
                                          unpad=False)
    tail = bytes(a ^ b for a, b in zip(dm[:r], partial))
    return plain_prefix + tail


def _aes_checksum(key: bytes, usage: int, plaintext: bytes) -> bytes:
    return hmac.new(key, _usage_le(usage) + plaintext, hashlib.sha1).digest()[:12]


def aes_decrypt(key: bytes, cipher: bytes, usage: int, etype: int) -> bytes | None:
    """Decrypt an AES-CTS Kerberos blob and verify HMAC-SHA1-96.

    Returns the confounder-prefixed plaintext (the first 16 bytes are the
    confounder) or ``None`` when the checksum does not match.
    """
    if etype not in (17, 18) or len(cipher) < 16 + 12:
        return None
    blob, checksum = bytes(cipher[:-12]), bytes(cipher[-12:])
    try:
        plaintext = aes_cts_decrypt(blob, key)
    except (ValueError, IndexError):
        return None
    if not hmac.compare_digest(checksum, _aes_checksum(key, usage, plaintext)):
        return None
    return plaintext


def _aes_encrypt(plaintext: bytes, key: bytes, usage: int,
                 confounder: bytes | None = None) -> bytes:
    confounder = confounder if confounder is not None else b"\x00" * 16
    basic = bytes(confounder) + bytes(plaintext)
    return aes_cts_encrypt(basic, key) + _aes_checksum(key, usage, basic)


def derive_key(password: str, salt: bytes, etype: int) -> bytes:
    """Derive a Kerberos key with PBKDF2-HMAC-SHA1 (RC4 uses the NT hash)."""
    if etype == 23:
        return crypto.nt_hash(password)
    dklen = 16 if etype == 17 else 32
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), bytes(salt),
                               4096, dklen=dklen)


def password_salt(realm: str, principal: str) -> bytes:
    """Return the standard Kerberos salt ``realm + principal components``."""
    components = [part for part in str(principal).split("/") if part]
    return str(realm).encode("utf-8") + b"".join(
        part.encode("utf-8") for part in components)


def decrypt_encrypted_part(cipher: bytes, etype: int, key: bytes,
                           usage: int) -> bytes | None:
    """Decrypt an EncryptedData cipher blob for RC4 or AES etypes."""
    if etype == 23:
        return rc4_hmac_decrypt(key, cipher, usage)
    if etype in (17, 18):
        return aes_decrypt(key, cipher, usage, etype)
    return None


def encrypt_encrypted_part(plaintext: bytes, etype: int, key: bytes,
                           usage: int,
                           confounder: bytes | None = None) -> bytes:
    """Encrypt like Kerberos does; used by tests and fixture builders."""
    if etype == 23:
        return _rc4_hmac_encrypt(plaintext, key, usage, confounder)
    if etype in (17, 18):
        return _aes_encrypt(plaintext, key, usage, confounder)
    raise ValueError(f"unsupported etype {etype}")


# ---------------------------------------------------------------------------
# Keytab (MIT file format)
# ---------------------------------------------------------------------------
def _keytab_counted(data: bytes, pos: int) -> tuple[bytes, int]:
    if pos + 2 > len(data):
        raise ValueError("truncated keytab string length")
    length = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if pos + length > len(data):
        raise ValueError("truncated keytab string")
    return data[pos:pos + length], pos + length


def parse_keytab(data: bytes) -> list[dict[str, Any]]:
    """Parse a version 0x0502 MIT keytab into a list of entries."""
    entries: list[dict[str, Any]] = []
    try:
        if len(data) < 6 or data[:2] != b"\x05\x02":
            return entries
        count = int.from_bytes(data[2:6], "big")
        pos = 6
        for _ in range(min(count, MAX_KEYTAB_ENTRIES)):
            num_components = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            if num_components > 64:
                break
            realm_raw, pos = _keytab_counted(data, pos)
            components = []
            for _ in range(num_components):
                part, pos = _keytab_counted(data, pos)
                components.append(part.decode("utf-8", "replace"))
            name_type = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            timestamp = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            kvno8 = data[pos]
            pos += 1
            enctype = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            key_len = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            if pos + key_len > len(data):
                break
            key = data[pos:pos + key_len]
            pos += key_len
            kvno = kvno8
            if pos + 4 <= len(data):
                trailer = int.from_bytes(data[pos:pos + 4], "big")
                pos += 4
                if trailer:
                    kvno = trailer
            entries.append({
                "realm": realm_raw.decode("utf-8", "replace"),
                "components": components,
                "principal": "/".join(components),
                "name_type": name_type,
                "timestamp": timestamp,
                "kvno": kvno,
                "enctype": enctype,
                "etype_name": ETYPE_NAMES.get(enctype, f"etype={enctype}"),
                "key": key,
                "key_hex": key.hex(),
            })
    except (ValueError, IndexError, struct.error):
        pass
    return entries


def keytab_keys(keytab: list[dict[str, Any]], realm: str,
                principal_components: str | Iterable[str] | None = None
                ) -> list[dict[str, Any]]:
    """Filter keytab entries by realm and optional principal components."""
    if principal_components is None:
        wanted = None
    elif isinstance(principal_components, str):
        wanted = [part.casefold() for part in principal_components.split("/")
                  if part]
    else:
        wanted = [str(part).casefold() for part in principal_components]
    matches = []
    for entry in keytab or []:
        if str(entry.get("realm", "")).casefold() != str(realm).casefold():
            continue
        components = [str(part).casefold()
                      for part in entry.get("components", [])]
        if wanted is not None and components[:len(wanted)] != wanted:
            continue
        matches.append(entry)
    return matches


# ---------------------------------------------------------------------------
# PAC (MS-PAC / KERB_VALIDATION_INFO)
# ---------------------------------------------------------------------------
def _le16(buf: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(buf):
        return 0
    return int.from_bytes(buf[off:off + 2], "little")


def _le32(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        return 0
    return int.from_bytes(buf[off:off + 4], "little")


def _rpc_string(buf: bytes, off: int) -> str:
    if off < 0 or off + 8 > len(buf):
        return ""
    length = _le16(buf, off)
    pointer = _le32(buf, off + 4)
    if length == 0 or length > MAX_STRING_BYTES:
        return ""
    if pointer > len(buf) or pointer + length > len(buf):
        return ""
    return buf[pointer:pointer + length].decode("utf-16-le", "replace").rstrip("\x00")


def _sid_string(buf: bytes, off: int) -> str:
    if off <= 0 or off + 8 > len(buf):
        return ""
    revision = buf[off]
    count = buf[off + 1]
    if revision != 1 or count > 15 or off + 8 + 4 * count > len(buf):
        return ""
    authority = int.from_bytes(buf[off + 2:off + 8], "big")
    subs = [str(_le32(buf, off + 8 + 4 * i)) for i in range(count)]
    return "-".join(["S", str(revision), str(authority)] + subs)


def _parse_logon_info(buf: bytes) -> dict[str, Any] | None:
    if len(buf) < 96:
        return None
    info: dict[str, Any] = {
        "user": _rpc_string(buf, 48),
        "full_name": _rpc_string(buf, 56),
        "logon_script": _rpc_string(buf, 64),
        "profile_path": _rpc_string(buf, 72),
        "home_directory": _rpc_string(buf, 80),
        "home_drive": _rpc_string(buf, 88),
        "logon_count": _le16(buf, 96),
        "bad_password_count": _le16(buf, 98),
        "user_id": _le32(buf, 100),
        "primary_group_id": _le32(buf, 104),
        "group_count": _le32(buf, 108),
        "group_ids": [],
        "logon_server": "",
        "domain": "",
        "domain_sid": "",
        "sids": [],
    }
    group_offset = _le32(buf, 112)
    for i in range(min(info["group_count"], 256)):
        if group_offset and group_offset + 4 * i + 4 <= len(buf):
            info["group_ids"].append(_le32(buf, group_offset + 4 * i))
    if len(buf) >= 152:
        info["logon_server"] = _rpc_string(buf, 136)
        info["domain"] = _rpc_string(buf, 144)
        domain_sid = _sid_string(buf, _le32(buf, 152))
        if domain_sid:
            info["domain_sid"] = domain_sid
            info["sids"].append(domain_sid)
        if len(buf) >= 204:
            sid_count = _le32(buf, 196)
            extra_offset = _le32(buf, 200)
            if 0 < sid_count <= 32 and extra_offset:
                for i in range(sid_count):
                    sid = _sid_string(buf, _le32(buf, extra_offset + 4 * i))
                    if sid and sid not in info["sids"]:
                        info["sids"].append(sid)
    return info


def _parse_credential_info(buf: bytes) -> dict[str, Any] | None:
    for off in (0, 8, 12, 16):
        if off + 40 > len(buf):
            continue
        version = _le32(buf, off)
        flags = _le32(buf, off + 4)
        if off and version > 4:
            continue
        lm = buf[off + 8:off + 24]
        nt = buf[off + 24:off + 40]
        return {
            "version": version,
            "flags": flags,
            "lm_hash": lm.hex().upper(),
            "nt_hash": nt.hex().upper(),
            "hash": nt.hex().upper(),
        }
    return None


def _parse_client_info(buf: bytes) -> dict[str, Any] | None:
    if len(buf) < 8:
        return None
    name = buf[8:].decode("utf-16-le", "replace").rstrip("\x00")
    return {"client_id": int.from_bytes(buf[:8], "little"), "name": name}


def _parse_checksum(buf: bytes) -> dict[str, Any]:
    if len(buf) < 4:
        return {"type": None, "checksum": buf.hex()}
    return {"type": _le32(buf, 0), "checksum": buf[4:].hex()}


def parse_pac(data: bytes) -> dict[str, Any]:
    """Parse an AD PAC blob (logon info, credentials, checksums, client info)."""
    result: dict[str, Any] = {
        "version": 0,
        "buffers": [],
        "types": {},
        "logon": None,
        "credential": None,
        "checksums": {},
        "client_info": None,
    }
    try:
        if len(data) < 8 or len(data) > MAX_PAC:
            return result
        count = int.from_bytes(data[0:4], "little")
        result["version"] = int.from_bytes(data[4:8], "little")
        count = max(0, min(count, MAX_PAC_BUFFERS))
        count = min(count, max(0, (len(data) - 8) // 12))
        expected = 8 + count * 12
        for index in range(count):
            base = 8 + index * 12
            ptype = int.from_bytes(data[base:base + 4], "little")
            first = int.from_bytes(data[base + 4:base + 8], "little")
            second = int.from_bytes(data[base + 8:base + 12], "little")
            offset, length = first, second
            chosen = None
            for candidate_offset, candidate_length in ((first, second),
                                                       (second, first)):
                if (candidate_offset >= 8
                        and candidate_offset + candidate_length <= len(data)):
                    if candidate_offset == expected:
                        chosen = (candidate_offset, candidate_length)
                        break
                    if chosen is None:
                        chosen = (candidate_offset, candidate_length)
            if chosen is not None:
                offset, length = chosen
            if offset > len(data):
                offset, length = len(data), 0
            length = min(length, len(data) - offset, MAX_PAC_BUFFER)
            expected = offset + length
            payload = data[offset:offset + length]
            name = PAC_TYPE_NAMES.get(ptype, f"type={ptype}")
            result["buffers"].append({
                "type": ptype,
                "name": name,
                "offset": offset,
                "length": length,
            })
            result["types"][name] = payload
            if ptype == 1:
                result["logon"] = _parse_logon_info(payload)
            elif ptype == 2:
                result["credential"] = _parse_credential_info(payload)
            elif ptype in (6, 7):
                result["checksums"][name] = _parse_checksum(payload)
            elif ptype == 10:
                result["client_info"] = _parse_client_info(payload)
    except (ValueError, IndexError, struct.error):
        pass
    return result


# ---------------------------------------------------------------------------
# Hashcat / timeline helpers
# ---------------------------------------------------------------------------
def _hex_cipher(cipher: bytes | bytearray | str) -> str:
    if isinstance(cipher, (bytes, bytearray)):
        return bytes(cipher).hex()
    text = str(cipher or "")
    return "".join(ch for ch in text if ch in "0123456789abcdefABCDEF").lower()


def hashcat_lines(msg_type: int, user: str, realm: str, spn: str, etype: int,
                  cipher: bytes | bytearray | str) -> list[str]:
    """Build hashcat input lines for an AS-REP, TGS-REP or pre-auth blob."""
    blob = _hex_cipher(cipher)
    if not blob:
        return []
    user = user or "unknown"
    realm = (realm or "UNKNOWN.REALM").upper()
    spn = spn or "unknown"
    lines: list[str] = []
    if etype == 23:
        if len(blob) < 32:
            return []
        checksum, edata = blob[-32:], blob[:-32]
        if msg_type == 11:
            lines.append(f"$krb5asrep$23${user}@{realm}:{checksum}${edata}")
        elif msg_type == 13:
            lines.append(f"$krb5tgs$23$*{user}${realm}${spn}*${checksum}${edata}")
        elif msg_type == 10:
            lines.append(f"$krb5pa$23${user}${realm}${edata}{checksum}")
        return lines
    if etype in (17, 18):
        if len(blob) <= 24:
            return []
        edata, checksum = blob[:-24], blob[-24:]
        if msg_type == 11:
            lines.append(f"$krb5asrep${etype}${user}@{realm}:{edata}${checksum}")
        elif msg_type == 13:
            lines.append(
                f"$krb5tgs${etype}$*{user}${realm}${spn}*${edata}${checksum}")
        elif msg_type == 10:
            lines.append(f"$krb5pa${etype}${user}${realm}${edata}${checksum}")
    return lines


def hashcat_modes(msg_type: int, etype: int) -> list[int]:
    """Return the hashcat mode numbers for a Kerberos message and etype."""
    table = {
        (23, 11): [18200],
        (23, 13): [13100],
        (23, 10): [7500],
        (17, 11): [19800],
        (17, 13): [19600],
        (18, 11): [19900],
        (18, 13): [19700],
    }
    return list(table.get((etype, msg_type), []))


def build_timeline(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise auth events and sort them by time then frame number."""
    rows: list[dict[str, Any]] = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        raw_msg = event.get("msg_type")
        if isinstance(raw_msg, int):
            msg_name = MSG_NAMES.get(raw_msg, f"type={raw_msg}")
        else:
            msg_name = str(raw_msg or "")
        try:
            error = int(event.get("error_code") or 0)
        except (TypeError, ValueError):
            error = 0
        status = str(event.get("status") or "")
        if status not in ("success", "error"):
            status = "error" if error else "success"
        try:
            frame = int(event.get("frame") or 0)
        except (TypeError, ValueError):
            frame = 0
        service = (event.get("service") or event.get("spn")
                   or event.get("sname") or "")
        rows.append({
            "time": str(event.get("time") or ""),
            "frame": frame,
            "user": str(event.get("user") or "unknown"),
            "realm": str(event.get("realm") or "").upper(),
            "service": str(service),
            "msg_type": msg_name,
            "src": str(event.get("src") or ""),
            "status": status,
        })
    rows.sort(key=lambda row: (row["time"], row["frame"], row["user"]))
    return rows


def summarise_timeline(events: Iterable[dict[str, Any]]) -> str:
    """Return per-user success/error counts as readable text."""
    counts: dict[tuple[str, str], list[int]] = {}
    for row in build_timeline(events):
        key = (row["user"], row["realm"])
        bucket = counts.setdefault(key, [0, 0, 0])
        bucket[0] += 1
        bucket[1 if row["status"] == "success" else 2] += 1
    lines = []
    for (user, realm), (total, ok, bad) in sorted(counts.items()):
        label = f"{user}@{realm}" if realm else user
        lines.append(f"{label}: {total} (success {ok}, error {bad})")
    return "\n".join(lines)
