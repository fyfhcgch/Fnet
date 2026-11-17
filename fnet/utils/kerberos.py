"""Kerberos 5 message parsing, decryption and offline-cracking helpers.

The feature handler in :mod:`fnet.features.kerberos` only sees what tshark
flattens into columns.  For CTF and incident work we also want the raw
structure: the DER layout of AS/TGS messages, the encrypted part, keytab
entries, PAC logon data and the exact hashcat line for a captured cipher.

Everything here is read-only and uses the standard library plus the small
pure-Python AES/RC4/MD4 primitives in :mod:`fnet.utils.crypto`.  The parsing
entry points are deliberately tolerant: malformed input returns ``None`` or
an empty result instead of raising.

References: RFC 4120 (Kerberos), RFC 3961/3962 (AES), RFC 4757 (RC4-HMAC),
MS-PAC, MS-KILE and the MIT keytab file format.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections.abc import Iterable, Mapping
from functools import reduce
from math import gcd
from typing import Any

from fnet.utils import crypto

MAX_DER = 16 * 1024 * 1024

#: Encryption types worth naming in a report.
ETYPE_NAMES = {
    1: "DES-CBC-CRC",
    3: "DES-CBC-MD5",
    16: "DES3-CBC-SHA1-KD",
    17: "AES128-CTS-HMAC-SHA1-96",
    18: "AES256-CTS-HMAC-SHA1-96",
    23: "RC4-HMAC",
    24: "RC4-HMAC-EXP",
}

#: Kerberos message types (RFC 4120 section 7.5.1).
MSG_NAMES = {
    10: "AS-REQ",
    11: "AS-REP",
    12: "TGS-REQ",
    13: "TGS-REP",
    14: "AP-REQ",
    15: "AP-REP",
    20: "KRB-SAFE",
    21: "KRB-PRIV",
    22: "KRB-CRED",
    30: "KRB-ERROR",
}

#: Pre-authentication data types.
PADATA_NAMES = {
    1: "PA-TGS-REQ",
    2: "PA-ENC-TIMESTAMP",
    3: "PA-PW-SALT",
    11: "PA-ETYPE-INFO",
    12: "PA-SAM-CHALLENGE",
    13: "PA-SAM-RESPONSE",
    16: "PA-PK-AS-REQ",
    17: "PA-PK-AS-REP",
    19: "PA-ETYPE-INFO2",
    20: "PA-USE-SPECIFIED-KVNO",
    128: "PA-PAC-REQUEST",
    129: "PA-FOR-USER",
    133: "PA-FX-COOKIE",
    136: "PA-FX-FAST",
    137: "PA-FX-ERROR",
    138: "PA-ENCRYPTED-CHALLENGE",
    141: "PA-OTP-CHALLENGE",
    142: "PA-OTP-REQUEST",
    167: "PA-PAC-OPTIONS",
}

#: Common PAC buffer types.
PAC_BUFFER_NAMES = {
    1: "LOGON_INFO",
    2: "CREDENTIAL_INFO",
    3: "SERVER_CHECKSUM (old)",
    6: "SERVER_CHECKSUM",
    7: "PRIVSVR_CHECKSUM",
    10: "CLIENT_INFO",
    11: "S4U_DELEGATION_INFO",
    12: "UPN_DNS_INFO",
    13: "PAC_ATTRIBUTES_INFO",
    14: "PAC_REQUESTOR",
    17: "PAC_DEVICE_INFO",
}

#: hashcat mode for a ``(message type, etype)`` pair.
HASHCAT_MODES = {
    (11, 23): (18200,),
    (13, 23): (13100,),
    (11, 17): (19800,),
    (11, 18): (19900,),
    (13, 17): (19600,),
    (13, 18): (19700,),
}


# ---------------------------------------------------------------------------
# Minimal DER (definite length) parser
# ---------------------------------------------------------------------------
class DerError(ValueError):
    """Raised when a DER TLV is truncated or uses an unsupported encoding."""


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one DER TLV and return ``(tag, value, next_offset)``.

    High-tag-number form and indefinite lengths are rejected: Kerberos does
    not use them, and failing loudly keeps callers from walking bad data.
    """
    if offset < 0 or offset >= len(data):
        raise DerError("truncated tag")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("unsupported high tag number")
    if offset >= len(data):
        raise DerError("truncated length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length is not supported")
    else:
        count = first & 0x7F
        if count > 4 or offset + count > len(data):
            raise DerError("invalid length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if length > MAX_DER or offset + length > len(data):
        raise DerError("truncated value")
    return tag, data[offset:offset + length], offset + length


def _children(data: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = read_tlv(data, offset)
        items.append((tag, value))
    return items


def parse_sequence(data: bytes, offset: int = 0
                   ) -> tuple[list[tuple[int, bytes]], int]:
    """Parse a SEQUENCE at ``offset`` and return its child TLVs and end."""
    tag, value, end = read_tlv(data, offset)
    if tag != 0x30:
        raise DerError(f"expected SEQUENCE, got tag {tag:#x}")
    return _children(value), end


def parse_int(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Parse an INTEGER at ``offset`` and return ``(value, next_offset)``."""
    tag, value, end = read_tlv(data, offset)
    if tag != 0x02:
        raise DerError(f"expected INTEGER, got tag {tag:#x}")
    if not value:
        raise DerError("empty INTEGER")
    return int.from_bytes(value, "big", signed=True), end


def parse_octet_string(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Parse an OCTET STRING at ``offset`` and return ``(value, end)``."""
    tag, value, end = read_tlv(data, offset)
    if tag != 0x04:
        raise DerError(f"expected OCTET STRING, got tag {tag:#x}")
    return value, end


_STRING_TAGS = {0x0C, 0x13, 0x16, 0x1B}


def parse_general_string(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Parse a Kerberos string (UTF8/Printable/IA5/GeneralString)."""
    tag, value, end = read_tlv(data, offset)
    if tag not in _STRING_TAGS:
        raise DerError(f"expected KerberosString, got tag {tag:#x}")
    return value.decode("utf-8", "replace"), end


def find_context(children: Iterable[tuple[int, bytes]],
                 number: int) -> bytes | None:
    """Return the value of context-specific tag ``[number]``, if present."""
    for tag, value in children:
        if tag & 0xC0 == 0x80 and tag & 0x1F == number:
            return value
    return None


def _unwrap(value: bytes | None, tags: set[int]) -> bytes:
    """Remove one explicit-tag wrapper when it matches ``tags``."""
    if not value:
        return b""
    try:
        tag, inner, end = read_tlv(value, 0)
    except DerError:
        return value
    if end == len(value) and tag in tags:
        return inner
    return value


def _int_value(value: bytes | None) -> int | None:
    """Decode an INTEGER context value, accepting explicit or implicit tags."""
    if not value:
        return None
    try:
        tag, inner, end = read_tlv(value, 0)
        if end == len(value) and tag == 0x02:
            value = inner
    except DerError:
        pass
    if not value:
        return None
    return int.from_bytes(value, "big", signed=True)


def _str_value(value: bytes | None) -> str:
    if not value:
        return ""
    return _unwrap(value, _STRING_TAGS).decode("utf-8", "replace")


def _octets_value(value: bytes | None) -> bytes:
    if not value:
        return b""
    return _unwrap(value, {0x04})


def _seq_children(value: bytes | None) -> list[tuple[int, bytes]]:
    """Children of a context/application wrapped SEQUENCE, best effort."""
    if not value:
        return []
    data = value
    for _ in range(4):
        try:
            tag, inner, end = read_tlv(data, 0)
        except DerError:
            break
        if end != len(data):
            break
        if tag in (0x30, 0x31):
            return _children(inner)
        if tag & 0x20 and tag & 0xC0 in (0x40, 0x80):
            data = inner  # unwrap APPLICATION/context-specific wrapper
            continue
        break
    try:
        return _children(data)
    except DerError:
        return []


def _principal(value: bytes | None) -> str:
    """Render a PrincipalName as ``component/component``."""
    parts: list[str] = []
    for tag, item in _seq_children(value):
        if tag & 0xC0 == 0x80 and tag & 0x1F == 1:
            for _str_tag, raw in _seq_children(item):
                text = raw.decode("utf-8", "replace")
                if text:
                    parts.append(text)
    return "/".join(parts)


def _padata(value: bytes | None) -> list[dict[str, Any]]:
    """Decode a SEQUENCE OF PA-DATA into ``type``/``name``/``value`` dicts."""
    entries: list[dict[str, Any]] = []
    for tag, item in _seq_children(value):
        if tag != 0x30:
            continue
        entry_type: int | None = None
        entry_value = b""
        for field_tag, field_value in _children(item):
            number = field_tag & 0x1F if field_tag & 0xC0 == 0x80 else None
            if number == 1:
                entry_type = _int_value(field_value)
            elif number == 2:
                entry_value = _octets_value(field_value)
            elif field_tag == 0x02 and entry_type is None:
                entry_type = _int_value(field_value)
            elif field_tag == 0x04 and not entry_value:
                entry_value = field_value
        if entry_type is not None:
            entries.append({
                "type": entry_type,
                "name": PADATA_NAMES.get(entry_type, str(entry_type)),
                "value": entry_value,
            })
    return entries


def _encrypted_part(value: bytes | None) -> dict[str, Any] | None:
    """Decode an EncryptedData structure from a tagged field value."""
    if not value:
        return None
    children = _seq_children(value)
    if not children:
        return None
    etype = _int_value(find_context(children, 0))
    cipher = _octets_value(find_context(children, 2))
    if etype is None or not cipher:
        return None
    kvno = _int_value(find_context(children, 1))
    return {"etype": etype, "kvno": kvno, "cipher": cipher}


def parse_encrypted_part(data: bytes) -> dict[str, Any] | None:
    """Parse an EncryptedData SEQUENCE (tagged, bare or context-wrapped)."""
    try:
        children = _seq_children(data)
        if not children:
            return None
        etype = _int_value(find_context(children, 0))
        cipher = _octets_value(find_context(children, 2))
        if etype is None or not cipher:
            return None
        return {
            "etype": etype,
            "kvno": _int_value(find_context(children, 1)),
            "cipher": cipher,
        }
    except Exception:  # noqa: BLE001 - parser contract: never raise
        return None


def _ticket(value: bytes | None) -> dict[str, Any] | None:
    children = _seq_children(value)
    if not children:
        return None
    return {
        "realm": _str_value(find_context(children, 1)),
        "sname": _principal(find_context(children, 2)),
        "enc_part": _encrypted_part(find_context(children, 3)),
    }


def _parse_kdc_rep(data: bytes, app_tag: int,
                   msg_type: int) -> dict[str, Any] | None:
    """Shared parser for AS-REP (11) and TGS-REP (13)."""
    try:
        tag, outer, _end = read_tlv(data, 0)
        if tag != app_tag:
            return None
        children = _seq_children(outer)
        if not children:
            return None
        parsed_type = _int_value(find_context(children, 1))
        if parsed_type is not None and parsed_type != msg_type:
            return None
        ticket = _ticket(find_context(children, 5))
        enc_part = _encrypted_part(find_context(children, 6))
        return {
            "pvno": _int_value(find_context(children, 0)),
            "msg_type": msg_type,
            "cname": _principal(find_context(children, 4)),
            "realm": _str_value(find_context(children, 3)),
            "sname": ticket.get("sname", "") if ticket else "",
            "etypes": [enc_part["etype"]] if enc_part else [],
            "padata": _padata(find_context(children, 2)),
            "enc_part": enc_part,
            "ticket": ticket,
            "error": None,
        }
    except Exception:  # noqa: BLE001 - parser contract: never raise
        return None


def parse_as_rep(data: bytes) -> dict[str, Any] | None:
    """Parse an AS-REP (APPLICATION 11) into a plain dictionary."""
    return _parse_kdc_rep(data, 0x6B, 11)


def parse_tgs_rep(data: bytes) -> dict[str, Any] | None:
    """Parse a TGS-REP (APPLICATION 13) into a plain dictionary."""
    return _parse_kdc_rep(data, 0x6D, 13)


def _parse_kdc_req(data: bytes, app_tag: int,
                   msg_type: int) -> dict[str, Any] | None:
    """Shared parser for AS-REQ (10) and TGS-REQ (12)."""
    try:
        tag, outer, _end = read_tlv(data, 0)
        if tag != app_tag:
            return None
        children = _seq_children(outer)
        if not children:
            return None
        parsed_type = _int_value(find_context(children, 2))
        if parsed_type is not None and parsed_type != msg_type:
            return None
        body = _seq_children(find_context(children, 4))
        etypes: list[int] = []
        for item_tag, item in _seq_children(find_context(body, 8)):
            value = _int_value(item)
            if value is not None:
                etypes.append(value)
        padata = _padata(find_context(children, 3))
        enc_part = None
        for entry in padata:
            if entry["type"] == 2:  # PA-ENC-TIMESTAMP
                enc_part = parse_encrypted_part(entry["value"])
                break
        return {
            "pvno": _int_value(find_context(children, 1)),
            "msg_type": msg_type,
            "cname": _principal(find_context(body, 1)),
            "realm": _str_value(find_context(body, 2)),
            "sname": _principal(find_context(body, 3)),
            "etypes": etypes,
            "padata": padata,
            "enc_part": enc_part,
            "ticket": None,
            "error": None,
        }
    except Exception:  # noqa: BLE001 - parser contract: never raise
        return None


def parse_as_req(data: bytes) -> dict[str, Any] | None:
    """Parse an AS-REQ (APPLICATION 10) into a plain dictionary."""
    return _parse_kdc_req(data, 0x6A, 10)


def parse_tgs_req(data: bytes) -> dict[str, Any] | None:
    """Parse a TGS-REQ (APPLICATION 12) into a plain dictionary."""
    return _parse_kdc_req(data, 0x6C, 12)


def parse_krb_error(data: bytes) -> dict[str, Any] | None:
    """Parse a KRB-ERROR (APPLICATION 30) into a plain dictionary."""
    try:
        tag, outer, _end = read_tlv(data, 0)
        if tag != 0x7E:
            return None
        children = _seq_children(outer)
        if not children:
            return None
        msg_type = _int_value(find_context(children, 1))
        return {
            "pvno": _int_value(find_context(children, 0)),
            "msg_type": msg_type if msg_type is not None else 30,
            "cname": _principal(find_context(children, 8)),
            "realm": _str_value(find_context(children, 9)),
            "sname": _principal(find_context(children, 10)),
            "etypes": [],
            "padata": [],
            "enc_part": None,
            "ticket": None,
            "error": _int_value(find_context(children, 6)),
            "error_text": _str_value(find_context(children, 11)),
            "e_data": _octets_value(find_context(children, 12)),
        }
    except Exception:  # noqa: BLE001 - parser contract: never raise
        return None


# ---------------------------------------------------------------------------
# AES-CBC-CS3 (RFC 3962), key derivation and HMAC-SHA1-96
# ---------------------------------------------------------------------------
def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _nfold(data: bytes, size: int) -> bytes:
    """RFC 3961 n-fold: stretch ``data`` to ``size`` bytes."""
    if not data or size <= 0:
        return b""

    def rotate_right(block: bytes, bits: int) -> bytes:
        nbytes, remain = (bits // 8) % len(block), bits % 8
        if remain == 0:
            return bytes(block[i - nbytes] for i in range(len(block)))
        return bytes(
            ((block[i - nbytes] >> remain) |
             ((block[i - nbytes - 1] << (8 - remain)) & 0xFF))
            for i in range(len(block))
        )

    def add_ones_complement(left: bytes, right: bytes) -> bytes:
        values = [a + b for a, b in zip(left, right)]
        while any(value > 0xFF for value in values):
            count = len(values)
            values = [(values[(i - 1) % count] >> 8) + (values[i] & 0xFF)
                      for i in range(count)]
        return bytes(values)

    length = len(data)
    lcm = size * length // gcd(size, length)
    big = b"".join(rotate_right(data, 13 * i) for i in range(lcm // length))
    chunks = [big[pos:pos + size] for pos in range(0, lcm, size)]
    return reduce(add_ones_complement, chunks)


def aes_cts_encrypt(plaintext: bytes, key: bytes,
                    iv: bytes | None = None) -> bytes:
    """Encrypt with AES-CBC-CS3 (ciphertext stealing, last blocks swapped).

    Kerberos always uses an all-zero IV.  The last two ciphertext blocks are
    swapped even when the length is a multiple of the block size, which is
    what RFC 3962 specifies and what the Kerberos test vectors require.
    """
    block_size = 16
    if not plaintext:
        return b""
    iv = (iv or b"\x00" * block_size)[:block_size].ljust(block_size, b"\x00")
    if len(plaintext) <= block_size:
        block = plaintext.ljust(block_size, b"\x00")
        return crypto.aes_encrypt_block(_xor(block, iv), key)
    blocks = [plaintext[pos:pos + block_size]
              for pos in range(0, len(plaintext), block_size)]
    full, last = blocks[:-1], blocks[-1]
    cipher_blocks: list[bytes] = []
    previous = iv
    for block in full:
        previous = crypto.aes_encrypt_block(_xor(block, previous), key)
        cipher_blocks.append(previous)
    remainder = len(last)
    if remainder == block_size:
        previous = crypto.aes_encrypt_block(_xor(last, previous), key)
        cipher_blocks.append(previous)
        cipher_blocks[-2], cipher_blocks[-1] = (
            cipher_blocks[-1], cipher_blocks[-2])
        return b"".join(cipher_blocks)
    padded = last.ljust(block_size, b"\x00")
    final = crypto.aes_encrypt_block(_xor(padded, previous), key)
    return (b"".join(cipher_blocks[:-1]) + final
            + cipher_blocks[-1][:remainder])


def aes_cts_decrypt(ciphertext: bytes, key: bytes,
                    iv: bytes | None = None) -> bytes:
    """Inverse of :func:`aes_cts_encrypt` (AES-CBC-CS3)."""
    block_size = 16
    if not ciphertext:
        return b""
    iv = (iv or b"\x00" * block_size)[:block_size].ljust(block_size, b"\x00")
    if len(ciphertext) <= block_size:
        padded = ciphertext.ljust(block_size, b"\x00")
        return _xor(crypto.aes_decrypt_block(padded, key), iv)[:len(ciphertext)]
    full = len(ciphertext) // block_size
    remainder = len(ciphertext) % block_size
    if remainder == 0:
        blocks = [ciphertext[pos:pos + block_size]
                  for pos in range(0, len(ciphertext), block_size)]
        if len(blocks) == 1:
            return _xor(crypto.aes_decrypt_block(blocks[0], key), iv)
        blocks[-2], blocks[-1] = blocks[-1], blocks[-2]
        out = bytearray()
        previous = iv
        for block in blocks:
            out += _xor(crypto.aes_decrypt_block(block, key), previous)
            previous = block
        return bytes(out)
    head = ciphertext[:(full - 1) * block_size]
    cn = ciphertext[(full - 1) * block_size:full * block_size]
    stolen = ciphertext[full * block_size:]
    decrypted_cn = crypto.aes_decrypt_block(cn, key)
    previous_cipher = stolen + decrypted_cn[remainder:]
    out = bytearray()
    previous = iv
    for pos in range(0, len(head), block_size):
        block = head[pos:pos + block_size]
        out += _xor(crypto.aes_decrypt_block(block, key), previous)
        previous = block
    out += _xor(crypto.aes_decrypt_block(previous_cipher, key), previous)
    out += bytes(a ^ b for a, b in zip(decrypted_cn[:remainder], stolen))
    return bytes(out)


def derive_key_constant(key: bytes, constant: bytes) -> bytes:
    """RFC 3961 DK: expand ``constant`` with n-fold and AES under ``key``."""
    if not key:
        return b""
    block = _nfold(constant, 16)
    seed = b""
    while len(seed) < len(key):
        block = aes_cts_encrypt(block, key)
        seed += block
    return seed[:len(key)]


def derive_random(key: bytes, usage: int, marker: int) -> bytes:
    """Derive a per-usage key (``marker`` is 0x55, 0x99 or 0xAA)."""
    constant = struct.pack(">I", usage & 0xFFFFFFFF) + bytes([marker & 0xFF])
    return derive_key_constant(key, constant)


def aes_hmac_sha1_encrypt(key: bytes, usage: int, plaintext: bytes,
                          confounder: bytes | None = None) -> bytes:
    """Encrypt with the Kerberos aes*-cts-hmac-sha1-96 profile."""
    ke = derive_random(key, usage, 0xAA)
    ki = derive_random(key, usage, 0x55)
    conf = confounder if confounder is not None else os.urandom(16)
    conf = bytes(conf)[:16].ljust(16, b"\x00")
    basic = conf + plaintext
    mac = hmac.new(ki, basic, hashlib.sha1).digest()[:12]
    return aes_cts_encrypt(basic, ke) + mac


def aes_hmac_sha1_decrypt(key: bytes, usage: int,
                          cipher: bytes) -> tuple[bytes, bool]:
    """Decrypt aes*-cts-hmac-sha1-96 and return ``(plaintext, valid)``.

    The confounder is stripped from the returned plaintext.  A checksum
    failure is reported through the boolean instead of raising so callers can
    still inspect attacker-controlled data.
    """
    cipher = _as_bytes(cipher)
    if len(cipher) < 28:
        return b"", False
    basic_cipher, mac = cipher[:-12], cipher[-12:]
    ke = derive_random(key, usage, 0xAA)
    ki = derive_random(key, usage, 0x55)
    basic = aes_cts_decrypt(basic_cipher, ke)
    expected = hmac.new(ki, basic, hashlib.sha1).digest()[:12]
    plaintext = basic[16:] if len(basic) >= 16 else b""
    return plaintext, hmac.compare_digest(expected, mac)


# ---------------------------------------------------------------------------
# RC4-HMAC (RFC 4757)
# ---------------------------------------------------------------------------
_RC4_USAGE_MAP = {3: 8, 23: 13}


def _rc4_usage(usage: int) -> int:
    """Map RFC 4120 key usages to the RC4-HMAC usage numbers."""
    return _RC4_USAGE_MAP.get(usage, usage)


def _rc4_checksum(key: bytes, usage: int, data: bytes) -> tuple[bytes, bytes]:
    k1 = hmac.new(key, struct.pack("<I", usage & 0xFFFFFFFF),
                  hashlib.md5).digest()
    checksum = hmac.new(k1, data, hashlib.md5).digest()
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()
    return checksum, k3


def rc4_hmac_encrypt(key: bytes, usage: int, plaintext: bytes,
                     confounder: bytes | None = None) -> bytes:
    """Encrypt with rc4-hmac: ``checksum || RC4(confounder || plaintext)``."""
    conf = confounder if confounder is not None else os.urandom(8)
    conf = bytes(conf)[:8].ljust(8, b"\x00")
    data = conf + plaintext
    checksum, k3 = _rc4_checksum(key, _rc4_usage(usage), data)
    return checksum + crypto.rc4(k3, data)


def _rc4_hmac_decrypt_with(key: bytes, usage: int, checksum: bytes,
                           body: bytes) -> tuple[bytes, bool]:
    k1 = hmac.new(key, struct.pack("<I", usage & 0xFFFFFFFF),
                  hashlib.md5).digest()
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()
    data = crypto.rc4(k3, body)
    expected = hmac.new(k1, data, hashlib.md5).digest()
    return data[8:], hmac.compare_digest(expected, checksum)


def rc4_hmac_decrypt(key: bytes, usage: int,
                     cipher: bytes) -> tuple[bytes, bool]:
    """Decrypt rc4-hmac and return ``(plaintext, checksum_valid)``.

    Key usage 9 is retried as 8 to accommodate the RFC 4757 errata that some
    implementations follow.
    """
    cipher = _as_bytes(cipher)
    if len(cipher) < 24:
        return b"", False
    checksum, body = cipher[:16], cipher[16:]
    plaintext, valid = _rc4_hmac_decrypt_with(
        key, _rc4_usage(usage), checksum, body)
    if not valid and usage == 9:
        plaintext, valid = _rc4_hmac_decrypt_with(
            key, 8, checksum, body)
    return plaintext, valid


# ---------------------------------------------------------------------------
# Password-to-key helpers
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: str, etype: int,
               iterations: int = 4096) -> bytes:
    """Derive a long-term key from a password.

    AES etypes use PBKDF2-HMAC-SHA1 with 4096 iterations by default; RC4-HMAC
    uses the NT hash (MD4 of the UTF-16-LE password), as required by RFC 4757.
    """
    if etype in (23, 24):
        return crypto.nt_hash(password)
    if etype in (17, 18):
        length = 16 if etype == 17 else 32
        return hashlib.pbkdf2_hmac(
            "sha1", password.encode("utf-8"), salt.encode("utf-8"),
            iterations, length)
    raise ValueError(f"unsupported etype {etype}")


def string_to_key(password: str, salt: str, etype: int,
                  iterations: int = 4096) -> bytes:
    """Full RFC 3962 string-to-key (PBKDF2 followed by ``DK(key, kerberos)``)."""
    seed = derive_key(password, salt, etype, iterations)
    if etype in (23, 24):
        return seed
    return derive_key_constant(seed, b"kerberos")


def password_salt(realm: str, principal: str) -> str:
    """Default AD salt: uppercase realm followed by the principal name."""
    return f"{(realm or '').upper()}{principal or ''}"


# ---------------------------------------------------------------------------
# EncryptedData convenience wrappers
# ---------------------------------------------------------------------------
def _as_bytes(value: Any) -> bytes:
    """Accept bytes or a hex string; anything else becomes ``b""``."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
        if len(cleaned) % 2:
            return b""
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return b""
    return b""


def _as_int(value: Any, default: int | None = 0) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def decrypt_encrypted_part(enc_part: Mapping[str, Any], key: bytes,
                           usage: int = 3) -> dict[str, Any]:
    """Decrypt an ``enc_part`` dict and report integrity separately."""
    result: dict[str, Any] = {
        "ok": False, "checksum_ok": False, "plaintext": b"",
        "etype": None, "usage": usage, "error": "",
    }
    if not isinstance(enc_part, Mapping):
        result["error"] = "no encrypted part"
        return result
    etype = _as_int(enc_part.get("etype"), None)
    cipher = _as_bytes(enc_part.get("cipher"))
    result["etype"] = etype
    if etype is None or not cipher:
        result["error"] = "missing etype or cipher"
        return result
    if etype in (23, 24):
        plaintext, valid = rc4_hmac_decrypt(key, usage, cipher)
    elif etype in (17, 18):
        plaintext, valid = aes_hmac_sha1_decrypt(key, usage, cipher)
    else:
        result["error"] = f"unsupported etype {etype}"
        return result
    result["plaintext"] = plaintext
    result["checksum_ok"] = valid
    result["ok"] = valid
    if not valid:
        result["error"] = "checksum mismatch"
    return result


def encrypt_encrypted_part(etype: int, key: bytes, usage: int,
                           plaintext: bytes,
                           confounder: bytes | None = None) -> dict[str, Any]:
    """Build an ``enc_part`` dict; used by tests and fixture generators."""
    plaintext = _as_bytes(plaintext)
    if etype in (23, 24):
        cipher = rc4_hmac_encrypt(key, usage, plaintext, confounder)
    elif etype in (17, 18):
        cipher = aes_hmac_sha1_encrypt(key, usage, plaintext, confounder)
    else:
        return {}
    return {"etype": etype, "kvno": 0, "cipher": cipher}


# ---------------------------------------------------------------------------
# MIT keytab files
# ---------------------------------------------------------------------------
def _counted_octet_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated counted string")
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + length > len(data):
        raise ValueError("counted string out of range")
    return data[offset:offset + length], offset + length


def _parse_keytab_entry(blob: bytes) -> dict[str, Any] | None:
    try:
        offset = 0
        count = struct.unpack_from(">H", blob, offset)[0]
        offset += 2
        realm, offset = _counted_octet_string(blob, offset)
        components: list[str] = []
        for _ in range(count):
            raw, offset = _counted_octet_string(blob, offset)
            components.append(raw.decode("utf-8", "replace"))
        name_type = struct.unpack_from(">I", blob, offset)[0]
        timestamp = struct.unpack_from(">I", blob, offset + 4)[0]
        offset += 8
        kvno8 = blob[offset]
        offset += 1
        etype, key_len = struct.unpack_from(">HH", blob, offset)
        offset += 4
        if offset + key_len > len(blob):
            return None
        key = blob[offset:offset + key_len]
        offset += key_len
        kvno32 = struct.unpack_from(">I", blob, offset)[0] \
            if offset + 4 <= len(blob) else 0
        principal = "/".join(components)
        realm_text = realm.decode("utf-8", "replace")
        if realm_text:
            principal = f"{principal}@{realm_text}"
        return {
            "realm": realm_text,
            "components": components,
            "principal": principal,
            "name_type": name_type,
            "timestamp": timestamp,
            "kvno": kvno32 or kvno8,
            "etype": etype,
            "key": key,
        }
    except (struct.error, ValueError, IndexError):
        return None


def parse_keytab(data: bytes) -> list[dict[str, Any]]:
    """Parse a version 0x0502 MIT keytab; malformed entries are skipped."""
    entries: list[dict[str, Any]] = []
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2:
        return entries
    data = bytes(data)
    try:
        offset = 2  # version (0x0502) is informational only
        while offset + 4 <= len(data):
            size = struct.unpack_from(">i", data, offset)[0]
            offset += 4
            if size < 0:  # hole left by a deleted entry
                offset += -size
                continue
            if size == 0:
                continue
            end = offset + size
            if end > len(data):
                break
            entry = _parse_keytab_entry(data[offset:end])
            if entry is not None:
                entries.append(entry)
            offset = end
    except (struct.error, ValueError):
        pass
    return entries


def keytab_keys(data: bytes) -> dict[str, dict[int, bytes]]:
    """Return ``principal -> {etype: key}`` for every keytab entry."""
    keys: dict[str, dict[int, bytes]] = {}
    for entry in parse_keytab(data):
        keys.setdefault(entry["principal"], {})[entry["etype"]] = entry["key"]
    return keys


# ---------------------------------------------------------------------------
# Privilege Attribute Certificate (PAC)
# ---------------------------------------------------------------------------
def _pac_buffers(data: bytes) -> list[dict[str, Any]]:
    """Decode the PAC header and its buffer descriptors."""
    if len(data) < 8:
        return []
    count, _version = struct.unpack_from("<II", data, 0)
    if count == 0 or count > 128 or 8 + count * 12 > len(data):
        return []
    raw = [struct.unpack_from("<III", data, 8 + 12 * index)
           for index in range(count)]
    # The on-wire order is (type, size, offset).  Some hand-built fixtures
    # use (type, offset, size); try both and keep the layout that fits.
    for length_first in (True, False):
        buffers: list[dict[str, Any]] = []
        for buffer_type, first, second in raw:
            length, offset = (first, second) if length_first else (second, first)
            if offset + length > len(data):
                break
            buffers.append({
                "type": buffer_type,
                "name": PAC_BUFFER_NAMES.get(buffer_type, str(buffer_type)),
                "length": length,
                "offset": offset,
            })
        else:
            return buffers
    return []


def _plausible_unicode(raw: bytes) -> str:
    """Decode UTF-16-LE only when the result looks like a real string."""
    if len(raw) < 2 or len(raw) % 2:
        return ""
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return ""
    text = text.rstrip("\x00")
    if not text or "\x00" in text:
        return ""
    printable = sum(ch.isprintable() or ch in "\t\r\n" for ch in text)
    if printable / len(text) < 0.9:
        return ""
    return text


def _read_unicode_field(blob: bytes, struct_offset: int, pac_data: bytes,
                        blob_offset: int) -> str:
    """Read an RPC_UNICODE_STRING, trying the common pointer bases."""
    if struct_offset < 0 or struct_offset + 8 > len(blob):
        return ""
    length, _maximum, pointer = struct.unpack_from(
        "<HHI", blob, struct_offset)
    length = min(length, 4096)
    if length < 2:
        return ""
    if length % 2:
        length -= 1
    candidates = [
        (pac_data, pointer),
        (pac_data, pointer + blob_offset),
        (pac_data, pointer + 8),
        (blob, pointer),
    ]
    for container, start in candidates:
        if start < 0 or start + length > len(container):
            continue
        text = _plausible_unicode(container[start:start + length])
        if text:
            return text
    return ""


def _parse_sid(data: bytes, offset: int) -> tuple[str, int]:
    """Decode an RPC_SID (revision, count, authority, sub-authorities)."""
    if offset + 8 > len(data):
        return "", offset
    revision = data[offset]
    count = data[offset + 1]
    authority = int.from_bytes(data[offset + 2:offset + 8], "big")
    end = offset + 8 + 4 * count
    if count > 15 or end > len(data):
        return "", offset
    sub_authorities = [struct.unpack_from("<I", data, offset + 8 + 4 * i)[0]
                       for i in range(count)]
    text = f"S-{revision}-{authority}"
    text += "".join(f"-{value}" for value in sub_authorities)
    return text, end


def _parse_logon_info(blob: bytes, pac_data: bytes,
                      blob_offset: int) -> dict[str, Any]:
    """Decode KERB_VALIDATION_INFO (PAC buffer type 1)."""
    info: dict[str, Any] = {
        "user": "", "full_name": "", "domain": "", "logon_server": "",
        "user_id": 0, "primary_group_id": 0, "group_ids": [],
        "logon_count": 0, "bad_password_count": 0,
        "domain_sid": "", "user_sid": "", "sids": [],
    }
    if len(blob) < 96:
        return info
    info["user"] = _read_unicode_field(blob, 48, pac_data, blob_offset)
    info["full_name"] = _read_unicode_field(blob, 56, pac_data, blob_offset)
    offset = 96
    info["logon_count"], info["bad_password_count"] = struct.unpack_from(
        "<HH", blob, offset)
    offset += 4
    if offset + 12 > len(blob):
        return info
    info["user_id"], info["primary_group_id"], group_count = struct.unpack_from(
        "<III", blob, offset)
    offset += 12
    if group_count > 1024 or offset + 4 * group_count + 20 > len(blob):
        group_count = 0
    groups = [struct.unpack_from("<I", blob, offset + 4 * i)[0]
              for i in range(group_count)]
    info["group_ids"] = groups
    offset += 4 * group_count
    offset += 4   # UserFlags
    offset += 16  # UserSessionKey
    info["logon_server"] = _read_unicode_field(
        blob, offset, pac_data, blob_offset)
    offset += 8
    info["domain"] = _read_unicode_field(blob, offset, pac_data, blob_offset)
    offset += 8
    domain_sid, _end = _parse_sid(blob, offset)
    info["domain_sid"] = domain_sid
    sids: list[str] = []
    if domain_sid:
        sids.append(domain_sid)
        if info["user_id"]:
            info["user_sid"] = f"{domain_sid}-{info['user_id']}"
            sids.append(info["user_sid"])
        for group_id in groups:
            if group_id:
                sids.append(f"{domain_sid}-{group_id}")
    info["sids"] = sids
    return info


def _ntlm_from_credential_data(data: bytes) -> tuple[bytes, bytes]:
    """Find an NTLM_SUPPLEMENTAL_CREDENTIAL inside credential data."""

    def check(blob: bytes) -> tuple[bytes, bytes] | None:
        if len(blob) < 40:
            return None
        version, flags = struct.unpack_from("<II", blob, 0)
        if version != 0 or flags != 0:
            return None
        lm_hash, nt_hash = blob[8:24], blob[24:40]
        if lm_hash == b"\x00" * 16 and nt_hash == b"\x00" * 16:
            return None
        return lm_hash, nt_hash

    direct = check(data)
    if direct:
        return direct
    if len(data) >= 4:
        count = struct.unpack_from("<I", data, 0)[0]
        offset = 4
        if 0 < count <= 64:
            for _ in range(count):
                if offset + 8 > len(data):
                    break
                credential_type, length = struct.unpack_from(
                    "<II", data, offset)
                offset += 8
                if offset + length > len(data):
                    break
                found = check(data[offset:offset + length])
                offset += length
                if credential_type == 2 and found:
                    return found
    for start in range(0, max(0, len(data) - 39)):
        if data[start:start + 8] == b"\x00" * 8:
            found = check(data[start:start + 40])
            if found:
                return found
    return b"", b""


def _parse_credential_info(blob: bytes) -> dict[str, Any]:
    """Decode PAC_CREDENTIAL_INFO (buffer type 2), plaintext fixtures too."""
    info: dict[str, Any] = {
        "version": 0, "etype": 0, "serialized_length": 0,
        "lm_hash": "", "ntlm_hash": "", "nt_hash": b"", "lm_hash_bytes": b"",
    }
    if len(blob) < 12:
        serialized = blob
    else:
        info["version"], info["etype"], length = struct.unpack_from(
            "<III", blob, 0)
        info["serialized_length"] = length
        if length and 12 + length <= len(blob):
            serialized = blob[12:12 + length]
        else:
            serialized = blob[12:]
    lm_hash, nt_hash = _ntlm_from_credential_data(serialized)
    info["lm_hash_bytes"] = lm_hash
    info["nt_hash"] = nt_hash
    info["lm_hash"] = lm_hash.hex().upper()
    info["ntlm_hash"] = nt_hash.hex().upper()
    return info


def _parse_client_info(blob: bytes) -> dict[str, Any]:
    """Decode PAC_CLIENT_INFO (buffer type 10)."""
    info: dict[str, Any] = {"client_id": 0, "name": ""}
    if len(blob) < 10:
        return info
    info["client_id"] = int.from_bytes(blob[:8], "little")
    length = struct.unpack_from("<H", blob, 8)[0]
    offset = 10
    if length == 0 or offset + length > len(blob):
        length = struct.unpack_from("<I", blob, 8)[0]
        offset = 12
        if length == 0 or offset + length > len(blob):
            return info
    if length % 2:
        length -= 1
    if length <= 0:
        return info
    info["name"] = blob[offset:offset + length].decode(
        "utf-16-le", "replace").rstrip("\x00")
    return info


def _parse_server_checksum(blob: bytes) -> dict[str, Any]:
    """Decode PAC_SERVER_CHECKSUM / PAC_PRIVSVR_CHECKSUM."""
    if len(blob) < 4:
        return {}
    return {
        "signature_type": struct.unpack_from("<I", blob, 0)[0],
        "signature": blob[4:],
    }


def _empty_pac() -> dict[str, Any]:
    return {
        "buffers": [], "logon_info": None, "credential_info": {},
        "client_info": {}, "server_checksum": {},
        "user": "", "domain": "", "sids": [],
        "ntlm_hash": "", "lm_hash": "",
    }


def parse_pac(data: bytes) -> dict[str, Any]:
    """Parse a PAC blob and return logon/credential/checksum information.

    The function never raises: an empty or corrupt buffer yields the default
    dictionary with empty fields.
    """
    result = _empty_pac()
    try:
        if not isinstance(data, (bytes, bytearray)) or len(data) < 8:
            return result
        data = bytes(data)
        buffers = _pac_buffers(data)
        result["buffers"] = buffers
        for buffer in buffers:
            start = buffer["offset"]
            end = start + buffer["length"]
            blob = data[start:end]
            buffer_type = buffer["type"]
            if buffer_type == 1:
                result["logon_info"] = _parse_logon_info(blob, data, start)
            elif buffer_type == 2:
                result["credential_info"] = _parse_credential_info(blob)
            elif buffer_type == 6:
                result["server_checksum"] = _parse_server_checksum(blob)
            elif buffer_type == 10:
                result["client_info"] = _parse_client_info(blob)
        logon = result["logon_info"] or {}
        client = result["client_info"] or {}
        credential = result["credential_info"] or {}
        result["user"] = logon.get("user") or client.get("name", "")
        result["domain"] = logon.get("domain", "")
        result["sids"] = logon.get("sids", [])
        result["ntlm_hash"] = credential.get("ntlm_hash", "")
        result["lm_hash"] = credential.get("lm_hash", "")
    except Exception:  # noqa: BLE001 - parser contract: never raise
        pass
    return result


# ---------------------------------------------------------------------------
# hashcat helpers
# ---------------------------------------------------------------------------
def find_pac(data: bytes, *, limit: int = 65_536) -> tuple[dict[str, Any], int]:
    """Locate an embedded PAC inside decrypted Kerberos plaintext.

    The PAC sits inside the authorization-data field of an AS/TGS reply, so
    its offset is not fixed.  Scan the first ``limit`` bytes for a PAC header
    whose buffer descriptors fit and that carries at least one known buffer
    type.  Returns ``(parsed_pac, offset)``; ``({}, -1)`` when nothing looks
    like a PAC.
    """
    blob = bytes(data or b"")[:max(0, int(limit))]
    if len(blob) < 8:
        return {}, -1
    checked = 0
    for offset in range(0, len(blob) - 8):
        if blob[offset] == 0 and blob[offset + 1] == 0:
            continue  # PAC count is never zero
        checked += 1
        if checked > 4096:
            break
        buffers = _pac_buffers(blob[offset:])
        if not buffers:
            continue
        types = {buffer["type"] for buffer in buffers}
        if not types & {1, 2, 6, 7, 10}:
            continue
        parsed = parse_pac(blob[offset:])
        logon = parsed.get("logon_info") or {}
        if parsed.get("user") or not types & {1, 2, 10}:
            return parsed, offset
    return {}, -1


# ---------------------------------------------------------------------------
# hashcat helpers
# ---------------------------------------------------------------------------
def hashcat_modes(msg_type: int, etype: int) -> list[int]:
    """Return the hashcat mode numbers matching ``(msg_type, etype)``."""
    try:
        return list(HASHCAT_MODES.get((int(msg_type), int(etype)), ()))
    except (TypeError, ValueError):
        return []


def hashcat_lines(msg_type: int, user: str, realm: str, spn: str,
                  etype: int, cipher: bytes) -> list[str]:
    """Build hashcat lines for an AS-REP or TGS-REP encrypted part.

    RC4-HMAC stores its 16-byte checksum before the encrypted data, while the
    AES etypes append a 12-byte HMAC-SHA1-96 checksum.  hashcat expects the
    checksum first in both cases, so the cipher is split according to the
    etype and then reordered.
    """
    try:
        msg_type = int(msg_type)
        etype = int(etype)
    except (TypeError, ValueError):
        return []
    cipher = _as_bytes(cipher)
    if msg_type not in (11, 13) or etype not in (17, 18, 23):
        return []
    if not cipher:
        return []
    if etype == 23:
        if len(cipher) <= 16:
            return []
        checksum, edata = cipher[:16], cipher[16:]
    else:
        if len(cipher) <= 12:
            return []
        checksum, edata = cipher[-12:], cipher[:-12]
    user = user or "unknown"
    realm = (realm or "UNKNOWN.REALM").upper()
    checksum_hex, edata_hex = checksum.hex(), edata.hex()
    if msg_type == 11:
        return [f"$krb5asrep${etype}${user}@{realm}:"
                f"{checksum_hex}${edata_hex}"]
    service = spn or "unknown"
    return [f"$krb5tgs${etype}$*{user}${realm}${service}*$"
            f"{checksum_hex}${edata_hex}"]


# ---------------------------------------------------------------------------
# Timeline helpers
# ---------------------------------------------------------------------------
def _event_time(event: Mapping[str, Any]) -> float:
    for key in ("time", "timestamp", "ts", "epoch"):
        if key not in event:
            continue
        try:
            return float(event[key])
        except (TypeError, ValueError):
            continue
    return 0.0


def build_timeline(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalise Kerberos events into a time-ordered timeline.

    Each input mapping may carry ``time``/``timestamp``, ``frame``,
    ``msg_type``, ``user``, ``realm``, ``spn``, ``etype``, ``error`` and
    ``detail``.  Unknown or malformed events are skipped.
    """
    timeline: list[dict[str, Any]] = []
    for event in events or ():
        if not isinstance(event, Mapping):
            continue
        msg_type = _as_int(event.get("msg_type"))
        frame = _as_int(event.get("frame"), None)
        error_value = event.get("error")
        error = (_as_int(error_value, None)
                 if error_value is not None else None)
        etype_value = event.get("etype")
        etype = _as_int(etype_value, None) if etype_value is not None else None
        timeline.append({
            "time": _event_time(event),
            "frame": frame,
            "msg_type": msg_type,
            "message": MSG_NAMES.get(msg_type, f"type={msg_type}"),
            "user": str(event.get("user") or ""),
            "realm": str(event.get("realm") or ""),
            "spn": str(event.get("spn") or ""),
            "etype": etype,
            "error": error,
            "detail": str(event.get("detail") or ""),
        })
    timeline.sort(key=lambda item: (
        item["time"], item["frame"] if item["frame"] is not None else 0))
    return timeline


def summarise_timeline(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Count messages, users, etypes and errors in a Kerberos timeline."""
    timeline = build_timeline(events)
    messages: dict[str, int] = {}
    users: dict[str, int] = {}
    etypes: dict[str, int] = {}
    errors: dict[str, int] = {}
    for item in timeline:
        messages[item["message"]] = messages.get(item["message"], 0) + 1
        account = (f"{item['user']}@{item['realm']}"
                   if item["realm"] else item["user"])
        if account:
            users[account] = users.get(account, 0) + 1
        if item["etype"] is not None:
            key = str(item["etype"])
            etypes[key] = etypes.get(key, 0) + 1
        if item["error"] is not None:
            key = str(item["error"])
            errors[key] = errors.get(key, 0) + 1
    first = timeline[0]["time"] if timeline else None
    last = timeline[-1]["time"] if timeline else None
    return {
        "count": len(timeline),
        "first": first,
        "last": last,
        "duration": (last - first) if timeline else 0.0,
        "messages": messages,
        "users": users,
        "etypes": etypes,
        "errors": errors,
    }
