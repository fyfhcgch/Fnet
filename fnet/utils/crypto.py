"""Pure-Python crypto primitives used by the CTF handlers.

The primitives for webshell / Shiro / Cobalt Strike decryption live here so a
plain ``pip install`` is enough and no third-party crypto package is required;
optional libraries such as ``cryptography`` are still used when present for
speed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# AES (FIPS-197), compact implementation: ECB/CBC, PKCS#7
# ---------------------------------------------------------------------------
SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
RSBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    RSBOX[_v] = _i
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d)


def _expand_key(key: bytes) -> tuple[list[list[int]], int]:
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = words[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return words, nr


def _add_round_key(state: list[int], words: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            state[4 * c + r] ^= words[4 * rnd + c][r]


def _mix_columns(state: list[int]) -> None:
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        state[4 * c] ^= t ^ _xtime(a[0] ^ a[1])
        state[4 * c + 1] ^= t ^ _xtime(a[1] ^ a[2])
        state[4 * c + 2] ^= t ^ _xtime(a[2] ^ a[3])
        state[4 * c + 3] ^= t ^ _xtime(a[3] ^ u)


def _xtime(b: int) -> int:
    b <<= 1
    return (b ^ 0x1B) & 0xFF if b & 0x100 else b


def _inv_mix_columns(state: list[int]) -> None:
    for c in range(4):
        a = state[4 * c:4 * c + 4]
        state[4 * c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        state[4 * c + 1] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        state[4 * c + 2] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        state[4 * c + 3] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)


def _mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


def _shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    words, nr = _expand_key(key)
    state = list(block)
    _add_round_key(state, words, 0)
    for rnd in range(1, nr):
        state = [SBOX[b] for b in state]
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, words, rnd)
    state = [SBOX[b] for b in state]
    _shift_rows(state)
    _add_round_key(state, words, nr)
    return bytes(state)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("block must be 16 bytes")
    words, nr = _expand_key(key)
    state = list(block)
    _add_round_key(state, words, nr)
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        state = [RSBOX[b] for b in state]
        _add_round_key(state, words, rnd)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    state = [RSBOX[b] for b in state]
    _add_round_key(state, words, 0)
    return bytes(state)


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= block and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    if pad:
        data = pkcs7_pad(data)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = aes_encrypt_block(block, key)
        out += prev
    return bytes(out)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    prev = iv
    out = bytearray()
    for i in range(0, len(data) - len(data) % 16, 16):
        block = data[i:i + 16]
        decrypted = aes_decrypt_block(block, key)
        out += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = block
    return pkcs7_unpad(bytes(out)) if unpad else bytes(out)


def aes_ecb_encrypt(data: bytes, key: bytes, pad: bool = True) -> bytes:
    if pad:
        data = pkcs7_pad(data)
    return b"".join(aes_encrypt_block(data[i:i + 16], key)
                    for i in range(0, len(data), 16))


def aes_ecb_decrypt(data: bytes, key: bytes, unpad: bool = True) -> bytes:
    out = b"".join(aes_decrypt_block(data[i:i + 16], key)
                   for i in range(0, len(data) - len(data) % 16, 16))
    return pkcs7_unpad(out) if unpad else out


# ---------------------------------------------------------------------------
# AES-GCM (Shiro GCM, modern Java/JWT payloads)
# ---------------------------------------------------------------------------
_GCM_R = 0xE1000000000000000000000000000000


def _gf128_mul(x: int, y: int) -> int:
    """Multiply two 128-bit big-endian integers in GF(2^128) (GCM)."""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_R
        else:
            v >>= 1
    return z


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    def blocks(data: bytes):
        for i in range(0, len(data), 16):
            yield data[i:i + 16].ljust(16, b"\x00")

    y = 0
    for block in blocks(aad):
        y = _gf128_mul(y ^ int.from_bytes(block, "big"), h)
    for block in blocks(ciphertext):
        y = _gf128_mul(y ^ int.from_bytes(block, "big"), h)
    length = (len(aad) * 8) << 64 | (len(ciphertext) * 8)
    y = _gf128_mul(y ^ length, h)
    return y


def _ctr32(counter: bytes) -> bytes:
    prefix, last = counter[:12], int.from_bytes(counter[12:], "big")
    return prefix + ((last + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def aes_gcm_decrypt(data: bytes, key: bytes, iv: bytes,
                    aad: bytes = b"", tag_len: int = 16,
                    check_tag: bool = True) -> tuple[bytes, bool]:
    """Decrypt AES-GCM and return ``(plaintext, tag_valid)``.

    ``data`` is ``ciphertext || tag``.  A 12 byte IV uses the standard
    ``J0 = IV || 0x00000001`` fast path; any other length goes through GHASH,
    which is what Shiro's 128-bit IV produces.
    """
    if len(data) < tag_len:
        return b"", False
    ciphertext, tag = data[:-tag_len], data[-tag_len:]
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, key), "big")
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        j0 = _ghash(h, b"", iv).to_bytes(16, "big")
    counter = j0
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        counter = _ctr32(counter)
        stream = aes_encrypt_block(counter, key)
        block = ciphertext[i:i + 16]
        out += bytes(a ^ b for a, b in zip(block, stream))
    expected = (int.from_bytes(aes_encrypt_block(j0, key), "big")
                ^ _ghash(h, aad, ciphertext)).to_bytes(16, "big")[:tag_len]
    return bytes(out), (expected == tag)


def aes_gcm_encrypt(data: bytes, key: bytes, iv: bytes,
                    aad: bytes = b"", tag_len: int = 16) -> bytes:
    """Encrypt AES-GCM (``ciphertext || tag``); used by the tests."""
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, key), "big")
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        j0 = _ghash(h, b"", iv).to_bytes(16, "big")
    counter = j0
    out = bytearray()
    for i in range(0, len(data), 16):
        counter = _ctr32(counter)
        stream = aes_encrypt_block(counter, key)
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], stream))
    tag = (int.from_bytes(aes_encrypt_block(j0, key), "big")
           ^ _ghash(h, aad, bytes(out))).to_bytes(16, "big")[:tag_len]
    return bytes(out) + tag


# ---------------------------------------------------------------------------
# RC4 / MD4 / HMAC (NTLM, CS, WinRM)
# ---------------------------------------------------------------------------
def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def md4(data: bytes) -> bytes:
    """RFC 1320 MD4 (needed for NT password hashes)."""
    def left_rotate(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bit_len = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for offset in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[offset:offset + 64])
        a, b, c, d = h
        for i in range(16):
            k = i
            s = (3, 7, 11, 19)[i % 4]
            f = (b & c) | (~b & d)
            a = left_rotate(a + f + x[k], s)
            a, b, c, d = d, a, b, c
        for i in range(16):
            k = (i % 4) * 4 + i // 4
            s = (3, 5, 9, 13)[i % 4]
            f = (b & c) | (b & d) | (c & d)
            a = left_rotate(a + f + x[k] + 0x5A827999, s)
            a, b, c, d = d, a, b, c
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in range(16):
            k = order[i]
            s = (3, 9, 11, 15)[i % 4]
            f = b ^ c ^ d
            a = left_rotate(a + f + x[k] + 0x6ED9EBA1, s)
            a, b, c, d = d, a, b, c
        h = [(v + w) & 0xFFFFFFFF for v, w in zip(h, [a, b, c, d])]
    return struct.pack("<4I", *h)


def nt_hash(password: str) -> bytes:
    return md4(password.encode("utf-16le"))


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


# ---------------------------------------------------------------------------
# Minimal DER / RSA PKCS#1 v1.5
# ---------------------------------------------------------------------------
@dataclass
class RSAKey:
    n: int
    e: int
    d: int


def _read_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos >= len(data):
        raise ValueError("truncated DER")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise ValueError("truncated DER length")
    first = data[pos]
    pos += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or pos + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    else:
        length = first
    if pos + length > len(data):
        raise ValueError("DER value out of range")
    return tag, data[pos:pos + length], pos + length


def _parse_rsa_private(der: bytes) -> RSAKey | None:
    try:
        tag, seq, _ = _read_tlv(der, 0)
        if tag != 0x30:
            return None
        pos = 0
        ints = []
        while pos < len(seq):
            tag, value, pos = _read_tlv(seq, pos)
            if tag == 0x02:
                ints.append(int.from_bytes(value, "big"))
            elif tag == 0x30 and len(ints) == 1 and len(value) > 8:
                # PKCS#8 -> skip AlgorithmIdentifier then OCTET STRING
                continue
            elif tag == 0x04:
                nested = _parse_rsa_private(value)
                if nested:
                    return nested
        if len(ints) >= 4:
            return RSAKey(n=ints[1], e=ints[2], d=ints[3])
    except (ValueError, IndexError):
        return None
    return None


def load_rsa_private_key(data: bytes) -> RSAKey | None:
    """Parse a PEM/DER RSA private key, or scan a Java-serialized blob."""
    if b"-----BEGIN" in data:
        match = re.search(
            rb"-----BEGIN (?:RSA )?PRIVATE KEY-----(.+?)-----END (?:RSA )?PRIVATE KEY-----",
            data, re.S)
        if match:
            try:
                data = base64.b64decode(re.sub(rb"\s+", b"", match.group(1)))
            except Exception:  # noqa: BLE001
                pass
    key = _parse_rsa_private(data)
    if key:
        return key
    # Java serialization wraps the key; hunt for plausible DER sequences.
    for match in re.finditer(rb"\x30\x82..\x02\x01\x00\x02", data, re.S):
        candidate = data[match.start():]
        key = _parse_rsa_private(candidate)
        if key and key.n.bit_length() >= 512:
            return key
    for match in re.finditer(rb"\x30[\x81\x82\x83\x84]", data):
        candidate = data[match.start():]
        key = _parse_rsa_private(candidate)
        if key and key.n.bit_length() >= 512:
            return key
    return None


def rsa_decrypt_pkcs1v15(ciphertext: bytes, key: RSAKey) -> bytes | None:
    size = (key.n.bit_length() + 7) // 8
    if len(ciphertext) > size:
        ciphertext = ciphertext[-size:]
    value = int.from_bytes(ciphertext, "big")
    if value >= key.n:
        return None
    plain = pow(value, key.d, key.n).to_bytes(size, "big")
    if len(plain) < 11 or plain[0] != 0 or plain[1] != 2:
        return None
    end = plain.find(b"\x00", 2)
    if end < 10:
        return None
    return plain[end + 1:]


# ---------------------------------------------------------------------------
# Misuse helpers
# ---------------------------------------------------------------------------
def try_base64(value: str) -> bytes | None:
    cleaned = re.sub(r"\s+", "", value or "")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception:  # noqa: BLE001
        return None


def looks_printable(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    good = sum(32 <= b < 127 or b in (9, 10, 13) or b > 127 for b in data)
    return good / len(data) >= threshold


# ---------------------------------------------------------------------------
# AES-CTR (big-endian counter) + OpenSSL EVP_BytesToKey key derivation
# CTF: ``openssl enc -aes-256-ctr -d -nosalt -in flag -out out.bin -pass pass:...``
# ---------------------------------------------------------------------------
def _increment_counter(counter: bytes) -> bytes:
    """Increment a 128-bit big-endian counter by one (mod 2**128)."""
    value = (int.from_bytes(counter, "big") + 1) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    return value.to_bytes(16, "big")


def aes_ctr_crypt(data: bytes, key: bytes, counter: bytes = b"\x00" * 16) -> bytes:
    """Encrypt ``data`` with AES in CTR mode (big-endian counter).

    ``counter`` is the initial counter block (defaults to 16 zero bytes).
    CTR only XORs the AES-encrypted counter stream over the data, so
    encryption and decryption are identical; this shares the AES block
    implementation used by the existing ECB/CBC/GCM handlers.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    if len(counter) != 16:
        raise ValueError("AES-CTR counter must be 16 bytes")
    out = bytearray()
    block_counter = counter
    for i in range(0, len(data), 16):
        stream = aes_encrypt_block(block_counter, key)
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, stream))
        block_counter = _increment_counter(block_counter)
    return bytes(out)


def aes_ctr_decrypt(data: bytes, key: bytes, counter: bytes = b"\x00" * 16) -> bytes:
    """Decrypt AES-CTR ciphertext (symmetric with :func:`aes_ctr_crypt`)."""
    return aes_ctr_crypt(data, key, counter)


_DIGEST_MODS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


def evp_bytes_to_key(password, salt: bytes | None, key_len: int, iv_len: int,
                     dgst: str = "md5") -> tuple[bytes, bytes]:
    """OpenSSL ``EVP_BytesToKey`` key/IV derivation.

    With no ``-md`` flag OpenSSL 1.1+ uses SHA-256, but the classic
    ``openssl enc`` (and the pre-1.1.0 default) uses MD5; the default here is
    MD5 for CTF compatibility.

    ``D_1 = HASH(password + salt)``,
    ``D_i = HASH(D_{i-1} + password + salt)`` for i = 2..count.
    The concatenated ``D_i`` fills ``key`` (first ``key_len`` bytes) and then
    ``iv`` (next ``iv_len`` bytes). ``None`` (or empty) salt is treated as no
    salt. Supports ``md5/sha1/sha256/...`` digest names.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    dgst_lc = (dgst or "md5").lower()
    mod = _DIGEST_MODS.get(dgst_lc)
    if mod is None:
        # Also accept bare "sha" aliases and tolerate hashlib constructor name.
        mod = getattr(hashlib, dgst_lc, None)
        if mod is None and not dgst_lc.startswith("sha"):
            raise ValueError(f"不支持的摘要算法: {dgst}")
    if mod is None:
        raise ValueError(f"不支持的摘要算法: {dgst}")

    material = b"" if not salt else salt
    d = b""
    total = key_len + iv_len
    data = b""
    while len(data) < total:
        block = d + password + material
        d = mod(block).digest()
        data += d
    return data[:key_len], data[key_len:key_len + iv_len]


def openssl_derive(password, salt: bytes | None = None, key_len: int = 32,
                   iv_len: int = 16, dgst: str = "md5") -> tuple[bytes, bytes]:
    """Convenience wrapper around :func:`evp_bytes_to_key` for AES-256 + CBC."""
    return evp_bytes_to_key(password, salt, key_len, iv_len, dgst)
