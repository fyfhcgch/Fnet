"""Pure helpers for WPA/WPA2/WPA3 handshake forensics.

The handler used to rely on aircrack-ng for everything.  This module adds the
pieces needed to *describe* a capture without running external tools:

* rebuild a complete EAPOL-Key frame from the fields tshark exposes, so a
  hashcat ``22000`` line can be produced even when ``hcxtools`` is missing;
* pair M1/M2/M3/M4 messages per ``(BSSID, station)`` and report which
  handshakes are actually crackable;
* de-duplicate PMKIDs across access points and stations;
* recognise SAE (WPA3) authentication and explain the available paths.

Everything here is a pure function; the feature handler owns tshark and I/O.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

EAPOL_TYPE_KEY = 3
BROADCAST = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""}

#: RSN AKM suite types (``wlan.rsn.akms.type``).
AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SUITE-B-192",
    12: "802.1X-SUITE-B-192-SHA384",
    18: "OWE",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}
SAE_AKMS = {8, 9, 24, 25}

#: EAPOL-Key key information bits.
KEY_INFO_INSTALL = 0x0040
KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200
KEY_INFO_ERROR = 0x0400
KEY_INFO_REQUEST = 0x0800
KEY_INFO_ENCRYPTED = 0x1000
KEY_INFO_SMK = 0x2000
KEY_DESCRIPTOR_VERSION = 0x0007

PMKID_KDE = bytes.fromhex("dd14000fac04")


def normalize_mac(value: str) -> str:
    """Return a lower-case 12 hex digit MAC, or ``""`` when invalid."""
    text = re.sub(r"(?i)[^0-9a-f]", "", value or "")
    return text.lower() if len(text) == 12 else ""


def mac_colon(value: str) -> str:
    """Normalise a MAC for display (``aa:bb:cc:dd:ee:ff``)."""
    text = normalize_mac(value)
    return ":".join(text[i:i + 2] for i in range(0, 12, 2)) if text else ""


def normalize_pmkid(value: str) -> str:
    text = re.sub(r"(?i)[^0-9a-f]", "", value or "")
    return text.lower() if len(text) == 32 else ""


def _hex_bytes(value: str) -> bytes:
    text = re.sub(r"(?i)[^0-9a-f]", "", value or "")
    if len(text) % 2:
        text = text[:-1]
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _int(value: str, default: int = 0) -> int:
    text = str(value or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return default


def ssid_hex(ssid: str) -> str:
    return (ssid or "").encode("utf-8", "replace").hex()


def ssid_text(value: str) -> str:
    """Decode the hex form tshark uses for the ``wlan.ssid`` byte field."""
    text = str(value or "")
    if len(text) >= 2 and len(text) % 2 == 0 and re.fullmatch(
            r"(?i)[0-9a-f]+", text):
        try:
            decoded = bytes.fromhex(text).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return text
        if decoded and all(ch.isprintable() for ch in decoded):
            return decoded
    return text


def pmkid_hash(pmkid: str, bssid: str, station: str, ssid: str) -> str:
    """Build a hashcat 22000 PMKID line (SSID is hex encoded)."""
    pmk = normalize_pmkid(pmkid)
    ap = normalize_mac(bssid)
    sta = normalize_mac(station)
    if not pmk or not ap or not sta:
        return ""
    return f"WPA*01*{pmk}*{ap}*{sta}*{ssid_hex(ssid)}***"


def parse_pmkid_kde(value: str) -> list[str]:
    """Extract PMKIDs from a key-data / RSN IE hex blob.

    Accepts the EAPOL vendor KDE (``dd 14 00 0f ac 04`` + 16 bytes), the bare
    16 byte PMKID and comma separated lists of either form.
    """
    found: list[str] = []
    for part in re.split(r"[\s,;]+", value or ""):
        raw = _hex_bytes(part)
        if not raw:
            continue
        if len(raw) == 16:
            found.append(raw.hex())
            continue
        index = 0
        while index + 6 <= len(raw):
            if raw[index:index + 6] == PMKID_KDE:
                chunk = raw[index + 6:index + 22]
                if len(chunk) == 16:
                    found.append(chunk.hex())
                index += 22
            else:
                index += 1
    return list(dict.fromkeys(found))


@dataclass
class EapolMessage:
    """One EAPOL-Key frame as reported by tshark (or rebuilt for tests)."""

    frame: str = ""
    time: float = 0.0
    bssid: str = ""
    station: str = ""
    ssid: str = ""
    message: int = 0
    key_info: int = 0
    key_length: int = 0
    replay: int = 0
    nonce: bytes = b""
    iv: bytes = b""
    rsc: bytes = b""
    key_id: bytes = b""
    mic: bytes = b""
    key_data: bytes = b""
    pmkids: list[str] = field(default_factory=list)
    version: int = 2

    @property
    def ack(self) -> bool:
        return bool(self.key_info & KEY_INFO_ACK)

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & KEY_INFO_MIC)

    @property
    def secure(self) -> bool:
        return bool(self.key_info & KEY_INFO_SECURE)

    @property
    def encrypted(self) -> bool:
        return bool(self.key_info & KEY_INFO_ENCRYPTED)

    @property
    def descriptor_version(self) -> int:
        return self.key_info & KEY_DESCRIPTOR_VERSION

    def eapol_frame(self, *, zero_mic: bool = False) -> bytes:
        """Rebuild the complete 802.1X EAPOL-Key frame."""
        mic = b"\x00" * len(self.mic) if zero_mic else self.mic
        key_data = self.key_data or b""
        body = (
            struct.pack(">H", self.key_info & 0xFFFF)
            + struct.pack(">H", self.key_length & 0xFFFF)
            + (self.replay & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
            + (self.nonce or b"\x00" * 32)[:32].ljust(32, b"\x00")
            + (self.iv or b"\x00" * 16)[:16].ljust(16, b"\x00")
            + (self.rsc or b"\x00" * 8)[:8].ljust(8, b"\x00")
            + (self.key_id or b"\x00" * 8)[:8].ljust(8, b"\x00")
            + (mic or b"\x00" * 16)[:16].ljust(16, b"\x00")
            + struct.pack(">H", len(key_data))
            + key_data
        )
        descriptor = bytes([2]) + body
        return (bytes([self.version or 2, EAPOL_TYPE_KEY])
                + struct.pack(">H", len(descriptor)) + descriptor)


def message_number(key_info: int, *, has_mic: bool) -> int:
    """Derive the 4-way handshake message number from the key info bits."""
    ack = bool(key_info & KEY_INFO_ACK)
    mic = bool(key_info & KEY_INFO_MIC)
    secure = bool(key_info & KEY_INFO_SECURE)
    install = bool(key_info & KEY_INFO_INSTALL)
    if ack and not mic:
        return 1
    if ack and mic and not secure:
        return 3
    if ack and mic and (secure or install):
        return 3
    if not ack and mic:
        return 2 if not secure else 4
    return 0


def eapol_from_values(values: dict, fallback_message: int = 0) -> EapolMessage | None:
    """Build an :class:`EapolMessage` from a ``{tshark_field: value}`` row."""
    bssid = normalize_mac(values.get("wlan.bssid", ""))
    ta = normalize_mac(values.get("wlan.ta", ""))
    ra = normalize_mac(values.get("wlan.ra", ""))
    sa = normalize_mac(values.get("wlan.sa", ""))
    da = normalize_mac(values.get("wlan.da", ""))
    key_info = _int(values.get("wlan_rsna_eapol.keydes.key_info", ""))
    key_data = _hex_bytes(values.get("wlan_rsna_eapol.keydes.data", ""))
    nonce = _hex_bytes(values.get("wlan_rsna_eapol.keydes.nonce", ""))
    mic = _hex_bytes(values.get("wlan_rsna_eapol.keydes.mic", ""))
    if not (key_info or nonce or mic or key_data):
        return None
    message = _int(values.get("wlan_rsna_eapol.keydes.msgnr", ""), 0)
    derived = message_number(key_info, has_mic=bool(mic))
    if derived:
        message = derived
    elif not message:
        message = fallback_message
    # The transmitter/receiver pair identifies the AP even when wlan.bssid is
    # unavailable (some radiotap captures).
    if not bssid:
        candidates = [addr for addr in (ta, ra, sa, da)
                      if addr and addr not in BROADCAST]
        bssid = candidates[0] if candidates else ""
    station = ""
    for addr in (ta, ra, sa, da):
        if addr and addr not in BROADCAST and addr != bssid:
            station = addr
            break
    if message in (1, 3) and ta:
        bssid, station = ta, station or ra
    elif message in (2, 4) and ta:
        station, bssid = ta, bssid or ra
    pmkids = parse_pmkid_kde(values.get("wlan_rsna_eapol.keydes.data", ""))
    for field_name in ("wlan.rsn.ie.pmkid", "wlan.rsn.pmkid.list"):
        pmkids += parse_pmkid_kde(values.get(field_name, ""))
    return EapolMessage(
        frame=str(values.get("frame.number") or ""),
        time=_float(values.get("frame.time_relative", "")),
        bssid=bssid,
        station=station,
        ssid=str(values.get("wlan.ssid") or ""),
        message=message,
        key_info=key_info,
        key_length=_int(values.get("eapol.keydes.key_len", "")),
        replay=_int(values.get("wlan_rsna_eapol.keydes.replay_counter", "")),
        nonce=nonce,
        iv=_hex_bytes(values.get("eapol.keydes.key_iv", "")),
        rsc=_hex_bytes(values.get("wlan_rsna_eapol.keydes.rsc", "")),
        key_id=_hex_bytes(values.get("wlan_rsna_eapol.keydes.id", "")),
        mic=mic,
        key_data=key_data,
        pmkids=list(dict.fromkeys(pmkids)),
        version=_int(values.get("eapol.version", ""), 2) or 2,
    )


def _float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def handshake_key(bssid: str, station: str) -> tuple[str, str]:
    return normalize_mac(bssid), normalize_mac(station)


def handshake_state(message_numbers) -> str:
    """Describe an EAPOL message-number set in human readable form."""
    numbers = sorted({int(n) for n in message_numbers
                      if str(n).isdigit() and int(n) > 0})
    if not numbers:
        return "无 EAPOL 消息"
    missing = [n for n in (1, 2, 3, 4) if n not in numbers]
    if not missing:
        return "完整握手 (M1-M4)"
    if 1 in numbers and 2 in numbers:
        return "握手可用 (M1/M2)"
    if 2 in numbers and 3 in numbers:
        return "握手可用 (M2/M3)"
    return "握手不完整，缺少 " + "/".join(f"M{n}" for n in missing)


def usable_pair(messages: list[EapolMessage]) -> tuple[EapolMessage, EapolMessage] | None:
    """Return the (AP nonce message, client MIC message) pair to crack with."""
    by_number: dict[int, EapolMessage] = {}
    for message in messages:
        if message.message and message.message not in by_number:
            by_number[message.message] = message
    anonce_msg = by_number.get(1) or by_number.get(3)
    snonce_msg = by_number.get(2)
    if not anonce_msg or not snonce_msg:
        return None
    if not anonce_msg.nonce or not snonce_msg.nonce or not snonce_msg.mic:
        return None
    return anonce_msg, snonce_msg


def eapol_hash(messages: list[EapolMessage], ssid: str = "") -> str:
    """Build a hashcat 22000 EAPOL line for a complete/usable handshake."""
    pair = usable_pair(messages)
    if pair is None:
        return ""
    ap_msg, sta_msg = pair
    essid = ssid or ap_msg.ssid or sta_msg.ssid
    ap = normalize_mac(ap_msg.bssid or sta_msg.bssid)
    sta = normalize_mac(sta_msg.station or ap_msg.station)
    if not ap or not sta:
        return ""
    message_pair = "00" if (ap_msg.message == 1 and sta_msg.message == 2) else "02"
    return (f"WPA*02*{sta_msg.mic.hex()}*{ap}*{sta}*{ssid_hex(essid)}*"
            f"{ap_msg.nonce.hex()}*{sta_msg.nonce.hex()}*"
            f"{sta_msg.eapol_frame(zero_mic=True).hex()}*{message_pair}")


def pmkid_entries(messages: list[EapolMessage]) -> list[tuple[str, str, str, str]]:
    """Return de-duplicated ``(pmkid, bssid, station, ssid)`` tuples."""
    seen: dict[tuple[str, str, str], tuple[str, str, str, str]] = {}
    for message in messages:
        for pmkid in message.pmkids:
            ap = message.bssid
            sta = message.station
            if not ap or not sta:
                continue
            key = (pmkid, ap, sta)
            if key not in seen:
                seen[key] = (pmkid, ap, sta, message.ssid)
    return list(seen.values())


def handshake_groups(messages: list[EapolMessage]) -> dict[tuple[str, str], list[EapolMessage]]:
    groups: dict[tuple[str, str], list[EapolMessage]] = {}
    for message in messages:
        if not message.message:
            continue
        key = handshake_key(message.bssid, message.station)
        if not key[0] or not key[1]:
            continue
        groups.setdefault(key, []).append(message)
    return groups


def sae_akms(value: str) -> list[int]:
    """Return SAE AKM suite numbers present in a tshark AKM list."""
    found: list[int] = []
    for part in re.split(r"[\s,;]+", value or ""):
        token = part.strip()
        if not token:
            continue
        number = _int(token, -1)
        if number > 0xFF and token.lower().startswith("0x"):
            number &= 0xFF
        if number < 0:
            # Suite lists are rendered as ``00-0f-ac-8`` or ``00:0f:ac:08``.
            tail = re.split(r"[-:.]", token)[-1]
            number = int(tail, 16) if re.fullmatch(
                r"(?i)[0-9a-f]{1,2}", tail) else -1
            if number < 0:
                number = _int(tail, -1)
        if number in SAE_AKMS:
            found.append(number)
    return sorted(set(found))


def akm_name(number: int) -> str:
    return AKM_NAMES.get(number, f"AKM-{number}")


def sae_path(akms: list[int]) -> str:
    if not akms:
        return ""
    names = ", ".join(akm_name(number) for number in akms)
    return (f"检测到 WPA3/SAE 认证（{names}）：SAE 使用 Dragonfly 握手，"
            "没有可离线字典破解的 PMKID/四次握手；可尝试捕获 SAE 提交/确认帧做"
            "被动分析，或检查是否同时启用了 WPA2-PSK 过渡模式并抓取其握手。")


def hcxtools_recipe(pcap: str, hash_file: str = "wifi.hc22000",
                    legacy_file: str = "wifi.hc16800") -> list[str]:
    """Commands for whichever hcxtools binary is installed."""
    from fnet.tools.runner import find_tool
    from shlex import quote

    source = quote(str(pcap))
    lines: list[str] = []
    modern = find_tool("hcxpcapngtool")
    legacy = find_tool("hcxpcaptool")
    if modern:
        lines += [
            f"# hcxpcapngtool: 同时导出 22000/16800/EAPOL",
            f"hcxpcapngtool -o {hash_file} -k {legacy_file} "
            f"-z {hash_file}.pmkid {source}",
        ]
    elif legacy:
        lines += [
            f"# hcxpcaptool（旧版）: 22000 与 16800",
            f"hcxpcaptool -o {hash_file} -k {legacy_file} "
            f"-z {hash_file}.pmkid {source}",
        ]
    else:
        lines += [
            "# 未找到 hcxpcapngtool/hcxpcaptool；安装 hcxtools 后执行：",
            f"hcxpcapngtool -o {hash_file} -k {legacy_file} {source}",
        ]
    lines += [
        "# 字典破解（PMKID 与 EAPOL 共用 -m 22000）",
        f"hashcat -m 22000 -a 0 {hash_file} wordlist.txt",
        "# 查看结果",
        f"hashcat -m 22000 --show {hash_file}",
    ]
    return lines


# ---------------------------------------------------------------------------
# WPA2 key derivation (IEEE 802.11i) and CCMP / AES-CCM decryption
#
# The helpers below turn a passphrase plus a captured 4-way handshake into the
# temporal key, and rebuild the plaintext of CCMP-protected data frames.  They
# are deliberately pure functions so the feature handler keeps owning tshark
# and all I/O.  Only the standard library and ``fnet.utils.crypto`` are used.
# ---------------------------------------------------------------------------
import hashlib
import hmac

from fnet.utils.crypto import aes_encrypt_block

PRF_LABEL = b"Pairwise key expansion"
CCMP_HEADER_LEN = 8
CCMP_MIC_LEN = 8
LLC_SNAP_PREFIX = b"\xaa\xaa\x03"


def _pn_bytes(pn: bytes | int) -> bytes:
    """Return a 48-bit packet number as ``PN5 .. PN0`` (big endian)."""
    if isinstance(pn, int):
        if not 0 <= pn < 1 << 48:
            raise ValueError("PN must fit in 48 bits")
        return pn.to_bytes(6, "big")
    raw = bytes(pn or b"")
    if len(raw) == 6:
        return raw
    if len(raw) in (1, 2, 3, 4, 5):
        return raw.rjust(6, b"\x00")
    raise ValueError("PN must be 6 bytes or an int")


def derive_pmk(psk: str, ssid: str) -> bytes:
    """Derive the WPA2 PMK from a passphrase and SSID (PBKDF2-HMAC-SHA1).

    ``PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32)`` as defined by
    IEEE 802.11i / RFC 2898.  The SSID is used verbatim (no length prefix).
    """
    return hashlib.pbkdf2_hmac(
        "sha1", (psk or "").encode("utf-8"), (ssid or "").encode("utf-8"),
        4096, 32)


def _prf_sha1(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    """IEEE 802.11i PRF (HMAC-SHA1): ``label || 0x00 || data || counter``."""
    output = bytearray()
    counter = 0
    while len(output) < length:
        counter += 1
        output += hmac.new(
            key, label + b"\x00" + data + bytes([counter]), hashlib.sha1
        ).digest()
    return bytes(output[:length])


def derive_ptk(pmk: bytes, anonce: bytes, snonce: bytes,
               ap: str, sta: str) -> dict:
    """Derive the CCMP PTK (PRF-512 truncated to 48 bytes).

    ``data = min(AP,STA) || max(AP,STA) || min(ANonce,SNonce) ||
    max(ANonce,SNonce)``; the shorter MAC/nonce pair comes first as required by
    IEEE 802.11i.  Returns ``{"kck", "kek", "tk", "ptk"}`` byte strings.
    """
    pmk = bytes(pmk or b"")
    if len(pmk) != 32:
        raise ValueError("PMK must be 32 bytes")
    ap_bytes = bytes.fromhex(normalize_mac(ap))
    sta_bytes = bytes.fromhex(normalize_mac(sta))
    if len(ap_bytes) != 6 or len(sta_bytes) != 6:
        raise ValueError("AP and station must be MAC addresses")
    anonce = bytes(anonce or b"")
    snonce = bytes(snonce or b"")
    if len(anonce) != 32 or len(snonce) != 32:
        raise ValueError("ANonce and SNonce must be 32 bytes")
    mac_lo, mac_hi = sorted((ap_bytes, sta_bytes))
    nonce_lo, nonce_hi = sorted((anonce, snonce))
    data = mac_lo + mac_hi + nonce_lo + nonce_hi
    ptk = _prf_sha1(pmk, PRF_LABEL, data, 48)
    return {
        "kck": ptk[0:16],
        "kek": ptk[16:32],
        "tk": ptk[32:48],
        "ptk": ptk,
    }


# ---------------------------------------------------------------------------
# AES-CCM (RFC 3610)
# ---------------------------------------------------------------------------
def _ccm_check(key: bytes, nonce: bytes, tag_len: int) -> int:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    if not 7 <= len(nonce) <= 13:
        raise ValueError("CCM nonce must be 7..13 bytes")
    if tag_len not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError("CCM tag length must be 4..16 and even")
    return 15 - len(nonce)


def _ccm_b0(nonce: bytes, aad_len: int, msg_len: int, tag_len: int) -> bytes:
    """Build the first CBC-MAC block ``B0``."""
    length_field = 15 - len(nonce)
    flags = (((tag_len - 2) // 2) << 3) | (length_field - 1)
    if aad_len:
        flags |= 0x40
    return bytes([flags]) + nonce + msg_len.to_bytes(length_field, "big")


def _ccm_xor_block(state: bytes, block: bytes) -> bytes:
    padded = block.ljust(16, b"\x00")
    return bytes(a ^ b for a, b in zip(state, padded))


def _ccm_cbc_mac(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes,
                 tag_len: int) -> bytes:
    """Raw CCM CBC-MAC value ``T`` (before the ``S_0`` mask)."""
    aad = bytes(aad or b"")
    plaintext = bytes(plaintext or b"")
    state = aes_encrypt_block(_ccm_b0(nonce, len(aad), len(plaintext), tag_len), key)
    if aad:
        size = len(aad)
        if size < 0xFF00:
            prefix = size.to_bytes(2, "big")
        elif size < 1 << 32:
            prefix = b"\xff\xfe" + size.to_bytes(4, "big")
        else:
            prefix = b"\xff\xff" + size.to_bytes(8, "big")
        encoded = prefix + aad
        for offset in range(0, len(encoded), 16):
            state = aes_encrypt_block(
                _ccm_xor_block(state, encoded[offset:offset + 16]), key)
    for offset in range(0, len(plaintext), 16):
        state = aes_encrypt_block(
            _ccm_xor_block(state, plaintext[offset:offset + 16]), key)
    return state[:tag_len]


def ccm_mac(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes,
            tag_len: int = 8) -> bytes:
    """Compute the CCM authentication tag ``U`` over ``aad || plaintext``.

    This is the value appended to the ciphertext (RFC 3610 ``U = T xor
    S_0``), not the bare CBC-MAC intermediate.
    """
    length_field = _ccm_check(key, nonce, tag_len)
    raw = _ccm_cbc_mac(key, nonce, aad, plaintext, tag_len)
    s0 = aes_encrypt_block(
        bytes([length_field - 1]) + nonce + b"\x00" * length_field, key)
    return bytes(a ^ b for a, b in zip(raw, s0[:tag_len]))


def _ccm_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """CCM counter-mode keystream (counter starts at 1)."""
    length_field = 15 - len(nonce)
    prefix = bytes([length_field - 1]) + nonce
    output = bytearray()
    for block_index, offset in enumerate(range(0, len(data), 16), start=1):
        stream = aes_encrypt_block(
            prefix + block_index.to_bytes(length_field, "big"), key)
        chunk = data[offset:offset + 16]
        output += bytes(a ^ b for a, b in zip(chunk, stream))
    return bytes(output)


def ccm_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes,
                tag_len: int = 8) -> bytes:
    """AES-CCM encrypt; returns ``ciphertext || tag``."""
    plaintext = bytes(plaintext or b"")
    aad = bytes(aad or b"")
    _ccm_check(key, nonce, tag_len)
    ciphertext = _ccm_ctr_crypt(key, nonce, plaintext)
    return ciphertext + ccm_mac(key, nonce, aad, plaintext, tag_len)


def ccm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                ciphertext_with_tag: bytes,
                tag_len: int = 8) -> tuple[bytes, bool]:
    """AES-CCM decrypt; returns ``(plaintext, tag_valid)``.

    The MIC is always recomputed, so a tampered payload returns the decrypted
    bytes *and* ``False`` instead of raising.
    """
    data = bytes(ciphertext_with_tag or b"")
    _ccm_check(key, nonce, tag_len)
    if len(data) < tag_len:
        return b"", False
    ciphertext, tag = data[:-tag_len], data[-tag_len:]
    plaintext = _ccm_ctr_crypt(key, nonce, ciphertext)
    expected = ccm_mac(key, nonce, bytes(aad or b""), plaintext, tag_len)
    return plaintext, hmac.compare_digest(expected, tag)


# ---------------------------------------------------------------------------
# 802.11 / CCMP frame helpers
# ---------------------------------------------------------------------------
def parse_dot11_header(frame: bytes) -> dict | None:
    """Parse the fixed 802.11 MAC header.

    Returns ``None`` when the frame is too short.  ``qos`` is true for QoS data
    frames (2 extra bytes), ``has_addr4`` for WDS data frames (ToDS and FromDS
    both set, 6 extra bytes); the HT-control field is included when the Order
    bit is set on a QoS data frame.
    """
    data = bytes(frame or b"")
    if len(data) < 2:
        return None
    fc = data[0] | (data[1] << 8)
    version = fc & 0x0003
    frame_type = (fc >> 2) & 0x03
    subtype = (fc >> 4) & 0x0F
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    retry = bool(fc & 0x0800)
    protected = bool(fc & 0x4000)
    order = bool(fc & 0x8000)
    has_addr4 = bool(to_ds and from_ds and frame_type == 2)
    qos = bool(frame_type == 2 and subtype & 0x08)
    header_len = 24 + (6 if has_addr4 else 0) + (2 if qos else 0)
    if order and qos:
        header_len += 4
    if len(data) < header_len:
        return None
    a1 = mac_colon(data[4:10].hex())
    a2 = mac_colon(data[10:16].hex())
    a3 = mac_colon(data[16:22].hex())
    a4 = mac_colon(data[24:30].hex()) if has_addr4 else ""
    sequence = data[22] | (data[23] << 8)
    qos_value = (data[24 + (6 if has_addr4 else 0)]
                 | (data[25 + (6 if has_addr4 else 0)] << 8)) if qos else 0
    # The CCMP nonce priority octet carries the QoS traffic identifier.
    priority = qos_value & 0x0F if qos else 0
    return {
        "header_len": header_len,
        "fc": fc,
        "version": version,
        "type": frame_type,
        "subtype": subtype,
        "protected": protected,
        "to_ds": to_ds,
        "from_ds": from_ds,
        "retry": retry,
        "order": order,
        "a1": a1,
        "a2": a2,
        "a3": a3,
        "a4": a4,
        "has_addr4": has_addr4,
        "qos": qos,
        "qos_value": qos_value,
        "priority": priority,
        "sequence": sequence,
    }


def ccmp_nonce(a2: bytes, pn: bytes, priority: int = 0) -> bytes:
    """Build the 13-byte CCMP nonce: priority || A2 || PN5..PN0."""
    address = bytes(a2 or b"")
    if len(address) != 6:
        raise ValueError("A2 must be 6 bytes")
    return bytes([priority & 0xFF]) + address + _pn_bytes(pn)


def _ccmp_header(pn: bytes | int, key_id: int = 0) -> bytes:
    """Build the 8-byte CCMP header (PN0, PN1, Rsvd, KeyID/ExtIV, PN2..PN5)."""
    packet_number = _pn_bytes(pn)
    key_id_byte = 0x20 | ((key_id & 0x03) << 6)
    return bytes([
        packet_number[5], packet_number[4], 0x00, key_id_byte,
        packet_number[3], packet_number[2], packet_number[1],
        packet_number[0],
    ])


def ccmp_aad(header: bytes, header_len: int, pn: bytes,
             key_id: int = 0) -> bytes:
    """Build the CCMP AAD: MPDU header + CCMP header.

    The Frame Control protected bit is set and the retry bit cleared, matching
    what the transmitter feeds into AES-CCM.  CCMP keeps the MIC outside the
    MPDU header, so no MIC field needs zeroing here.
    """
    raw = bytearray(bytes(header or b"")[:header_len])
    if len(raw) < 2:
        raise ValueError("header is too short")
    fc = (raw[0] | (raw[1] << 8) | 0x4000) & ~0x0800
    raw[0] = fc & 0xFF
    raw[1] = (fc >> 8) & 0xFF
    return bytes(raw) + _ccmp_header(pn, key_id)


def ccmp_decrypt_frame(tk: bytes, frame: bytes) -> dict | None:
    """Decrypt one CCMP-protected data frame (8-byte MIC).

    Returns ``{"plaintext", "pn", "pn_bytes", "key_id", "a1", "a2", "a3",
    "tag_valid", "header_len", "priority"}`` or ``None`` when the frame is not
    a CCMP data frame / is truncated.
    """
    data = bytes(frame or b"")
    info = parse_dot11_header(data)
    if info is None or not info["protected"] or info["type"] != 2:
        return None
    header_len = info["header_len"]
    if len(data) < header_len + CCMP_HEADER_LEN + CCMP_MIC_LEN:
        return None
    ccmp_header = data[header_len:header_len + CCMP_HEADER_LEN]
    key_id = (ccmp_header[3] >> 6) & 0x03
    packet_number = bytes([
        ccmp_header[7], ccmp_header[6], ccmp_header[5], ccmp_header[4],
        ccmp_header[1], ccmp_header[0],
    ])
    address2 = data[10:16]
    nonce = ccmp_nonce(address2, packet_number, info["priority"])
    aad = ccmp_aad(data[:header_len], header_len, packet_number, key_id)
    plaintext, valid = ccm_decrypt(
        bytes(tk or b""), nonce, aad, data[header_len + CCMP_HEADER_LEN:],
        CCMP_MIC_LEN)
    return {
        "plaintext": plaintext,
        "pn": int.from_bytes(packet_number, "big"),
        "pn_bytes": packet_number.hex(),
        "key_id": key_id,
        "a1": info["a1"],
        "a2": info["a2"],
        "a3": info["a3"],
        "tag_valid": valid,
        "header_len": header_len,
        "priority": info["priority"],
    }


def ccmp_encrypt_frame(tk: bytes, frame_with_plaintext: bytes,
                       pn: bytes | int, key_id: int = 0) -> bytes:
    """Encrypt a plaintext data frame with CCMP (used for tests/fixtures).

    ``frame_with_plaintext`` carries a normal 802.11 header followed by the
    LLC/SNAP payload.  The protected bit is set, the CCMP header inserted and
    the 8-byte MIC appended.
    """
    data = bytes(frame_with_plaintext or b"")
    info = parse_dot11_header(data)
    if info is None or info["type"] != 2:
        raise ValueError("frame must be 802.11 data with a full MAC header")
    header_len = info["header_len"]
    header = bytearray(data[:header_len])
    fc = (header[0] | (header[1] << 8)) | 0x4000
    header[0] = fc & 0xFF
    header[1] = (fc >> 8) & 0xFF
    packet_number = _pn_bytes(pn)
    nonce = ccmp_nonce(bytes(header[10:16]), packet_number, info["priority"])
    aad = ccmp_aad(bytes(header), header_len, packet_number, key_id)
    ciphertext = ccm_encrypt(
        bytes(tk or b""), nonce, aad, data[header_len:], CCMP_MIC_LEN)
    return bytes(header) + _ccmp_header(packet_number, key_id) + ciphertext


def to_ethernet(plaintext: bytes, a1: str, a2: str) -> bytes | None:
    """Convert an LLC/SNAP payload to a 14-byte Ethernet frame.

    Any SNAP OUI is accepted (RFC 1042 ``00:00:00`` and bridge-tunnel
    ``00:00:f8`` included); the EtherType is copied verbatim.  ``a1`` becomes
    the destination and ``a2`` the source address.
    """
    data = bytes(plaintext or b"")
    if len(data) < 8 or data[0:3] != LLC_SNAP_PREFIX:
        return None
    dst = bytes.fromhex(normalize_mac(a1))
    src = bytes.fromhex(normalize_mac(a2))
    if len(dst) != 6 or len(src) != 6:
        return None
    return dst + src + data[6:8] + data[8:]


def _strip_radiotap(frame: bytes) -> bytes:
    """Drop a leading radiotap header when the raw frame contains one."""
    if len(frame) >= 8 and frame[0] == 0 and frame[1] == 0:
        length = frame[2] | (frame[3] << 8)
        if 8 <= length <= len(frame) - 2:
            return frame[length:]
    return frame


def decrypt_frames(tk: bytes, rows) -> list[dict]:
    """Decrypt CCMP frames from ``[frame_number, frame_raw_hex, time]`` rows.

    Frames that are not protected CCMP data frames (or are truncated) are
    skipped.  ``tag_valid`` mirrors the MIC check so a tampered frame is still
    reported with its (untrusted) plaintext.
    """
    results: list[dict] = []
    for row in rows or []:
        try:
            number, raw_hex, timestamp = row[0], row[1], row[2]
        except (TypeError, IndexError, KeyError):
            continue
        frame = _strip_radiotap(_hex_bytes(str(raw_hex or "")))
        if not frame:
            continue
        info = parse_dot11_header(frame)
        if info is None or not info["protected"] or info["type"] != 2:
            continue
        decrypted = ccmp_decrypt_frame(bytes(tk or b""), frame)
        if decrypted is None:
            continue
        results.append({
            "frame": str(number),
            "time": _float(str(timestamp or "")),
            "plaintext": decrypted["plaintext"],
            "ethernet": to_ethernet(
                decrypted["plaintext"], decrypted["a1"], decrypted["a2"]),
            "a1": decrypted["a1"],
            "a2": decrypted["a2"],
            "a3": decrypted["a3"],
            "pn": decrypted["pn"],
            "key_id": decrypted["key_id"],
            "tag_valid": decrypted["tag_valid"],
            "header_len": decrypted["header_len"],
        })
    return results
