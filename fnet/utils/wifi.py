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
