"""WPA/WPA2 handshake / PMKID detection and offline cracking helpers.

A dictionary run can spend hours inside ``aircrack-ng``, so the handler
always reports the captured material first and writes ready-to-run hashcat
recipes:

* ``wifi_pmkid.hc22000`` — de-duplicated PMKID lines (``WPA*01*``);
* ``wifi_handshake.hc22000`` — reconstructed M1/M2 EAPOL lines (``WPA*02*``);
* ``wifi_summary.txt`` — per-AP/STA handshake completeness and WPA3 notes.

Actual cracking only happens when the user asks for it with
``wifi_crack=1`` (aircrack-ng) or ``wifi_run=1`` (hcxtools + hashcat).
"""
from __future__ import annotations

import re
from pathlib import Path
from shlex import quote

from fnet.features.common import table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.paths import WORDLIST_DIR, wordlist
from fnet.tools.runner import find_tool, run
from fnet.utils import wifi as wifilib

# Re-exported helpers: the WebUI/tests import them from this module.
normalize_mac = wifilib.normalize_mac
normalize_pmkid = wifilib.normalize_pmkid
pmkid_hash = wifilib.pmkid_hash
handshake_state = wifilib.handshake_state
sae_akms = wifilib.sae_akms

FIELDS = [
    "frame.number", "frame.time_relative", "wlan.bssid", "wlan.ssid",
    "wlan.ta", "wlan.ra", "wlan.sa", "wlan.da",
    "eapol.version", "eapol.type", "eapol.keydes.key_len",
    "eapol.keydes.key_iv",
    "wlan_rsna_eapol.keydes.msgnr", "wlan_rsna_eapol.keydes.key_info",
    "wlan_rsna_eapol.keydes.replay_counter",
    "wlan_rsna_eapol.keydes.nonce", "wlan_rsna_eapol.keydes.rsc",
    "wlan_rsna_eapol.keydes.id", "wlan_rsna_eapol.keydes.mic",
    "wlan_rsna_eapol.keydes.data",
    "wlan.rsn.ie.pmkid", "wlan.rsn.pmkid.list", "wlan.rsn.akms.list",
    "wlan.rsn.akms", "wlan.rsn.akms.type",
    "wlan.fixed.auth.alg", "wlan.fc.type_subtype",
]
FILTER = ("eapol || wlan.fc.type_subtype == 0x08 || "
          "wlan.fc.type_subtype == 0x0b")
BROADCAST = wifilib.BROADCAST


def hashcat_recipe(pcap: str, wordlist_path: str,
                   hash_file: str = "wifi.hc22000") -> list[str]:
    """Commands that turn the capture into a hashcat 22000 run."""
    source = quote(str(pcap))
    word = quote(str(wordlist_path or "wordlist.txt"))
    return [
        "# 1) 从抓包提取 22000 哈希（hcxtools）",
        f"hcxpcapngtool -o {hash_file} {source}",
        "# 2) 字典破解（PMKID 与 EAPOL 共用 -m 22000）",
        f"hashcat -m 22000 -a 0 {hash_file} {word}",
        "# 3) 查看结果",
        "hashcat -m 22000 --show " + hash_file,
    ]


def _station_mac(row: list[str], bssid: str) -> str:
    """Pick the client MAC from the four address columns."""
    for value in row[8:12]:
        mac = normalize_mac(value)
        if mac and mac not in BROADCAST and mac != normalize_mac(bssid):
            return mac
    return ""


def _row_values(row: list[str]) -> dict[str, str]:
    row = list(row) + [""] * (len(FIELDS) - len(row))
    values = dict(zip(FIELDS, row))
    values["wlan.ssid"] = wifilib.ssid_text(values.get("wlan.ssid", ""))
    return values


def _ssid_for_bssid(values: dict[str, str], messages, ssid_by_bssid) -> str:
    ssid = values.get("wlan.ssid") or ""
    bssid = normalize_mac(values.get("wlan.bssid", ""))
    if ssid and bssid:
        ssid_by_bssid.setdefault(bssid, ssid)
    return ssid


def _psk_bytes(value: str) -> bytes | None:
    """Return the raw PMK for a 64-hex PSK, else ``None`` for a passphrase."""
    text = str(value or "").strip()
    if re.fullmatch(r"(?i)[0-9a-f]{64}", text):
        return bytes.fromhex(text)
    return None


def _decrypted_feedback(ctx: FeatureContext, path: Path) -> None:
    """Run HTTP/DNS extraction over the decrypted pcap."""
    if ctx.tshark is None:
        return
    fields = ["frame.number", "http.request.method", "http.host",
              "http.request.uri", "http.response.code",
              "http.authorization", "dns.qry.name"]
    rows = ctx.tshark.fields(str(path), fields, "http or dns")
    rows = rows[:5_000]
    http_rows = [row for row in rows if len(row) > 1 and row[1]]
    dns_rows = [row for row in rows if len(row) > 6 and row[6]]
    if http_rows:
        ctx.report(f"解密后 HTTP 请求 {len(http_rows)} 条", "good")
    seen_hosts: set[str] = set()
    for row in http_rows[:200]:
        row += [""] * (len(fields) - len(row))
        frame, method, host, uri, code, auth, _dns = row[:7]
        ctx.report(f"[解密:{frame}] {method} {host}{uri} -> {code}", "info")
        if host and host not in seen_hosts:
            seen_hosts.add(host)
            ctx.add_finding("http", f"解密后访问 {host}", frame=frame,
                            detail=f"{method} {uri}", level="info",
                            extra={"host": host, "decrypted": True})
        if auth:
            ctx.report(f"[解密:{frame}] Authorization: {auth}", "good")
            ctx.add_finding("credential", "解密后 HTTP 认证头", frame=frame,
                            detail=auth, level="good",
                            extra={"protocol": "http", "secret": auth,
                                   "host": host, "decrypted": True})
    if dns_rows:
        names = list(dict.fromkeys(row[6] for row in dns_rows if row[6]))
        ctx.report("解密后 DNS 域名: " + ", ".join(names[:30]), "info")
        for name in names[:50]:
            ctx.add_finding("dns", name, detail="WPA 解密后 DNS 查询",
                            level="info", extra={"decrypted": True})


def _psk_decrypt(ctx: FeatureContext, groups, ssid_by_bssid) -> None:
    """Derive the CCMP key from a known PSK and decrypt data frames."""
    psk = str(ctx.params.get("wifi_psk") or "").strip()
    if not psk:
        return
    tshark = ctx.tshark.path if ctx.tshark is not None else ""
    if not tshark:
        ctx.report("需要 tshark 才能解密 WPA 数据帧", "warn")
        return
    fixed_pmk = _psk_bytes(psk)
    outdir = Path(ctx.output_dir or ".")
    decrypted_files: list[Path] = []
    total = 0
    valid = 0
    for (bssid, station), group in groups.items():
        ctx.check_cancel()
        pair = wifilib.usable_pair(group)
        if pair is None:
            continue
        m1, m2 = pair
        ssid = ssid_by_bssid.get(bssid, "")
        if not ssid:
            ctx.report(f"{wifilib.mac_colon(bssid)}: 缺少 SSID，无法派生 PMK",
                       "warn")
            continue
        pmk = fixed_pmk or wifilib.derive_pmk(psk, ssid)
        try:
            ptk = wifilib.derive_ptk(pmk, m1.nonce, m2.nonce, bssid, station)
        except ValueError as exc:
            ctx.report(f"PTK 派生失败: {exc}", "warn")
            continue
        label = f"{wifilib.mac_colon(bssid)}_{wifilib.mac_colon(station)}"
        label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
        temp = outdir / f"wifi_ccmp_{label}.pcap"
        if station:
            display = (f"wlan.fc.type == 2 && wlan.fc.protected == 1 && "
                       f"(wlan.bssid == {wifilib.mac_colon(bssid)} && "
                       f"(wlan.ta == {wifilib.mac_colon(station)} || "
                       f"wlan.ra == {wifilib.mac_colon(station)} || "
                       f"wlan.sa == {wifilib.mac_colon(station)} || "
                       f"wlan.da == {wifilib.mac_colon(station)}))")
        else:
            display = "wlan.fc.type == 2 && wlan.fc.protected == 1"
        code, out = run([tshark, "-r", ctx.pcap, "-Y", display,
                         "-F", "pcap", "-w", str(temp)], echo=False,
                        cancel=ctx.cancel)
        if code != 0 or not temp.is_file():
            ctx.report(f"提取加密数据帧失败: {out[-300:]}", "warn")
            continue
        try:
            packets, linktype = wifilib.read_pcap(temp)
        except (OSError, ValueError) as exc:
            ctx.report(f"读取临时 pcap 失败: {exc}", "warn")
            continue
        finally:
            temp.unlink(missing_ok=True)
        if linktype not in (105, 127):
            ctx.report(f"暂不支持链路类型 {linktype} 的 802.11 解密", "warn")
            continue
        rows = [[str(index), raw.hex(), str(ts)]
                for index, (ts, raw) in enumerate(packets, 1)]
        frames = wifilib.decrypt_frames(ptk["tk"], rows)
        ethernet = [(item["time"], item["ethernet"]) for item in frames
                    if item["ethernet"]]
        total += len(frames)
        good = sum(1 for item in frames if item["tag_valid"])
        valid += good
        if not ethernet:
            ctx.report(f"{label}: 未解出可用的以太网帧", "warn")
            continue
        target = outdir / f"wifi_decrypted_{label}.pcap"
        wifilib.write_pcap(target, ethernet, wifilib.LINKTYPE_ETHERNET)
        decrypted_files.append(target)
        ctx.report(f"{label}: 解密 {len(ethernet)} 帧（MIC 校验通过 {good}），"
                   f"已写入 {target.name}", "good")
        ctx.add_finding("protocol", f"WPA 解密 {label}", level="good",
                        detail=f"解密 {len(ethernet)} 帧，MIC 通过 {good}",
                        extra={"bssid": bssid, "station": station,
                               "frames": len(ethernet), "mic_ok": good})
    if not decrypted_files:
        if groups:
            ctx.report("没有可解密的完整 M1/M2 握手（需要 PSK 与 SSID）", "warn")
        return
    ctx.report(f"WPA 解密完成: {total} 帧，MIC 通过 {valid} 帧，"
               f"输出 {len(decrypted_files)} 个 pcap", "good")
    for path in decrypted_files[:10]:
        _decrypted_feedback(ctx, path)


def crack(ctx: FeatureContext) -> None:
    rows = tshark_rows(ctx, FIELDS, FILTER, limit=20_000)
    if not rows:
        ctx.report("没有发现 WPA/WPA2 握手或 beacon 帧", "warn")
        return

    table(ctx, "无线握手/Beacon", FIELDS[:5], rows, limit=80)

    bssids: dict[str, None] = {}
    ssids: dict[str, None] = {}
    ssid_by_bssid: dict[str, str] = {}
    messages = []
    sae_frames = 0
    sae_suites: set[int] = set()
    beacons = 0

    for index, row in enumerate(rows):
        if index % 200 == 0:
            ctx.check_cancel()
        values = _row_values(row)
        ssid = _ssid_for_bssid(values, messages, ssid_by_bssid)
        bssid = normalize_mac(values.get("wlan.bssid", ""))
        if bssid:
            bssids.setdefault(bssid, None)
        if ssid:
            ssids.setdefault(ssid, None)
        if values.get("wlan.fc.type_subtype", "").lower() in ("8", "0x0008",
                                                              "0x08"):
            beacons += 1
            akm_value = (values.get("wlan.rsn.akms.type")
                         or values.get("wlan.rsn.akms.list", ""))
            if not akm_value:
                akm_value = values.get("wlan.rsn.akms", "")
            sae_suites.update(sae_akms(akm_value))
        auth_alg = values.get("wlan.fixed.auth.alg", "")
        if auth_alg:
            try:
                number = int(auth_alg)
            except ValueError:
                number = -1
            if number in (3, 768) or (number & 0xFF00) == 0x0300:
                sae_frames += 1
        message = wifilib.eapol_from_values(values)
        if message is None:
            continue
        if not message.ssid:
            message.ssid = ssid_by_bssid.get(message.bssid, "")
        # Later beacons fill in an SSID we only learned from a message.
        if message.bssid and message.ssid:
            ssid_by_bssid.setdefault(message.bssid, message.ssid)
        messages.append(message)

    for bssid, ssid in ssid_by_bssid.items():
        messages_ssid = ssid or ""
        for message in messages:
            if message.bssid == bssid and not message.ssid:
                message.ssid = messages_ssid

    ctx.report(f"SSID: {', '.join(ssids) or '(隐藏)'}", "info")
    ctx.report(f"BSSID: {', '.join(wifilib.mac_colon(b) for b in bssids)}",
               "info")
    if beacons:
        ctx.report(f"Beacon/Beacon-like 帧 {beacons} 条", "info")
    eapol_count = len(messages)
    if eapol_count:
        ctx.report(f"EAPOL-Key 报文 {eapol_count} 条", "good")

    groups = wifilib.handshake_groups(messages)
    crackable = 0
    summary_lines = ["BSSID\tSTA\t消息\t状态\t可用哈希"]
    for (bssid, station), group in groups.items():
        numbers = {message.message for message in group}
        state = handshake_state(numbers)
        pair = wifilib.usable_pair(group)
        hash_line = wifilib.eapol_hash(
            group, ssid_by_bssid.get(bssid, ""))
        level = "good" if hash_line else (
            "good" if state.startswith(("完整", "握手可用")) else "warn")
        if hash_line:
            crackable += 1
        label = f"{wifilib.mac_colon(bssid)} / {wifilib.mac_colon(station)}"
        ctx.report(f"  {label}: {state}"
                   + ("，已生成 22000 哈希" if hash_line else ""), level)
        summary_lines.append("\t".join([
            wifilib.mac_colon(bssid), wifilib.mac_colon(station),
            ",".join(f"M{n}" for n in sorted(numbers)), state,
            "是" if hash_line else "否",
        ]))
        ctx.add_finding(
            "protocol", f"WPA 握手 {label}: {state}", level=level,
            detail="EAPOL 消息 " + ",".join(str(n) for n in sorted(numbers))
                   + (f"\n22000: {hash_line}" if hash_line else ""),
            extra={"bssid": bssid, "station": station})

    pmkids = wifilib.pmkid_entries(messages)
    pmkid_lines: list[str] = []
    for pmkid, bssid, station, ssid in pmkids:
        line = pmkid_hash(pmkid, bssid, station, ssid)
        if not line:
            ctx.report(f"PMKID {pmkid} 缺少 AP/STA MAC，无法生成 22000 哈希",
                       "warn")
            continue
        pmkid_lines.append(line)
        ctx.report(f"  PMKID {pmkid}  SSID {ssid or '(隐藏)'}  "
                   f"AP {wifilib.mac_colon(bssid)}", "good")
        ctx.add_finding("hash", f"WPA PMKID {bssid or '-'} {ssid or ''}".strip(),
                        detail=line, level="good",
                        extra={"protocol": "wifi", "hash": line,
                               "mode": "22000"})
    if pmkids:
        ctx.report(f"检测到 {len(pmkid_lines)} 个可用 PMKID（已去重）", "good")
        ctx.write_output("wifi_pmkid.hc22000", "\n".join(pmkid_lines) + "\n")

    eapol_lines: list[str] = []
    seen_eapol: set[str] = set()
    for group in groups.values():
        line = wifilib.eapol_hash(group, ssid_by_bssid.get(
            wifilib.handshake_key(group[0].bssid, group[0].station)[0], ""))
        if line and line not in seen_eapol:
            seen_eapol.add(line)
            eapol_lines.append(line)
    if eapol_lines:
        ctx.write_output("wifi_handshake.hc22000",
                         "\n".join(eapol_lines) + "\n")
        ctx.report(f"已从 {len(eapol_lines)} 组 M1/M2 握手重建 22000 EAPOL 哈希",
                   "good")

    _psk_decrypt(ctx, groups, ssid_by_bssid)

    if sae_frames or sae_suites:
        detail = wifilib.sae_path(sorted(sae_suites)) or (
            "检测到 SAE 认证帧，但没有解析到 AKM 套件")
        if sae_frames:
            detail = f"SAE Authentication 帧 {sae_frames} 条。{detail}"
        ctx.report(detail, "warn")
        ctx.add_finding("protocol", "WPA3/SAE 认证", level="warn",
                        detail=detail,
                        extra={"akm": ",".join(map(str, sorted(sae_suites)))})

    summary_lines.append("")
    summary_lines.append(f"PMKID 数量: {len(pmkid_lines)}")
    summary_lines.append(f"可破解 EAPOL 握手: {crackable}")
    if sae_suites:
        summary_lines.append("AKM: " + ", ".join(
            wifilib.akm_name(number) for number in sorted(sae_suites)))
    ctx.write_output("wifi_summary.txt", "\n".join(summary_lines) + "\n")

    if not eapol_count and not pmkids:
        ctx.report("只有 Beacon/认证帧，未捕获到 EAPOL 握手或 PMKID，"
                   "无法离线破解", "warn")
        ctx.set_progress(100)
        return

    # Resolve the wordlist for the generated recipe, but never block the
    # report when it is missing: the user may pick one later.
    default_list = WORDLIST_DIR / "wifi_top2000.txt"
    configured = (ctx.params.get("wordlist")
                  or (str(default_list) if default_list.is_file()
                      else ctx.config.get("passwddir")))
    word = wordlist(str(configured)) if configured else None
    if word is None or not word.is_file():
        ctx.report("找不到密码字典；hashcat 命令中的字典请自行替换", "warn")
        word_text = str(configured or "wordlist.txt")
    else:
        ctx.report(f"字典: {word}", "info")
        word_text = str(word)

    outdir = Path(ctx.output_dir or ".")
    recipe = wifilib.hcxtools_recipe(ctx.pcap)
    recipe += ["", "# 本工具直接生成的哈希"]
    if pmkid_lines:
        recipe.append("cat wifi_pmkid.hc22000 >> wifi.hc22000")
    if eapol_lines:
        recipe.append("cat wifi_handshake.hc22000 >> wifi.hc22000")
    recipe.append(f"hashcat -m 22000 -a 0 wifi.hc22000 {quote(word_text)}")
    ctx.write_output("wifi_hashcat.txt", "\n".join(recipe) + "\n")

    hc22000 = outdir / "wifi.hc22000"
    combined = pmkid_lines + eapol_lines
    if combined:
        hc22000.write_text("\n".join(combined) + "\n", encoding="utf-8")
        ctx.report(f"已生成合并 22000 哈希: {hc22000}", "good")

    hcx = find_tool("hcxpcapngtool") or find_tool("hcxpcaptool", "")
    if hcx and (eapol_count or not pmkids):
        tool = Path(hcx).name
        args = ([hcx, "-o", str(hc22000), ctx.pcap]
                if tool.startswith("hcxpcapngtool")
                else [hcx, "-o", str(hc22000), "-k",
                      str(outdir / "wifi.hc16800"), ctx.pcap])
        code, out = run(args, cancel=ctx.cancel, echo=False)
        if code == 0 and hc22000.is_file() and hc22000.stat().st_size:
            ctx.report(f"已用 {tool} 提取 22000 哈希: {hc22000}", "good")
            for line in hc22000.read_text(encoding="utf-8",
                                          errors="replace").splitlines():
                if line.startswith("WPA*"):
                    ctx.add_finding("hash", "WPA 22000 哈希", detail=line,
                                    level="good",
                                    extra={"protocol": "wifi", "hash": line,
                                           "mode": "22000"})
        else:
            ctx.report(f"{tool} 未生成哈希，可手动执行 wifi_hashcat.txt 中的命令",
                       "warn")

    want_aircrack = str(ctx.params.get("wifi_crack") or "0").lower() in (
        "1", "true", "yes", "on")
    aircrack = find_tool("aircrack-ng", ctx.config.get("aircrack", "paths"))
    if want_aircrack and aircrack and word and word.is_file() and eapol_lines:
        target = next((b for b, _s in groups), "")
        args = [aircrack, "-w", str(word)]
        if target:
            args += ["-b", wifilib.mac_colon(target)]
        args.append(ctx.pcap)
        ctx.report("调用 aircrack-ng 进行字典破解（大字典可能耗时较长）", "info")
        code, out = run(args, timeout=7200, cancel=ctx.cancel)
        ctx.report(out[-4000:] if out else f"aircrack-ng 退出码 {code}",
                   "good" if "KEY FOUND" in out else "info")
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", out)
        if match:
            password = match.group(1)
            ctx.report(f"WPA 密码: {password}", "good")
            ctx.write_output("wifi_password.txt", password + "\n")
            ctx.add_finding("credential", f"WPA 密码 {password}",
                            detail=f"BSSID {target}", level="good",
                            extra={"protocol": "wifi", "secret": password,
                                   "host": target})
        else:
            ctx.report("字典中没有匹配的密码（或握手不完整）", "warn")
        ctx.set_progress(100)
        return

    want_hashcat = str(ctx.params.get("wifi_run") or "0").lower() in (
        "1", "true", "yes", "on")
    hashcat = find_tool("hashcat", ctx.config.get("hashcat", "paths"))
    if want_hashcat and hashcat and hc22000.is_file() and word and word.is_file():
        out_file = outdir / "wifi_cracked.txt"
        code, out = run([hashcat, "-m", "22000", "-a", "0", str(hc22000),
                         str(word), "--potfile-disable", "-o", str(out_file)],
                        timeout=7200, cancel=ctx.cancel)
        if out_file.is_file() and out_file.stat().st_size:
            ctx.report("破解结果: " + out_file.read_text(
                encoding="utf-8", errors="replace"), "good")
            return
        ctx.report("hashcat 未能破解，输出: " + out[-1500:], "warn")
        return

    if not want_aircrack:
        ctx.report("已生成 wifi_hashcat.txt / wifi_pmkid.hc22000 / "
                   "wifi_handshake.hc22000；如需在本机直接破解，设置 "
                   "wifi_crack=1（aircrack-ng）或 wifi_run=1（hashcat）", "info")
    ctx.set_progress(100)
