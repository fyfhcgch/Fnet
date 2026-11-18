"""Sliver / meterpreter extended C2 analysis (the CS-handler counterpart).

Covers the C2 roadmap entry alongside :mod:`fnet.features.cs` (Cobalt
Strike) and :mod:`fnet.features.meterpreter` (plain TLV sessions):

* **Sliver HTTP(S) beacon** — procedural URIs classified by file extension
  (``.html/.jsp`` key exchange, ``.php`` session, ``.js`` poll, ``.png``
  close, ``.woff`` stager, ``.txt`` RSA key exchange) and the ``_=`` nonce
  argument; bodies are decoded through every known traffic encoder before
  session decryption.  Sliver v1.6 uses ChaCha20-Poly1305 (optionally with a
  signature prefix and gzip compression), v1.5/legacy fall back to AES-GCM;
  the symmetric key comes from ``sliver_session_key`` (hex);
* **Sliver DNS beacon** — query names are decoded with the modified
  Base32/Base58 alphabets, the ``dnspb.DNSMessage`` protobuf is reported and
  its ``Data`` field decrypted when a session key is available;
* **Sliver mTLS beacon** — server certificates are scored for the implant
  CA traits (ECDSA signature, clientAuth-only EKU, CN-only subject, 2-3 year
  validity);
* **meterpreter staging / encrypted transport** — the initial ``GET`` staging
  URI (checksum 92/93 or the classic ``INITM`` marker), the ``metsrv`` stage
  blob saved as an artifact, ``RECV`` poll bodies, and the XOR-obfuscated
  packet layer (32-byte modern / 12-byte legacy header) with AES-CBC
  decryption when ``meterpreter_symkey`` is configured (16 bytes = AES-128,
  32 bytes = AES-256).

Output conventions follow :mod:`fnet.features.cs`: Chinese log lines,
``ctx.write_output`` artifacts and findings recorded through
``ctx.add_finding`` so the WebUI table and reports stay consistent.
"""
from __future__ import annotations

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import c2ext, meterpreter_wire, sliver_c2
from fnet.utils.codec import find_flags
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio

HTTP_FIELDS = ["frame.number", "tcp.stream", "http.request.method",
               "http.request.uri", "http.host", "http.file_data",
               "http.response_in"]
RESP_FIELDS = ["frame.number", "tcp.stream", "http.response.code",
               "http.file_data", "http.content_type"]
DNS_FIELDS = ["frame.number", "dns.qry.name", "dns.qry.type"]
TLS_FIELDS = ["frame.number", "tcp.stream",
              "tls.handshake.certificates",
              "tls.handshake.extensions_server_name"]
TCP_FIELDS = ["frame.number", "tcp.stream", "tcp.payload"]

#: URIs scoring at least this value are recorded as suspected Sliver beacons.
SLIVER_URI_SCORE_MIN = 3
MAX_BLOBS = 200


def _hex_key(ctx: FeatureContext, name: str, sizes: tuple[int, ...],
             hint: str = "") -> bytes | None:
    """Parse a hex key parameter accepting any of ``sizes`` byte lengths."""
    value = str(ctx.params.get(name) or "").strip()
    if not value:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        ctx.report(f"{name} 参数不是有效的十六进制字符串", "error")
        return None
    if len(raw) not in sizes:
        ctx.report(f"{name} 需要 {' 或 '.join(str(size) for size in sizes)} 字节"
                   f"（{'/'.join(str(size * 2) for size in sizes)} 个十六进制字符），"
                   f"当前 {len(raw)} 字节；仍会解析流量，但无法解密该会话{hint}",
                   "error")
        return None
    return raw


def _load_keys(ctx: FeatureContext) -> dict:
    sliver = _hex_key(ctx, "sliver_session_key", (32, 16),
                      "（32 字节=v1.5/v1.6，16 字节=旧版 AES-GCM）")
    meterpreter = _hex_key(ctx, "meterpreter_symkey", (32, 16),
                           "（16 字节=AES-128，32 字节=AES-256）")
    if meterpreter is not None:
        ctx.report(f"meterpreter_symkey 为 {len(meterpreter)} 字节，使用 "
                   f"{'AES-256' if len(meterpreter) == 32 else 'AES-128'}-CBC",
                   "info")
    if sliver is not None and len(sliver) == 16:
        ctx.report("sliver_session_key 为 16 字节，按旧版 AES-GCM 处理"
                   "（32 字节为 v1.5/v1.6 密钥）", "info")
    return {"sliver": sliver, "meterpreter": meterpreter}


def _report_flag_lines(ctx: FeatureContext, frame: str, text: str) -> None:
    for flag in find_flags(text):
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=frame, detail="来自 C2 会话解密",
                        level="good")


def _cipher_name(value: object) -> str:
    """Normalise the core's cipher identifiers for Chinese reports."""
    text = str(value or "").lower()
    return {"chacha20-poly1305": "ChaCha20-Poly1305",
            "aes-gcm": "AES-GCM"}.get(text, str(value) or "未知")


def _envelope_text(envelope: dict | None) -> str:
    """Short Chinese suffix describing a parsed Sliver envelope."""
    if not envelope:
        return ""
    env_id = envelope.get("id")
    env_type = envelope.get("type")
    if env_id is not None or env_type is not None:
        return (f"，Envelope ID={env_id if env_id is not None else '-'} "
                f"Type={env_type if env_type is not None else '-'}")
    if envelope.get("unknown"):
        return "，Envelope 格式未识别"
    return ""


def _sliver_artifact_name(frame: str, stats: dict) -> str:
    base = f"c2_sliver_session_{frame}"
    used = stats.setdefault("_sliver_names", set())
    name = base + ".bin"
    index = 2
    while name in used:
        name = f"{base}_{index}.bin"
        index += 1
    used.add(name)
    return name


def _report_sliver_plaintext(ctx: FeatureContext, frame: str, source: str,
                             plain: bytes, info: dict, stats: dict) -> None:
    """Log/artifact/finding for one successfully decrypted Sliver payload."""
    stats["decrypted"] += 1
    cipher = _cipher_name(info.get("cipher"))
    signature = ("已跳过签名前缀" if info.get("signature_skipped")
                 else "无签名前缀")
    compressed = "gzip 已解压" if info.get("compressed") else "未压缩"
    envelope = sliver_c2.parse_envelope(plain)
    summary = sliver_c2.sliver_summary(plain)
    text = str(summary.get("text") or payload_text(plain))
    flags = summary.get("flags") or []

    ctx.report(f"===== 帧 {frame} Sliver 会话载荷解密成功 ({source}) =====",
               "good")
    ctx.report(f"  加密 {cipher}，{signature}，{compressed}"
               f"{_envelope_text(envelope)}", "good")
    for line in text.splitlines()[:80]:
        if line.strip():
            ctx.report("  " + clean_cell(line, 260), "info")

    name = _sliver_artifact_name(frame, stats)
    ctx.write_output(name, plain)
    detail = (f"恢复 {len(plain)} 字节明文，加密 {cipher}，{signature}，"
              f"{compressed}{_envelope_text(envelope)}")
    if flags:
        detail += "，flag 候选 " + ",".join(str(flag) for flag in flags[:10])
    ctx.add_finding("protocol", f"Sliver 会话载荷解密 {source}", frame=frame,
                    level="good", detail=detail,
                    extra={"protocol": "sliver", "cipher": cipher,
                           "source": source,
                           "compressed": bool(info.get("compressed")),
                           "signature_skipped": bool(info.get("signature_skipped"))})
    _report_flag_lines(ctx, frame, text)


def _sliver_key_exchange(ctx: FeatureContext, frame: str, uri: str,
                         blob: bytes, stats: dict) -> bool:
    """Report a Sliver key-exchange blob; never treat it as decrypted flags."""
    info = sliver_c2.classify_key_exchange(blob, uri)
    if not info:
        return False
    version = str(info.get("version") or "-")
    kind = str(info.get("kind") or "-")
    summary = f"Sliver 密钥交换 ({version}, {kind})"
    parts = [f"URI {clean_cell(uri, 200)}", f"版本 {version}", f"类型 {kind}"]
    for key, value in info.items():
        if key in ("version", "kind"):
            continue
        if isinstance(value, (list, tuple, set)):
            if value:
                parts.append(f"{key}={','.join(str(item) for item in value)}")
        elif isinstance(value, dict):
            continue
        elif value not in (None, ""):
            parts.append(f"{key}={value}")
    ctx.report(f"帧 {frame} {summary} "
               f"载荷 {len(blob)} 字节 "
               f"URI {clean_cell(uri, 120)}", "good")
    ctx.add_finding("protocol", summary, frame=frame, level="warn",
                    detail="，".join(parts),
                    extra={"protocol": "sliver", "key_exchange": True,
                           "version": version, "kind": kind})
    stats["key_exchange"] += 1
    return True


def _sliver_bodies(ctx: FeatureContext, frame: str, uri: str,
                   candidates: list[tuple[bytes, str]], key: bytes | None,
                   stats: dict) -> None:
    """Try key-exchange classification and session decryption on candidates."""
    seen: set[bytes] = set()
    for blob, encoder in candidates:
        ctx.check_cancel()
        if not blob or blob in seen:
            continue
        seen.add(blob)
        if _sliver_key_exchange(ctx, frame, uri, blob, stats):
            continue
        if key is None:
            continue
        info = sliver_c2.decrypt_session(blob, key)
        if not info or not info.get("plaintext"):
            continue
        source = uri or f"HTTP 编码器 {encoder or 'raw'}"
        _report_sliver_plaintext(ctx, frame, source, info["plaintext"],
                                 info, stats)


# ---------------------------------------------------------------------------
# Sliver HTTP(S)
# ---------------------------------------------------------------------------
def _analyze_sliver_http(ctx: FeatureContext, reqs: list[list[str]],
                         resps: dict[str, dict], keys: dict,
                         stats: dict) -> None:
    key = keys["sliver"]
    for raw in reqs:
        ctx.check_cancel()
        row = raw + [""] * (len(HTTP_FIELDS) - len(raw))
        item = dict(zip(HTTP_FIELDS, row))
        uri = item.get("http.request.uri", "") or ""
        classified = c2ext.classify_sliver_uri(uri)
        if classified is None or classified["score"] < SLIVER_URI_SCORE_MIN:
            continue
        stats["http_hits"] += 1
        frame = item["frame.number"]
        summary = (f"Sliver HTTP beacon {classified['ext']} "
                   f"({classified['message']})")
        body = hex_to_bytes(item.get("http.file_data", ""))
        candidates = sliver_c2.decode_body_candidates(body, uri) if body else []
        encoders = sorted({name for _, name in candidates if name})

        ctx.report(f"帧 {frame} {summary} "
                   f"nonce={'有' if classified['nonce'] else '无'} "
                   f"路径词命中 {','.join(classified['word_hits']) or '-'} "
                   f"载荷编码 {','.join(encoders) or '-'}", "good")
        ctx.add_finding("protocol", summary, frame=frame, level="warn",
                        detail=f"URI {clean_cell(uri, 200)} "
                               f"nonce={classified['nonce']} "
                               f"编码器={','.join(encoders) or '-'}",
                        extra={"protocol": "sliver", "ext": classified["ext"],
                               "nonce": classified["nonce"],
                               "encoders": encoders})
        _sliver_bodies(ctx, frame, uri, candidates, key, stats)

        response_frame = item.get("http.response_in", "")
        resp = resps.get(response_frame)
        if resp:
            resp_body = hex_to_bytes(resp.get("http.file_data", ""))
            resp_candidates = (sliver_c2.decode_body_candidates(resp_body, uri)
                               if resp_body else [])
            _sliver_bodies(ctx, resp["frame.number"], uri, resp_candidates,
                           key, stats)


# ---------------------------------------------------------------------------
# meterpreter staging + encrypted HTTP transport
# ---------------------------------------------------------------------------
def _analyze_meterpreter_http(ctx: FeatureContext, reqs: list[list[str]],
                              resps: dict[str, dict], keys: dict,
                              stats: dict) -> None:
    key = keys["meterpreter"]
    reported: set[tuple] = set()
    for raw in reqs:
        ctx.check_cancel()
        row = raw + [""] * (len(HTTP_FIELDS) - len(raw))
        item = dict(zip(HTTP_FIELDS, row))
        uri = item.get("http.request.uri", "") or ""
        body = hex_to_bytes(item.get("http.file_data", ""))
        stage_info = meterpreter_wire.meterpreter_stage_uri(uri)
        response_frame = item.get("http.response_in", "")
        resp = resps.get(response_frame)
        blob = hex_to_bytes(resp.get("http.file_data", "")) if resp else b""
        # Only treat a response body as a metsrv stage when the request URI is
        # an actual staging URI; arbitrary binary responses must not be flagged.
        stage = (meterpreter_wire.parse_stage_blob(blob)
                 if stage_info and blob else None)

        if stage_info:
            ctx.report(f"帧 {item['frame.number']} meterpreter 分阶段 "
                       f"staging 请求 ({stage_info['reason']}, "
                       f"{stage_info['arch']}) URI {clean_cell(uri, 120)}",
                       "good")
            # A bare staging URI is low value; only record it when a stage
            # body (or a wire packet below) was actually recovered.
            if stage:
                ctx.add_finding(
                    "protocol", f"meterpreter staging 请求 {stage_info['arch']}",
                    frame=item["frame.number"], level="warn",
                    detail=f"URI {clean_cell(uri, 200)} "
                           f"({stage_info['reason']})",
                    extra={"protocol": "meterpreter"})
            stats["stage_seen"] = True

        if stage:
            stage_bytes = stage.get("stage") or b""
            size = stage.get("size") or len(stage_bytes)
            is_pe = bool(stage.get("is_pe") or stage_bytes[:2] == b"MZ")
            name = f"c2_meterpreter_stage_{resp['frame.number']}.bin"
            ctx.write_output(name, stage_bytes)
            ctx.report(
                f"帧 {resp['frame.number']} stage 已还原 "
                f"{size} 字节"
                f"{'（MZ PE，metsrv）' if is_pe else ''} "
                f"长度前缀={'是' if stage.get('length_prefixed') else '否'}",
                "good")
            ctx.add_finding(
                "file", f"meterpreter stage {size} 字节",
                frame=resp["frame.number"], level="warn",
                detail=name,
                extra={"protocol": "meterpreter", "pe": is_pe})
            strings = stage.get("strings") or meterpreter_wire.flag_strings(
                stage_bytes)
            for text in strings[:20]:
                ctx.report(f"  stage 字符串: {clean_cell(text, 160)}", "debug")
            _report_flag_lines(ctx, resp["frame.number"],
                               "\n".join(str(strings_value)
                                         for strings_value in strings[:200]))
            stats["stage_seen"] = True

        if body.strip().upper() == b"RECV":
            ctx.report(f"帧 {item['frame.number']} meterpreter HTTP 轮询 "
                       f"(RECV body)", "info")
            # RECV alone is just keep-alive noise: keep the log, no finding.

        # XOR-obfuscated / AES encrypted packet in the request body.
        _meterpreter_wire_body(ctx, item["frame.number"], body, key, stats,
                               reported)
        # ... and in the matching response body.
        if resp:
            resp_body = hex_to_bytes(resp.get("http.file_data", ""))
            _meterpreter_wire_body(ctx, resp["frame.number"], resp_body,
                                   key, stats, reported)


def _meterpreter_explain(packet, info: dict | None = None) -> str:
    """Human readable ``explain_packet`` projection for logs and findings."""
    if info is None:
        try:
            info = meterpreter_wire.explain_packet(packet)
        except Exception:  # noqa: BLE001 - explanation must never break a job
            return ""
    if not isinstance(info, dict):
        return str(info) if info else ""
    for key in ("detail", "summary", "text", "description"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return clean_cell(value, 240)
    return "，".join(f"{key}={clean_cell(str(value), 80)}"
                    for key, value in info.items()
                    if value not in (None, "", [], {}))


def _meterpreter_tlv_names(packet, info: dict | None = None) -> str:
    names = (info or {}).get("tlvs")
    if names is None:
        names = packet.tlv_summary
    if isinstance(names, (list, tuple, set)):
        return ",".join(str(name) for name in names) or "-"
    if isinstance(names, dict):
        return ",".join(str(name) for name in names) or "-"
    return str(names) if names else "-"


def _report_meterpreter_packet(ctx: FeatureContext, frame: str, packet,
                               key: bytes | None, stats: dict,
                               reported: set[tuple], *, stream: str | None = None,
                               wire: bytes = b"") -> bool:
    """Log and record one strictly parsed meterpreter wire packet."""
    # Dedupe across the encoder candidates (raw / base64 / url): the same
    # packet can surface twice with different offsets.  Keep frame locality so
    # genuine repeats in other frames are still reported.
    identity = (frame, packet.version, packet.total, packet.command_hex,
                getattr(packet, "guid_hex", "") or "-",
                tuple(str(tlv.get("name", "")) for tlv in packet.tlvs[:8]))
    if identity in reported:
        return False
    # The old loose parser turned arbitrary bytes into a "legacy" packet with
    # no TLVs and a '-' command.  Such a packet carries no actionable data.
    if not packet.encrypted and not packet.tlvs and packet.command_hex in (
            "-", ""):
        return False
    reported.add(identity)
    stats["wire_packets"] += 1

    info = {}
    try:
        info = meterpreter_wire.explain_packet(packet) or {}
    except Exception:  # noqa: BLE001
        info = {}
    if not isinstance(info, dict):
        info = {}
    kind = packet.kind or "unknown"
    command = packet.command_hex
    if not command or command == "-":
        command = info.get("command_hex") if info.get("command_hex") not in (
            None, "-") else f"0x{int(packet.packet_type):08x}"
    summary = f"meterpreter {kind} {command}"
    version = packet.version or "-"
    guid_raw = getattr(packet, "guid_hex", "") or ""
    guid = "无" if guid_raw in ("", "-") else guid_raw
    encryption = packet.encryption_name or "无"
    tlv_names = _meterpreter_tlv_names(packet, info)
    explain = _meterpreter_explain(packet, info)

    if not packet.encrypted:
        decrypt = "未加密（XOR 混淆）"
    elif packet.decrypt_ok:
        decrypt = "AES 解密校验通过"
    elif key is None:
        decrypt = "缺少 meterpreter_symkey"
    else:
        decrypt = (f"AES 解密校验失败："
                   f"{packet.decrypt_reason or '密钥或填充不匹配'}")

    detail = (f"版本 {version}，GUID {guid}，加密 {encryption}，"
              f"TLV {tlv_names}，{decrypt}")
    if explain:
        detail += f"，解析 {explain}"
    extra = {"protocol": "meterpreter", "guid": guid,
             "encrypted": bool(packet.encrypted),
             "decrypt_ok": bool(packet.decrypt_ok),
             "command": command}
    if stream is not None:
        detail = f"流 {stream}, " + detail
        extra["stream"] = str(stream)

    ctx.report(f"帧 {frame} {summary}（{version} 头，{encryption}，"
               f"GUID {guid}，{decrypt}）", "good")
    ctx.add_finding("protocol", summary, frame=frame, level="warn",
                    detail=detail, extra=extra)

    for tlv in packet.tlvs[:16]:
        ctx.report(f"  TLV {tlv.get('name', '-')} = "
                   f"{clean_cell(str(tlv.get('value', '')), 160)}", "debug")
    if packet.encrypted and not packet.decrypt_ok:
        stats["encrypted_candidates"] += 1
        ciphertext = packet.ciphertext or wire
        if ciphertext:
            suffix = f"_{stream}" if stream is not None else f"_{frame}"
            ctx.write_output(
                f"c2_meterpreter_enc{suffix}_{stats['encrypted_candidates']}.bin",
                ciphertext)
    if packet.plaintext and printable_ratio(packet.plaintext) > 0.7:
        _report_flag_lines(ctx, frame, payload_text(packet.plaintext))
    return True


def _meterpreter_wire_body(ctx: FeatureContext, frame: str, blob: bytes,
                           key: bytes | None, stats: dict,
                           reported: set[tuple]) -> None:
    if not blob:
        return
    seen: set[bytes] = set()
    for wire, encoder in meterpreter_wire.wire_body_candidates(blob):
        ctx.check_cancel()
        if not wire or wire in seen:
            continue
        seen.add(wire)
        for packet in meterpreter_wire.iter_packets(wire, key=key):
            _report_meterpreter_packet(ctx, frame, packet, key, stats,
                                       reported, wire=wire)


# ---------------------------------------------------------------------------
# Sliver DNS
# ---------------------------------------------------------------------------
def _analyze_sliver_dns(ctx: FeatureContext, rows: list[list[str]],
                        keys: dict, stats: dict) -> None:
    key = keys["sliver"]
    parents = tuple(
        value.strip() for value in
        str(ctx.params.get("sliver_dns_domain") or "").split(",") if value.strip())
    for raw in rows:
        ctx.check_cancel()
        row = raw + [""] * (len(DNS_FIELDS) - len(raw))
        item = dict(zip(DNS_FIELDS, row))
        qname = item.get("dns.qry.name", "").strip()
        decoded = c2ext.decode_sliver_dns_subdomain(qname, parents)
        if decoded is None:
            continue
        message = decoded["message"]
        stats["dns_hits"] += 1
        frame = item["frame.number"]
        type_name = c2ext.DNS_MESSAGE_TYPES.get(message["type"], "未知")
        ctx.report(
            f"帧 {frame} Sliver DNS beacon "
            f"({decoded['encoding']}) 类型 {type_name} "
            f"ID {message['id']} 数据 {len(message['data'])} 字节 "
            f"子域 {decoded['subdata'][:64]}", "good")

        data = message["data"]
        info = None
        plain = None
        if data:
            ctx.write_output(f"c2_sliver_dns_{frame}.bin", data)
            if key:
                info = sliver_c2.decrypt_session(data, key)
                if info and info.get("plaintext"):
                    plain = info["plaintext"]

        detail = (f"编码 {decoded['encoding']}, 消息类型 {type_name}, "
                  f"会话/ID {message['id']}, Size {message['size']}")
        if info and plain:
            cipher = _cipher_name(info.get("cipher"))
            envelope = sliver_c2.parse_envelope(plain)
            detail += f"，解密 {cipher}{_envelope_text(envelope)}"
        ctx.add_finding("dns", f"Sliver DNS C2 消息 ({type_name})",
                        frame=frame, level="warn", detail=detail,
                        extra={"protocol": "sliver", "qname": qname[:254],
                               "encoding": decoded["encoding"]})

        if plain:
            cipher = _cipher_name(info.get("cipher"))
            envelope = sliver_c2.parse_envelope(plain)
            text = payload_text(plain)
            ctx.report(f"  Data 解密成功 {len(plain)} 字节（{cipher}）"
                       f"{_envelope_text(envelope)}", "good")
            for line in text.splitlines()[:40]:
                if line.strip():
                    ctx.report("  " + clean_cell(line, 220), "info")
            _report_flag_lines(ctx, frame, text)
        elif data:
            ctx.report("  Data 需要会话密钥（sliver_session_key）才能解密",
                       "debug")


# ---------------------------------------------------------------------------
# Sliver mTLS certificate heuristic
# ---------------------------------------------------------------------------
def _analyze_sliver_mtls(ctx: FeatureContext, rows: list[list[str]],
                         stats: dict) -> None:
    seen = set()
    for raw in rows:
        ctx.check_cancel()
        row = raw + [""] * (len(TLS_FIELDS) - len(raw))
        item = dict(zip(TLS_FIELDS, row))
        cert_blob = hex_to_bytes(item.get("tls.handshake.certificates", ""))
        if not cert_blob:
            continue
        for der in c2ext._der_children(cert_blob):
            profile = c2ext.looks_like_sliver_mtls_cert(der)
            if profile is None:
                continue
            key = (item["tcp.stream"], profile.common_name)
            if key in seen:
                continue
            seen.add(key)
            stats["mtls_hits"] += 1
            sni = clean_cell(item.get(
                "tls.handshake.extensions_server_name", ""), 120) or "-"
            summary = (f"疑似 Sliver mTLS 证书 CN={profile.common_name}")
            ctx.report(f"帧 {item['frame.number']} {summary} "
                       f"SNI {sni}（{'；'.join(profile.reasons)}）", "good")
            ctx.add_finding("tls_fingerprint", summary,
                            frame=item["frame.number"], level="warn",
                            detail="；".join(profile.reasons) +
                                   f"，流 {item['tcp.stream']} SNI {sni}",
                            extra={"protocol": "sliver",
                                   "cn": profile.common_name})


# ---------------------------------------------------------------------------
# raw TCP fallback for XOR packets
# ---------------------------------------------------------------------------
def _analyze_meterpreter_tcp(ctx: FeatureContext, keys: dict,
                             stats: dict) -> None:
    key = keys["meterpreter"]
    rows = tshark_rows(ctx, TCP_FIELDS, "tcp.len > 0", limit=50_000)
    by_stream: dict[str, list[bytes]] = {}
    frame_by_stream: dict[str, str] = {}
    for raw in rows:
        row = raw + [""] * (len(TCP_FIELDS) - len(raw))
        stream, frame, payload = row[1], row[0], hex_to_bytes(row[2])
        if payload:
            by_stream.setdefault(stream, []).append(payload)
            frame_by_stream.setdefault(stream, frame)
    reported: set[tuple] = set()
    for stream, chunks in by_stream.items():
        ctx.check_cancel()
        data = b"".join(chunks)
        seen: set[bytes] = set()
        packets = []
        for wire, encoder in meterpreter_wire.wire_body_candidates(data):
            if not wire or wire in seen:
                continue
            seen.add(wire)
            packets.extend(meterpreter_wire.iter_packets(wire, key=key))
        if not packets:
            continue
        stats["tcp_sessions"] += 1
        ctx.report(f"TCP 流 {stream} 识别到 {len(packets)} 个 "
                   f"XOR 编码的 meterpreter 包（首帧 "
                   f"{frame_by_stream.get(stream, '-')}）", "good")
        for packet in packets[:MAX_BLOBS]:
            _report_meterpreter_packet(ctx,
                                       frame_by_stream.get(stream, ""),
                                       packet, key, stats, reported,
                                       stream=stream, wire=data)


def analyze(ctx: FeatureContext) -> None:
    keys = _load_keys(ctx)
    reqs = tshark_rows(ctx, HTTP_FIELDS, "http.request", limit=100_000)
    resps: dict[str, dict] = {}
    for raw in tshark_rows(ctx, RESP_FIELDS, "http.response", limit=100_000):
        row = raw + [""] * (len(RESP_FIELDS) - len(raw))
        item = dict(zip(RESP_FIELDS, row))
        resps[item["frame.number"]] = item
    dns_rows = tshark_rows(ctx, DNS_FIELDS, "dns.flags.response == 0",
                           limit=100_000)
    tls_rows = tshark_rows(ctx, TLS_FIELDS, "tls.handshake.certificates",
                           limit=10_000)

    stats = {"http_hits": 0, "dns_hits": 0, "mtls_hits": 0,
             "decrypted": 0, "key_exchange": 0, "stage_seen": False,
             "wire_packets": 0, "tcp_sessions": 0,
             "encrypted_candidates": 0}

    ctx.set_progress(10)
    _analyze_sliver_http(ctx, reqs, resps, keys, stats)
    ctx.set_progress(35)
    _analyze_meterpreter_http(ctx, reqs, resps, keys, stats)
    ctx.set_progress(55)
    _analyze_sliver_dns(ctx, dns_rows, keys, stats)
    ctx.set_progress(75)
    _analyze_sliver_mtls(ctx, tls_rows, stats)
    ctx.set_progress(85)
    if not any((stats["http_hits"], stats["dns_hits"], stats["mtls_hits"],
                stats["wire_packets"], stats["stage_seen"], reqs)):
        _analyze_meterpreter_tcp(ctx, keys, stats)

    total = (stats["http_hits"] + stats["dns_hits"] + stats["mtls_hits"]
             + stats["wire_packets"] + stats["tcp_sessions"]
             + (1 if stats["stage_seen"] else 0) + stats["key_exchange"])
    if total:
        ctx.report(
            f"共识别 C2 线索 {total} 处：Sliver HTTP {stats['http_hits']}、"
            f"Sliver DNS {stats['dns_hits']}、Sliver mTLS 证书 "
            f"{stats['mtls_hits']}、meterpreter wire 包 "
            f"{stats['wire_packets']}、TCP 会话 {stats['tcp_sessions']}；"
            f"解密会话载荷 {stats['decrypted']} 个，"
            f"密钥交换 {stats['key_exchange']} 处", "good")
    else:
        ctx.report("未识别到 Sliver / meterpreter C2 特征", "warn")
        ctx.report("提示：Sliver HTTP beacon 按 URI 扩展名分类（.php/.js/"
                   ".html/.png/.woff/.txt）并携带 _= nonce，v1.6 使用 "
                   "ChaCha20-Poly1305（可带签名前缀/gzip），旧版为 AES-GCM；"
                   "DNS beacon 使用自定义 Base32/Base58 子域编码；meterpreter "
                   "staging 的 GET URI 校验和为 92/93（含 INITM 标记），wire 包 "
                   "支持 AES-128/256 CBC。如需解密会话，请设置 "
                   "sliver_session_key / meterpreter_symkey 参数", "info")
        if keys["sliver"] is None and keys["meterpreter"] is None:
            ctx.write_output(
                "c2_README.txt",
                "本模块识别 Sliver / meterpreter C2。\n"
                "Sliver 参数 sliver_session_key（hex）：\n"
                "- v1.6：32 字节 ChaCha20-Poly1305，载荷可带 74 字节 minisign 签名前缀，"
                "明文可经 gzip 压缩；\n"
                "- v1.5：32 字节会话密钥（兼容 AES-GCM 回退）；\n"
                "- v1.4 及更早：16 字节 AES-GCM 密钥，nonce 为载荷前 12 字节。\n"
                "meterpreter 参数 meterpreter_symkey（hex）：\n"
                "- 16 字节 = AES-128-CBC（wire 加密标志 2）；\n"
                "- 32 字节 = AES-256-CBC（wire 加密标志 1）。\n"
                "其他参数：sliver_dns_domain（已知 DNS beacon 父域名，逗号分隔）。\n"
                "流量侧覆盖 Sliver HTTP 编解码器（Base64/Hex 等）、密钥交换，"
                "以及 meterpreter staging（92/93/INITM）、RECV 轮询与 XOR/AES "
                "wire 包。密钥可在分析参数中提供后重新分析。\n")
    ctx.set_progress(100)
