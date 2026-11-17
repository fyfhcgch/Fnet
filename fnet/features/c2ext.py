"""Sliver / meterpreter extended C2 analysis (the CS-handler counterpart).

Covers the C2 roadmap entry alongside :mod:`fnet.features.cs` (Cobalt
Strike) and :mod:`fnet.features.meterpreter` (plain TLV sessions):

* **Sliver HTTP(S) beacon** — procedural URIs classified by file extension
  (``.html/.jsp`` key exchange, ``.php`` session, ``.js`` poll, ``.png``
  close, ``.woff`` stager, ``.txt`` RSA key exchange) and the ``_=`` nonce
  argument; session payloads are AES-GCM decrypted when a symmetric session
  key is configured (``sliver_session_key`` hex parameter);
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
  decryption when ``meterpreter_symkey`` is configured.

Output conventions follow :mod:`fnet.features.cs`: Chinese log lines,
``ctx.write_output`` artifacts and findings recorded through
``ctx.add_finding`` so the WebUI table and reports stay consistent.
"""
from __future__ import annotations

import base64
import re

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils import c2ext
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


def _hex_key(ctx: FeatureContext, name: str, size: int) -> bytes | None:
    value = str(ctx.params.get(name) or "").strip()
    if not value:
        return None
    value = value.strip().lower()
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        ctx.report(f"{name} 参数不是有效的十六进制字符串", "error")
        return None
    if len(raw) != size:
        ctx.report(f"{name} 需要 {size} 字节（{size * 2} 个十六进制字符），"
                   f"当前 {len(raw)} 字节", "error")
        return None
    return raw


def _load_keys(ctx: FeatureContext) -> dict:
    return {
        "sliver": _hex_key(ctx, "sliver_session_key", 32),
        "meterpreter": _hex_key(ctx, "meterpreter_symkey", 32),
    }


def _report_flag_lines(ctx: FeatureContext, frame: str, text: str) -> None:
    for flag in find_flags(text):
        ctx.report(f"发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=frame, detail="来自 C2 会话解密",
                        level="good")


def _decode_body_candidates(body: bytes) -> list[bytes]:
    """Candidate AES-GCM blobs: raw body or base64 wrapped (Sliver encoders)."""
    candidates = [body]
    text = payload_text(body)
    for match in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", match.group()))
        except Exception:  # noqa: BLE001
            continue
        if len(raw) >= 28:
            candidates.append(raw)
    return candidates[:MAX_BLOBS]


def _sliver_gcm_candidates(ctx: FeatureContext, frame: str, uri: str,
                           body: bytes, key: bytes | None,
                           stats: dict) -> bool:
    """Try AES-GCM session decryption on one HTTP body; True when decrypted."""
    if key is None or not body:
        return False
    for blob in _decode_body_candidates(body):
        plain = c2ext.sliver_aesgcm_decrypt(blob, key)
        if plain is None:
            continue
        stats["decrypted"] += 1
        text = payload_text(plain)
        ctx.report(f"===== 帧 {frame} Sliver 会话载荷解密成功 ({uri or 'HTTP'}) "
                   f"=====", "good")
        for line in text.splitlines()[:80]:
            if line.strip():
                ctx.report("  " + clean_cell(line, 260), "info")
        ctx.write_output(f"c2_sliver_session_{frame}.bin", plain)
        ctx.add_finding("protocol", f"Sliver 会话载荷解密 {uri or '(响应)'}",
                        frame=frame, level="good",
                        detail=f"恢复 {len(plain)} 字节明文",
                        extra={"protocol": "sliver", "uri": uri or ""})
        _report_flag_lines(ctx, frame, text)
        return True
    return False


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
        summary = (f"Sliver HTTP beacon {classified['ext']} "
                   f"({classified['message']})")
        ctx.report(f"帧 {item['frame.number']} {summary} "
                   f"nonce={'有' if classified['nonce'] else '无'} "
                   f"路径词命中 {','.join(classified['word_hits']) or '-'}",
                   "good")
        ctx.add_finding("protocol", summary, frame=item["frame.number"],
                        level="warn",
                        detail=f"URI {clean_cell(uri, 200)} "
                               f"nonce={classified['nonce']}",
                        extra={"protocol": "sliver", "ext": classified["ext"],
                               "nonce": classified["nonce"]})
        body = hex_to_bytes(item.get("http.file_data", ""))
        if body:
            _sliver_gcm_candidates(ctx, item["frame.number"], uri, body,
                                   key, stats)
        response_frame = item.get("http.response_in", "")
        resp = resps.get(response_frame)
        if resp:
            resp_body = hex_to_bytes(resp.get("http.file_data", ""))
            if resp_body:
                _sliver_gcm_candidates(ctx, resp["frame.number"], uri,
                                       resp_body, key, stats)


# ---------------------------------------------------------------------------
# meterpreter staging + encrypted HTTP transport
# ---------------------------------------------------------------------------
def _analyze_meterpreter_http(ctx: FeatureContext, reqs: list[list[str]],
                              resps: dict[str, dict], keys: dict,
                              stats: dict) -> None:
    key = keys["meterpreter"]
    for raw in reqs:
        ctx.check_cancel()
        row = raw + [""] * (len(HTTP_FIELDS) - len(raw))
        item = dict(zip(HTTP_FIELDS, row))
        uri = item.get("http.request.uri", "") or ""
        body = hex_to_bytes(item.get("http.file_data", ""))
        stage_info = c2ext.meterpreter_stage_uri(uri)
        if stage_info:
            ctx.report(f"帧 {item['frame.number']} meterpreter 分阶段 "
                       f"staging 请求 ({stage_info['reason']}, "
                       f"{stage_info['arch']}) URI {clean_cell(uri, 120)}",
                       "good")
            ctx.add_finding(
                "protocol", f"meterpreter staging 请求 {stage_info['arch']}",
                frame=item["frame.number"], level="warn",
                detail=f"URI {clean_cell(uri, 200)} "
                       f"({stage_info['reason']})",
                extra={"protocol": "meterpreter"})
            stats["stage_seen"] = True
        if stage_info:
            response_frame = item.get("http.response_in", "")
            resp = resps.get(response_frame)
            blob = hex_to_bytes(resp.get("http.file_data", "")) if resp else b""
            if blob:
                stage = c2ext.parse_stage_blob(blob)
                if stage is not None:
                    name = f"c2_meterpreter_stage_{resp['frame.number']}.bin"
                    ctx.write_output(name, stage.stage)
                    ctx.report(
                        f"帧 {resp['frame.number']} stage 已还原 "
                        f"{stage.size} 字节"
                        f"{'（MZ PE，metsrv）' if stage.is_pe else ''} "
                        f"长度前缀={'是' if stage.length_prefixed else '否'}",
                        "good")
                    ctx.add_finding(
                        "file", f"meterpreter stage {stage.size} 字节",
                        frame=resp["frame.number"], level="warn",
                        detail=name,
                        extra={"protocol": "meterpreter",
                               "pe": stage.is_pe})
                    for text in stage.strings[:20]:
                        ctx.report(f"  stage 字符串: {clean_cell(text, 160)}",
                                   "debug")
                    _report_flag_lines(ctx, resp["frame.number"],
                                       "\n".join(stage.strings[:200]))
        if body.strip().upper() == b"RECV":
            ctx.report(f"帧 {item['frame.number']} meterpreter HTTP 轮询 "
                       f"(RECV body)", "info")
            ctx.add_finding("protocol", "meterpreter HTTP 轮询 (RECV)",
                            frame=item["frame.number"],
                            extra={"protocol": "meterpreter"})
        # XOR-obfuscated / AES encrypted packet in the request body.
        _meterpreter_wire_body(ctx, item["frame.number"], body, key, stats)
        # ... and in the matching response body.
        response_frame = item.get("http.response_in", "")
        resp = resps.get(response_frame)
        if resp:
            resp_body = hex_to_bytes(resp.get("http.file_data", ""))
            _meterpreter_wire_body(ctx, resp["frame.number"], resp_body,
                                   key, stats)


def _meterpreter_wire_body(ctx: FeatureContext, frame: str, blob: bytes,
                           key: bytes | None, stats: dict) -> None:
    if not blob:
        return
    packets = c2ext.iter_packets(blob, key=key)
    for packet in packets:
        stats["wire_packets"] += 1
        guid = packet.session_guid.hex() or "-"
        ctx.report(
            f"帧 {frame} meterpreter {packet.kind} 包 ({packet.version} "
            f"头) 加密={'AES256' if packet.encrypt_flags == 1 else 'AES128' if packet.encrypt_flags == 2 else '无'} "
            f"GUID {guid} 命令 {packet.command_hex}", "good")
        ctx.add_finding(
            "protocol", f"meterpreter {packet.kind} 包 {packet.command_hex}",
            frame=frame, level="warn",
            detail=(f"加密标志 {packet.encrypt_flags}, 会话 GUID {guid}, "
                    f"{len(packet.tlvs)} 个 TLV"),
            extra={"protocol": "meterpreter", "guid": guid,
                   "encrypted": packet.encrypted})
        for tlv in packet.tlvs[:16]:
            ctx.report(f"  TLV {tlv['name']} = {clean_cell(tlv['value'], 160)}",
                       "debug")
        if packet.encrypted and not packet.plaintext:
            stats["encrypted_candidates"] += 1
            ctx.write_output(f"c2_meterpreter_enc_{frame}_{stats['encrypted_candidates']}.bin",
                             blob)
        if packet.plaintext:
            text = payload_text(packet.plaintext)
            if printable_ratio(packet.plaintext) > 0.7:
                _report_flag_lines(ctx, frame, text)


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
        type_name = c2ext.DNS_MESSAGE_TYPES.get(message["type"], "未知")
        ctx.report(
            f"帧 {item['frame.number']} Sliver DNS beacon "
            f"({decoded['encoding']}) 类型 {type_name} "
            f"ID {message['id']} 数据 {len(message['data'])} 字节 "
            f"子域 {decoded['subdata'][:64]}", "good")
        detail = (f"编码 {decoded['encoding']}, 消息类型 {type_name}, "
                  f"会话/ID {message['id']}, Size {message['size']}")
        ctx.add_finding("dns",
                        f"Sliver DNS C2 消息 ({type_name})",
                        frame=item["frame.number"], level="warn",
                        detail=detail,
                        extra={"protocol": "sliver", "qname": qname[:254],
                               "encoding": decoded["encoding"]})
        data = message["data"]
        if data:
            ctx.write_output(
                f"c2_sliver_dns_{item['frame.number']}.bin", data)
            plain = None
            if key and len(data) >= 28:
                plain = c2ext.sliver_aesgcm_decrypt(data, key)
            if plain is not None:
                text = payload_text(plain)
                ctx.report(f"  Data 解密成功 {len(plain)} 字节", "good")
                for line in text.splitlines()[:40]:
                    if line.strip():
                        ctx.report("  " + clean_cell(line, 220), "info")
                _report_flag_lines(ctx, item["frame.number"], text)
            else:
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
    for stream, chunks in by_stream.items():
        data = b"".join(chunks)
        packets = c2ext.iter_packets(data, key=key)
        if not packets:
            continue
        stats["tcp_sessions"] += 1
        ctx.report(f"TCP 流 {stream} 识别到 {len(packets)} 个 "
                   f"XOR 编码的 meterpreter 包（首帧 "
                   f"{frame_by_stream.get(stream, '-')}）", "good")
        for packet in packets[:MAX_BLOBS]:
            guid = packet.session_guid.hex() or "-"
            ctx.add_finding(
                "protocol", f"meterpreter {packet.kind} 包 {packet.command_hex}",
                frame=frame_by_stream.get(stream, ""), level="warn",
                detail=(f"流 {stream}, {packet.version} 头, 加密标志 "
                        f"{packet.encrypt_flags}, GUID {guid}"),
                extra={"protocol": "meterpreter", "stream": stream,
                       "guid": guid})
            if packet.encrypted and not packet.plaintext:
                stats["encrypted_candidates"] += 1
                ctx.write_output(
                    f"c2_meterpreter_enc_tcp_{stream}_{stats['encrypted_candidates']}.bin",
                    data[packet.offset:packet.offset + packet.total])
            if packet.plaintext and printable_ratio(packet.plaintext) > 0.7:
                _report_flag_lines(ctx, frame_by_stream.get(stream, ""),
                                   payload_text(packet.plaintext))


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
             "decrypted": 0, "stage_seen": False, "wire_packets": 0,
             "tcp_sessions": 0, "encrypted_candidates": 0}

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
             + (1 if stats["stage_seen"] else 0))
    if total:
        ctx.report(
            f"共识别 C2 线索 {total} 处：Sliver HTTP {stats['http_hits']}、"
            f"Sliver DNS {stats['dns_hits']}、Sliver mTLS 证书 "
            f"{stats['mtls_hits']}、meterpreter wire 包 "
            f"{stats['wire_packets']}、TCP 会话 {stats['tcp_sessions']}；"
            f"解密会话载荷 {stats['decrypted']} 个", "good")
    else:
        ctx.report("未识别到 Sliver / meterpreter C2 特征", "warn")
        ctx.report("提示：Sliver HTTP beacon 按 URI 扩展名分类（.php/.js/"
                   ".html/.png/.woff/.txt）并携带 _= nonce；DNS beacon 使用 "
                   "自定义 Base32/Base58 子域编码；meterpreter staging 的 "
                   "GET URI 校验和为 92/93（含 INITM 标记）。如需解密会话，"
                   "请设置 sliver_session_key / meterpreter_symkey 参数",
                   "info")
        if keys["sliver"] is None and keys["meterpreter"] is None:
            ctx.write_output(
                "c2_README.txt",
                "本模块识别 Sliver / meterpreter C2；解密需要：\n"
                "- sliver_session_key: Sliver 会话 AES-256 密钥（hex）\n"
                "- meterpreter_symkey: meterpreter AES-256 对称密钥（hex）\n"
                "密钥可在分析参数中提供后重新分析。\n")
    ctx.set_progress(100)
