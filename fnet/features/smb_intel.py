"""SMB3 加密链路智能综合分析（"神器式" CTF 自动串联流水线）。

把一条完整 CTF 链路自动化串联：用户只需提供少量显式候选密码，Fnet 就能
自动完成  NTLM 身份提取 -> SMB3 解密 -> 文件导出 -> 熵识别 -> 提示 flag。
核心是**轻量、非阻塞**的自动回退流水线：

    NTLM 账号提取 -> 显式候选密码（≤8 个）-> 逐个候选 decrypt_capture
    （失败自动回退下一个，直到成功或耗尽）-> 文件/flag 摘要 -> 熵标注

**流水线绝不卡在爆破上。** 暴力枚举 / 账号派生的地毯式搜索被刻意排除在
流水线之外——那会同步阻塞整条分析。需要穷举时，请用"结果页的 NTLM
离线破解"后台动作（异步、可选、不阻塞任务）。

自动回退/健壮性
----------------
本模块对三个"可能尚未就绪"的并行依赖一律用 ``try/except`` 包裹导入，
缺失时**降级为跳过并记日志**，绝不因缺模块而让整条流水线崩溃：

    * :mod:`fnet.utils.ntlmcrack` —— NTLM 密码离线验证（``verify_password``）;
    * :mod:`fnet.utils.entropy`    —— 导出文件的熵/加密识别;
    * :mod:`fnet.features.smb_password` —— 候选密码生成（同模块演进）。

每个入选的候选密码都会依次尝试 :func:`fnet.smb3.decrypt_capture`；一旦某个
候选返回 ``ok``（AEAD 标签通过，即密钥正确），立即停止并汇报，否则记录失败
原因、回退到下一个候选。候选耗尽时提示改用 hashcat ``-m 5600`` 或结果页的
NTLM 离线破解。

注意：本模块把 :func:`fnet.smb3.decrypt_capture` 当作**黑盒**调用，不复制
其内部任何解密逻辑。
"""
from __future__ import annotations

import re
from pathlib import Path

from fnet import smb3
from fnet.features.common import protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import smb as smb_util

#: 识别加密 SMB3 变换流的魔术字节（TRANSFORM_HEADER）。
SMB3_TRANSFORM_MAGIC = b"\xfdSMB"


def _parse_bool(value, default: bool = False) -> bool:
    """把 params 里五花八门的布尔值归一化。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return default


def _collect_accounts(groups) -> tuple[list[dict], bool]:
    """从重组流里提取每条 SMB 流的 NTLM 账号线索与加密标记。

    返回 ``(accounts, has_encrypted)``：
        accounts —— 每条流一个 dict，含 ``stream / user / domain /
                    workstation / challenge / nt_response``。
        has_encrypted —— 是否检测到 ``\\xfdSMB`` 加密变换流。
    """
    accounts: list[dict] = []
    has_encrypted = False
    for stream_id, group in groups.items():
        ctx_stream = {"stream": stream_id, "user": "", "domain": "",
                      "workstation": "", "challenge": b"",
                      "nt_response": b""}
        for stream in group:
            for message in smb_util.parse_messages(stream.data):
                if message.encrypted:
                    has_encrypted = True
                if not message.security_blob:
                    continue
                if message.security_blob.startswith(smb_util.NTLMSSP) \
                        and message.is_response \
                        and len(message.security_blob) >= 32:
                    challenge = message.security_blob[24:32]
                    if len(challenge) == 8:
                        ctx_stream["challenge"] = challenge
                found = smb_util.find_ntlm_type3(message.security_blob)
                if found:
                    ctx_stream["user"] = found.get("user", "")
                    ctx_stream["domain"] = found.get("domain", "")
                    ctx_stream["workstation"] = found.get("workstation", "")
                    if not ctx_stream["nt_response"]:
                        ctx_stream["nt_response"] = \
                            bytes(found.get("nt") or b"")
        accounts.append(ctx_stream)
    return accounts, has_encrypted


#: 自动解密流水线最多尝试的显式候选数。暴力枚举绝不进入流水线（见下），
#: 因此这个上限防止用户一次性塞入超大 ``passwords`` 把任务拖卡。
MAX_PIPELINE_CANDIDATES = 8


def _collect_candidates(ctx: FeatureContext, accounts: list[dict]) -> list[str]:
    """仅收集**显式提供**的少量候选密码，用于流水线内快速试解密。

    流水线绝不在这里触发暴力枚举或账号派生的地毯式搜索——那会同步阻塞整条
    分析直到爆破完成，正是我们要避免的"卡住推进"。

    优先 ``password`` -> ``passwords``/``password_candidates``（显式列表），
    去重且受到 :data:`MAX_PIPELINE_CANDIDATES` 上限约束。若需要穷举，
    应当用"结果页的 NTLM 离线破解"后台动作，而不是塞进流水线。
    """
    params = ctx.params or {}
    ordered: list[str] = []

    def _push(values) -> None:
        for value in values or []:
            text = str(value or "").strip()
            if text and text not in ordered:
                ordered.append(text)

    explicit = str(params.get("password") or "").strip()
    if explicit:
        ordered.append(explicit)
    _push(re.split(r"[;]", str(params.get("passwords") or "")))
    _push(re.split(r"[,]", str(params.get("password_candidates") or "")))

    if len(ordered) > MAX_PIPELINE_CANDIDATES:
        ctx.report(
            f"候选密码超过 {MAX_PIPELINE_CANDIDATES} 个，自动解密流水线仅用前 "
            f"{MAX_PIPELINE_CANDIDATES} 个快速尝试；其余可用结果页的 "
            "NTLM 离线破解后台处理", "warn")
        ordered = ordered[:MAX_PIPELINE_CANDIDATES]
    return ordered


def _verify_passwords(ctx: FeatureContext, accounts: list[dict],
                      candidates: list[str]) -> list[str]:
    """用 NTLM 离线验证过滤候选：只保留能被某个账号"认账"的密码。

    ``fnet.utils.ntlmcrack`` 未就绪时整体降级（返回空，由调用方改用
    hashcat 提示）。验证命中的密码仍会进入解密候选列表。
    """
    try:
        from fnet.utils import ntlmcrack
    except Exception:  # noqa: BLE001 - NTLM 密码验证模块未就绪
        ctx.report("NTLM 密码验证模块未就绪，跳过验证，直接尝试解密", "warn")
        return []

    verified: list[str] = []
    matched_accounts = 0
    for password in candidates:
        ctx.check_cancel()
        for account in accounts:
            challenge = account.get("challenge")
            nt_response = account.get("nt_response")
            if not challenge or not nt_response:
                continue
            try:
                if ntlmcrack.verify_password(
                        password, bytes(challenge), bytes(nt_response),
                        user=account.get("user"),
                        domain=account.get("domain")):
                    if password not in verified:
                        verified.append(password)
                    matched_accounts += 1
                    label = (f"{account.get('domain') or ''}"
                             f"\\{account.get('user') or '?'}").lstrip("\\") or "?"
                    ctx.report(f"密码 {password!r} 通过账号 {label} 的 "
                               "NTLMv2 验证", "good")
                    ctx.add_finding(
                        "credential", f"NTLM 密码验证命中 {label}",
                        level="good", detail=f"password={password}",
                        extra={"protocol": "smb2", "account": label,
                               "password": password,
                               "verified": True, "mode": "5600"})
                    break
            except Exception:  # noqa: BLE001 - 单条验证失败不致命
                continue
    if verified:
        ctx.report(f"NTLM 验证命中 {len(verified)} 个密码"
                   f"（涉及 {matched_accounts} 条账号记录）", "good")
    return verified


def _classify_entropy(ctx: FeatureContext, files) -> None:
    """对导出的文件尝试熵分类，标注疑似加密项。

    :mod:`fnet.utils.entropy` 未就绪时静默跳过（不崩溃）。疑似加密文件
    会被记录为 ``file`` finding，提示可交给 OpenSSL 解密特性。
    """
    if not files:
        return
    try:
        from fnet.utils import entropy
    except Exception:  # noqa: BLE001 - 熵分析模块未就绪，跳过
        return

    for item in files:
        name = item.get("name") if isinstance(item, dict) else str(item)
        path = Path(item.get("path", item)) if isinstance(item, dict) \
            else Path(str(item))
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        try:
            verdict = entropy.classify(data)
        except Exception:  # noqa: BLE001 - 单文件熵失败不致命
            verdict = None
        if not isinstance(verdict, dict):
            continue
        suspicious = bool(verdict.get("encrypted") or verdict.get("suspicious")
                          or bool(verdict.get("high"))
                          or float(verdict.get("score") or 0) > 7.0)
        ctx.report(f"文件 {name} 熵={verdict.get('score', '?')} "
                   f"疑似加密={suspicious}，可交给 OpenSSL 解密", "warn"
                   if suspicious else "info")
        if suspicious:
            ctx.add_finding(
                "file", f"疑似加密文件 {name}", level="warn",
                detail=f"entropy={verdict.get('score')} "
                       f"分类={verdict.get('label', '?')}",
                extra={"protocol": "smb3", "name": name, "path": str(path),
                       "entropy": verdict.get("score"),
                       "encrypted": True,
                       "hint": "可尝试 OpenSSL 解密特性"})


def analyze(ctx: FeatureContext) -> None:
    """SMB3 加密链路智能综合分析入口。"""
    streams = protocol_streams(ctx, "smb2")
    if not streams:
        ctx.report("没有 SMB 流量", "warn")
        return

    # 分组：同一 TCP 流的两方向归并。
    groups: dict[str, list] = {}
    for stream in streams:
        groups.setdefault(stream.stream, []).append(stream)
    ctx.report(f"识别到 {len(groups)} 条 SMB 流", "info")

    accounts, has_encrypted = _collect_accounts(groups)
    account_labels = [
        (f"{acc.get('domain') or ''}\\{acc.get('user') or '?'}"
         if acc.get("user") else "?")
        for acc in accounts]
    known_accounts = [lab for lab in account_labels if lab != "?"]
    if known_accounts:
        ctx.report("NTLM 账号: " + ", ".join(known_accounts), "good")
        for idx, acc in enumerate(accounts):
            if not acc.get("user"):
                continue
            extra = {"protocol": "smb2", "account": account_labels[idx],
                     "user": acc.get("user"), "domain": acc.get("domain"),
                     "workstation": acc.get("workstation"),
                     "stream": acc.get("stream")}
            # 把挑战/响应一并写入 extra：结果页的"NTLM 离线破解"动作依赖
            # 这三个字段（user + challenge + nt_response）才能定位目标。
            challenge = bytes(acc.get("challenge") or b"")
            nt_response = bytes(acc.get("nt_response") or b"")
            if challenge:
                extra["challenge"] = challenge.hex()
            if nt_response:
                extra["nt_response"] = nt_response.hex()
                if len(nt_response) > 24:
                    extra["hash"] = (f"{acc.get('user') or ''}::"
                                     f"{acc.get('domain') or ''}:"
                                     f"{challenge.hex()}:"
                                     f"{nt_response[:16].hex()}:"
                                     f"{nt_response[16:].hex()}")
                    extra["mode"] = "5600"
            ctx.add_finding(
                "credential", f"SMB NTLM 账号 {account_labels[idx]}",
                level="good",
                detail=(f"user={acc.get('user')} "
                        f"domain={acc.get('domain')} "
                        f"workstation={acc.get('workstation')} "
                        f"stream={acc.get('stream')}"),
                extra=extra)

    ctx.set_progress(30)
    candidates = _collect_candidates(ctx, accounts)
    if not candidates:
        ctx.report("未提供任何候选密码；可在本次分析后用结果页的 NTLM 离线"
                   "破解或 SMB3 手动解密动作补充", "warn")

    # 通过 NTLM 离线验证提升候选质量（缺模块则跳过；候选本就 ≤8 个，很轻）。
    verified = _verify_passwords(ctx, accounts, candidates)
    # 验证命中优先；其余仍保留作试解密候选。
    ordered = _dedupe(verified + candidates)

    # -------- SMB3 解密自动流水线（轻量、非阻塞） --------
    if not has_encrypted:
        ctx.report("未检测到 SMB3 加密变换流（\\xfdSMB），无需解密", "info")
        ctx.set_progress(100)
        return

    ctx.report("检测到 SMB3 加密流量，对显式候选做快速自动回退解密", "info")
    attempts = 0
    success = False
    for password in ordered:
        ctx.check_cancel()
        attempts += 1
        ctx.set_progress(min(100, 35 + int(attempts / max(1, len(ordered)) * 55)))
        result = _run_decrypt(ctx, password)
        if not isinstance(result, dict):
            continue
        if result.get("ok"):
            success = True
            break  # 已解密成功，停止回退
        ctx.report(f"候选 {password!r} 解密失败（自动回退）: "
                   f"{result.get('error') or '密钥不匹配'}", "warn")
    if not success:
        ctx.report("显式候选密码均未能即时解密 SMB3 流量；可用 hashcat "
                   "-m 5600 破解 NetNTLMv2 哈希，或先在结果页跑 NTLM 离线"
                   "破解拿到真实口令，再通过 SMB3 手动解密填入", "warn")
    ctx.set_progress(100)


def _run_decrypt(ctx: FeatureContext, password: str) -> dict | None:
    """用单个密码调用 smb3.decrypt_capture 并汇报结果。

    成功时记录 ``grade`` finding（含 frame / extra / decrypted / flag），
    并对导出的文件做熵标注。
    """
    try:
        result = smb3.decrypt_capture(
            ctx.pcap, ctx.tshark, password=password,
            output_dir=ctx.output_dir, cancel=ctx.cancel)
    except Exception as exc:  # noqa: BLE001 - 黑盒调用失败不致命
        ctx.report(f"smb3.decrypt_capture 调用失败: {exc}", "error")
        return {"ok": False, "error": str(exc)}

    if not isinstance(result, dict):
        return {"ok": False, "error": "解密返回格式异常"}

    decrypted = int(result.get("decrypted") or 0)
    flags = list(result.get("flags") or [])
    files = list(result.get("files") or [])
    sessions = list(result.get("sessions") or [])

    if result.get("ok"):
        detail = (f"password={password} 解密 {decrypted} 条 "
                  f"会话={len(sessions)} 文件={len(files)}"
                  + (f" flag={' '.join(flags)}" if flags else ""))
        ctx.report(f"SMB3 解密成功: 密码 {password!r} 解密 {decrypted} 条 "
                   f"消息 {len(files)} 个文件", "good")

        extra = {"protocol": "smb3", "password": password,
                 "decrypted": decrypted, "files": len(files),
                 "sessions": len(sessions)}
        if flags:
            extra["flag"] = flags
        for idx, session in enumerate(sessions):
            if not isinstance(session, dict):
                continue
            extra.setdefault("session", {})[idx] = {
                "stream": session.get("stream"),
                "user": session.get("user"),
                "domain": session.get("domain"),
                "cipher": session.get("cipher"),
                "session_key": session.get("session_key"),
                "key_source": session.get("key_source"),
                "decrypted": session.get("decrypted"),
            }
        ctx.add_finding(
            "grade", f"SMB3 解密成功（密码 {password!r}）",
            frame="", level="good", detail=detail, extra=extra)

        # 文件/flag 摘要。
        _summarize_files(ctx, files, flags)

        if flags:
            ctx.report("=== flag ===", "good")
            for flag in flags:
                ctx.report("  " + flag, "good")
        else:
            ctx.report("解密成功但未发现 flag；请查看导出的文件", "info")
        return result

    # 失败分支：记录日志（不当作 finding，避免 flooding）。
    ctx.report(f"候选 {password!r} 未解密：{result.get('error') or '无'}", "debug")
    return result


def _summarize_files(ctx: FeatureContext, files: list, flags: list) -> None:
    """聚合导出文件并逐文件调用熵分类标注疑似加密项。"""
    if files:
        ctx.report(f"SMB3 导出文件 {len(files)} 个", "info")
    # 熵标注只对实际落盘的文件生效（files 里是 {name,size} 元数据）。
    resolved: list[dict] = []
    base = Path(ctx.output_dir or ".")
    for item in files:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        entry = {"name": name, "path": base / name}
        resolved.append(entry)
        ctx.add_finding(
            "file", f"SMB3 导出文件 {name}", level="info",
            detail=(f"size={item.get('size')} "
                    f"md5={item.get('md5', '-')}"),
            extra={"protocol": "smb3", "name": name,
                   "path": str(base / name),
                   "size": item.get("size"),
                   "md5": item.get("md5", ""),
                   "hint": "疑似加密可交 OpenSSL 解密"})
    _classify_entropy(ctx, resolved)
    if flags:
        ctx.report("已提取 flag: " + ", ".join(flags), "good")


def _dedupe(values):
    out: list = []
    for value in values:
        if value not in out:
            out.append(value)
    return out