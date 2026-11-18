"""NetNTLMv2 离线密码验证 handler（hashcat 的本地回退）。

配合 ``fnet/utils/ntlmcrack.py``，在缺少 hashcat 时直接从捕获的 NTLM
挑战/响应验证候选密码或做受控的短口令枚举。默认不强攻（避免卡死），
仅当用户提供 ``password`` / ``password_candidates`` / ``bruteforce=1``
参数时才真正枚举。未命中时给出 hashcat -m 5600 / -m 5500 的提示。
"""
from __future__ import annotations

from fnet.features import ntlm as ntlm_feat
from fnet.features.registry import FeatureContext
from fnet.utils import ntlmcrack

#: ``password_candidates`` 支持的内置候选字典名 -> 口令列表。真正的
#: 大字典太大不内置，这里放小而常用的示例，供离线快速验证。
_DEFAULT_CANDIDATES: dict[str, list[str]] = {
    "examples": ["Password123", "admin", "password", "123456", "alice"],
}


def _param_string(ctx: FeatureContext, name: str, default: str = "") -> str:
    value = ctx.params.get(name, default)
    if not isinstance(value, str):
        value = str(value or "")
    return value.strip()


def _split_candidates(value: str) -> list[str]:
    """把分号/逗号分隔的候选口令拆成列表。"""
    out: list[str] = []
    for part in value.replace(",", ";").split(";"):
        part = part.strip()
        if part:
            out.append(part)
    return out


def _parse_bool(ctx: FeatureContext, name: str) -> bool:
    value = _param_string(ctx, name, "0").lower()
    return value in {"1", "true", "yes", "on"}


def verify(ctx: FeatureContext) -> None:
    """验证捕获 NTLM 账号的密码（NetNTLMv2 本地回退）。"""
    events = ntlm_feat._collect(ctx)  # noqa: SLF001 - 复用内部收集器
    if not events:
        ctx.report("没有发现 NTLMSSP 认证流量，跳过密码验证", "warn")
        return

    explicit_password = _param_string(ctx, "password", "")
    candidates_text = _param_string(ctx, "password_candidates", "")
    do_bruteforce = _parse_bool(ctx, "bruteforce")

    # 收集每账号的 challenge + nt_response + blob
    challenge_by_stream: dict = {}
    targets: list[dict] = []
    for event in events:
        ctx.check_cancel()
        stream = event["stream"]
        if event["type"] == ntlm_feat.TYPE2:
            challenge = event.get("challenge") or b""
            if challenge:
                challenge_by_stream[stream] = challenge
            continue
        if event["type"] != ntlm_feat.TYPE3:
            continue
        item = event.get("item", {})
        user = event.get("user") or item.get("ntlmssp.auth.username", "")
        domain = event.get("domain") or item.get("ntlmssp.auth.domain", "")
        challenge = (event.get("challenge") or challenge_by_stream.get(stream)
                     or b"")
        nt = event.get("nt") or b""
        ntproof = event.get("ntproof") or b""
        if user and challenge and (len(nt) > 24 or ntproof):
            proof = ntproof or nt[:16]
            blob = nt[16:] if len(nt) > 16 else b""
            if proof and blob:
                targets.append({
                    "frame": event["frame"], "user": user, "domain": domain,
                    "challenge": challenge, "proof": proof, "blob": blob,
                    "nt": nt, "identity": f"{domain}\\{user}",
                })
    if not targets:
        ctx.report("未找到同时含 challenge 与 nt_response 的 NTLMv2 账号", "warn")
        return

    ctx.report(f"找到 {len(targets)} 个可验证的 NetNTLMv2 账号", "info")

    # 预构造候选口令列表
    candidates: list[str] = []
    if explicit_password:
        candidates.append(explicit_password)
    if candidates_text:
        for token in _split_candidates(candidates_text):
            # 支持内置字典名（如 examples），其余视为明文
            if token in _DEFAULT_CANDIDATES:
                candidates.extend(_DEFAULT_CANDIDATES[token])
            else:
                candidates.append(token)
    if do_bruteforce:
        generated = ntlmcrack.generate_candidates(
            min_len=6, max_len=6, max_count=200_000,
            # ntlmcrack 的 cancel 回调语义是"返回 True 继续"；
            # check_cancel() 在已取消时抛 CancelledError（被回调内部当作停止）。
            cancel=lambda: not ctx.cancelled())
        for word in generated:
            candidates.append(word)

    resolved: list[dict] = []
    for target in targets:
        found = None
        nt_response = target["proof"] + target["blob"]
        if candidates:
            found = ntlmcrack.brute_force_ntlmv2(
                target["challenge"], nt_response, target["user"],
                target["domain"], candidates=candidates,
                max_attempts=500_000,
                # 回调返回 True 表示继续（ntlmcrack 内部取反为 should_stop）。
                cancel=lambda: not ctx.cancelled())
        else:
            # 预览：仅当用户显式给了 password 参数时做单口令验证
            if explicit_password:
                ok = ntlmcrack.verify_password(
                    explicit_password, target["challenge"], nt_response,
                    target["user"], target["domain"])
                found = explicit_password if ok else None

        record = dict(target)
        record["found"] = found
        resolved.append(record)

        if found:
            ctx.report(
                f"帧 {target['frame']} 账号 {target['identity']} 命中密码: {found}",
                "good")
            ctx.add_finding(
                "credential", f"NTLM 密码 {target['user']}=>{found}",
                frame=target["frame"], level="good",
                detail=f"{target['identity']} 的 NetNTLMv2 密码验证命中",
                extra={"kind": "ntlm-password", "account": target["identity"],
                       "user": target["user"], "domain": target["domain"],
                       "password": found})
        else:
            ctx.report(
                f"帧 {target['frame']} 账号 {target['identity']} 未命中，"
                "可改用 hashcat -m 5600（NetNTLMv2）/ -m 5500（NetNTLMv1）",
                "warn")

    # 落盘命中结果
    hits = [r for r in resolved if r["found"]]
    if hits:
        lines = [f"{r['identity']}    {r['found']}" for r in hits]
        ctx.write_output("ntlm_passwords.txt", "\n".join(lines) + "\n")
    ctx.report(
        f"验证完成：{len(hits)}/{len(resolved)} 个账号命中密码", "info")
    ctx.set_progress(100)