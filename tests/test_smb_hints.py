"""Unit tests for the SMB3 解密 “自动填入” suggestion builder (offline)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fnet import findings, smb3, smb_hints

NETNTLMV2 = ("alice::CORP:1122334455667788:"
             "aabbccddeeff00112233445566778899:0101000000000000")
NT_HASH = "8846f7eaee8fb117ad06bdd830b7586c"
BASE_KEY = "00112233445566778899aabbccddeeff" * 2
CIPHER_KEY = "a2f5e80e5d59103034f32e52f698e5ec"


def credential(frame="12", user="alice", domain="CORP", stream="3",
               with_hash=True) -> dict:
    """The ``SMB 账号 …`` credential finding written by features/smb.py."""
    extra = {"protocol": "smb2", "account": f"{domain}\\{user}",
             "user": user, "domain": domain, "workstation": "WS01",
             "auth": "NTLM", "stream": stream, "server": "10.0.0.2:445"}
    if with_hash:
        extra["hash"] = NETNTLMV2
        extra["mode"] = "5600"
    return findings.make("credential", f"SMB 账号 {domain}\\{user}",
                         frame=frame, level="good", detail="x", extra=extra)


def hash_finding(frame="12", user="alice", domain="CORP", stream="3") -> dict:
    return findings.make(
        "hash", f"SMB NetNTLMv2 {domain}\\{user}", frame=frame, level="good",
        detail=NETNTLMV2,
        extra={"protocol": "smb2", "account": f"{domain}\\{user}",
               "user": user, "domain": domain, "stream": stream,
               "hash": NETNTLMV2, "mode": "5600"})


def encrypted_traffic(stream="3", frame="21") -> dict:
    """The ``SMB3 加密流量`` finding: stream only, no account at all."""
    return findings.make(
        "protocol", "SMB3 加密流量", frame=frame, level="warn",
        detail=f"stream={stream} 加密消息=40",
        extra={"protocol": "smb2", "smb": "encrypted", "stream": stream,
               "session_id": "0x4000", "transforms": 40,
               "nonce": "01000000000000000000000000000000",
               "first_frame": frame})


def ntlm_password(password="Passw0rd!", user="alice", domain="CORP",
                  frame="33") -> dict:
    return findings.make(
        "credential", f"NTLM 密码 {password}", frame=frame, level="good",
        detail="NetNTLMv2 密码验证命中",
        extra={"kind": "ntlm-password", "account": f"{domain}\\{user}",
               "user": user, "domain": domain, "password": password})


def smb3_success(password="Passw0rd!") -> dict:
    """features/smb_intel.py 的结果：``session`` 会被 make() 字符串化。"""
    return findings.make(
        "grade", f"SMB3 解密成功（密码 {password!r}）", level="good",
        detail=f"password={password} 解密 4 条",
        extra={"protocol": "smb3", "password": password, "decrypted": 4,
               "sessions": 1,
               "session": {0: {"stream": "3", "user": "alice",
                               "session_key": CIPHER_KEY}}})


def saved_key(stream="3", session_key=BASE_KEY, cipher_key=CIPHER_KEY,
              user="alice", domain="CORP") -> dict:
    return {"stream": stream, "session_id": "0x4000", "cipher": "AES-GCM",
            "key_source": "ntlmv2+key-exchange:SMBC2SCipherKey:16",
            "session_key": session_key, "cipher_key": cipher_key,
            "user": user, "domain": domain}


class ShapeTest(unittest.TestCase):
    def test_shape_is_always_complete(self):
        result = smb_hints.decrypt_hints([])
        self.assertEqual(set(result), {"hints", "sources", "accounts",
                                       "notes"})
        for group in ("hints", "sources"):
            self.assertEqual(set(result[group]), set(smb_hints.FIELDS))
            for value in result[group].values():
                self.assertIsInstance(value, str)
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["notes"], [smb_hints.NOTHING_NOTE])

    def test_only_digits_streams(self):
        result = smb_hints.decrypt_hints([encrypted_traffic("3")],
                                         stream="abc")
        self.assertEqual(result["hints"]["stream"], "3")
        result = smb_hints.decrypt_hints([encrypted_traffic("3")],
                                         stream=" 7 ")
        self.assertEqual(result["hints"]["stream"], "7")
        self.assertEqual(result["sources"]["stream"], "用户指定的 TCP 流")


class JoinTest(unittest.TestCase):
    def test_account_password_and_stream_join(self):
        result = smb_hints.decrypt_hints(
            [credential(), hash_finding(), encrypted_traffic(),
             ntlm_password()])
        hints = result["hints"]
        self.assertEqual(hints["user"], "alice")
        self.assertEqual(hints["domain"], "CORP")
        self.assertEqual(hints["stream"], "3")
        self.assertEqual(hints["password"], "Passw0rd!")
        # SMB3 加密流量 结果里没有账号，只能靠 credential 结果关联出来
        self.assertEqual(result["sources"]["user"], "SMB NTLM 认证（帧 12）")
        self.assertEqual(result["sources"]["password"], "NTLM 破解命中")
        self.assertTrue(result["sources"]["stream"].startswith(
            "SMB3 加密流量（帧 21）"))
        self.assertEqual(len(result["accounts"]), 1, result["accounts"])
        account = result["accounts"][0]
        self.assertEqual(set(account), set(smb_hints.ACCOUNT_FIELDS))
        self.assertEqual(account["hash"], NETNTLMV2)
        self.assertEqual(account["mode"], "5600")
        self.assertEqual(account["password"], "Passw0rd!")
        notes = " ".join(result["notes"])
        self.assertIn("账号 CORP\\alice 来自", notes)
        self.assertIn("TCP 流 3 来自", notes)

    def test_netntlmv2_never_lands_in_nt_hash(self):
        result = smb_hints.decrypt_hints([credential(), hash_finding()])
        self.assertEqual(result["hints"]["nt_hash"], "")
        self.assertEqual(result["accounts"][0]["nt_hash"], "")
        self.assertEqual(result["accounts"][0]["hash"], NETNTLMV2)

    def test_bare_nt_hash_lands(self):
        record = findings.make(
            "credential", "SMB 账号 CORP\\alice", frame="12",
            extra={"protocol": "smb2", "account": "CORP\\alice",
                   "user": "alice", "domain": "CORP", "stream": "3",
                   "nt_hash": NT_HASH.upper()})
        result = smb_hints.decrypt_hints([record, encrypted_traffic()])
        self.assertEqual(result["hints"]["nt_hash"], NT_HASH)
        self.assertEqual(result["accounts"][0]["nt_hash"], NT_HASH)
        self.assertTrue(result["sources"]["nt_hash"].startswith(
            "SMB 账号发现"))

    def test_smb3_success_password_and_stringified_session(self):
        result = smb_hints.decrypt_hints([credential(with_hash=False),
                                          encrypted_traffic(),
                                          smb3_success()])
        self.assertEqual(result["hints"]["password"], "Passw0rd!")
        self.assertEqual(result["sources"]["password"],
                         "SMB3 智能串联解密成功")
        # 字符串化的 session 字典不解析，绝不外泄成 nt_hash/session_key
        self.assertEqual(result["hints"]["session_key"], "")
        self.assertEqual(result["hints"]["nt_hash"], "")

    def test_smb3_success_password_without_any_account(self):
        # SMB3 解密成功 只有密码（session 已被字符串化），没有账号也要给出密码
        result = smb_hints.decrypt_hints([smb3_success()])
        self.assertEqual(result["hints"]["password"], "Passw0rd!")
        self.assertEqual(result["sources"]["password"],
                         "SMB3 智能串联解密成功")
        self.assertEqual(result["hints"]["user"], "")
        self.assertEqual(len(result["accounts"]), 1, result["accounts"])
        self.assertEqual(result["accounts"][0]["source"],
                         "SMB3 智能串联解密成功")

    def test_anonymous_password_ignored_when_accounts_are_ambiguous(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False),
             credential(user="bob", stream="4", with_hash=False),
             smb3_success()])
        self.assertEqual(result["hints"]["password"], "")

    def test_hash_without_password_tells_user_to_crack(self):
        result = smb_hints.decrypt_hints([credential(), encrypted_traffic()])
        self.assertEqual(result["hints"]["password"], "")
        self.assertEqual(result["hints"]["user"], "alice")
        self.assertTrue(any("5600" in note for note in result["notes"]),
                        result["notes"])


class CrackedTest(unittest.TestCase):
    def test_cracked_entry_attaches_case_insensitively(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False), encrypted_traffic()],
            cracked=[{"user": "ALICE", "domain": "corp",
                      "password": "hunter2", "stream": "3",
                      "source": "hashcat 任务 7"}])
        self.assertEqual(result["hints"]["password"], "hunter2")
        self.assertEqual(result["sources"]["password"], "hashcat 任务 7")
        self.assertEqual(result["accounts"][0]["password"], "hunter2")

    def test_cracked_entry_can_create_account(self):
        result = smb_hints.decrypt_hints(
            [], cracked=[{"user": "bob", "domain": "LAB", "password": "x",
                          "stream": "5", "source": "本地 NTLM 破解"}])
        self.assertEqual(result["hints"]["user"], "bob")
        self.assertEqual(result["hints"]["domain"], "LAB")
        self.assertEqual(result["hints"]["password"], "x")

    def test_single_account_gets_the_only_password(self):
        # NTLM 验证命中给的身份和 SMB 账号对不上，但只有一个账号。
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False),
             ntlm_password(password="solo", user="OTHER", domain="OTHER")])
        self.assertEqual(result["hints"]["password"], "solo")


class SavedKeysTest(unittest.TestCase):
    def test_session_key_prefers_matching_stream(self):
        records = [credential(with_hash=False), encrypted_traffic("3")]
        result = smb_hints.decrypt_hints(
            records, saved_keys=[saved_key(stream="7", session_key=NT_HASH),
                                 saved_key(stream="3")])
        self.assertEqual(result["hints"]["session_key"], BASE_KEY)
        self.assertEqual(result["sources"]["session_key"],
                         "上次 SMB3 解密（smb3_keys.txt）")
        self.assertIn("会话密钥来自", " ".join(result["notes"]))

    def test_session_key_by_requested_stream(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False)], stream="7",
            saved_keys=[saved_key(stream="3"),
                        saved_key(stream="7", session_key=NT_HASH)])
        self.assertEqual(result["hints"]["session_key"], NT_HASH)
        self.assertEqual(result["hints"]["stream"], "7")

    def test_session_key_only_entry(self):
        result = smb_hints.decrypt_hints([], saved_keys=[saved_key()])
        self.assertEqual(result["hints"]["session_key"], BASE_KEY)

    def test_garbage_session_key_falls_back_then_ignored(self):
        result = smb_hints.decrypt_hints(
            [], saved_keys=[saved_key(session_key="zzzz"),
                            saved_key(stream="9")])
        self.assertEqual(result["hints"]["session_key"], BASE_KEY)
        self.assertEqual(result["sources"]["session_key"],
                         "上次 SMB3 解密（smb3_keys.txt）")
        result = smb_hints.decrypt_hints(
            [], saved_keys=[saved_key(session_key=""),
                            saved_key(session_key="不是十六进制")])
        self.assertEqual(result["hints"]["session_key"], "")
        self.assertEqual(result["sources"]["session_key"], "")


class DefensiveTest(unittest.TestCase):
    def test_garbage_inputs_never_raise(self):
        cases = [
            None,
            [],
            "不是列表",
            {"a": 1},
            [None, "x", 7, {}, {"extra": "不是字典"},
             findings.make("hash", "x", extra={"protocol": "smb2",
                                               "stream": 3, "user": None,
                                               "hash": {"a": 1},
                                               "mode": ["5600"]})],
            [encrypted_traffic(stream="x"), credential()],
            [smb3_success()],
        ]
        for item in cases:
            with self.subTest(findings=item):
                result = smb_hints.decrypt_hints(item)
                self.assertEqual(set(result), {"hints", "sources",
                                               "accounts", "notes"})
                self.assertIsInstance(result["notes"], list)
                self.assertLessEqual(len(result["notes"]),
                                     smb_hints.MAX_NOTES)

    def test_bad_optional_arguments(self):
        result = smb_hints.decrypt_hints([credential()], stream=None,
                                        cracked="oops", saved_keys=5)
        self.assertEqual(result["hints"]["user"], "alice")
        self.assertEqual(result["hints"]["session_key"], "")
        result = smb_hints.decrypt_hints([credential()], cracked=[None, 3],
                                        saved_keys=[None, "x", [1]])
        self.assertEqual(result["hints"]["user"], "alice")

    def test_notes_capped(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False), encrypted_traffic()],
            cracked=[{"user": "alice", "domain": "CORP", "password": "p",
                      "nt_hash": NT_HASH, "source": "任务"}],
            saved_keys=[saved_key()])
        self.assertLessEqual(len(result["notes"]), smb_hints.MAX_NOTES)
        self.assertTrue(all(isinstance(note, str) and note
                            for note in result["notes"]))


class FakeJobs:
    """最小 JobManager 替身：只提供 findings_for / output_dir_for。"""

    def __init__(self, records, output=None, raises=False):
        self.records = records
        self.output = output
        self.raises = raises

    def findings_for(self, job_id, query="", kind="", level="",
                     limit=5000) -> dict | None:
        if self.raises:
            raise RuntimeError("任务不存在")
        return {"findings": list(self.records), "total": len(self.records)}

    def output_dir_for(self, job_id):
        return Path(self.output) if self.output else None


class HintsForJobTest(unittest.TestCase):
    def test_reads_findings_and_key_file(self):
        records = [credential(with_hash=False), encrypted_traffic()]
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / smb3.KEYS_FILE_NAME).write_text(
                smb3.keys_file_text([saved_key()]), encoding="utf-8")
            result = smb_hints.hints_for_job(FakeJobs(records, tmp), "job-1")
        self.assertEqual(result["hints"]["user"], "alice")
        self.assertEqual(result["hints"]["domain"], "CORP")
        self.assertEqual(result["hints"]["stream"], "3")
        self.assertEqual(result["hints"]["session_key"], BASE_KEY)
        self.assertEqual(result["sources"]["session_key"],
                         "上次 SMB3 解密（smb3_keys.txt）")

    def test_stream_argument_passed_through(self):
        records = [credential(with_hash=False), encrypted_traffic("3")]
        result = smb_hints.hints_for_job(FakeJobs(records), "job-1",
                                         stream="9")
        self.assertEqual(result["hints"]["stream"], "9")

    def test_missing_key_file_is_fine(self):
        result = smb_hints.hints_for_job(
            FakeJobs([credential(), encrypted_traffic()], "/nonexistent"),
            "job-1")
        self.assertEqual(result["hints"]["user"], "alice")
        self.assertEqual(result["hints"]["session_key"], "")

    def test_broken_manager_degrades(self):
        for manager in (FakeJobs([], None, raises=True), object(), None):
            with self.subTest(manager=type(manager).__name__):
                result = smb_hints.hints_for_job(manager, "job-x")
                self.assertEqual(set(result), {"hints", "sources",
                                               "accounts", "notes"})
                self.assertFalse(any(result["hints"].values()))
                self.assertTrue(result["notes"])

    def test_none_findings_payload(self):
        class Empty:
            def findings_for(self, job_id, **kwargs):
                return None

            def output_dir_for(self, job_id):
                return None

        result = smb_hints.hints_for_job(Empty(), "job-y")
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["notes"], [smb_hints.NOTHING_NOTE])


# ---------------------------------------------------------------------------
# 双加密流 / 新 finding 形状的回归夹具（离线）
# ---------------------------------------------------------------------------
def ntlm_line(user="Administrator", domain="LAB", seed="aa") -> str:
    return (f"{user}::{domain}:1122334455667788:"
            f"{seed}00112233445566778899:{seed}aabbccddeeff")


def ntlm_hash_extract(user="Administrator", domain="LAB", frame="8") -> dict:
    """features/ntlm.py 的 ``NTLM HASH提取``：没有 user / stream 键。"""
    line = ntlm_line(user, domain)
    return findings.make(
        "hash", f"{domain}\\{user} NTLM HASH提取", frame=frame, level="good",
        detail=line,
        extra={"protocol": "ntlm", "account": f"{domain}\\{user}",
               "domain": domain, "hash": line, "mode": "5600"})


def verified_hit(label: str, password: str, frame="") -> dict:
    """features/smb_intel.py 的 ``NTLM 密码验证命中``：只有 account 标签。"""
    return findings.make(
        "credential", f"NTLM 密码验证命中 {label}", frame=frame, level="good",
        detail=f"password={password}",
        extra={"protocol": "smb2", "account": label, "password": password,
               "verified": True, "mode": "5600"})


def intel_account(user: str, domain: str, stream: str, frame="") -> dict:
    label = f"{domain}\\{user}"
    return findings.make(
        "credential", f"SMB NTLM 账号 {label} (stream={stream})", frame=frame,
        level="good", detail=f"user={user} domain={domain} stream={stream}",
        extra={"protocol": "smb2", "account": label, "user": user,
               "domain": domain, "stream": stream,
               "challenge": "1122334455667788", "nt_response": "aa" * 32,
               "session": {stream: {"stream": stream, "user": user}}})


def encrypted_with_identity(stream: str, user: str, domain: str,
                            frame="21") -> dict:
    label = f"{domain}\\{user}"
    return findings.make(
        "protocol", "SMB3 加密流量", frame=frame, level="warn",
        detail=f"stream={stream} 加密消息=40",
        extra={"protocol": "smb2", "smb": "encrypted", "stream": stream,
               "account": label, "user": user, "domain": domain,
               "hash": ntlm_line(user, domain, "bb"), "mode": "5600",
               "session_id": f"0x8{stream}", "first_frame": frame})


def legacy_candidates(stream: str, user: str, domain: str) -> dict:
    """旧任务的候选密码信息行：candidates 是一大串，绝不能当密码。"""
    label = f"{domain}\\{user}"
    return findings.make(
        "protocol", f"SMB 候选密码 流 {stream}", level="info",
        detail=f"账号={label} 样例=LEGACY_SENTINEL_{stream}",
        extra={"protocol": "smb2", "stream": stream, "account": label,
               "candidates": [f"LEGACY_SENTINEL_{stream}_{i}"
                              for i in range(50)]})


def legacy_negotiate(stream: str) -> dict:
    return findings.make(
        "protocol", "SMB 协商 SMB 3.1.1", level="info",
        detail=f"stream={stream}",
        extra={"protocol": "smb2", "smb": "negotiate", "stream": stream,
               "dialect": "SMB 3.1.1"})


def screenshot_findings() -> list[dict]:
    """截图里的 12 条结果：两条加密流、两个账号、混合新老 finding 形状。"""
    return [
        ntlm_hash_extract("Administrator", "LAB", "8"),
        ntlm_hash_extract("winuser", "LAB", "9"),
        legacy_candidates("0", "winuser", "LAB"),
        legacy_candidates("1", "Administrator", "LAB"),
        legacy_negotiate("0"),
        legacy_negotiate("1"),
        encrypted_with_identity("0", "winuser", "LAB", "21"),
        encrypted_with_identity("1", "Administrator", "LAB", "22"),
        intel_account("winuser", "LAB", "0", "12"),
        intel_account("Administrator", "LAB", "1", "14"),
        verified_hit("LAB\\winuser", "WinPass123", "33"),
        verified_hit("LAB\\Administrator", "AdminPass456", "34"),
    ]


def assert_shape(test, result: dict) -> None:
    test.assertEqual(set(result), {"hints", "sources", "accounts", "notes"})
    for group in ("hints", "sources"):
        test.assertEqual(set(result[group]), set(smb_hints.FIELDS))
        for value in result[group].values():
            test.assertIsInstance(value, str)
    for account in result["accounts"]:
        test.assertEqual(set(account), set(smb_hints.ACCOUNT_FIELDS))
        for value in account.values():
            test.assertIsInstance(value, str)
    for note in result["notes"]:
        test.assertIsInstance(note, str)
    test.assertLessEqual(len(result["notes"]), smb_hints.MAX_NOTES)
    json.dumps(result, ensure_ascii=False)


class ScreenshotTest(unittest.TestCase):
    """复现真实截图：两条加密流互不串号。"""

    def test_stream_zero_uses_winuser(self):
        result = smb_hints.decrypt_hints(screenshot_findings(), stream="0")
        assert_shape(self, result)
        hints = result["hints"]
        self.assertEqual((hints["user"], hints["domain"], hints["stream"]),
                         ("winuser", "LAB", "0"))
        self.assertEqual(hints["password"], "WinPass123")
        self.assertNotIn("AdminPass456", hints["password"])
        self.assertEqual(hints["nt_hash"], "")
        account = next(a for a in result["accounts"]
                       if a["user"] == "winuser")
        self.assertEqual(account["stream"], "0")
        self.assertEqual(account["password"], "WinPass123")
        self.assertEqual(account["hash"], ntlm_line("winuser", "LAB"))
        self.assertEqual(account["mode"], "5600")

    def test_stream_one_uses_administrator_and_netntlmv2(self):
        result = smb_hints.decrypt_hints(screenshot_findings(), stream="1")
        assert_shape(self, result)
        hints = result["hints"]
        self.assertEqual((hints["user"], hints["domain"], hints["stream"]),
                         ("Administrator", "LAB", "1"))
        self.assertEqual(hints["password"], "AdminPass456")
        self.assertNotIn("WinPass123", hints["password"])
        self.assertEqual(hints["nt_hash"], "")
        account = next(a for a in result["accounts"]
                       if a["user"] == "Administrator")
        self.assertEqual(account["stream"], "1")
        self.assertEqual(account["password"], "AdminPass456")
        self.assertEqual(account["hash"], ntlm_line("Administrator", "LAB"))
        self.assertEqual(account["mode"], "5600")

    def test_no_stream_is_deterministic_and_notes_multiple_streams(self):
        records = screenshot_findings()
        first = smb_hints.decrypt_hints(records)
        second = smb_hints.decrypt_hints(list(reversed(records)))
        assert_shape(self, first)
        # 输入顺序不影响选中的流/账号/口令，也不影响账号排序。
        self.assertEqual(first["hints"], second["hints"])
        selected = lambda result: [
            (a["user"], a["domain"], a["stream"], a["password"], a["hash"])
            for a in result["accounts"]]
        self.assertEqual(selected(first), selected(second))
        self.assertEqual(first["hints"]["stream"], "0")
        self.assertEqual(first["hints"]["user"], "winuser")
        notes = " ".join(first["notes"])
        self.assertIn("2 条 SMB3 加密流", notes)
        self.assertEqual(len(first["accounts"]), 2)
        self.assertEqual(
            sorted((a["user"], a["password"]) for a in first["accounts"]),
            [("Administrator", "AdminPass456"), ("winuser", "WinPass123")])

    def test_no_account_gets_another_accounts_secret(self):
        for requested in ("", "0", "1"):
            with self.subTest(stream=requested):
                result = smb_hints.decrypt_hints(screenshot_findings(),
                                                 stream=requested)
                for account in result["accounts"]:
                    expected = ("WinPass123" if account["user"] == "winuser"
                                else "AdminPass456")
                    self.assertEqual(account["password"], expected)
                    self.assertTrue(account["hash"].startswith(
                        f"{account['user']}::LAB:"))
                    self.assertEqual(result["hints"]["nt_hash"], "")

    def test_legacy_candidates_never_become_password(self):
        result = smb_hints.decrypt_hints(screenshot_findings())
        blob = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("LEGACY_SENTINEL", blob)
        self.assertNotIn("LEGACY_SENTINEL", result["hints"]["password"])


class NewSourcesTest(unittest.TestCase):
    def test_ntlm_hash_extract_merges_with_smb_credential(self):
        line = ntlm_line("Administrator", "LAB", "cc")
        record = findings.make(
            "hash", "LAB\\Administrator NTLM HASH提取", frame="8",
            extra={"protocol": "ntlm", "account": "LAB\\Administrator",
                   "domain": "LAB", "hash": line, "mode": "5600"})
        result = smb_hints.decrypt_hints(
            [record, credential(user="Administrator", domain="LAB",
                                stream="1", with_hash=False)], stream="1")
        assert_shape(self, result)
        self.assertEqual(len(result["accounts"]), 1)
        self.assertEqual(result["hints"]["user"], "Administrator")
        self.assertEqual(result["accounts"][0]["hash"], line)
        self.assertEqual(result["hints"]["nt_hash"], "")

    def test_verified_hit_without_kind_uses_account_label(self):
        result = smb_hints.decrypt_hints(
            [intel_account("winuser", "LAB", "0"),
             verified_hit("LAB\\winuser", "P@ss123")], stream="0")
        self.assertEqual(result["hints"]["password"], "P@ss123")
        self.assertEqual(result["hints"]["user"], "winuser")
        self.assertEqual(len(result["accounts"]), 1)


class GuardTest(unittest.TestCase):
    def test_anonymous_password_gets_a_note_when_ambiguous(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False),
             credential(user="bob", stream="4", with_hash=False),
             smb3_success()])
        self.assertEqual(result["hints"]["password"], "")
        notes = " ".join(result["notes"])
        self.assertIn("忽略", notes)

    def test_unrelated_saved_keys_ignored_with_note(self):
        result = smb_hints.decrypt_hints(
            [credential(with_hash=False), encrypted_traffic("3")],
            stream="9",
            saved_keys=[saved_key(stream="0", session_key=NT_HASH),
                        saved_key(stream="1")])
        self.assertEqual(result["hints"]["session_key"], "")
        notes = " ".join(result["notes"])
        self.assertIn("会话密钥", notes)
        self.assertIn("忽略", notes)

    def test_legacy_noise_alone_is_not_a_hint_source(self):
        result = smb_hints.decrypt_hints(
            [legacy_candidates("3", "alice", "CORP"), legacy_negotiate("3")])
        assert_shape(self, result)
        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["hints"]["password"], "")
        self.assertNotIn("LEGACY_SENTINEL", json.dumps(result))

    def test_colon_separated_hash_never_becomes_nt_hash(self):
        colon_line = ":".join(["ab"] * 16)  # 剥掉冒号正好 32 位十六进制
        record = findings.make(
            "credential", "SMB 账号 CORP\\alice",
            extra={"protocol": "smb2", "user": "alice", "domain": "CORP",
                   "stream": "3", "hash": colon_line})
        result = smb_hints.decrypt_hints([record])
        self.assertEqual(result["hints"]["nt_hash"], "")
        self.assertEqual(result["accounts"][0]["hash"], colon_line)

    def test_malformed_extra_shapes_never_raise(self):
        records = [
            {"extra": None},
            {"extra": {"protocol": ["smb2"], "user": {"u": 1},
                       "domain": None, "stream": [3], "hash": ["aa"],
                       "account": 42, "verified": "True",
                       "password": ["p"]}},
            findings.make("hash", "LAB\\big NTLM HASH提取",
                          extra={"protocol": "ntlm",
                                 "account": "LAB\\" + "A" * 5000,
                                 "domain": "LAB", "hash": "f" * 9000,
                                 "mode": "5600"}),
            None, 12, "x",
        ]
        result = smb_hints.decrypt_hints(records)
        assert_shape(self, result)
        for account in result["accounts"]:
            self.assertLessEqual(len(account["user"]), 128)
            self.assertLessEqual(len(account["domain"]), 128)
            self.assertLessEqual(len(account["hash"]), 200)

    def test_account_count_and_account_sorting_are_bounded(self):
        records = [
            findings.make("credential", f"SMB 账号 LAB\\u{i}",
                          extra={"protocol": "smb2", "user": f"u{i}",
                                 "domain": "LAB", "stream": str(i % 3),
                                 "hash": ntlm_line(f"u{i}", "LAB")})
            for i in range(100)]
        result = smb_hints.decrypt_hints(records)
        assert_shape(self, result)
        self.assertLessEqual(len(result["accounts"]), 64)
        keys = [(a["stream"], a["user"], a["domain"])
                for a in result["accounts"]]
        self.assertEqual(keys, sorted(keys, key=lambda k: (
            int(k[0]) if k[0].isdigit() else 10 ** 9, k[1], k[2])))
        self.assertTrue(any("64" in note for note in result["notes"]))

    def test_5200_findings_stay_bounded(self):
        records = [
            findings.make("hash", f"LAB\\u{i} NTLM HASH提取",
                          extra={"protocol": "ntlm",
                                 "account": f"LAB\\u{i}", "domain": "LAB",
                                 "hash": ntlm_line(f"u{i}", "LAB"),
                                 "mode": "5600"})
            for i in range(5200)]
        result = smb_hints.decrypt_hints(records)
        assert_shape(self, result)
        self.assertLessEqual(len(result["accounts"]), 64)


if __name__ == "__main__":
    unittest.main()
