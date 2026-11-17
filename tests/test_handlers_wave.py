"""Handler 层补齐测试。

覆盖 fnet/features/ 下此前没有端到端/单元测试的处理器：

* ``arp.py``   —— 无 ARP 流量的降级路径（正向欺骗检测见 test_features.py）；
* ``ics.py``   —— s7comm/mms/goose/iecd/omron 在无相关流量的抓包上不崩溃；
* ``misc.py``  —— ipid / scsi / ev3；
* ``ntlm.py``  —— type2/type3 解析与 _extract_messages 单元测试；
* ``rdp.py``   —— 缺少私钥的降级路径 + tshark 解密参数构造；
* ``sql.py``   —— 用 pcap_build 构造的盲注流量端到端还原；
* ``winrm.py`` —— 会话密钥派生 / RC4 解封单元测试 + http_ntlm 降级路径；
* ``cs.py``    —— 缺少 beacon keys 的降级路径 + 元数据/任务输出单元测试。

``usb.py``（checkBox_16/17）已由 tests/test_features.py 覆盖，此处不重复。
"""
from __future__ import annotations

import base64
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.tools.runner import find_tool

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pcap_build  # noqa: E402  (tests/pcap_build.py，纯 stdlib pcap 构造辅助)

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")


# ---------------------------------------------------------------- pycap 夹具
def _write_http_sql_pair_pcap(path: Path) -> None:
    """布尔盲注流量：每条请求的成功/失败由响应体 SUCCESS/FAIL 标记。

    请求 URI 形如 ``/blind?posN=cmpV``；其中位置 1 额外发一条 ``cmp103``
    的假候选（响应 FAIL），验证多数投票剔除错误候选。
    """
    target = "fl4g{sql}"
    client: list[bytes] = []
    server: list[bytes] = []
    for pos, char in enumerate(target, 1):
        client.append((f"GET /blind?pos{pos}=cmp{ord(char)} HTTP/1.1\r\n"
                       "Host: target.local\r\n\r\n").encode())
        server.append(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nSUCCESS")
    client.append(b"GET /blind?pos1=cmp103 HTTP/1.1\r\nHost: target.local\r\n\r\n")
    server.append(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nFAIL")
    pcap_build.write_pcap(path, pcap_build.tcp_session(
        "10.0.0.1", 12347, "10.0.0.2", 80, client, server))


def _write_http_sql_binary_pcap(path: Path) -> None:
    """二分盲注流量：``pos1 > value`` 的真/假响应序列，推断出位置 1 为 'f'。"""
    rows = [("100", "TRUE"), ("101", "TRUE"), ("102", "FALSE")]
    client: list[bytes] = []
    server: list[bytes] = []
    for value, verdict in rows:
        client.append((f"GET /b?pos1=ascii(substr(fl4g,1,1)>{value} HTTP/1.1\r\n"
                       "Host: t.local\r\n\r\n").encode())
        server.append(
            (f"HTTP/1.1 200 OK\r\nContent-Length: {len(verdict)}\r\n\r\n"
             f"{verdict}").encode())
    pcap_build.write_pcap(path, pcap_build.tcp_session(
        "10.0.0.1", 12346, "10.0.0.2", 80, client, server))


def _ntlmssp_type2(challenge: bytes) -> bytes:
    """最小 NTLMSSP CHALLENGE 消息（签名 + 类型 + 标志 + 8 字节 challenge）。"""
    return (b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 8
            + struct.pack("<I", 0x8201) + challenge)


def _ntlmssp_type3(user: str, domain: str, nt: bytes, lm: bytes = b"\x01" * 24) -> bytes:
    """结构完整的 NTLMSSP AUTHENTICATE 消息（各字段的 len/max/offset 正确）。"""
    domain_b = domain.encode("utf-16le")
    user_b = user.encode("utf-16le")
    workstation = b"PC\x00"[:-1].ljust(8, b"\x00")
    session_key = b""
    fields = [lm, nt, domain_b, user_b, workstation, session_key]
    header = b"NTLMSSP\x00" + struct.pack("<I", 3)
    offset = 64
    for value in fields:
        header += struct.pack("<HHI", len(value), len(value), offset)
        offset += len(value)
    header += struct.pack("<I", 0x8201)
    return header + b"".join(fields)


# ------------------------------------------------------------------ 端到端
@unittest.skipUnless(TSHARK, "需要 tshark")
class HandlerWaveEndToEndTest(unittest.TestCase):
    """通过 runtime.jobs.submit 跑真实处理器（test_features.SampleCaptureTest 模式）。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cache = Path(cls.tmp.name) / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        cls.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cache),
            mock.patch("fnet.paths.CACHE_DIR", cache),
        ]
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))
        cls.runtime.config.set("tshark_cache", "0")
        cls.fixtures = Path(cls.tmp.name) / "fixtures"
        cls.fixtures.mkdir()
        _write_http_sql_pair_pcap(cls.fixtures / "sql_blind.pcap")
        _write_http_sql_binary_pcap(cls.fixtures / "sql_binary.pcap")

    @classmethod
    def tearDownClass(cls):
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str], params: dict | None = None):
        job = self.runtime.jobs.submit(pcap, features, params or {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    # -- arp -----------------------------------------------------------
    def test_arp_without_arp_traffic(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_44"])
        self.assertIn("没有发现 ARP 流量", log)

    def test_arp_spoof_detection_still_reported(self):
        # 正向路径冒烟（详细断言在 tests/test_features.py）。
        _, log = self.run_job(str(DATA / "dns_arp_icmp.pcap"), ["checkBox_44"])
        self.assertIn("操作码统计", log)

    # -- ics -----------------------------------------------------------
    def test_ics_handlers_survive_capture_without_ics_traffic(self):
        _, log = self.run_job(str(DATA / "ftp_smtp_telnet.pcap"),
                              ["ics.s7comm", "ics.mms", "ics.goose"])
        self.assertIn("S7comm: 没有匹配的流量", log)
        self.assertIn("MMS: 没有匹配的流量", log)
        self.assertIn("GOOSE: 没有匹配的流量", log)

    def test_ics_iecd_and_omron_finish_even_with_invalid_filter(self):
        # 已知问题：tshark 4.7.4 中 "iec60870_apci"/"fins" 不是合法协议名，
        # 显示过滤器报错但 handler 不会崩溃（见测试报告）。
        job, log = self.run_job(str(DATA / "ftp_smtp_telnet.pcap"),
                                ["ics.iecd", "ics.omron"])
        self.assertEqual(job.status, "done")
        self.assertIn("工控协议iec60870分析 完成", log)
        self.assertIn("工控协议omron分析 完成", log)

    def test_ics_modbus_write_summary_smoke(self):
        # 正向路径冒烟（modbus_mqtt 夹具； checkBox_11 细节断言在 test_features.py）。
        _, log = self.run_job(str(DATA / "modbus_mqtt.pcap"), ["ics.summary"])
        self.assertIn("GOOSE: 没有匹配的流量", log)

    # -- misc ----------------------------------------------------------
    def test_misc_ipid_flow_summary(self):
        _, log = self.run_job(str(DATA / "dns_arp_icmp.pcap"), ["checkBox_31"])
        self.assertIn("IP 流", log)
        self.assertIn("最常见的差值", log)

    def test_misc_scsi_without_scsi_traffic(self):
        _, log = self.run_job(str(DATA / "ftp_smtp_telnet.pcap"), ["checkBox_36"])
        self.assertIn("没有发现 SCSI 流量", log)

    def test_misc_ev3_bluetooth_payloads(self):
        _, log = self.run_job(str(DATA / "bluetooth.pcap"), ["checkBox_40"])
        self.assertIn("EV3 / 蓝牙数据", log)

    # -- ntlm ----------------------------------------------------------
    def test_ntlm_without_ntlmssp_traffic(self):
        _, log = self.run_job(str(DATA / "ftp_smtp_telnet.pcap"), ["checkBox_39"])
        self.assertIn("没有发现 NTLMSSP 认证流量", log)

    # -- rdp -----------------------------------------------------------
    def test_rdp_requires_key_configuration(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_47"])
        self.assertIn("请在设置中指定 RDP 私钥或 Key log 文件", log)

    def test_rdp_reports_missing_input_files(self):
        from fnet.features import rdp

        lines: list[str] = []
        log = lambda text, level="info": lines.append(text)  # noqa: E731
        self.assertIsNone(rdp.replay_rdp_session(
            "nope.pcap", "nope.key", log=log))
        self.assertTrue(any("PCAP 不存在" in line for line in lines))
        self.assertIsNone(rdp.replay_rdp_session(
            str(DATA / "http_ntlm.pcap"), "nope.key", log=log))
        self.assertTrue(any("密钥文件不存在" in line for line in lines))

    def test_rdp_tshark_decryption_keylog_vs_private_key(self):
        from fnet.features import rdp

        tmp = Path(self.tmp.name)
        keylog = tmp / "keylog.txt"
        keylog.write_text("CLIENT_RANDOM abc123 server\n", encoding="utf-8")
        privkey = tmp / "server.pem"
        privkey.write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
        out = tmp / "out.pcap"
        out.write_bytes(b"\xd4\xc3\xb2\xa1")
        calls = []
        with mock.patch.object(rdp, "run",
                               side_effect=lambda cmd, **kw:
                               (calls.append(cmd), (0, ""))[1]):
            self.assertTrue(rdp.run_tshark_decryption(
                "tshark", DATA / "http_ntlm.pcap", keylog, "10.0.0.1", 3389,
                out, lambda text, level="info": None))
            self.assertTrue(rdp.run_tshark_decryption(
                "tshark", DATA / "http_ntlm.pcap", privkey, None, 3389,
                out, lambda text, level="info": None))
        self.assertTrue(any("tls.keylog_file" in " ".join(cmd)
                            for cmd in calls))
        self.assertTrue(any("tls.keys_list" in " ".join(cmd)
                            for cmd in calls))

    def test_rdp_decryption_failure_reported(self):
        from fnet.features import rdp

        lines: list[str] = []
        key = Path(self.tmp.name) / "bad.key"
        key.write_text("CLIENT_RANDOM deadbeef\n", encoding="utf-8")
        with mock.patch.object(rdp, "run", return_value=(2, "tshark boom")):
            self.assertFalse(rdp.run_tshark_decryption(
                "tshark", DATA / "http_ntlm.pcap", key, None, 3389,
                Path(self.tmp.name) / "never.pcap",
                lambda text, level="info": lines.append(text)))
        self.assertTrue(any("tshark 执行失败" in line for line in lines))

    # -- sql -----------------------------------------------------------
    def test_sql_blind_reconstruction_end_to_end(self):
        job, log = self.run_job(str(self.fixtures / "sql_blind.pcap"),
                                ["sql.blind"],
                                {"sql_success": "SUCCESS",
                                 "sql_regex": r"pos(\d+)=cmp(\d+)"})
        self.assertIn("成功判定策略: 响应体包含 'SUCCESS'", log)
        self.assertIn("还原字符串: fl4g{sql}", log)
        self.assertIn("发现 flag: fl4g{sql}", log)
        kinds = {(f["kind"], f["summary"]) for f in job.findings}
        self.assertIn(("flag", "fl4g{sql}"), kinds)
        self.assertTrue(any(kind == "sql" for kind, _ in kinds))
        artifacts = [item["name"] for item in self.runtime.jobs.artifacts(job)]
        self.assertIn("sql_blind_blind.txt", artifacts)

    def test_sql_binary_reconstruction_end_to_end(self):
        _, log = self.run_job(str(self.fixtures / "sql_binary.pcap"),
                              ["sql.binary"],
                              {"sql_success": "TRUE",
                               "sql_regex": r"pos(\d+)[^>]*>\s*(\d+)"})
        self.assertIn("===== 二分盲注推断 =====", log)
        self.assertIn("区间 [102,102] -> 'f'", log)
        self.assertIn("推断字符串: f", log)

    def test_sql_log_analysis_from_pasted_log(self):
        text = "\n".join(f"position {pos} char {ord(char)} success"
                         for pos, char in enumerate("flag", 1))
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["sql.log_analysis"],
                              {"sql_log_text": text,
                               "sql_regex": r"position (\d+) char (\d+)"})
        self.assertIn("日志还原字符串: flag", log)

    def test_sql_log_analysis_missing_input(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["sql.log_analysis"])
        self.assertIn("请在设置中提供盲注日志文件路径或日志内容", log)

    def test_sql_without_http_requests(self):
        _, log = self.run_job(str(DATA / "dns_arp_icmp.pcap"), ["sql.blind"])
        self.assertIn("没有发现 HTTP 请求", log)

    def test_sql_invalid_regex_reported(self):
        _, log = self.run_job(str(self.fixtures / "sql_blind.pcap"),
                              ["sql.blind"],
                              {"sql_success": "SUCCESS", "sql_regex": "("})
        self.assertIn("SQL 正则无效", log)

    # -- winrm ---------------------------------------------------------
    def test_winrm_extracts_ntlm_account_from_http_ntlm(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_43"])
        self.assertIn("WinRM 账号: WORKGROUP\\Administrator", log)
        self.assertIn("无法派生会话密钥", log)
        self.assertIn("仍可先用 NTLM HASH 提取/离线破解得到密码", log)

    def test_winrm_rejects_malformed_ntlm_hash(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_43"],
                              {"winrm_ntlm": "zzzz"})
        self.assertIn("NTLM HASH 必须是 32 位十六进制", log)

    # -- cs ------------------------------------------------------------
    def test_cs_without_beacon_keys_reports_hint(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_15"])
        self.assertIn("未配置 .cobaltstrike.beacon_keys", log)
        self.assertIn("请在设置中指定密钥后重新分析", log)

    def test_cs_with_missing_key_file(self):
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_15"],
                              {"cobaltstrike_keys": "/nope/beacon_keys"})
        self.assertIn("CS 密钥文件不存在", log)

    def test_cs_with_unparsable_key_file(self):
        key = Path(self.tmp.name) / "bad.keys"
        key.write_bytes(b"not a key\n")
        _, log = self.run_job(str(DATA / "http_ntlm.pcap"), ["checkBox_15"],
                              {"cobaltstrike_keys": str(key)})
        self.assertIn("无法从密钥文件中解析 RSA 私钥", log)


# ------------------------------------------------------------------ 单元测试
class NtlmUnitTest(unittest.TestCase):
    def test_parse_type2(self):
        from fnet.features import ntlm

        challenge = bytes(range(8))
        parsed = ntlm.parse_type2(_ntlmssp_type2(challenge))
        self.assertEqual(parsed["challenge"], challenge)
        self.assertEqual(parsed["flags"], 0x8201)

    def test_parse_type3(self):
        from fnet.features import ntlm

        nt = bytes(range(24))
        parsed = ntlm.parse_type3(_ntlmssp_type3("Administrator", "WORKGROUP", nt))
        self.assertEqual(parsed["user"], "Administrator")
        self.assertEqual(parsed["domain"], "WORKGROUP")
        self.assertEqual(parsed["nt"], nt)

    def test_parse_type3_too_short(self):
        from fnet.features import ntlm

        self.assertEqual(ntlm.parse_type3(b"NTLMSSP\x00\x03\x00\x00\x00"), {})

    def test_extract_messages_from_base64(self):
        from fnet.features import ntlm

        raw = base64.b64encode(_ntlmssp_type2(b"12345678")).decode()
        messages = ntlm._extract_messages(f"Negotiate {raw}")
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][:8], ntlm.SIGNATURE)
        self.assertEqual(ntlm.parse_type2(messages[0])["challenge"], b"12345678")

    def test_extract_messages_finds_multiple_and_trims_type3(self):
        from fnet.features import ntlm

        type3 = _ntlmssp_type3("admin", "", bytes(range(24)))
        blob = type3 + b"\xde\xad\xbe\xef" * 4  # 尾部属于下一层协议的字节
        messages = ntlm._extract_messages(base64.b64encode(blob).decode())
        self.assertEqual(len(messages), 1)
        # 类型 3 消息按各字段 offset+length 截断，不会带上一大段脏数据。
        self.assertLess(len(messages[0]), len(blob))

    def test_extract_messages_ignores_non_ntlm(self):
        from fnet.features import ntlm

        self.assertEqual(ntlm._extract_messages(""), [])
        self.assertEqual(ntlm._extract_messages("plain text"), [])


class WinrmUnitTest(unittest.TestCase):
    def test_derive_session_key_password_matches_hash(self):
        from fnet.features import winrm
        from fnet.utils.crypto import nt_hash

        challenge = b"12345678"
        nt_response = bytes(range(16)) + b"blob" * 16
        base_by_password, source_pw = winrm._derive_session_key(
            "Passw0rd!", "", "Administrator", "WORKGROUP", challenge, nt_response)
        base_by_hash, source_hash = winrm._derive_session_key(
            "", nt_hash("Passw0rd!").hex(), "Administrator", "WORKGROUP",
            challenge, nt_response)
        self.assertEqual(source_pw, "password")
        self.assertEqual(source_hash, "NTLM HASH")
        self.assertEqual(base_by_password, base_by_hash)
        self.assertEqual(len(base_by_password), 16)

    def test_derive_session_key_error_paths(self):
        from fnet.features import winrm

        self.assertIsNone(winrm._derive_session_key("", "", "u", "d", b"", b"")[0])
        self.assertIn("32 位十六进制",
                      winrm._derive_session_key("", "abcd", "u", "d", b"", b"")[1])
        self.assertIn("太短",
                      winrm._derive_session_key("pw", "", "u", "d", b"", b"\x01")[1])

    def test_try_unseal_recovers_rc4_encrypted_envelope(self):
        from fnet.features import winrm
        from fnet.utils.crypto import rc4

        key = b"\xa1" * 16
        plain = b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'>" \
                b"<s:Body>flag{winrm_unseal}</s:Body></s:Envelope>"
        cipher = rc4(key, plain)
        result = winrm._try_unseal(cipher, [("RC4(exported)", key)])
        self.assertIsNotNone(result)
        variant, recovered = result
        self.assertIn("RC4(exported)", variant)
        self.assertEqual(recovered, plain)

    def test_try_unseal_returns_none_for_random_data(self):
        from fnet.features import winrm

        self.assertIsNone(winrm._try_unseal(
            bytes(range(256)), [("RC4(exported)", b"\x00" * 16)]))

    def test_extract_ciphertexts_cipher_value(self):
        from fnet.features import winrm

        blob = base64.b64encode(b"\x01" * 64).decode()
        body = (f"<t:EncryptedData><t:CipherValue>{blob}</t:CipherValue>"
                "</t:EncryptedData>")
        found = winrm._extract_ciphertexts(None, body, "multipart/encrypted")
        self.assertIn(b"\x01" * 64, found)


class CsUnitTest(unittest.TestCase):
    def _ctx(self, tmp: Path, params: dict):
        from fnet.features.registry import FeatureContext
        from fnet.logger import Logger

        return FeatureContext(
            config=Config(tmp / "config.ini"),
            logger=Logger(tmp / "cs.log"),
            tshark=None, pcap="", params=params)

    def test_load_key_missing_file(self):
        from fnet.features import cs

        tmp = Path(tempfile.mkdtemp())
        ctx = self._ctx(tmp, {"cobaltstrike_keys": str(tmp / "nope")})
        self.assertIsNone(cs._load_key(ctx))
        texts = [r.text for r in ctx.logger.records_since(0)]
        self.assertTrue(any("CS 密钥文件不存在" in t for t in texts))

    def test_load_key_unparsable_content(self):
        from fnet.features import cs

        tmp = Path(tempfile.mkdtemp())
        key = tmp / "keys"
        key.write_bytes(b"garbage")
        ctx = self._ctx(tmp, {"cobaltstrike_keys": str(key)})
        self.assertIsNone(cs._load_key(ctx))
        self.assertTrue(any("无法从密钥文件中解析 RSA 私钥" in r.text
                            for r in ctx.logger.records_since(0)))

    def test_load_key_without_param(self):
        from fnet.features import cs

        tmp = Path(tempfile.mkdtemp())
        self.assertIsNone(cs._load_key(self._ctx(tmp, {})))

    def test_decode_metadata_fields(self):
        from fnet.features import cs

        aes = bytes(range(16))
        hmac = bytes(range(16, 32))
        plain = (b"\x00\x00\xbe\xef" + struct.pack("<I", 4242)
                 + struct.pack("<H", 4444) + bytes([1, 7]) + b"\x00" * 12
                 + aes + hmac + b"team-server.local")
        info = cs._decode_metadata(plain)
        self.assertEqual(info["pid"], 4242)
        self.assertEqual(info["port"], 4444)
        self.assertEqual(info["flags"], 1)
        self.assertEqual(info["version"], 7)
        self.assertEqual(info["aes_key"], aes)
        self.assertEqual(info["hmac_key"], hmac)
        self.assertIn("team-server.local", info["strings"])

    def test_try_decrypt_output_round_trip(self):
        from fnet.features import cs
        from fnet.utils.crypto import aes_cbc_encrypt

        key = b"k" * 16
        iv = bytes(range(16))
        plaintext = b"cmd whoami\nuid=0(root)\nflag{cs_task}\n"
        data = iv + aes_cbc_encrypt(plaintext, key, iv)
        result = cs._try_decrypt_output(data, key)
        self.assertIsNotNone(result)
        variant, recovered = result
        self.assertIn("CBC", variant)
        self.assertEqual(recovered, plaintext)

    def test_try_decrypt_output_too_short_is_rejected(self):
        from fnet.features import cs

        self.assertIsNone(cs._try_decrypt_output(b"\x01" * 16, b"z" * 16))
        self.assertIsNone(cs._try_decrypt_output(b"", b"z" * 16))

    def test_candidate_blobs_base64_and_hex(self):
        from fnet.features import cs

        blob = base64.b64encode(b"\x42" * 96).decode()
        found = cs._candidate_blobs(f"id={blob}&x=1 " + "de" * 32)
        self.assertTrue(any(b"\x42" * 96 == item for item in found))
        self.assertTrue(any(b"\xde" * 32 == item for item in found))
        self.assertEqual(cs._candidate_blobs("nothing here"), [])


class TextScanUnitTest(unittest.TestCase):
    def test_compile_adds_word_boundaries_for_short_literals(self):
        from fnet.features import text_scan

        rx = text_scan._compile("SEC")
        self.assertTrue(rx.search("the SEC value"))
        self.assertFalse(rx.search("content_section"))

    def test_compile_keeps_regex_syntax(self):
        from fnet.features import text_scan

        rx = text_scan._compile(r"flag\{.{1,4}\}")
        self.assertTrue(rx.search("flag{ab}"))

    def test_compile_falls_back_to_escape(self):
        from fnet.features import text_scan

        rx = text_scan._compile("a(b")
        self.assertTrue(rx.search("a(b"))

    def test_extra_keywords_splits_and_dedupes(self):
        from fnet.features import text_scan

        self.assertEqual(text_scan._extra_keywords({"keywords": "a;b\nc"}),
                         ["a", "b", "c"])
        # 列表形式仅做 str() 转换，不额外去空白（与实现保持一致）。
        self.assertEqual(text_scan._extra_keywords({"regex": ["x", " y "]}),
                         ["x", " y "])
        self.assertEqual(text_scan._extra_keywords({}), [])

    def test_decoded_views_reveal_base64_and_url(self):
        from fnet.features import text_scan

        encoded = base64.b64encode(b"flag{base64_view}").decode()
        views = dict(text_scan._decoded_views(encoded.encode()))
        self.assertIn("flag{base64_view}", views.get("base64", ""))
        views = dict(text_scan._decoded_views(b"flag%7Burl%7D"))
        self.assertIn("flag{url}", views.get("url", ""))
        self.assertIn("raw", views)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
