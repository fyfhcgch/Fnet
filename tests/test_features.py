"""End-to-end checks on the synthetic captures in ``tests/data``.

These tests need ``tshark``; they are skipped when it is not installed.
"""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from fnet.app import build
from fnet.config import Config
from fnet.tools.runner import find_tool

DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")


@unittest.skipUnless(TSHARK, "需要 tshark")
class SampleCaptureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        from unittest import mock

        cls.patch = mock.patch("fnet.jobs.CACHE_DIR", Path(cls.tmp.name))
        cls.patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str]) -> str:
        job, text = self.run_job_object(pcap, features)
        return text

    def run_job_object(self, pcap: str, features: list[str]):
        job = self.runtime.jobs.submit(str(DATA / pcap), features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_keyword_scan_finds_flags(self):
        log = self.run_job("ftp_smtp_telnet.pcap", ["checkBox_10"])
        self.assertIn("flag{ftp_download}", log)
        self.assertIn("flag{telnet_shell}", log)

    def test_http_basic_auth_and_webshell_uri(self):
        log = self.run_job("http_ntlm.pcap", ["checkBox_30"])
        self.assertIn("admin:P@ssw0rd", log)
        self.assertIn("/shell.php", log)
        self.assertIn("rememberMe", log)

    def test_webshell_plaintext(self):
        log = self.run_job("http_ntlm.pcap", ["webshell.decrypt"])
        self.assertIn("明文/Base64 载荷", log)
        self.assertIn("flag{webshell_plain}", log)
        self.assertIn("uid=33(www-data)", log)

    def test_usb_keyboard_flag(self):
        log = self.run_job("usb_kbd.pcap", ["checkBox_16"])
        self.assertIn("flag{usb_kbd}", log)

    def test_usb_mouse_trajectory(self):
        log = self.run_job("usb_mouse.pcap", ["checkBox_17"])
        self.assertIn("轨迹点", log)
        self.assertIn("x=0..80 y=0..80", log)

    def test_bluetooth_att_flag(self):
        log = self.run_job("bluetooth.pcap", ["checkBox_21"])
        self.assertIn("flag{ble_ctf}", log)

    def test_ntlm_hash(self):
        log = self.run_job("http_ntlm.pcap", ["checkBox_39"])
        self.assertIn("NetNTLMv1", log)
        self.assertIn("Administrator::WORKGROUP:", log)
        self.assertIn("1122334455667788", log)

    def test_shiro_gcm_cookie(self):
        log = self.run_job("http_ntlm.pcap", ["checkBox_42"])
        self.assertIn("GCM(IV=前16字节)", log)
        self.assertIn("flag{shiro_gcm_decrypted}", log)

    def test_dns_tunnel_base64(self):
        log = self.run_job("dns_arp_icmp.pcap", ["checkBox_23"])
        self.assertIn("ZmxhZ3tkbnNfdHVubmVsfQ", log)
        self.assertIn("flag{dns_tunnel}", log)

    def test_icmp_payload(self):
        log = self.run_job("dns_arp_icmp.pcap", ["checkBox_20"])
        self.assertIn("flag{icmp_payload}", log)

    def test_arp_spoof_detection(self):
        log = self.run_job("dns_arp_icmp.pcap", ["checkBox_44"])
        self.assertIn("疑似 ARP 欺骗", log)
        self.assertIn("aa:aa:aa:aa:aa:01", log)

    def test_ftp_credentials(self):
        log = self.run_job("ftp_smtp_telnet.pcap", ["checkBox_27"])
        self.assertIn("FTP 凭据: USER alice", log)
        self.assertIn("FTP 凭据: PASS s3cr3t", log)

    def test_modbus_write_detection(self):
        log = self.run_job("modbus_mqtt.pcap", ["checkBox_11"])
        self.assertIn("包含写操作", log)
        self.assertIn("功能码 6", log)

    def test_mqtt_topic_and_payload(self):
        log = self.run_job("modbus_mqtt.pcap", ["checkBox_13"])
        self.assertIn("sensors", log)
        self.assertIn("666c61677b6f777d", log)

    def test_websocket_fragments_control_and_deflate(self):
        log = self.run_job("websocket.pcap", ["protocols.credentials"])
        self.assertIn("消息级还原", log)
        self.assertIn("flag{ws_text}", log)
        self.assertIn("flag{ws_fragment}", log)
        self.assertIn("flag{ws_deflate}", log)
        self.assertIn("ping", log)

    def test_redis_detected_on_nondefault_port(self):
        log = self.run_job("redis_nonstandard.pcap", ["protocols.credentials"])
        self.assertIn("非默认端口", log)
        self.assertIn("16379", log)
        self.assertIn("Redis AUTH password", log)
        self.assertIn("flag{redis_move}", log)

    def test_deep_protocol_parsers(self):
        job, log = self.run_job_object("protocol_deep.pcap",
                                       ["protocols.credentials"])
        # Redis RESP3, EVAL and cluster redirection.
        self.assertIn("HELLO 3 AUTH admin secret", log)
        self.assertIn("Redis AUTH admin:secret", log)
        self.assertIn("MOVED slot 3999", log)
        self.assertIn("flag{redis_resp3}", log)
        # PostgreSQL extended query, cleartext auth and COPY data.
        self.assertIn("SELECT * FROM users WHERE name=$1", log)
        self.assertIn("$1=alice(text,text)", log)
        self.assertIn("PostgreSQL 明文密码 pg_secret", log)
        self.assertIn("flag{pg_copy}", log)
        # MongoDB credentials and a reassembled GridFS file.
        self.assertIn("MongoDB password=mongo_pass", log)
        self.assertIn("GridFS 文件 flag.txt", log)
        self.assertIn("flag{mongo_gridfs}", log)
        self.assertTrue((job.output_dir / "gridfs_flag.txt").is_file())
        self.assertEqual((job.output_dir / "gridfs_flag.txt").read_bytes(),
                         b"flag{mongo_gridfs}")
        self.assertTrue((job.output_dir / "postgres_queries.txt").is_file())
        self.assertTrue(list(job.output_dir.glob("postgres_copy_*_in.txt")))

    def test_cross_protocol_credential_correlation(self):
        log = self.run_job(
            "ftp_smtp_telnet.pcap",
            ["checkBox_27", "forensics.correlate", "forensics.timeline"])
        self.assertIn("跨协议凭据关联", log)
        self.assertIn("ftp alice @ -", log)
        self.assertIn("FTP 登录 alice:s3cr3t", log)
        self.assertIn("认证/文件时间线", log)

    def test_http2_hpack_grpc_and_bodies(self):
        job, log = self.run_job_object("http2_deep.pcap",
                                       ["protocols.credentials"])
        self.assertIn("HTTP/2 GET https://ctf.local/flag{http2_deep}", log)
        self.assertIn("HTTP/2 Basic admin:http2pass", log)
        self.assertIn("flag{http2_body}", log)
        self.assertIn("flag{http2_response}", log)
        self.assertIn("[gRPC]", log)
        self.assertIn("flag{grpc}", log)
        self.assertTrue((job.output_dir / "http2_streams.txt").is_file())
        self.assertTrue(list(job.output_dir.glob("http2_body_*_1_req.bin")))

    def test_ldap_bind_search_and_attributes(self):
        job, log = self.run_job_object("ldap_deep.pcap",
                                       ["protocols.credentials"])
        self.assertIn("LDAP 简单绑定", log)
        self.assertIn("ldap_pass", log)
        self.assertIn("LDAP 条目 cn=alice,dc=ctf,dc=local", log)
        self.assertIn("P@ssw0rd", log)
        self.assertIn("flag{ldap_entry}", log)
        self.assertIn("非默认端口 1389", log)
        self.assertTrue((job.output_dir / "ldap_objects.txt").is_file())
        self.assertTrue((job.output_dir / "ldap_queries.txt").is_file())

    def test_smb2_share_ntlm_and_file_roundtrip(self):
        job, log = self.run_job_object("smb2_deep.pcap",
                                       ["protocols.smb2"])
        self.assertIn("连接共享 \\\\FS01\\share", log)
        self.assertIn("CTF\\alice", log)
        self.assertIn("SMB 文件 \\\\FS01\\share\\flag.txt", log)
        self.assertIn("flag{smb2_file}", log)
        self.assertIn("SMB 3.1.1", log)
        self.assertTrue((job.output_dir / "smb2_files.txt").is_file())
        exported = list(job.output_dir.glob("smb2_file_*_读取_flag.txt.bin"))
        self.assertTrue(exported)
        self.assertEqual(exported[0].read_bytes(), b"flag{smb2_file}")

    def test_tls_certificate_chain_and_key_update(self):
        job, log = self.run_job_object("tls_deep.pcap", ["checkBox_24"])
        self.assertIn("TLS 证书链", log)
        self.assertIn("test.example.org", log)
        self.assertIn("alt.example.org", log)
        self.assertIn("自签名证书", log)
        self.assertIn("TLS 1.3 KeyUpdate", log)
        self.assertTrue((job.output_dir / "findings.json").is_file())

    def test_quic_v1_v2_sni_and_alpn(self):
        job, log = self.run_job_object("quic.pcap", ["checkBox_24"])
        self.assertIn("发现 2 个 QUIC 连接", log)
        self.assertIn("QUIC v1 (RFC 9000)", log)
        self.assertIn("QUIC v2 (RFC 9369)", log)
        self.assertIn("quic.example.org", log)
        self.assertIn("cdn.example.org", log)
        self.assertIn("h3", log)
        csv = (job.output_dir / "quic_connections.csv").read_text(
            encoding="utf-8")
        self.assertIn("quic.example.org", csv)
        self.assertIn("cdn.example.org", csv)
        # Both v1 and v2 Initials must be named even though tshark leaves the
        # legacy packet-type field empty for v2.
        self.assertEqual(csv.count("Initial=1"), 2)

    def test_wifi_pmkid_handshake_and_sae(self):
        job, log = self.run_job_object("wifi_eapol.pcap", ["checkBox_18"])
        self.assertIn("完整握手 (M1-M4)", log)
        self.assertIn("PMKID 00112233445566778899aabbccddeeff", log)
        self.assertIn("WPA3/SAE", log)
        self.assertIn("Dragonfly", log)
        pmkid = (job.output_dir / "wifi_pmkid.hc22000").read_text(
            encoding="utf-8")
        self.assertTrue(pmkid.startswith(
            "WPA*01*00112233445566778899aabbccddeeff*aabbccddeeff*"
            "112233445566*746573746e6574***"))
        handshake = (job.output_dir / "wifi_handshake.hc22000").read_text(
            encoding="utf-8")
        self.assertTrue(handshake.startswith(
            "WPA*02*33333333333333333333333333333333*"))
        self.assertTrue((job.output_dir / "wifi_summary.txt").is_file())



if __name__ == "__main__":
    unittest.main()
