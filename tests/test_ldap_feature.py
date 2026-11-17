"""End-to-end test for the ``ldap.analyze`` feature (checkBox_48)."""
from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config
from fnet.tools.runner import find_tool

DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")


@unittest.skipUnless(TSHARK, "需要 tshark")
class LdapFeatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.patch = mock.patch("fnet.jobs.CACHE_DIR", Path(cls.tmp.name))
        cls.patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()
        cls.tmp.cleanup()

    def run_job(self, pcap: str, features: list[str]):
        job = self.runtime.jobs.submit(str(DATA / pcap), features, {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        text = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        return job, text

    def test_ldap_bind_search_entries_and_artifacts(self):
        job, log = self.run_job("ldap_deep.pcap", ["checkBox_48"])
        # 简单绑定凭据（非默认端口 1389 也必须靠载荷识别出来）
        self.assertIn("LDAP 简单绑定", log)
        self.assertIn("cn=admin,dc=ctf,dc=local", log)
        self.assertIn("ldap_pass", log)
        # 查询与条目
        self.assertIn("LDAP 查询", log)
        self.assertIn("base=dc=ctf,dc=local", log)
        self.assertIn("(objectClass=*)", log)
        self.assertIn("LDAP 条目", log)
        self.assertIn("cn=alice,dc=ctf,dc=local", log)
        self.assertIn("P@ssw0rd", log)
        self.assertIn("flag{ldap_entry}", log)
        self.assertIn("敏感属性: userPassword=P@ssw0rd", log)
        # 统计与落盘
        self.assertIn("LDAP 消息统计: 绑定=1 SASL=0 查询=1 条目=1 "
                      "StartTLS=0", log)
        self.assertTrue((job.output_dir / "ldap_searches.txt").is_file())
        self.assertTrue((job.output_dir / "ldap_entries.txt").is_file())
        entries = (job.output_dir / "ldap_entries.txt").read_text(
            encoding="utf-8")
        self.assertIn("userPassword: P@ssw0rd", entries)
        # findings 与日志保持同步
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)
        self.assertIn("protocol", kinds)

    def test_ldap_without_traffic_warns(self):
        job, log = self.run_job("dns_arp_icmp.pcap", ["checkBox_48"])
        self.assertIn("没有发现 LDAP 流量", log)


if __name__ == "__main__":
    unittest.main()
