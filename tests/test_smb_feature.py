"""End-to-end test for the ``smb.analyze`` feature (checkBox_49)."""
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
class SmbFeatureTest(unittest.TestCase):
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

    def test_smb_share_ntlm_and_file_recovery(self):
        job, log = self.run_job("smb2_deep.pcap", ["checkBox_49"])
        self.assertIn("SMB 会话认证", log)
        self.assertIn("账号=CTF\\alice", log)
        self.assertIn("连接共享 \\\\FS01\\share", log)
        self.assertIn("打开文件 \\\\FS01\\share\\flag.txt", log)
        self.assertIn("写入文件 \\\\FS01\\share\\flag.txt", log)
        self.assertIn("SMB 方言: SMB 3.1.1", log)
        self.assertIn("SMB 文件 \\\\FS01\\share\\flag.txt 已还原 15 字节",
                      log)
        self.assertTrue((job.output_dir / "smb_shared_files.txt").is_file())
        exported = list(job.output_dir.glob("smb_file_*_flag.txt.bin"))
        self.assertTrue(exported)
        self.assertEqual(exported[0].read_bytes(), b"flag{smb2_file}")
        summary = (job.output_dir / "smb_shared_files.txt").read_text(
            encoding="utf-8")
        self.assertIn("md5=", summary)
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)
        self.assertIn("file", kinds)

    def test_smb_without_traffic_warns(self):
        job, log = self.run_job("dns_arp_icmp.pcap", ["checkBox_49"])
        self.assertIn("没有发现 SMB 流量", log)


if __name__ == "__main__":
    unittest.main()
