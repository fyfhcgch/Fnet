"""End-to-end test for the ``redis.analyze`` feature (checkBox_52).

Uses ``redis_nonstandard.pcap`` (Redis on port 16379) so the test also
covers payload-based stream detection without any dissector.
"""
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
class RedisFeatureTest(unittest.TestCase):
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

    def test_redis_auth_commands_and_values(self):
        job, log = self.run_job("redis_nonstandard.pcap", ["checkBox_52"])
        self.assertIn("Redis 流 0 命令统计: AUTH=1, SET=1", log)
        self.assertIn("Redis [10.0.0.5:40021 -> 10.0.0.70:16379] "
                      "AUTH password", log)
        self.assertIn("SET flag flag{redis_move}", log)
        self.assertIn("Redis 认证 [AUTH password] 用户=- 密码=password",
                      log)
        self.assertIn("Redis 写入值: flag{redis_move}", log)
        self.assertTrue((job.output_dir / "redis_session.txt").is_file())
        session = (job.output_dir / "redis_session.txt").read_text(
            encoding="utf-8")
        self.assertIn("SET flag flag{redis_move}", session)
        kinds = {item["kind"] for item in job.findings}
        self.assertIn("credential", kinds)

    def test_redis_without_traffic_warns(self):
        job, log = self.run_job("dns_arp_icmp.pcap", ["checkBox_52"])
        self.assertIn("没有发现 Redis 流量", log)


if __name__ == "__main__":
    unittest.main()
