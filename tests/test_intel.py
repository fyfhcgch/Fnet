"""Unit tests for the optional online intel client (fnet.utils.intel).

No real network traffic ever happens here: every HTTP interaction goes to
a local ``http.server`` instance, and the offline-default behaviour is
asserted to produce **zero** requests even when a server is listening.
"""
from __future__ import annotations

import contextlib
import http.server
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fnet.config import Config
from fnet.jobs import JobManager
from fnet.utils import intel as intel_mod

DATA = Path(__file__).resolve().parent / "data"


# -- local fake provider servers ---------------------------------------
_STATE = {"current": None}


def _vt_payload(malicious: int = 5, suspicious: int = 1,
                harmless: int = 60, undetected: int = 28) -> bytes:
    return json.dumps({"data": {"type": "ip_address", "attributes": {
        "last_analysis_stats": {"malicious": malicious,
                                "suspicious": suspicious,
                                "harmless": harmless,
                                "undetected": undetected},
        "reputation": -10}}}).encode("utf-8")


def _otx_payload(pulses: int = 2) -> bytes:
    names = [{"name": f"Pulse #{index}"} for index in range(max(pulses, 0))]
    return json.dumps({"pulse_info": {"count": pulses, "pulses": names},
                       "reputation": {"trust": 0}}).encode("utf-8")


def _route(path: str, state: dict) -> tuple[int, bytes]:
    mode = state.get("mode", "ok")
    if mode == "http401":
        body = json.dumps({"error": "invalid api key "
                           + state.get("echo_key", "")}).encode("utf-8")
        return 401, body
    if mode == "badjson":
        return 200, b"<html>not json</html>"
    if mode == "server500":
        return 500, b"boom"
    if path.startswith("/api/v3/"):
        return 200, _vt_payload(state.get("vt_malicious", 5))
    if path.startswith("/api/v1/indicators/"):
        return 200, _otx_payload(state.get("otx_pulses", 2))
    return 404, b"{}"


class _FakeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        state = _STATE["current"] or {}
        state.setdefault("requests", []).append(
            {"path": self.path, "headers": dict(self.headers),
             "time": time.monotonic()})
        status, body = _route(self.path, state)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


@contextlib.contextmanager
def fake_intel_server(**state):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.setdefault("requests", [])
    _STATE["current"] = state
    try:
        yield state, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        _STATE["current"] = None
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def client(base: str, **kwargs) -> intel_mod.IntelClient:
    kwargs.setdefault("vt_interval", 0.0)  # 仅限速专项测试再显式覆盖
    return intel_mod.IntelClient(vt_key=kwargs.pop("vt_key", ""),
                                 otx_key=kwargs.pop("otx_key", ""),
                                 vt_base=f"{base}/api/v3",
                                 otx_base=f"{base}/api/v1",
                                 **kwargs)


# -- indicator classification ------------------------------------------
class DetectTypeTest(unittest.TestCase):
    def test_types(self):
        self.assertEqual(intel_mod.detect_type("1.2.3.4"), "ip")
        self.assertEqual(intel_mod.detect_type("::1"), "ip")
        self.assertEqual(intel_mod.detect_type("evil.example.com"), "domain")
        self.assertEqual(intel_mod.detect_type("d" * 32), "hash")
        self.assertEqual(intel_mod.detect_type("a" * 40), "hash")
        self.assertEqual(intel_mod.detect_type("b" * 64), "hash")

    def test_unknown(self):
        self.assertEqual(intel_mod.detect_type("https://a.b/c"), "")
        self.assertEqual(intel_mod.detect_type(""), "")
        self.assertEqual(intel_mod.detect_type("1.2.3.4.5"), "")

    def test_redact(self):
        self.assertEqual(intel_mod.redact("k=SECRET", "SECRET"), "k=[redacted]")


# -- VirusTotal --------------------------------------------------------
class VirusTotalTest(unittest.TestCase):
    def test_request_construction_and_parse(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT-SECRET-1", vt_min_malicious=3)
            result = cli.lookup("1.2.3.4")
            self.assertEqual(len(result), 1)
            hit = result[0]
            self.assertTrue(hit["ok"])
            self.assertTrue(hit["malicious"])
            self.assertEqual(hit["provider"], "vt")
            self.assertEqual(hit["malicious_engines"], 5)
            self.assertEqual(hit["engines_total"], 94)
            self.assertIn("5/94", hit["score"])
            self.assertEqual(hit["detail"]["suspicious"], 1)
            request = state["requests"][0]
            self.assertEqual(request["path"], "/api/v3/ip_addresses/1.2.3.4")
            self.assertEqual(request_header(state, "x-apikey"),
                             "VT-SECRET-1")
            # 结果里绝不能带 key
            self.assertNotIn("VT-SECRET-1", json.dumps(result))

    def test_threshold_benign(self):
        with fake_intel_server(vt_malicious=2) as (_, base):
            cli = client(base, vt_key="VT-SECRET-1", vt_min_malicious=3)
            hit = cli.lookup("1.2.3.4")[0]
            self.assertTrue(hit["ok"])
            self.assertFalse(hit["malicious"])

    def test_hash_query_path(self):
        md5 = "d" * 32
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT-SECRET-1")
            hit = cli.lookup(md5)[0]
            self.assertTrue(hit["ok"])
            self.assertEqual(state["requests"][0]["path"],
                             f"/api/v3/files/{md5}")

    def test_http_error_and_redaction(self):
        with fake_intel_server(mode="http401", echo_key="VT-SECRET-1") as \
                (_, base):
            cli = client(base, vt_key="VT-SECRET-1")
            hit = cli.lookup("1.2.3.4")[0]
            self.assertFalse(hit["ok"])
            self.assertIn("HTTP 401", hit["error"])
            self.assertIn("[redacted]", hit["error"])
            self.assertNotIn("VT-SECRET-1", hit["error"])

    def test_bad_json(self):
        with fake_intel_server(mode="badjson") as (_, base):
            cli = client(base, vt_key="VT-SECRET-1")
            hit = cli.lookup("1.2.3.4")[0]
            self.assertFalse(hit["ok"])
            self.assertIn("JSON", hit["error"])


# -- AlienVault OTX ----------------------------------------------------
class OtxTest(unittest.TestCase):
    def test_request_construction_and_parse(self):
        with fake_intel_server(otx_pulses=2) as (state, base):
            cli = client(base, otx_key="OTX-SECRET-2", otx_min_pulses=1)
            hit = cli.lookup("evil.example.com")[0]
            self.assertTrue(hit["ok"])
            self.assertTrue(hit["malicious"])
            self.assertEqual(hit["pulses"], 2)
            self.assertEqual(hit["pulse_names"][0], "Pulse #0")
            self.assertEqual(state["requests"][0]["path"],
                             "/api/v1/indicators/domain/evil.example.com"
                             "/general")
            self.assertEqual(request_header(state, "x-otx-api-key"),
                             "OTX-SECRET-2")

    def test_threshold(self):
        with fake_intel_server(otx_pulses=1) as (_, base):
            cli = client(base, otx_key="OTX-SECRET-2", otx_min_pulses=5)
            self.assertFalse(cli.lookup("evil.example.com")[0]["malicious"])


def request_header(state: dict, name: str) -> str | None:
    """Case-insensitive header lookup (urllib capitalises header names)."""
    for key, value in state["requests"][0]["headers"].items():
        if key.lower() == name.lower():
            return value
    return None


# -- client behaviour --------------------------------------------------
class ClientBehaviourTest(unittest.TestCase):
    def test_offline_default_zero_requests(self):
        with fake_intel_server() as (state, base):
            cli = client(base)  # 没有任何 key
            self.assertFalse(cli.enabled)
            result = cli.lookup("1.2.3.4")
            self.assertFalse(result[0]["ok"])
            self.assertIn("离线", result[0]["error"])
            self.assertEqual(state["requests"], [])

    def test_provider_selection(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT", otx_key="OTX", provider="otx")
            hits = cli.lookup("1.2.3.4")
            self.assertEqual([h["provider"] for h in hits], ["otx"])
            self.assertEqual(len(state["requests"]), 1)

    def test_unknown_type_no_request(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT")
            hit = cli.lookup("https://a.b/c")[0]
            self.assertFalse(hit["ok"])
            self.assertEqual(state["requests"], [])

    def test_rate_limit(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT", vt_interval=0.5)
            started = time.monotonic()
            cli.lookup_many(["1.1.1.1", "2.2.2.2"])
            elapsed = time.monotonic() - started
            self.assertEqual(len(state["requests"]), 2)
            gap = state["requests"][1]["time"] - state["requests"][0]["time"]
            self.assertGreaterEqual(gap, 0.45)
            self.assertLess(elapsed, 5.0)

    def test_cache_avoids_second_request(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT")
            cli.lookup("1.2.3.4")
            cli.lookup("1.2.3.4")
            self.assertEqual(len(state["requests"]), 1)

    def test_query_ioc_rows_maps_report_kinds(self):
        rows = [("IP", "1.2.3.4", 3, "c2"), ("域名", "evil.example.com", 2, "dns"),
                ("URL", "http://1.2.3.4/x", 1, "http"),
                ("SHA256", "b" * 64, 1, "file")]
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT")
            results = cli.query_ioc_rows(rows)
        paths = [r["path"] for r in state["requests"]]
        self.assertEqual(len(results), 3)  # URL 不参与在线查询
        self.assertIn("/api/v3/ip_addresses/1.2.3.4", paths)
        self.assertIn("/api/v3/domains/evil.example.com", paths)
        self.assertIn(f"/api/v3/files/{'b' * 64}", paths)


# -- config wiring -----------------------------------------------------
class ConfigTest(unittest.TestCase):
    def _config(self) -> Config:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Config(path=Path(tmp.name) / "config.ini")

    def test_default_offline(self):
        config = self._config()
        cli = intel_mod.IntelClient.from_config(config)
        self.assertFalse(cli.enabled)
        self.assertEqual(config.get("provider", "intel"), "")
        self.assertEqual(config.get("vt_api_key", "intel"), "")
        self.assertEqual(config.get_int("vt_min_malicious", "intel"), 3)
        self.assertEqual(config.get_int("otx_min_pulses", "intel"), 1)

    def test_configured_client(self):
        config = self._config()
        config.set("vt_api_key", "VT-SECRET-1", "intel")
        config.set("provider", "vt", "intel")
        cli = intel_mod.IntelClient.from_config(config)
        self.assertTrue(cli.enabled)
        self.assertEqual(cli._active_providers(), ["vt"])


# -- findings write-back -----------------------------------------------
class StubLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []

    def debug(self, text: str) -> None:
        self.records.append(("debug", text))

    def info(self, text: str) -> None:
        self.records.append(("info", text))

    def good(self, text: str) -> None:
        self.records.append(("good", text))

    def warn(self, text: str) -> None:
        self.records.append(("warn", text))

    def error(self, text: str) -> None:
        self.records.append(("error", text))


class StubJob:
    def __init__(self, findings: list) -> None:
        self.findings = findings
        self.log = StubLogger()


class EnrichTest(unittest.TestCase):
    def test_enrich_findings_shapes(self):
        results = [
            {"value": "1.2.3.4", "type": "ip", "provider": "vt", "ok": True,
             "malicious": True, "score": "VT: 8/94 引擎判定恶意",
             "detail": {"malicious": 8}, "error": ""},
            {"value": "9.9.9.9", "type": "ip", "provider": "vt", "ok": True,
             "malicious": False, "score": "VT: 0/94 引擎判定恶意",
             "detail": {}, "error": ""},
            {"value": "1.2.3.4", "type": "ip", "provider": "vt",
             "ok": False, "malicious": None, "score": "", "detail": {},
             "error": "HTTP 401"},
        ]
        findings_list: list[dict] = []
        added = intel_mod.enrich_findings(results, findings_list)
        self.assertEqual(len(added), 2)  # 失败的结果不写 findings
        self.assertEqual(len(findings_list), 2)
        self.assertEqual(findings_list[0]["kind"], "other")
        self.assertEqual(findings_list[0]["level"], "warn")
        self.assertEqual(findings_list[0]["feature"], "intel.vt")
        self.assertIn("情报: 1.2.3.4", findings_list[0]["summary"])
        self.assertEqual(findings_list[1]["level"], "debug")
        self.assertNotIn("SECRET", json.dumps(findings_list))

    def test_enrich_job_offline(self):
        job = StubJob([{"kind": "dns", "summary": "解析 evil.example.com"}])
        cli = intel_mod.IntelClient()  # 无 key，完全离线
        added = intel_mod.enrich_job(job, cli)
        self.assertEqual(added, 0)
        self.assertEqual(len(job.findings), 1)
        self.assertEqual(job.log.records[0][0], "debug")

    def test_enrich_job_with_local_server(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT-SECRET-1", vt_min_malicious=3)
            job = StubJob([{"kind": "dns", "feature": "flows.dns",
                            "summary": "解析 evil.example.com -> 1.2.3.4"}])
            added = intel_mod.enrich_job(job, cli)
        self.assertEqual(added, 2)
        self.assertEqual(len(job.findings), 3)
        labels = {item["feature"] for item in job.findings
                  if item["feature"].startswith("intel.")}
        self.assertEqual(labels, {"intel.vt"})
        self.assertTrue(any(item.get("level") == "warn"
                            for item in job.findings))
        # 两个 IOC（域名 + IP）各发一次请求，且日志不含 key
        self.assertEqual(len(state["requests"]), 2)
        self.assertNotIn("VT-SECRET-1", job.log.records[0][1])

    def test_enrich_job_no_iocs(self):
        with fake_intel_server() as (state, base):
            cli = client(base, vt_key="VT")
            job = StubJob([{"kind": "flag",
                            "summary": "flag{nothing-to-see-here}"}])
            added = intel_mod.enrich_job(job, cli)
        self.assertEqual(added, 0)
        self.assertEqual(state["requests"], [])


class JobManagerIntelTest(unittest.TestCase):
    """JobManager wiring: offline by default, opt-in enrichment otherwise."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = Path(self.tmp.name) / "cache"
        cache.mkdir()
        patches = (mock.patch("fnet.jobs.CACHE_DIR", cache),
                   mock.patch("fnet.paths.CACHE_DIR", cache))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.manager = JobManager(
            Config(Path(self.tmp.name) / "config.ini"),
            SimpleNamespace(tshark=lambda: None))

    def _job(self):
        from dataclasses import replace

        job = self.manager.create(str(DATA / "http_ntlm.pcap"),
                                  ["checkBox_10"], {})
        job.features = [replace(job.features[0], handler="stub.collect",
                                title="情报桩")]
        return job

    def _run(self, job):
        def handler(ctx):
            ctx.add_finding("dns", "解析 evil.example.com -> 1.2.3.4")

        with mock.patch("fnet.features.registry.resolve",
                        return_value=handler):
            self.manager._run_job(job)

    @staticmethod
    def _log_text(job) -> str:
        return "\n".join(record.text for record
                         in job.log.records_since(0, limit=5000))

    def _findings(self, job) -> list[dict]:
        return json.loads(
            (job.output_dir / "findings.json").read_text(encoding="utf-8")
        )["findings"]

    def test_offline_job_never_touches_network_or_logs(self):
        job = self._job()
        with mock.patch("urllib.request.urlopen",
                        side_effect=AssertionError("离线模式不应访问网络")) as url:
            self._run(job)
        self.assertEqual(url.call_count, 0)
        log = self._log_text(job)
        self.assertNotIn("在线情报", log)
        self.assertEqual(len(self._findings(job)), 1)

    def test_configured_intel_enriches_before_findings_flush(self):
        job = self._job()
        with fake_intel_server(vt_malicious=5) as (state, base):
            cli = client(base, vt_key="VT-SECRET-1", vt_min_malicious=3)
            with mock.patch.object(intel_mod.IntelClient, "from_config",
                                   return_value=cli):
                self._run(job)
            self.assertEqual(len(state["requests"]), 2)  # 域名 + IP
        raw = (job.output_dir / "findings.json").read_text(encoding="utf-8")
        items = json.loads(raw)["findings"]
        self.assertEqual(len(items), 3)  # 1 条原发现 + 2 条情报结果
        self.assertEqual(sum(1 for item in items
                             if item.get("feature") == "intel.vt"), 2)
        self.assertNotIn("VT-SECRET-1", raw)
        self.assertIn("在线情报查询", self._log_text(job))


if __name__ == "__main__":
    unittest.main()
