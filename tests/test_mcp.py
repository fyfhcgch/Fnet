"""Tests for the MCP stdio server (``fnet.mcp_server``) and ``fnet --mcp``.

Covered here:

* unit tests of the JSON-RPC 2.0 message dispatcher (``handle_message`` /
  ``handle_line``): initialize handshake, notifications, tools/list,
  tools/call, unknown methods and malformed JSON;
* an in-process end-to-end ``analyze`` run over a small fixture from
  ``tests/data`` (skipped without tshark), plus ``get_findings`` /
  ``get_packet`` on the resulting job;
* a subprocess end-to-end handshake + tool call against
  ``python3 -m fnet --mcp`` with ``FNET_HOME`` isolated to a temp dir.

Job outputs go through ``fnet.jobs.CACHE_DIR`` / ``fnet.paths.CACHE_DIR``;
both are patched to a temp dir so the real cache is never touched.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.features.registry import FEATURES
from fnet.mcp_server import PROTOCOL_VERSION, MCPServer
from fnet.app import build
from fnet.tools.runner import find_tool

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / "data"
TSHARK = find_tool("tshark", "")


class DispatcherTest(unittest.TestCase):
    """Message-level tests; none of these need tshark or a runtime."""

    def setUp(self):
        self.server = MCPServer()

    def request(self, obj):
        return self.server.handle_message(obj)

    def call(self, name, arguments=None, msg_id=10):
        return self.request({"jsonrpc": "2.0", "id": msg_id,
                             "method": "tools/call",
                             "params": {"name": name,
                                        "arguments": arguments or {}}})

    # -- handshake ------------------------------------------------------
    def test_initialize_returns_protocol_and_server_info(self):
        response = self.request({"jsonrpc": "2.0", "id": 1,
                                 "method": "initialize", "params": {}})
        self.assertIsNone(response.get("error"))
        result = response["result"]
        self.assertEqual(response["id"], 1)
        self.assertEqual(result["protocolVersion"], PROTOCOL_VERSION)
        self.assertEqual(result["serverInfo"]["name"], "fnet")
        self.assertTrue(result["serverInfo"]["version"])
        self.assertIn("tools", result["capabilities"])

    def test_initialized_notification_is_ignored(self):
        self.assertIsNone(self.request({
            "jsonrpc": "2.0", "method": "notifications/initialized"}))
        # Any notification must never produce a reply.
        self.assertIsNone(self.request({"jsonrpc": "2.0",
                                        "method": "some/other/notification"}))

    # -- tools/list -----------------------------------------------------
    def test_tools_list_exposes_four_tools(self):
        response = self.request({"jsonrpc": "2.0", "id": 2,
                                 "method": "tools/list"})
        names = [tool["name"] for tool in response["result"]["tools"]]
        self.assertEqual(names, ["list_features", "analyze",
                                 "get_findings", "get_packet"])
        schemas = {tool["name"]: tool["inputSchema"] for tool
                   in response["result"]["tools"]}
        self.assertEqual(schemas["analyze"]["type"], "object")
        self.assertIn("pcap_path", schemas["analyze"]["properties"])

    # -- tools/call -----------------------------------------------------
    def test_call_list_features(self):
        response = self.call("list_features")
        self.assertFalse(response["result"]["isError"])
        text = response["result"]["content"][0]["text"]
        payload = json.loads(text)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], len(FEATURES))
        first = payload["features"][0]
        for key in ("id", "title", "category", "default"):
            self.assertIn(key, first)

    def test_call_unknown_tool_is_error(self):
        response = self.call("nope", msg_id=11)
        self.assertEqual(response["error"]["code"], -32602)
        self.assertIn("未知工具", response["error"]["message"])

    def test_call_missing_pcap_reports_is_error(self):
        response = self.call("analyze", {"features": ["checkBox_10"]})
        result = response["result"]
        self.assertTrue(result["isError"])
        self.assertIn("pcap_path", result["content"][0]["text"])

    # -- misc protocol --------------------------------------------------
    def test_unknown_method(self):
        response = self.request({"jsonrpc": "2.0", "id": 3,
                                 "method": "resources/list"})
        self.assertEqual(response["error"]["code"], -32601)

    def test_handle_line_malformed_json(self):
        response = json.loads(self.server.handle_line("{oops"))
        self.assertEqual(response["error"]["code"], -32700)
        self.assertIsNone(response["id"])

    def test_handle_line_blank_returns_none(self):
        self.assertIsNone(self.server.handle_line(""))
        self.assertIsNone(self.server.handle_line("   \n"))

    def test_handle_line_roundtrip(self):
        line = self.server.handle_line(json.dumps({
            "jsonrpc": "2.0", "id": 7, "method": "ping"}))
        payload = json.loads(line)
        self.assertEqual(payload["id"], 7)
        self.assertEqual(payload["result"], {})

    def test_serve_stops_on_eof(self):
        import io

        incoming = io.StringIO(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {}}) + "\n")
        out = io.StringIO()
        self.server.serve(stdin=incoming, stdout=out)
        lines = [line for line in out.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["result"]["protocolVersion"], PROTOCOL_VERSION)


@unittest.skipUnless(TSHARK, "需要 tshark")
class AnalyzeToolTest(unittest.TestCase):
    """In-process end-to-end run of the analyze/get_findings/get_packet tools."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cache = Path(cls.tmp.name) / "cache"
        cls.cache.mkdir(parents=True, exist_ok=True)
        cls.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", cls.cache),
            mock.patch("fnet.paths.CACHE_DIR", cls.cache),
        ]
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))
        cls.runtime.config.set("tshark_cache", "0")
        cls.server = MCPServer(runtime=cls.runtime)

    @classmethod
    def tearDownClass(cls):
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    def _call(self, name, arguments=None):
        response = self.server.handle_message({
            "jsonrpc": "2.0", "id": 99, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}})
        self.assertIsNone(response.get("error"), response)
        return json.loads(response["result"]["content"][0]["text"])

    def test_analyze_end_to_end(self):
        result = self._call("analyze", {
            "pcap_path": str(DATA / "ftp_smtp_telnet.pcap"),
            "features": ["flows.smtp"],
        })
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["status"], "done")
        self.assertTrue(result["job_id"])
        self.assertEqual(result["pcap_name"], "ftp_smtp_telnet.pcap")
        self.assertTrue(Path(result["report"]).is_file())
        self.assertTrue(Path(result["output_dir"]).is_file()
                        or Path(result["output_dir"]).is_dir())
        # The analyze call must register itself as the latest job.
        self.assertEqual(self.server.last_job_id, result["job_id"])

    def test_get_findings_latest_job(self):
        result = self._call("get_findings", {})
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(result["job_id"], self.server.last_job_id)
        self.assertTrue(result["findings"] or result["total"] == 0)
        self.assertEqual(result["count"], len(result["findings"]))

    def test_get_findings_unknown_job(self):
        result = self._call("get_findings", {"job_id": "0" * 16})
        self.assertFalse(result["ok"])
        self.assertIn("任务不存在", result["error"])

    def test_get_packet_frame_context(self):
        result = self._call("get_packet", {"frame": 2, "context": 1})
        self.assertTrue(result["ok"], result.get("text") or result.get("error"))
        self.assertEqual(result["frame"], 2)
        self.assertTrue(result["packet"])
        self.assertTrue(result["neighbors"])

    def test_get_packet_bad_frame(self):
        result = self._call("get_packet", {"frame": "abc"})
        self.assertFalse(result["ok"])
        self.assertIn("帧号无效", result["text"])


class SubprocessMCPTest(unittest.TestCase):
    """End-to-end handshake against ``python3 -m fnet --mcp`` (no tshark needed)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = dict(os.environ)
        self.env["FNET_HOME"] = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_handshake_tools_list_and_call(self):
        process = subprocess.Popen(
            [sys.executable, "-m", "fnet", "--mcp"],
            cwd=str(ROOT), env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)

        def send(obj):
            assert process.stdin is not None
            process.stdin.write(json.dumps(obj) + "\n")
            process.stdin.flush()

        def recv():
            assert process.stdout is not None
            return json.loads(process.stdout.readline())

        try:
            send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05"}})
            hello = recv()
            self.assertEqual(hello["id"], 1)
            self.assertEqual(hello["result"]["protocolVersion"], PROTOCOL_VERSION)
            self.assertEqual(hello["result"]["serverInfo"]["name"], "fnet")

            # Notification must not produce a response; the next reply we
            # read belongs to tools/list.
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tools = recv()
            names = [tool["name"] for tool in tools["result"]["tools"]]
            self.assertEqual(names, ["list_features", "analyze",
                                     "get_findings", "get_packet"])

            send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                  "params": {"name": "list_features", "arguments": {}}})
            listed = recv()
            payload = json.loads(listed["result"]["content"][0]["text"])
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["count"], len(FEATURES))
            # stdout must only ever carry protocol lines.
            for raw in (json.dumps(hello), json.dumps(tools)):
                self.assertTrue(raw.startswith('{"jsonrpc"'))
            process.stdin.close()
            self.assertEqual(process.wait(timeout=30), 0)
        finally:
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
