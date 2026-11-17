"""MCP (Model Context Protocol) server over stdio — standard library only.

协议：行分隔的 JSON-RPC 2.0（newline-delimited JSON）。每条请求/响应占一行
UTF-8 JSON，以 ``\\n`` 结尾；服务器逐行读取 stdin，处理完立即把一行响应写回
stdout 并 flush。选择行分隔而不是 ``Content-Length`` 分帧，是因为它实现最简
单，且主流 MCP 客户端（stdio transport）同样接受。

stdout 只承载协议消息；所有日志一律写到 stderr。

暴露的 MCP 工具（与 CLI / WebUI 共用同一套装配，见 ``fnet.app.build``）：

* ``list_features`` —— 列出功能目录（checkbox id / 标题 / 分类 / 是否默认）；
* ``analyze``       —— 同步运行一次分析任务并等待结束，返回 findings 摘要
  与报告路径；
* ``get_findings``  —— 按任务 id（缺省为最近一次任务）查询结构化结果；
* ``get_packet``    —— 返回某帧及其前后帧的上下文（复用 ``fnet.services``）。

pcap 路径只来自调用方参数或 CLI 预载参数，不写死任何绝对路径；输出目录走
``fnet.paths`` / ``JobManager`` 的既有机制。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from fnet import __version__
from fnet.features.registry import CATEGORIES, FEATURES

#: MCP protocol version advertised during the ``initialize`` handshake.
PROTOCOL_VERSION = "2024-11-05"

JSONRPC_VERSION = "2.0"

# JSON-RPC 2.0 error codes used here.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


def log(message: str) -> None:
    """stderr-only logging: stdout must stay protocol-clean."""
    print(f"[fnet-mcp] {message}", file=sys.stderr, flush=True)


def _category_name(key: str) -> str:
    for category in CATEGORIES:
        if category["key"] == key:
            return category.get("name") or key
    return key


def tool_definitions() -> list[dict]:
    """JSON schemas for the exposed tools (``tools/list`` payload)."""
    return [
        {
            "name": "list_features",
            "description": "列出 Fnet 全部分析功能（复选框 id、标题、分类、是否默认勾选）。",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": True},
        },
        {
            "name": "analyze",
            "description": (
                "对一个 pcap/pcapng 文件同步运行分析任务并等待完成，"
                "返回 findings 摘要、统计与报告路径。"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pcap_path": {
                        "type": "string",
                        "description": "pcap/pcapng 文件路径；缺省时使用启动 fnet 时预载的流量包",
                    },
                    "features": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "功能列表（checkBox_10 或 http.extract 等 handler 名）；缺省为默认勾选项",
                    },
                    "params": {
                        "type": "object",
                        "description": "传给分析功能的额外参数，如 {\"wifi_psk\": \"...\"}",
                        "additionalProperties": True,
                    },
                    "shards": {
                        "type": "integer",
                        "description": "无状态功能按 N 个帧区间分片执行（默认 1）",
                    },
                },
            },
        },
        {
            "name": "get_findings",
            "description": "查询一个任务（缺省为最近一次分析任务）的结构化结果。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "任务 id；缺省为最近一次任务"},
                    "kind": {"type": "string", "description": "按 kind 过滤（可选）"},
                    "query": {"type": "string", "description": "文本过滤（可选）"},
                    "level": {"type": "string", "description": "按级别过滤 info/warn/error（可选）"},
                    "limit": {"type": "integer", "description": "最多返回条数（默认 5000）"},
                },
            },
        },
        {
            "name": "get_packet",
            "description": "返回某帧的详情与前后帧上下文（对应 WebUI 的帧链接视图）。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "任务 id；缺省为最近一次任务"},
                    "frame": {"type": ["string", "integer"], "description": "帧号"},
                    "context": {"type": "integer", "description": "前后各取多少帧（默认 2，最大 20）"},
                },
                "required": ["frame"],
            },
        },
    ]


class MCPServer:
    """Line-delimited JSON-RPC 2.0 dispatcher plus the four tools."""

    def __init__(self, runtime=None, default_pcap: str = "",
                 default_features: list[str] | None = None) -> None:
        self._runtime = runtime
        self.default_pcap = str(default_pcap or "")
        self.default_features = list(default_features or [])
        self.last_job_id = ""

    # -- runtime -------------------------------------------------------
    @property
    def runtime(self):
        if self._runtime is None:
            from fnet.app import build

            self._runtime = build()
        return self._runtime

    # -- protocol ------------------------------------------------------
    def handle_line(self, line: str) -> str | None:
        """Parse one stdin line and return the response line (``None`` = no reply)."""
        line = (line or "").strip()
        if not line:
            return None
        try:
            message = json.loads(line)
        except ValueError:
            return self._encode(self._error(None, PARSE_ERROR, "无法解析 JSON"))
        response = self.handle_message(message)
        if response is None:
            return None
        return self._encode(response)

    @staticmethod
    def _encode(message: dict) -> str:
        return json.dumps(message, ensure_ascii=False)

    @staticmethod
    def _result(msg_id, result: dict) -> dict:
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id, code: int, message: str, data=None) -> dict:
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "error": error}

    def handle_message(self, message) -> dict | None:
        """Dispatch one decoded JSON-RPC message.

        Returns the response object, or ``None`` for notifications (which
        must never produce a reply, including errors).
        """
        if not isinstance(message, dict):
            return self._error(None, INVALID_REQUEST, "消息必须是 JSON 对象")
        # JSON-RPC 2.0: a message without "id" is a notification — no reply.
        is_notification = "id" not in message
        msg_id = message.get("id")
        method = str(message.get("method") or "")
        try:
            if method == "initialize":
                return self._result(msg_id, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "fnet", "version": __version__},
                    "instructions": "Fnet 流量分析：先 list_features 选择功能，"
                                    "再用 analyze 分析流量包，get_findings/get_packet 查看结果。",
                })
            if is_notification:
                # notifications/initialized 及其它通知一律忽略，不回包。
                log(f"忽略通知: {method or '(空)'}")
                return None
            if method == "ping":
                return self._result(msg_id, {})
            if method == "tools/list":
                return self._result(msg_id, {"tools": tool_definitions()})
            if method == "tools/call":
                try:
                    call_result = self._dispatch_call(message.get("params"))
                except ValueError as exc:
                    # Unknown tool / bad params are JSON-RPC level errors.
                    return self._error(msg_id, INVALID_PARAMS, str(exc))
                return self._result(msg_id, call_result)
            return self._error(msg_id, METHOD_NOT_FOUND, f"未知方法: {method}")
        except Exception as exc:  # noqa: BLE001 - one bad request must not kill the loop
            log(f"处理 {method or '消息'} 失败: {exc}")
            return self._error(msg_id, INVALID_REQUEST, f"内部错误: {exc}")

    def _dispatch_call(self, params) -> dict:
        """``tools/call`` payload -> tool result (MCP content envelope)."""
        if not isinstance(params, dict):
            return self._tool_error("params 必须是对象")
        name = str(params.get("name") or "")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        handler = {
            "list_features": self._tool_list_features,
            "analyze": self._tool_analyze,
            "get_findings": self._tool_get_findings,
            "get_packet": self._tool_get_packet,
        }.get(name)
        if handler is None:
            raise ValueError(f"未知工具: {name}")
        try:
            result = handler(arguments)
        except Exception as exc:  # noqa: BLE001 - tool failures are isError results
            log(f"工具 {name} 执行失败: {exc}")
            return self._tool_error(f"{name} 执行失败: {exc}")
        text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": result,
            "isError": bool(result.get("ok") is False),
        }

    @staticmethod
    def _tool_error(message: str) -> dict:
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    # -- tools ---------------------------------------------------------
    def _tool_list_features(self, arguments: dict) -> dict:
        items = [{
            "id": feature.checkbox,
            "handler": feature.handler,
            "title": feature.title,
            "category": feature.category,
            "category_name": _category_name(feature.category),
            "default": bool(feature.default),
        } for feature in FEATURES]
        return {"ok": True, "count": len(items), "features": items}

    def _tool_analyze(self, arguments: dict) -> dict:
        pcap = str(arguments.get("pcap_path") or arguments.get("pcap")
                   or self.default_pcap or "").strip()
        if not pcap:
            return {"ok": False, "error":
                    "缺少 pcap_path，且启动 fnet 时也没有预载流量包"}
        path = Path(pcap).expanduser()
        if not path.is_file():
            return {"ok": False, "error": f"流量包不存在: {path}"}
        features = arguments.get("features") or self.default_features
        if isinstance(features, str):
            features = [item.strip() for item in features.split(",") if item.strip()]
        features = [str(item).strip() for item in features or [] if str(item).strip()]
        if not features:
            features = [feature.checkbox for feature in FEATURES if feature.default]
        params = arguments.get("params")
        params = dict(params) if isinstance(params, dict) else {}
        try:
            shards = max(1, int(arguments.get("shards") or 1))
        except (TypeError, ValueError):
            shards = 1

        runtime = self.runtime
        try:
            job = runtime.jobs.submit(str(path.resolve()), features, params,
                                      shards=shards)
        except (ValueError, FileNotFoundError) as exc:
            return {"ok": False, "error": f"无法创建任务: {exc}"}
        self.last_job_id = job.id
        log(f"任务 {job.id} 开始: {path.name}（{len(job.features)} 个功能）")
        # 同步等待：MCP 客户端拿到响应时任务已经结束。
        if job.thread is not None:
            job.thread.join()
        found = runtime.jobs.findings_for(job.id, limit=50_000) or {}
        findings = found.get("findings") or []
        summary = {
            "ok": job.status == "done",
            "job_id": job.id,
            "status": job.status,
            "error": job.error,
            "pcap": job.pcap,
            "pcap_name": Path(job.pcap).name,
            "features": [feature.checkbox for feature in job.features],
            "succeeded": job.succeeded,
            "failed": job.failed,
            "progress": job.progress,
            "findings_count": found.get("total", len(job.findings)),
            "kinds": found.get("kinds") or {},
            "findings": findings[:500],
            "findings_truncated": len(findings) > 500,
            "report": job.report_path,
            "report_markdown": job.report_markdown_path,
            "report_html": job.report_html_path,
            "findings_json": job.findings_path,
            "output_dir": str(job.output_dir),
        }
        log(f"任务 {job.id} 结束: {job.status}，findings {summary['findings_count']} 条")
        return summary

    def _resolve_job_id(self, arguments: dict) -> str:
        job_id = str(arguments.get("job_id") or "").strip() or self.last_job_id
        if job_id:
            return job_id
        history = self.runtime.jobs.history(1)
        return str(history[0].get("id") or "") if history else ""

    def _tool_get_findings(self, arguments: dict) -> dict:
        job_id = self._resolve_job_id(arguments)
        if not job_id:
            return {"ok": False, "error": "没有可用任务（先调用 analyze）"}
        try:
            limit = max(1, int(arguments.get("limit") or 5000))
        except (TypeError, ValueError):
            limit = 5000
        found = self.runtime.jobs.findings_for(
            job_id,
            query=str(arguments.get("query") or ""),
            kind=str(arguments.get("kind") or ""),
            level=str(arguments.get("level") or ""),
            limit=limit)
        if found is None:
            return {"ok": False, "error": f"任务不存在: {job_id}"}
        return {"ok": True, "job_id": job_id, **found}

    def _tool_get_packet(self, arguments: dict) -> dict:
        job_id = self._resolve_job_id(arguments)
        if not job_id:
            return {"ok": False, "error": "没有可用任务（先调用 analyze）"}
        pcap = self.runtime.jobs.pcap_for(job_id)
        if not pcap or not Path(pcap).is_file():
            return {"ok": False, "error": f"任务的流量包不可用: {job_id}"}
        from fnet.services import frame_detail

        result = frame_detail(pcap, arguments.get("frame"), self.runtime.toolbox,
                              context=arguments.get("context", 2))
        result["job_id"] = job_id
        return result

    # -- serve loop ----------------------------------------------------
    def serve(self, stdin=None, stdout=None) -> None:
        """Read newline-delimited requests from ``stdin`` until EOF."""
        stream_in = stdin if stdin is not None else sys.stdin
        stream_out = stdout if stdout is not None else sys.stdout
        log(f"MCP server 就绪（protocol {PROTOCOL_VERSION}，等待 JSON-RPC 行）")
        while True:
            try:
                line = stream_in.readline()
            except (OSError, ValueError):
                break
            if not line:
                break
            response = self.handle_line(line)
            if response is None:
                continue
            try:
                stream_out.write(response + "\n")
                stream_out.flush()
            except (OSError, ValueError):
                break
        log("stdin 关闭，MCP server 退出")
