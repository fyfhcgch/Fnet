"""Command line entry point (``fnet`` / ``python -m fnet``).

Modes:

``fnet [capture.pcapng]``
    Start the local WebUI and open the browser.  Optionally pre-select a
    capture file.

``fnet -C capture.pcapng --features checkBox_10,http.extract``
    Run the analysis headless and stream the log to stdout.

``fnet -C access.log`` / ``fnet -C ceph.log``
    Analyse a plain-text log (.log/.txt/.jsonl/.csv) with the log features;
    no tshark is required for this path.

``fnet --mcp``
    Serve the MCP (Model Context Protocol) tools over stdio (JSON-RPC 2.0,
    newline-delimited); optional positional capture pre-loads the default
    ``pcap_path`` for the ``analyze`` tool.

``fnet --pcap-over-ip 18000``
    Listen for PCAP-over-IP streams and analyse every received capture.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

from fnet import APP_DISPLAY_NAME, __version__
from fnet.app import build, describe_environment
from fnet.features.registry import (
    CATEGORIES, BY_CHECKBOX, BY_HANDLER, FEATURES, default_features_for, resolve,
)
from fnet.logger import logger
from fnet.paths import USER_CONFIG
from fnet.utils.logfile import classify_input


class FeatureSelectionError(SystemExit, ValueError):
    """``--features`` 里有无法解析的条目；CLI 统一映射为退出码 2。

    同时继承 :class:`SystemExit`（历史上 ``select_features`` 就是这么失败的，
    第三方脚本用 ``except SystemExit`` 兼容）和 :class:`ValueError`，让所有
    调用方都能用同一种异常映射到退出码 2。
    """

    def __init__(self, message: str) -> None:
        # 只走 SystemExit.__init__，避免 ValueError 的参数元组覆盖 ``code``。
        SystemExit.__init__(self, message)
        self.message = message

    def __str__(self) -> str:
        return self.message


def _ensure_utf8_streams() -> None:
    """确保 CLI 的中文输出在 Windows/cp1252 控制台不 crash。

    GitHub Actions 的 Windows runner 默认 stdout 编码是 cp1252；直接 ``print``
    中文会抛 ``UnicodeEncodeError``。Python 3.7+ 的文本流支持 ``reconfigure``，
    对 StringIO 等测试流则没有该属性，这里统一做兼容处理。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            # 某些被包裹/关闭的流无法重配；此时保持原样，不让诊断命令失败。
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fnet",
        description=f"{APP_DISPLAY_NAME} {__version__}",
    )
    parser.add_argument("capture", nargs="?",
                        help="要分析的 pcap/pcapng 流量包或 .log/.txt/.jsonl/.csv 日志")
    parser.add_argument("-C", "--cli", action="store_true",
                        help="不启动 WebUI，直接在终端运行分析")
    parser.add_argument("--host", default=None, help="WebUI 监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=None, help="WebUI 端口（默认 8765）")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    parser.add_argument("--config", default=None, help="使用指定的 config.ini")
    parser.add_argument("--features", default="",
                        help="逗号分隔的功能（checkBox_10 或 http.extract）；缺省按输入类型选择（抓包 2 项、日志 5 项）")
    parser.add_argument("--all", action="store_true", help=f"运行全部 {len(FEATURES)} 个功能")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE",
                        help="传给分析功能的额外参数，可重复")
    parser.add_argument("--json", action="store_true",
                        help="只向 stdout 输出 JSON（任务、结构化结果与统计）")
    parser.add_argument("--rules", default="",
                        help="导入正则/YARA 子集规则文件，命中写入 findings")
    parser.add_argument("--shards", type=int, default=1,
                        help="无状态功能按 N 个帧区间分片执行（默认 1）")
    parser.add_argument("--resume", default="", metavar="JOB_ID",
                        help="继续一个已暂停/中断的任务")
    parser.add_argument("--compare", nargs=2, default=None,
                        metavar=("BASE", "TARGET"),
                        help="对比两个任务的 findings（输出新增/消失项）")
    parser.add_argument("--wpa-psk", default="",
                        help="已知 WPA/WPA2 PSK，用于解密 802.11 数据帧")
    parser.add_argument("--mcp", action="store_true",
                        help="以 MCP（Model Context Protocol）stdio 模式运行，"
                             "供 Claude 等 LLM 客户端调用；位置参数 pcap 可预载默认流量包")
    parser.add_argument("--pcap-over-ip", type=int, default=None, metavar="PORT",
                        help="监听 127.0.0.1:PORT 接收 PCAP-over-IP 字节流，"
                             "收到 pcap 后自动创建分析任务（地址可用 --host/config 覆盖）")
    parser.add_argument("--keytab", default="",
                        help="Kerberos keytab，用于解密 AS/TGS 响应与 PAC")
    parser.add_argument("--kerberos-password", default="",
                        help="Kerberos 账号密码，用于派生密钥并解密响应")
    parser.add_argument("--kerberos-key", default="",
                        help="Kerberos 原始密钥（hex），优先级最高")
    parser.add_argument("--clean-cache", action="store_true",
                        help="清理 tshark 结果缓存（按 TTL 与容量上限）后退出")
    parser.add_argument("--list-features", action="store_true", help="列出全部功能后退出")
    parser.add_argument("--list-tools", action="store_true", help="列出依赖的外部工具后退出")
    parser.add_argument("--doctor", action="store_true", help="检查运行环境后退出")
    parser.add_argument("--version", action="store_true", help="显示版本后退出")
    return parser


def parse_params(items: list[str]) -> dict:
    params: dict = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep:
            key, value = item, "1"
        key = key.strip()
        if not key:
            continue
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "on"):
            params[key] = True
        elif lowered in ("false", "no", "off"):
            params[key] = False
        else:
            params[key] = value
    return params


def list_features() -> None:
    print(f"{'复选框':<14s} {'分类':<10s} {'处理器':<26s} 标题")
    print("-" * 96)
    by_category: dict[str, list] = {}
    for feature in FEATURES:
        by_category.setdefault(feature.category, []).append(feature)
    names = {item["key"]: item["name"] for item in CATEGORIES}
    for category in CATEGORIES:
        items = by_category.get(category["key"], [])
        if not items:
            continue
        print(f"\n[{names.get(category['key'], category['key'])}]")
        for feature in items:
            flag = "*" if feature.default else " "
            print(f"{flag}{feature.checkbox:<13s} {feature.category:<10s} "
                  f"{feature.handler:<26s} {feature.title}")
            if feature.needs:
                print(f"{'':<14s} 需要: {', '.join(feature.needs)}")
    print("\n* = 默认勾选（抓包）；日志输入默认勾选 checkBox_61–checkBox_65")


def clean_cache() -> int:
    """``--clean-cache``：按 TTL 与容量上限清理 tshark 结果缓存。"""
    from fnet import paths as fnet_paths
    from fnet.tools.runner import (DEFAULT_CACHE_MAX_MB, DEFAULT_CACHE_TTL_DAYS,
                                   prune_cache)

    directory = Path(fnet_paths.CACHE_DIR) / "tshark"
    if not directory.is_dir():
        print(f"缓存目录为空: {directory}")
        return 0
    before = sum(entry.stat().st_size for entry in directory.glob("*.tsv")
                 if entry.is_file())
    removed, freed = prune_cache(
        directory, max_bytes=DEFAULT_CACHE_MAX_MB * 1024 * 1024,
        ttl_seconds=DEFAULT_CACHE_TTL_DAYS * 86_400)
    after = before - freed
    print(f"缓存目录: {directory}")
    print(f"删除 {removed} 个文件，释放 {freed / 1024 / 1024:.1f} MB；"
          f"剩余 {max(0, after) / 1024 / 1024:.1f} MB"
          f"（上限 {DEFAULT_CACHE_MAX_MB} MB / {DEFAULT_CACHE_TTL_DAYS} 天）")
    return 0


def select_features(spec: str, run_all: bool,
                    kind: str = "pcap") -> list[str]:
    """把 ``--features`` 解析为复选框/处理器 ID 列表。

    任何无法解析的 token（包括 ``foo.bar`` 这类点号处理器）都会抛
    :class:`FeatureSelectionError`，让 CLI 在创建任务前就以退出码 2 失败，
    而不是等运行时才炸。
    """
    if run_all:
        return [feature.checkbox for feature in FEATURES]
    if not spec:
        return default_features_for(kind)
    selected: list[str] = []
    for token in (part.strip() for part in spec.split(",")):
        if not token:
            continue
        feature = BY_CHECKBOX.get(token) or BY_HANDLER.get(token)
        if feature is None:
            if "." not in token:
                raise FeatureSelectionError(
                    f"未知功能: {token}（用 --list-features 查看）")
            # 没有复选框的真实处理器（如 webshell.decrypt / flows.http_login）
            # 允许直接写处理器名，但必须先确认它真的能被解析。
            try:
                resolve(token)
            except AttributeError:
                raise FeatureSelectionError(
                    f"未知功能: {token}（用 --list-features 查看）") from None
            selected.append(token)
            continue
        if feature.checkbox not in selected:
            selected.append(feature.checkbox)
    return selected


def _collect_params(args) -> dict:
    params = parse_params(args.param)
    if args.rules:
        params["rules"] = args.rules
    if args.wpa_psk:
        params["wifi_psk"] = args.wpa_psk
    if args.keytab:
        params["kerberos_keytab"] = args.keytab
    if args.kerberos_password:
        params["kerberos_password"] = args.kerberos_password
    if args.kerberos_key:
        params["kerberos_key"] = args.kerberos_key
    return params


def _wait_for_job(job, runtime, json_mode: bool = False) -> int:
    cursor = 0
    try:
        while True:
            for record in job.log.records_since(cursor):
                if not json_mode:
                    print(record.line, flush=True)
                cursor = record.seq
            if job.status in ("done", "error", "cancelled", "paused"):
                for record in job.log.records_since(cursor):
                    if not json_mode:
                        print(record.line, flush=True)
                break
            time.sleep(0.12)
    except KeyboardInterrupt:
        print("\n收到中断，正在取消任务…", file=sys.stderr)
        runtime.jobs.cancel(job.id)
        if job.thread:
            job.thread.join(timeout=10)
        return 130
    return 0


def run_headless(args, runtime) -> int:
    if not args.capture:
        print("需要指定输入文件（流量包或日志）", file=sys.stderr)
        return 2
    capture = Path(args.capture).expanduser()
    if not capture.is_file():
        print(f"输入文件不存在: {capture}", file=sys.stderr)
        return 2
    kind = classify_input(capture)
    if kind is None:
        print(f"不支持的输入文件类型: {capture.suffix or capture.name}",
              file=sys.stderr)
        return 2
    try:
        checkboxes = select_features(args.features, args.all, kind=kind)
    except FeatureSelectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not checkboxes:
        print("没有选择任何功能", file=sys.stderr)
        return 2
    params = _collect_params(args)
    try:
        job = runtime.jobs.submit(str(capture), checkboxes, params,
                                  shards=max(1, args.shards))
    except (ValueError, FileNotFoundError) as exc:
        print(f"无法创建任务: {exc}", file=sys.stderr)
        return 2

    if not args.json:
        print(f"任务 {job.id} | {capture.name} | {len(job.features)} 个功能")
        print(f"输出目录: {job.output_dir}")
        print("-" * 78)
    code = _wait_for_job(job, runtime, json_mode=args.json)
    if code:
        return code

    if args.json:
        found = runtime.jobs.findings_for(job.id, limit=50_000) or {}
        payload = {
            "ok": job.status in ("done", "cancelled"),
            "job": job.as_dict(),
            "findings": found.get("findings") or [],
            "count": found.get("total", len(job.findings)),
            "kinds": found.get("kinds") or {},
            "artifacts": runtime.jobs.artifacts(job),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        print("-" * 78)
        for label, path in (("报告", job.report_path),
                            ("Markdown 报告", job.report_markdown_path),
                            ("HTML 报告", job.report_html_path),
                            ("结构化结果", job.findings_path),
                            ("结果 CSV", job.findings_csv_path)):
            if path:
                print(f"{label}: {path}")
        if job.findings:
            print(f"共记录 {len(job.findings)} 条结构化结果"
                  "（WebUI 的“分析结果”页可排序筛选）")
    if job.status == "done":
        return 0
    if job.status in ("cancelled", "paused"):
        return 130
    return 1


def run_resume(args, runtime) -> int:
    job = runtime.jobs.resume(args.resume)
    if job is None:
        print(f"任务不可恢复或不存在: {args.resume}", file=sys.stderr)
        return 2
    if not args.json:
        print(f"继续任务 {job.id} | {Path(job.pcap).name} | "
              f"已完成 {len(job.completed)}/{len(job.features)}")
        print("-" * 78)
    code = _wait_for_job(job, runtime, json_mode=args.json)
    if code:
        return code
    if args.json:
        found = runtime.jobs.findings_for(job.id, limit=50_000) or {}
        print(json.dumps({
            "ok": job.status in ("done", "cancelled"),
            "job": job.as_dict(),
            "findings": found.get("findings") or [],
            "count": found.get("total", len(job.findings)),
            "kinds": found.get("kinds") or {},
        }, ensure_ascii=False, indent=2, default=str))
    return 0 if job.status == "done" else 1


def run_compare(args, runtime) -> int:
    base, target = args.compare
    result = runtime.jobs.compare(base, target)
    if result is None:
        print("任务不存在", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"ok": True, **result}, ensure_ascii=False,
                         indent=2, default=str))
        return 0
    counts = result["counts"]
    print(f"基准 {base} ({result.get('base_name') or '?'})")
    print(f"对比 {target} ({result.get('target_name') or '?'})")
    print(f"新增 {counts['added']} 条，消失 {counts['removed']} 条，"
          f"共有 {counts['common']} 条")
    for label, items in (("新增", result["added"]),
                         ("消失", result["removed"])):
        if not items:
            continue
        print(f"\n== {label} ==")
        for item in items[:100]:
            print(f"  [{item.get('kind')}] {item.get('summary')}")
    return 0


def serve(args, runtime) -> int:
    from fnet.webui.server import serve as serve_webui

    host = args.host or runtime.config.get("host") or "127.0.0.1"
    port = args.port or runtime.config.get_int("port", fallback=8765)
    open_browser = not args.no_browser and runtime.config.get_bool("open_browser", fallback=True)

    if args.capture:
        capture = Path(args.capture).expanduser()
        kind = classify_input(capture) if capture.is_file() else None
        if not capture.is_file():
            print(f"警告: 输入文件不存在: {capture}", file=sys.stderr)
        elif kind is None:
            print(f"警告: 不支持的文件类型: {capture.suffix}", file=sys.stderr)
        else:
            runtime.app.initial_pcap = str(capture.resolve())

    if args.features or args.all:
        try:
            runtime.app.initial_features = select_features(args.features, args.all)
        except FeatureSelectionError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    try:
        serve_webui(runtime.app, host=host, port=port, open_browser=open_browser)
    except OSError as exc:
        logger.error(f"无法在 {host}:{port} 启动服务: {exc}")
        print(f"无法在 {host}:{port} 启动服务: {exc}", file=sys.stderr)
        print("可以换一个端口: fnet --port 9000", file=sys.stderr)
        return 1
    return 0


def run_mcp(args, runtime) -> int:
    """``--mcp``：stdio MCP server；stdout 只输出 JSON-RPC 协议消息。"""
    from fnet.mcp_server import MCPServer

    default_features: list[str] | None = None
    default_pcap = ""
    input_kind = "pcap"
    if args.capture:
        capture = Path(args.capture).expanduser()
        if capture.is_file():
            default_pcap = str(capture.resolve())
            input_kind = classify_input(capture) or "pcap"
        else:
            print(f"警告: 输入文件不存在: {capture}", file=sys.stderr)
    if args.features or args.all:
        try:
            default_features = select_features(args.features, args.all,
                                               kind=input_kind)
        except FeatureSelectionError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    server = MCPServer(runtime=runtime, default_pcap=default_pcap,
                       default_features=default_features)
    server.serve()
    return 0


def run_pcapoip(args, runtime) -> int:
    """``--pcap-over-ip PORT``：监听 TCP 接收 pcap 字节流并自动分析。"""
    from fnet.pcapoip import PcapOverIPServer

    try:
        checkboxes = select_features(args.features, args.all)
    except FeatureSelectionError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not checkboxes:
        print("没有选择任何功能", file=sys.stderr)
        return 2
    params = _collect_params(args)
    server = PcapOverIPServer(runtime, args.pcap_over_ip, host=args.host,
                              features=checkboxes, params=params,
                              shards=max(1, args.shards))
    try:
        server.start()
    except OSError as exc:
        logger.error(f"无法在 {server.host}:{server.port} 启动 PCAP-over-IP 监听: {exc}")
        print(f"无法在 {server.host}:{server.port} 启动 PCAP-over-IP 监听: {exc}",
              file=sys.stderr)
        return 1
    print(f"PCAP-over-IP 监听 {server.host}:{server.port}"
          "（如需监听其他地址: fnet --host 0.0.0.0 --pcap-over-ip PORT）",
          file=sys.stderr)
    print(f"收到 pcap 后自动分析 {len(checkboxes)} 个功能；Ctrl+C 退出",
          file=sys.stderr)
    try:
        # 可中断等待：Event.wait 在收到 Ctrl+C 时立刻抛 KeyboardInterrupt，
        # 不必像 while True: time.sleep() 那样在两个 sleep 之间轮询。
        stop = threading.Event()
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        print("\n正在停止 PCAP-over-IP 监听…", file=sys.stderr)
    finally:
        server.stop()
    for job in server.jobs:
        state = f"{job.status}（已完成 {len(job.completed)}/{len(job.features)}）" \
            if job.status in ("paused", "interrupted") else job.status
        print(f"任务 {job.id}: {state} | 输出目录: {job.output_dir}",
              file=sys.stderr)
    if server.jobs:
        print("未完成的任务可用 fnet --resume <job-id> 继续", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"Fnet {__version__}")
        return 0
    if args.list_features:
        list_features()
        return 0
    if args.clean_cache:
        return clean_cache()

    if args.config:
        from fnet.config import Config

        config = Config(Path(args.config).expanduser())
        if config.load_error:
            print(config.load_error, file=sys.stderr)
            return 2
    else:
        config = None
    # 只 build 一次：WebUI/CLI/测试共用同一份 wiring（AGENTS.md 禁止并行接线）。
    runtime = build(config)

    if args.list_tools:
        print(describe_environment(runtime))
        return 0
    if args.doctor:
        print(describe_environment(runtime))
        print(f"配置文件: {runtime.config.path or USER_CONFIG}")
        print(f"Python: {sys.version.split()[0]} ({sys.platform})")
        missing = [key for key in runtime.toolbox.TOOL_NAMES if not runtime.toolbox.path(key)]
        print("缺失工具: " + (", ".join(missing) if missing else "无"))
        return 0

    if args.mcp:
        return run_mcp(args, runtime)
    if args.pcap_over_ip is not None:
        return run_pcapoip(args, runtime)
    if args.cli:
        return run_headless(args, runtime)
    if args.resume:
        return run_resume(args, runtime)
    if args.compare:
        return run_compare(args, runtime)
    return serve(args, runtime)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
