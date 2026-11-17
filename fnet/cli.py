"""Command line entry point (``fnet`` / ``python -m fnet``).

Two modes:

``fnet [capture.pcapng]``
    Start the local WebUI and open the browser.  Optionally pre-select a
    capture file.

``fnet -C capture.pcapng --features checkBox_10,http.extract``
    Run the analysis headless and stream the log to stdout.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from fnet import APP_DISPLAY_NAME, __version__
from fnet.app import build, describe_environment
from fnet.features.registry import FEATURES, CATEGORIES, BY_CHECKBOX, BY_HANDLER
from fnet.logger import logger
from fnet.paths import USER_CONFIG


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fnet",
        description=f"{APP_DISPLAY_NAME} {__version__}",
    )
    parser.add_argument("capture", nargs="?", help="要分析的 pcap/pcapng 文件")
    parser.add_argument("-C", "--cli", action="store_true",
                        help="不启动 WebUI，直接在终端运行分析")
    parser.add_argument("--host", default=None, help="WebUI 监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=None, help="WebUI 端口（默认 8765）")
    parser.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    parser.add_argument("--config", default=None, help="使用指定的 config.ini")
    parser.add_argument("--features", default="",
                        help="逗号分隔的功能（checkBox_10 或 http.extract），默认全部默认勾选项")
    parser.add_argument("--all", action="store_true", help="运行全部 37 个功能")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE",
                        help="传给分析功能的额外参数，可重复")
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
    print("\n* = 默认勾选")


def select_features(spec: str, run_all: bool) -> list[str]:
    if run_all:
        return [feature.checkbox for feature in FEATURES]
    if not spec:
        return [feature.checkbox for feature in FEATURES if feature.default]
    selected: list[str] = []
    for token in (part.strip() for part in spec.split(",")):
        if not token:
            continue
        feature = BY_CHECKBOX.get(token) or BY_HANDLER.get(token)
        if feature is None:
            if "." not in token:
                raise SystemExit(f"未知功能: {token}（用 --list-features 查看）")
            selected.append(token)
            continue
        if feature.checkbox not in selected:
            selected.append(feature.checkbox)
    return selected


def run_headless(args, runtime) -> int:
    capture = Path(args.capture).expanduser()
    if not capture.is_file():
        print(f"流量包不存在: {capture}", file=sys.stderr)
        return 2
    checkboxes = select_features(args.features, args.all)
    if not checkboxes:
        print("没有选择任何功能", file=sys.stderr)
        return 2
    params = parse_params(args.param)
    try:
        job = runtime.jobs.submit(str(capture), checkboxes, params)
    except (ValueError, FileNotFoundError) as exc:
        print(f"无法创建任务: {exc}", file=sys.stderr)
        return 2

    print(f"任务 {job.id} | {capture.name} | {len(job.features)} 个功能")
    print(f"输出目录: {job.output_dir}")
    print("-" * 78)
    cursor = 0
    try:
        while True:
            for record in job.log.records_since(cursor):
                print(record.line, flush=True)
                cursor = record.seq
            if job.status in ("done", "error", "cancelled"):
                for record in job.log.records_since(cursor):
                    print(record.line, flush=True)
                break
            time.sleep(0.12)
    except KeyboardInterrupt:
        print("\n收到中断，正在取消任务…", file=sys.stderr)
        runtime.jobs.cancel(job.id)
        job.thread.join(timeout=10) if job.thread else None
        return 130

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
    if job.status == "cancelled":
        return 130
    return 1


def serve(args, runtime) -> int:
    from fnet.webui.server import serve as serve_webui

    host = args.host or runtime.config.get("host") or "127.0.0.1"
    port = args.port or runtime.config.get_int("port", fallback=8765)
    open_browser = not args.no_browser and runtime.config.get_bool("open_browser", fallback=True)
    if args.no_browser:
        open_browser = False

    if args.capture:
        capture = Path(args.capture).expanduser()
        if not capture.is_file():
            print(f"警告: 流量包不存在: {capture}", file=sys.stderr)
        elif capture.suffix.lower() not in (".pcap", ".pcapng", ".cap", ".dmp", ".etl"):
            print(f"警告: 不支持的文件类型: {capture.suffix}", file=sys.stderr)
        else:
            runtime.app.initial_pcap = str(capture.resolve())

    if args.features or args.all:
        try:
            runtime.app.initial_features = select_features(args.features, args.all)
        except SystemExit as exc:
            print(str(exc.code), file=sys.stderr)
            return 2

    try:
        serve_webui(runtime.app, host=host, port=port, open_browser=open_browser)
    except OSError as exc:
        logger.error(f"无法在 {host}:{port} 启动服务: {exc}")
        print(f"无法在 {host}:{port} 启动服务: {exc}", file=sys.stderr)
        print("可以换一个端口: fnet --port 9000", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"Fnet {__version__}")
        return 0
    if args.list_features:
        list_features()
        return 0

    runtime = build()
    if args.config:
        from fnet.config import Config

        runtime = build(Config(Path(args.config).expanduser()))

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

    if args.cli:
        return run_headless(args, runtime)
    return serve(args, runtime)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
