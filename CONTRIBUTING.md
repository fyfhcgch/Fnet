# 贡献指南

感谢你愿意改进 Fnet。小改动（文档、拼写、单个功能修复）可以直接提 PR；涉及
架构、功能清单或界面的改动，建议先开一个 Issue 说明动机和方案，避免返工。

## 开发环境

- Python 3.10 及以上，`tshark` 在 `PATH` 中（`sudo apt install tshark`）
- **运行时不需要任何第三方 Python 包**，请保持这一点
- 只有生成样例抓包时才需要 scapy：`python3 -m pip install -e '.[samples]'`

```bash
python3 -m fnet --no-browser                     # 启动 WebUI
FNET_HOME=/tmp/fnet-dev python3 -m fnet          # 用临时目录隔离配置/日志
python3 -m fnet --list-features                  # 查看 50 个功能的复选框编号
python3 -m fnet --doctor                         # 检查 tshark/java/hashcat 等
python3 -m unittest discover -s tests -v         # 全量测试
python3 -m unittest tests.test_codec.CodecTest.test_base64 -v   # 单个用例
```

`tests/data/*.pcap` 是纳入版本库的样例，改动需刻意为之：
`python3 scripts/make_samples.py`。

## 目录速览

| 路径 | 作用 |
| --- | --- |
| `fnet/app.py` | 对象图组装，WebUI/CLI/测试共用 |
| `fnet/features/registry.py` | 唯一的 50 个功能清单（含复选框编号） |
| `fnet/features/` | 各分析功能，按主题分模块 |
| `fnet/tools/runner.py` | 外部工具与 `tshark` 封装 |
| `fnet/webui/` | HTTP 服务与前端静态页 |
| `fnet/report.py` | 纯文本 / Markdown / HTML 报告 |
| `tests/` | 单元测试、API 冒烟与样例抓包 |

## 新增一个分析功能

1. 在 `fnet/features/` 下实现处理函数，签名为 `def handler(ctx: FeatureContext) -> None`。
2. 用 `fnet/features/common.py` 的 `tshark_rows` / `table` / `csv_rows` 取数据，
   不要自己拼 `subprocess` 调用 `tshark`。
3. 用 `ctx.report(...)` 写日志，`ctx.write_output(...)` 存产出，循环里调用
   `ctx.check_cancel()`；值得汇总的结果用 `ctx.add_finding(kind, summary, ...)`。
4. 在 `fnet/features/registry.py:FEATURES` 注册，复选框 ID 是历史遗留的稀疏编号，
   **不要重编号**。
5. 同步更新 `docs/FEATURES.md`、README 中的功能统计，以及
   `tests/test_registry.py`、`tests/test_api.py`、`tests/test_uispec.py` 里的断言。
6. 为新增协议补充 `tests/data/` 样例与端到端断言。

## 代码约定

- 仅使用 Python 标准库；确需外部能力时优先复用已有的 `tshark` 与可选工具探测。
- 界面文案、日志、报告使用中文，保持术语一致。
- 子进程调用使用参数数组，不要 `shell=True`（兼容 Windows）。
- 报告渲染必须对来自抓包的所有文本做 HTML 转义。
- 提交前跑通全量测试；失败的处理函数会被记录并继续，测试应断言日志与产出，
  而不是断言异常。

## 提交与 PR

- 提交信息用一句中文概括改动，必要时在正文补充动机与影响。
- PR 描述里写明：改了什么、为什么、如何验证（命令或截图）。
- 不要提交 `__pycache__`、缓存目录、个人配置或与改动无关的文件。

## 安全与合法使用

Fnet 只用于合法的教学、竞赛与授权测试。Fnet 不会执行流量包中的任何代码。
安全问题请按 [docs/SECURITY.md](docs/SECURITY.md) 的方式私下反馈。
