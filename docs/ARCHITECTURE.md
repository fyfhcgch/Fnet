# 架构说明

Fnet 的目标是：**同一套分析内核，既能被本地 WebUI 调用，也能被 CLI 和测试
直接调用**。因此所有对象在 `fnet/app.py` 中一次性组装，WebUI 只是其中一个
前端。

## 进程与线程模型

```
浏览器
  │  HTTP (localhost only, X-Fnet-Token)
  ▼
ThreadingHTTPServer  ──►  FnetApp (config / toolbox / jobs / plugins)
  │                           │
  │  POST /api/analyze        │ submit()
  ▼                           ▼
JobManager ─────────────►  worker thread
                              │
                              ├─ FeatureContext.report() ─► JobLog ─► 日志缓冲
                              ├─ FeatureContext.set_progress()
                              ├─ FeatureContext.check_cancel() ─► threading.Event
                              └─ FeatureContext.write_output() ─► 任务输出目录
```

- **Web 服务**：`ThreadingHTTPServer`，每个请求一个线程。静态资源与
  `/api/health` 不需要 token；其余 API 都要 `X-Fnet-Token`。
- **分析任务**：`JobManager.submit()` 创建 `Job` 后启动一个后台线程，HTTP
  请求立即返回任务 id。前端轮询 `/api/jobs/<id>` 与 `/api/log`。
- **取消**：`Job.cancel_event` 由 `/api/jobs/<id>/cancel` 设置；tshark 子进程
  通过 `run(..., cancel=event)` 被终止，功能处理器在循环中调用
  `ctx.check_cancel()` 主动退出。
- **输出**：每个任务有独立目录 `~/.cache/fnet/jobs/<job-id>/`，报告会写成
  `report.txt`、`report.md` 与自包含的 `report.html`，结构化结果写成
  `findings.json` 与 `findings.csv`，其余为功能导出的文件
  （哈希、证书、解密载荷、CSV 等）。`job.json` 保存任务元数据（流量包、
  功能、参数、状态），供重启后的“任务历史”恢复；它不会出现在产出列表与
  打包 ZIP 中。
- **结构化结果**：`fnet/findings.py` 定义统一的记录格式（类别、级别、帧、
  功能、摘要、详情）。功能处理器在写日志的同时调用
  `ctx.add_finding(...)`，`JobManager` 负责归属功能、落盘，并通过
  `GET /api/findings` 提供给“分析结果”表格；报告与 CSV 复用同一批数据。
- **报告**：`fnet/report.py` 只依赖标准库，把任务元数据、日志、产出与结构化
  结果渲染为 Markdown/HTML。WebUI 的 `GET /api/report` 对运行中的任务使用
  内存日志，对重启后恢复的任务则从 `report.txt` 反解日志，再按 `sections`
  重新渲染。
- **数据包定位**：`GET /api/packet` 按 `job`/`frame` 找到抓包路径（历史任务
  从 `job.json` 恢复），调用 `fnet/services.py` 取相邻帧与 `-V` 解码；导出的
  片段写到任务目录 `frames/`，因此会进入产出列表与打包 ZIP。
- **断点与分片**：`Job` 在 `job.json` 中记录 `completed`、`feature_status`、
  `succeeded`、`failed`，任务只在功能边界暂停；`/api/jobs/<id>/pause` 设置
  `pause_event`，`resume()` 从下一个未完成功能继续。注册表中 `shardable=True`
  的无状态功能可用 `--shards N` 按帧区间切成临时 pcapng，`FeatureContext`
  通过 `frame_offset` 把分片帧号还原为原始帧号；流重组/解密类功能保持整包
  执行，避免跨分片状态丢失。
- **自定义规则**：`fnet/utils/rules.py` 只依赖标准库，解析 YARA 子集与逐行
  正则；`JobManager._apply_rules()` 在功能结束后扫描 pcap 载荷，把命中写入
  结构化结果的 `rule` 类别。未显式传 `--rules` 时回退到配置
  `paths.rules_file`，因此 WebUI 导入的规则对后续任务持续生效。
- **流式上传**：`/api/upload` 的 multipart 分支边读边写临时文件
  （`_MultipartStream`/`_stream_body`），内存占用与文件大小无关；结束后校验
  后缀并原子替换到 `<cache>/uploads/`，异常路径统一删除临时文件。
- **实时抓包**：`fnet/live.py` 管理单个 tshark 子进程，按 `tshark -D` 解析
  网卡，输出到 `<cache>/live/`；`FnetApp.live` 由 WebUI 的
  `/api/capture/*` 路由驱动，服务退出时 `serve()` 调用 `shutdown()` 清理进程。

## 目录与分层

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 入口 | `fnet/__main__.py`, `fnet/cli.py` | 参数解析、启动 WebUI、无头分析、JSON 输出、续跑与任务对比 |
| 组装 | `fnet/app.py` | `Config`、`ToolBox`、`JobManager`、`PluginManager`、`FnetApp` |
| 前端 | `fnet/webui/` | HTTP 路由、静态页面、WebUI 资源 |
| 任务 | `fnet/jobs.py` | 任务生命周期、进度、日志、报告、取消、断点/分片、对比 |
| 实时抓包 | `fnet/live.py` | tshark 网卡枚举与单实例抓包控制 |
| 结果 | `fnet/findings.py` | 结构化结果的格式、筛选、CSV 导出 |
| 报告 | `fnet/report.py` | Markdown/HTML 报告渲染、章节选择、旧报告反解 |
| 功能 | `fnet/features/` | 46 个分析功能，按主题拆文件 |
| 外部工具 | `fnet/tools/runner.py` | 工具发现、子进程、tshark 字段校验 |
| 工具库 | `fnet/utils/` | 编解码、AES/RC4/MD4/RSA/GCM、pcap 辅助、TCP 流重组、RESP/PostgreSQL/BSON-MongoDB/WebSocket/MySQL 解析、Kerberos 原语、DNS/ICMP 隧道、邮件 MIME、WPA CCMP 解密、规则解析 |
| 配置 | `fnet/config.py` | `config.ini` 默认值、读写、最近文件 |

## 功能注册表

`fnet/features/registry.py` 是唯一的“功能清单”：

```python
Feature("checkBox_10", "关键字检测", "text_scan.keyword_scan", "text",
        "在流量中查找 flag/关键字", default=True)
```

- `checkbox`：功能的固定编号，CLI 与 WebUI 都接受。
- `handler`：`模块.函数`，由 `resolve()` 动态导入。
- `category`：WebUI 侧栏分组。
- `needs`：需要的外部工具/库，仅用于提示，不阻止运行。
- `default`：是否默认勾选。

新增功能只需：

1. 在 `fnet/features/<module>.py` 写一个接受 `FeatureContext` 的函数；
2. 在 `FEATURES` 里登记；
3. 如需新分类，在 `CATEGORIES` 里加一项。

## 一次分析的完整流程

1. 前端 `POST /api/analyze`，传入 `pcap`、`features`、`params`。
2. `JobManager.create()` 校验文件后缀、解析复选框、创建输出目录。
3. worker 打开 `report.txt`，逐个调用 `call_feature(ctx, handler)`。
4. 每个功能：
   - 用 `tshark_rows(ctx, fields, filter)` 取字段；字段列表先经过
     `tshark -G fields` 校验，未知字段会被丢弃并按位置补空，避免整条查询
     静默失败。
   - 用 `ctx.report()` 写日志，用 `ctx.write_output()` 存文件。
   - 值得汇总的发现用 `ctx.add_finding()` 记成结构化结果（凭据、哈希、
     flag、导出文件等），日志仍然是完整的人读流水。
   - 定期 `ctx.check_cancel()`。
5. 任务结束写 `findings.json` / `findings.csv`，随后写 `report.txt`，并用
   同一批日志与结果渲染 `report.md` / `report.html`，状态置为 `done` /
   `error` / `cancelled`。
6. 前端轮询到终态后展示“分析结果”表格与产出列表，可排序、筛选、复制或
   导出 CSV，也可单文件下载或打包 ZIP。

无头模式复用同一内核：`-C` 建任务并流式打印日志，`--json` 在结束后把任务、
findings、统计与产出序列化为 JSON；`--resume`/`--compare` 直接调用
`JobManager.resume()` / `compare()`，因此 CLI、WebUI 与测试看到的结果一致。

## 配置与路径

- 静态资源：`fnet/assets/`（字典、Shiro 密钥、图标、默认 `config.ini`）。
- 用户配置：Linux `~/.config/fnet/config.ini`；Windows `%APPDATA%/Fnet/`；
  macOS `~/Library/Application Support/Fnet/`。
- 日志：Linux `~/.local/state/fnet/logs/`；缓存与任务输出
  `~/.cache/fnet/`。
- 环境变量：`FNET_HOME`（整体覆盖用户目录）、`FNET_ASSETS`（资源目录）、
  `FNET_TOOLS`（额外工具目录）。

## 错误处理原则

- 单个功能失败不会终止整个任务；异常写入日志并继续下一个功能。
- 缺少 `tshark` 时依赖它的功能会明确报告“未找到 tshark”，而不是静默返回空。
- 用户取消通过异常 `CancelledError` 向上传递，worker 捕获后置为 `cancelled`。
- WebUI 的写接口统一返回 `{"ok": false, "error": "..."}`，HTTP 状态码
  400/403/500 区分参数、权限与内部错误。

## 测试策略

- **纯函数**：AES/GCM/MD4/RC4/RSA 使用标准测试向量；编解码使用已知输入。
- **注册表**：46 个 handler 都可导入、checkbox 唯一、分类都存在。
- **API 冒烟**：启动临时服务，验证 health/meta/upload/analyze/log/download。
- **抓包**：`tests/data/*.pcap` 由 `scripts/make_samples.py` 生成，断言
  关键字、HTTP 凭据、Webshell、NTLM、DNS、Modbus/MQTT 等结果。
- **路线图回归**：`tests/test_roadmap.py` 覆盖流式上传、规则导入与执行、
  暂停/继续、任务对比、CLI `--json`/`--compare`/`--shards`/`--resume`、实时
  抓包网卡解析，以及 DNS/ICMP 隧道、SMTP、MySQL、Kerberos、WPA 的 handler
  集成。
- **实时抓包生命周期**：`tests/test_live.py` 用桩 `tshark` 覆盖 start/stop、
  “同时只允许一个抓包”、SIGINT 停止、输出与文件大小回报；重复 `stop()`
  必须幂等（早期版本在这里会因非重入锁自死锁）。
- **性能**：`scripts/bench.py` 生成 10/100/1000 MB 抓包，按功能记录耗时与
  峰值 RSS，并写入 [`docs/PERFORMANCE.md`](PERFORMANCE.md)。
- **CI**：GitHub Actions 在 Python 3.10–3.13 上安装 tshark，运行全量
  unittest 与 `node --check fnet/webui/static/app.js`。
