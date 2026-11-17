# WebUI 使用与接口

Fnet 启动后在本地开一个 HTTP 服务（默认 `http://127.0.0.1:8765`），浏览器
加载单页应用，所有分析通过 JSON API 驱动。

## 启动

```bash
python3 -m fnet                     # 自动打开浏览器
python3 -m fnet --no-browser        # 只启动服务
python3 -m fnet --host 0.0.0.0      # 明确允许局域网访问（默认不允许）
python3 -m fnet --port 9000
python3 -m fnet capture.pcapng --features checkBox_10,http.extract
```

`--host`/`--port` 也可写在配置文件的 `[config]` 段（`host`、`port`）。
`capture.pcapng` 与 `--features` 会作为 `initial` 字段返回，前端自动预选
流量包和复选框。

## 界面布局

```
┌──────────────────────────── 顶栏 ────────────────────────────┐
│ 品牌 全局搜索 文件/统计/设置/工具…菜单 tshark 徽标 语言 主题 │
├──────────┬──────────────────────────────────────────────────┤
│ 功能侧栏 │  日志 / 结果 / 产出 / 批量 / 图表 / 历史 / 文本 / 关于 │
│ 13 组    │  （胶囊 Tab 切换）                                │
│ 37 功能  │                                                  │
│ 全选/清空│  进度条 + 开始/取消按钮                            │
└──────────┴──────────────────────────────────────────────────┘
```

- **视觉风格**：暖中性色 + 陶土红强调色，参考 EBCTFCodeBox 的 Material 3
  取向（胶囊按钮、圆角卡片、内联 SVG 线性图标），不加载外部字体或图标资源。
- **响应式**：`>1100px` 双栏；`≤1100px` 顶栏收紧；`≤900px` 侧栏与主区
  上下堆叠；`≤560px` 单列、按钮全宽。
- **主题**：暖夜、暖昼、浅樱、暮玫、莓紫五套配色，选择保存在
  `localStorage`。浅色主题自动切换 `--on-accent`，保证主按钮文字对比度。
- **全局搜索**：顶栏搜索框与侧栏功能搜索双向同步，匹配功能名称、说明、分类
  与 handler；命中时自动展开分组并显示匹配数量，按 `/` 可快速聚焦。
  常用功能会出现在“最近使用”快捷标签中。
- **语言切换**：顶栏下拉框切换中文 / English。界面外壳、功能标题、功能说明
  与分类名使用 `title_en` / `description_en` / `name_en`，语言选择写入配置并
  持久化；日志与报告保持中文，保证证据文本在不同语言下一致。
- **上传进度与取消**：大文件上传使用 `XMLHttpRequest.upload.onprogress`
  显示百分比，按 `Esc` 或再次选择文件可中止，服务端会清理未完成的临时文件。
- **暂停 / 继续**：运行中可点击“暂停”，任务在当前功能结束后停在功能边界并
  保留 `job.json` 中的完成状态；点击“继续”或 `--resume <job-id>` 从断点续跑。
- **任务对比**：“任务历史”里的“对比两个任务”选择基准与目标任务，调用
  `/api/compare` 展示新增与消失的凭据、哈希、flag 等结构化结果。
- **自定义规则**：“设置 → 自定义规则…”导入 YARA 子集或逐行正则规则文件，
  命中结果写入 findings 的“自定义规则”类别并进入报告；路径保存为
  `paths.rules_file`，CLI 也可用 `--rules` 临时覆盖。
- **实时抓包**：工具栏“实时抓包”选择网卡与 BPF 过滤器，通过 tshark 写入
  `<cache>/live/`；停止后可直接把结果提交给当前勾选的功能进行分析。
- **任务历史**：完成的任务写入 `~/.cache/fnet/jobs/<id>/job.json`，可在
  “任务历史”页回看报告、一键重跑或删除；进程异常退出时未完成任务标记为
  “已中断”。历史参数保存在本机缓存目录，不要在不信任的机器上分析含敏感
  凭据的流量包。
- **日志**：按级别（info/good/warn/error/debug）与关键字过滤，支持复制、
  高亮 flag/哈希/URL、自动滚动。日志与分析结果表格里的“帧 N”可以点击：
  弹窗展示该帧摘要、前后文帧与 `tshark -V` 解码详情，并可导出上下文
  pcapng 片段或交给本机 Wireshark 打开。
- **分析结果**：凭据、哈希、flag、导出的文件等会进入可排序表格；支持按
  类别/级别筛选、关键字搜索、点击表头排序、分页与每页条数、列显示/隐藏
  （保存在浏览器本地）、复制本页/选中行、按帧号跳转与 CSV 导出。旧任务
  没有 `findings.json` 时会从日志推断，并在标题旁标注。
- **产出**：任务结束后列出文件，可单文件下载或一键打包 ZIP。
- **批量队列**：左侧文件选择框或拖拽区一次选择多个 pcap 时，会调用
  `/api/batch` 排队执行；面板可设置并发数（1–4），暂停/继续队列、拖拽调整
  排队顺序，逐行显示状态、进度、当前功能，并可查看日志、下载报告或取消任务；
  “合并报告”把已完成任务汇总为一个 Markdown/HTML 文档。刷新页面不会丢任务，
  因为队列状态保存在服务端 `JobManager` 中。
- **统计图表**：对当前流量包调用时间线、协议分层、IP 会话与拓扑统计，绘制
  SVG 流量时间线、协议分层、Top 会话柱状图和会话拓扑；可切换“按字节/按帧数”
  和 30/60/120 个时间桶。时间线支持滚轮缩放、拖拽框选与双击重置，点击时间桶
  或协议条可下钻到对应数据包；图表可导出 SVG/PNG。
- **TLS 密钥**：“设置 → 上传 TLS keylog / 私钥…”会把文件存入
  `<cache>/keys` 并写入 `tls_keylog` / `tls_private_key`；加密私钥可在
  `config.ini` 配置 `tls_key_passphrase`（或用 `FNET_TLS_KEY_PASS` 环境变量）
  自动解密。解密时会用证书链匹配私钥并按服务端端点选择，失败时列出本机可用
  密钥与排查建议；QUIC/HTTP3 连接也会一并识别。
- **报告**：自动生成纯文本、Markdown 与 HTML 版本；HTML 自带样式并支持
  打印为 PDF，“文件”菜单可选择导出章节，历史任务也可直接下载。
- **快捷键**：`Ctrl/Cmd + Enter` 开始分析；文件路径输入框回车加载。

## 安全模型

- 默认只绑定 `127.0.0.1`，不监听公网。
- 每次启动生成随机 token，注入 `index.html` 的 `window.FNET_TOKEN`；
  除 `/api/health` 外所有 API 都要求 `X-Fnet-Token` 或 `?token=`。
- 静态文件路径经过 `resolve()` 与根目录前缀校验，阻止目录穿越。
- 上传大小由 `max_upload_mb` 控制（默认 1024），只接受
  `.pcap/.pcapng/.cap/.dmp/.etl`；TLS 密钥上传（`X-Kind`）额外限制为
  8 MiB，并校验 keylog 标签或 PEM 私钥头。
- 响应带 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`；
  首页 CSP 把脚本、样式与连接限制在 `self`，只额外放行注入 token 的内联脚本。
- 服务没有“执行任意命令”的公开接口；菜单动作是固定枚举。

## API 一览

所有响应都是 JSON（下载接口除外）。错误格式：

```json
{"ok": false, "error": "说明"}
```

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 单页应用（注入 token/version） |
| GET | `/static/*` | CSS/JS/图标 |
| GET | `/api/health` | `{"ok":true,"version":"..."}`，无需 token |
| GET | `/api/meta` | 功能、分类、主题、工具、配置、路径、`initial` |
| GET | `/api/config` | 当前配置快照 |
| POST | `/api/config` | 保存某个 section 的键值 |
| GET | `/api/jobs` | 任务列表 |
| GET | `/api/jobs/<id>?cursor=N` | 任务状态、增量日志、产出列表 |
| POST | `/api/jobs/<id>/cancel` | 取消任务 |
| GET | `/api/history` | 历史任务列表（含已结束的磁盘任务） |
| GET | `/api/history/<id>` | 历史任务元数据、报告文本与产出 |
| POST | `/api/history/<id>/delete` | 删除历史任务及其输出目录 |
| GET | `/api/findings?job=<id>` | 结构化结果（`q`/`kind`/`level` 过滤，`format=csv` 下载） |
| GET | `/api/packet?job=<id>&frame=N&context=2` | 数据包摘要、相邻帧与 `-V` 解码详情；`format=pcap` 下载片段 |
| POST | `/api/analyze` | 创建分析任务 |
| POST | `/api/jobs/<id>/pause` | 请求在当前功能结束后暂停 |
| POST | `/api/jobs/<id>/resume` | 继续已暂停/中断的任务 |
| GET | `/api/compare?base=<id>&target=<id>` | 对比两个任务的 findings（新增/消失/共有） |
| GET | `/api/rules` | 当前自定义规则文件、规则数量与名称 |
| POST | `/api/rules` | 设置自定义规则文件路径（空字符串关闭） |
| GET | `/api/capture/interfaces` | 列出 tshark 可见网卡 |
| GET | `/api/capture/status` | 实时抓包状态、文件、大小与耗时 |
| POST | `/api/capture/start` | 开始抓包（`interface`、`filter`、`name`） |
| POST | `/api/capture/stop` | 停止抓包，可选 `analyze` 直接提交分析 |
| POST | `/api/batch` | 批量创建任务（`pcaps`、`features`、`params`、`concurrency`） |
| POST | `/api/upload` | 上传流量包（multipart 流式写入临时文件，或原始 body）；`X-Kind: keylog/key` 上传 TLS 密钥，`X-Kind: rules` 导入规则文件 |
| GET | `/api/log?job=<id>&since=N` | 仅取增量日志 |
| GET | `/api/report?job=<id>&format=<html\|markdown>&sections=...` | 渲染可下载/内联查看的报告 |
| GET | `/api/download?job=<id>&path=<file>` | 下载单个产出 |
| GET | `/api/download?job=<id>` | 打包下载全部产出（无 `path` 时） |
| POST | `/api/decode` | 文本解码（Base64/Hex/URL/XOR/解压/解码链） |
| POST | `/api/action` | 菜单动作（统计、分离、修复、插件等） |
| POST | `/api/shutdown` | 关闭服务 |

### 创建任务

```bash
curl -H "X-Fnet-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"pcap":"/abs/path/x.pcapng",
       "features":["checkBox_10","checkBox_30"],
       "params":{"webshell_password":"pass"}}' \
  http://127.0.0.1:8765/api/analyze
```

`features` 也可以传 handler（`text_scan.keyword_scan`），或使用
`handlers` 字段。返回：

```json
{"ok": true, "job": {"id": "…", "status": "running", "progress": 0, …}}
```

### 轮询任务

```bash
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/jobs/<id>?cursor=0"
```

响应包含 `job`、`logs`、`cursor`、`artifacts`。前端每次把 `cursor` 传回，
只取新增日志，避免长任务重复传输。

### 批量任务

```bash
curl -H "X-Fnet-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"pcaps":["/abs/a.pcapng","/abs/b.pcapng"],
       "features":["checkBox_10","http.extract"],
       "params":{},"concurrency":2}' \
  http://127.0.0.1:8765/api/batch
```

最多一次提交 50 个流量包，`concurrency` 会限制为 1–8。返回的 `jobs` 与
`/api/analyze` 相同，初始状态可能是 `queued` 或 `running`。前端通过
`GET /api/jobs` 轮询批量行；任务结束后单包状态、日志与产出仍走
`/api/jobs/<id>`。队列中尚未开始的任务可以直接取消。

队列控制接口：

| 接口 | 作用 |
| --- | --- |
| `GET /api/batch` | 队列快照：状态计数、待执行顺序、暂停标记与并发数 |
| `POST /api/batch/pause` | 暂停队列，正在运行的任务继续完成 |
| `POST /api/batch/resume` | 继续执行排队任务 |
| `POST /api/batch/reorder` | 传 `{"ids":[...]}` 调整排队顺序 |
| `POST /api/batch/concurrency` | 传 `{"concurrency":1-8}` 调整并发 |
| `GET /api/batch/report?jobs=<id,id>&format=md\|html` | 下载合并报告 |

### 上传 TLS 密钥

```bash
# NSS keylog
curl -H "X-Fnet-Token: $TOKEN" -H 'X-Filename: browser.log' \
  -H 'X-Kind: keylog' --data-binary @browser.log \
  http://127.0.0.1:8765/api/upload

# PEM 私钥（仅非前向保密套件）
curl -H "X-Fnet-Token: $TOKEN" -H 'X-Filename: server.pem' \
  -H 'X-Kind: key' --data-binary @server.pem \
  http://127.0.0.1:8765/api/upload
```

密钥保存到 `<cache>/keys`，响应中的 `config` 字段说明写入了哪个配置项
（`tls_keylog` 或 `tls_private_key`）。上传时会校验 keylog 标签或
`PRIVATE KEY` 头，格式不符直接返回 400。

### 任务历史

`GET /api/history` 同时扫描内存中的任务与 `~/.cache/fnet/jobs/*/job.json`，
按创建时间倒序返回。任务在创建与结束时各写一次快照，因此进程重启后仍可
回看已结束任务：

```bash
curl -H "X-Fnet-Token: $TOKEN" http://127.0.0.1:8765/api/history
curl -H "X-Fnet-Token: $TOKEN" http://127.0.0.1:8765/api/history/<id>
curl -X POST -H "X-Fnet-Token: $TOKEN" \
  http://127.0.0.1:8765/api/history/<id>/delete
```

详情接口返回 `job`、`report`（最多 200k 字符）与 `artifacts`。删除接口只
允许删除已结束的任务；正在运行的任务会返回 400。前端“重跑”会复用历史
任务的流量包路径、功能与参数，再次调用 `/api/analyze`。

### 报告导出

任务结束时会在输出目录自动写入三份报告：`report.txt`（纯文本）、
`report.md`（Markdown）和 `report.html`（自包含样式，可离线打开，也可用
浏览器打印为 PDF）。WebUI 的“文件”菜单可以查看 HTML 报告，或在导出对话框
里选择格式与章节；“任务历史”的每一行也提供 HTML 下载。

```bash
# 下载 HTML，仅包含概要和关键发现
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/report?job=<id>&format=html&sections=summary,findings"

# 在浏览器中直接打开（Content-Disposition: inline）
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/report?job=<id>&format=html&inline=1"
```

`sections` 取值：`summary`（概要）、`features`（功能清单）、
`findings`（关键发现）、`log`（完整日志）、`artifacts`（产出文件）、
`params`（分析参数）。留空时使用默认章节（不含参数）。旧任务没有
Markdown/HTML 文件时，会从 `report.txt` 重建日志后再渲染。

报告中的所有流量内容都会经过 HTML 转义，只有 `flag{...}` 会被包成
`<mark>` 高亮；HTML 响应带 `CSP: default-src 'none'`，不会执行流量包里的
任何脚本。

### 结构化结果

功能处理器在写日志的同时会把可汇总的发现记录成结构化结果，任务结束时写入
输出目录的 `findings.json` 与 `findings.csv`。接口：

```bash
# JSON：默认最多返回 5000 条
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/findings?job=<id>"

# 服务端过滤
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/findings?job=<id>&kind=hash&q=administrator&level=good"

# CSV 下载（不做截断）
curl -H "X-Fnet-Token: $TOKEN" \
  "http://127.0.0.1:8765/api/findings?job=<id>&format=csv" -o findings.csv
```

响应字段：

| 字段 | 说明 |
| --- | --- |
| `findings` | 记录数组，含 `kind`、`level`、`frame`、`feature`、`summary`、`detail`、`time` |
| `total` | 过滤前的总数 |
| `count` | 过滤后的数量 |
| `kinds` | 各分类计数，用于筛选下拉与摘要 |
| `derived` | 旧任务无 `findings.json` 时为 `true`，结果由日志推断 |
| `truncated` | 命中数量超过返回上限时为 `true` |

`kind` 取值：`flag`、`credential`、`hash`、`http`、`webshell`、`sql`、
`dns`、`file`、`protocol`、`log`、`other`；`level` 与日志级别相同。
导出 CSV 的列固定为 `类别,级别,帧,功能,摘要,详情`。

### 菜单动作

`POST /api/action` 的 `action` 取值：

| action | 额外字段 | 作用 |
| --- | --- | --- |
| `stats` | `sub=ports/http_uri/ip/hierarchy/timeline/topology/protocol/timeline_packets` | 端口、URI、IP 会话、协议分层、时间线、会话拓扑、协议下钻与时间桶数据包 |
| `export_objects` | — | 一键导出所有对象 |
| `carve` | — | 一键分离所有文件（foremost/binwalk） |
| `repair` | — | 用 pcapfix 修复 |
| `etl` | — | ETL 转 pcapng |
| `http_login` | — | 识别 HTTP 登录成功的账号密码（创建任务） |
| `plugin_run` | `key`, `target` | 运行 CyberChef 等工具 |
| `plugin_add` / `plugin_remove` | `name`, `command` | 管理自定义工具 |
| `open_path` / `open_log` | `path` | 在系统文件管理器中打开目录 |
| `open_url` | `url` | 在浏览器打开 http(s) 链接 |
| `save_config` / `reload_config` | — | 保存/重新加载配置 |
| `update_check` | — | 返回开源更新说明（不联网） |

需要外部工具的动作在工具缺失时返回明确的错误信息。

“专项功能”菜单中的“协议凭据提取”“SMB2 文件访问与 NTLM 认证”“协议自动识别”
“跨协议凭据关联”“认证时间线”和“深度 flag 扫描”不是复选框功能，前端会分别以
`protocols.credentials`、`protocols.smb2`、`protocols.detect`、
`forensics.correlate`、`forensics.timeline`、`text_scan.deep` 作为 handler 调用
`/api/analyze`，因此同样有日志、进度、报告与结构化结果。HTTP/2 与 LDAP 深度解析
也通过 `protocols.http2`、`protocols.ldap` 直接调用。

## 反代与远程访问

Fnet 没有内置 TLS，也不做多用户隔离。若确实需要远程访问，请放在
SSH 隧道或带认证的反向代理之后：

```bash
ssh -L 8765:127.0.0.1:8765 user@server
```

不要把 `--host 0.0.0.0` 直接暴露到公网。
