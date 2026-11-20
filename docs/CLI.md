# CLI 使用说明

Fnet 除了本地 WebUI（见 [docs/WEBUI.md](WEBUI.md)），还提供三种命令行运行
模式：无界面分析、PCAP-over-IP 接入与 MCP server。三种模式与 WebUI、测试
共用 `fnet/app.py:build()` 装配出的同一套对象图，功能目录、任务管线与报告
渲染完全一致。

## 无界面分析（`-C`）

```bash
python3 -m fnet -C capture.pcapng                          # 默认勾选项
python3 -m fnet -C access.log                              # 日志默认 5 项
python3 -m fnet -C capture.pcapng --features checkBox_10,http.extract
python3 -m fnet -C capture.pcapng --json                   # 机器可读输出
```

`-C` 的输入既可以是 pcap/pcapng 抓包，也可以是 `.log`/`.txt`/`.out`/`.jsonl`/
`.ndjson`/`.json`/`.csv`/`.tsv` 文本日志。日志任务使用内置解析器并默认选中
“日志分析”分类的 5 项功能，不依赖 `tshark`。

完整参数见 `python3 -m fnet --help` 与 README 的「无界面分析」一节；
`--shards` 分片与 `--resume` 断点续跑见 [docs/ARCHITECTURE.md](ARCHITECTURE.md)。

## tshark 结果缓存

tshark 字段提取按「命令 + 抓包大小/mtime」缓存成 TSV，默认上限 **512 MB /
14 天**，超出后按最近最少使用淘汰（命中时会刷新访问时间，常用条目不会被误删）。
上限可用 `config.ini` 的 `tshark_cache_max_mb` / `tshark_cache_ttl_days` 调整，
填 `0` 关闭对应限制；也可以随时手动清理：

```bash
python3 -m fnet --clean-cache
```

缓存只影响速度，删掉不会丢任何分析结果。

## 实时抓包与 PCAP-over-IP

WebUI 工具栏的「实时抓包」由 tshark 直接抓网卡并写入 `<cache>/live/`
（详见 [docs/WEBUI.md](WEBUI.md)）；当流量来自另一台机器或另一个工具时，
可以用 PCAP-over-IP 接收字节流，二者最终都进入同一条任务管线。

### 启动监听

```bash
python3 -m fnet --pcap-over-ip 18000                       # 监听 127.0.0.1:18000
python3 -m fnet --pcap-over-ip 18000 --features checkBox_10,webshell.decrypt
python3 -m fnet --pcap-over-ip 18000 --host 0.0.0.0        # 明确放开监听地址
```

* 第一个位置参数之外的 `PORT` 是必填的端口号；监听地址默认
  `127.0.0.1`，可用 `--host` 或 `config.ini` 的 `[config] host` 覆盖。
* `--features` / `--all` / `--param` / `--shards` 决定每个收到流量包的
  任务配置；缺省为全部默认勾选项。
* 启动后日志打印实际监听地址（`port` 传 0 时会回填系统分配的端口）。

### 客户端用法

服务器按全局头魔数识别 pcap / pcapng（含纳秒变体），客户端把**完整文件的
全部字节**写入 socket 后关闭连接即可，一个连接对应一个流量包：

```bash
# 抓包的同时把字节流灌给 Fnet
sudo tcpdump -i eth0 -w - 'tcp port 443' | nc 127.0.0.1 18000

# 已有文件直接发送
cat capture.pcapng | nc 127.0.0.1 18000

# Windows（nmap 自带的 ncat）
ncat --send-only 127.0.0.1 18000 < capture.pcap
```

纯 Python 客户端示例（stdlib）：

```python
import socket

with open("capture.pcapng", "rb") as fh:
    data = fh.read()
with socket.create_connection(("127.0.0.1", 18000)) as sock:
    sock.sendall(data)      # 写完直接关闭，触发服务端分析
```

与 tulip、pkappa2 等 A&D CTF 工具的 PCAP-over-IP 输出兼容：把 Fnet 的
监听地址填入它们的 pcap 推送配置即可。

### 落盘与任务管线

连接关闭后，字节流按端序重组校验并落盘到
`<cache>/pcap-over-ip/pcapoip-<时间戳>-<随机>.pcap[ng]`（路径全部来自
`fnet.paths`，`FNET_HOME` 可整体重定位），随后通过 `JobManager.submit`
创建分析任务——与 WebUI 上传、CLI `-C` 走完全相同的管线：日志、
`findings.json` / `findings.csv` 与三份报告都写入该任务的输出目录。
Ctrl+C 退出监听时会逐个打印已完成任务的状态与输出目录；被中断的任务可以
用 `python3 -m fnet --resume <job-id>` 继续跑。

### 安全默认

* **只绑回环**：默认监听 `127.0.0.1`，绝不默认 `0.0.0.0`；需要远程接收时
  必须用 `--host` 显式放开，并自行评估网络环境。
* **无鉴权**：监听端口没有 token 校验，能连上就能提交任务，不要在不可信
  网络中暴露。
* **资源限制**：魔数不识别的流立即拒绝；单连接默认 512 MiB 上限，接收
  超时 600 秒，防止连接把内存或线程拖垮。
* 收到的流量包与 WebUI 上传的文件同等对待：只被解析、不会被执行，其他
  输入处理约定见 [docs/SECURITY.md](SECURITY.md)。

## MCP server 模式

`--mcp` 把 Fnet 的分析能力暴露为
[MCP](https://modelcontextprotocol.io)（Model Context Protocol）工具，供
Claude Desktop、Claude Code 或任何支持 stdio transport 的 LLM 客户端调用。

### 启动

```bash
python3 -m fnet --mcp                  # 纯 stdio 服务，等待 JSON-RPC
python3 -m fnet --mcp capture.pcapng   # 预载默认抓包或日志，analyze 可省略 pcap_path
python3 -m fnet --mcp --features checkBox_10,webshell.decrypt   # 预设默认功能集
```

协议要点（与主流 MCP 客户端的 stdio transport 一致）：

* **行分隔 JSON-RPC 2.0**：每条请求/响应占一行 UTF-8 JSON，以 `\n` 结尾；
  服务器逐行读 stdin，处理完立即写一行响应到 stdout 并 flush。
* **stdout 只承载协议消息**，所有日志一律写到 stderr（前缀 `[fnet-mcp]`）。
* 支持 `initialize`（协议版本 `2024-11-05`）、`ping`、`tools/list` 与
  `tools/call`；通知（无 `id` 的消息）一律不回包。
* 一次只服务一个客户端：stdio 由客户端进程直接托管，不需要端口与 token。

### 暴露的工具

| 工具           | 用途                                       | 入参 |
| -------------- | ------------------------------------------ | ---- |
| `list_features` | 列出全部功能（复选框 id、handler、标题、分类、是否默认勾选），用于先选功能再分析 | 无 |
| `analyze`       | 同步运行一次分析任务并等待结束，返回 findings 摘要、统计与报告路径 | `pcap_path`（抓包或日志路径；缺省用启动时预载的文件）、`features`（复选框 id 或 handler 名数组）、`params`（功能参数对象，如 `{"wifi_psk": "..."}`）、`shards`（帧区间分片数，默认 1） |
| `get_findings`  | 按任务 id（缺省最近一次任务）查询结构化结果 | `job_id`、`kind`（按类别过滤）、`query`（文本过滤）、`level`（info/warn/error）、`limit`（默认 5000） |
| `get_packet`    | 返回某帧详情与前后帧上下文（对应 WebUI 的帧链接视图） | `frame`（必填）、`job_id`、`context`（前后各取多少帧，默认 2，最大 20） |

`analyze` 返回的 `job_id`、报告路径与 `findings` 摘要可以直接喂给后两个
工具做追问；报告与产出文件路径均在任务输出目录
`~/.cache/fnet/jobs/<job-id>/` 下（`FNET_HOME` 重定位规则同 CLI）。

### 安全注意

* **无 token、无网络面**：stdio 传输没有 HTTP 层，通信只发生在 fnet 与
  启动它的客户端进程之间；不要把 stdio 接到多个客户端共享的管道上。
* **路径约定**：输入路径只来自 MCP 调用参数或启动 `--mcp` 时的位置参数，
  服务器不写死任何绝对路径；输出目录走 `fnet.paths` / `JobManager` 的既有
  机制。客户端能传任意可读路径，等于把本机读权限交给 LLM——只在自己信任
  的机器上接入，敏感抓包或日志建议放在专用目录并用 `FNET_HOME` 隔离任务缓存。
* **权限对等**：MCP 客户端触发的是本机 Python 进程，会以运行 fnet 的账号
  调用 tshark 等外部工具；不要在服务器或高权限账号下长期挂 `--mcp`。
* **同步阻塞**：`analyze` 等任务结束才返回，大抓包或大日志会让这一条工具调用
  持续较久，客户端侧需要可接受的超时设置。

### Claude Desktop 配置示例

`claude_desktop_config.json`（菜单「开发者 → 编辑配置」）：

```json
{
  "mcpServers": {
    "fnet": {
      "command": "python3",
      "args": ["-m", "fnet", "--mcp"],
      "env": { "FNET_HOME": "/tmp/fnet-mcp" }
    }
  }
}
```

Windows 下把 `command` 换成 `python`，并给出 fnet 所在目录的绝对路径即可：

```json
{
  "mcpServers": {
    "fnet": {
      "command": "python",
      "args": ["-m", "fnet", "--mcp", "D:\\ctf\\wifi.pcap"]
    }
  }
}
```

其他支持 stdio MCP 的客户端（Claude Code、Cursor 等）用同样的
`command`/`args` 注册。接入后可先让模型调用 `list_features` 确认功能目录，
再按需 `analyze` → `get_findings` → `get_packet` 逐层下钻。
