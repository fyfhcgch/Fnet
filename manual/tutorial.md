---
layout: page
title: 实战教程
permalink: /manual/tutorial/
description: 跟着做一遍完整流量分析：找 flag、还原 Web 与 Webshell、解密 TLS、提取凭据、批量复盘。
---

这一页按真实分析顺序走一遍：**准备抓包 → 选择功能 → 查看结果 → 定位数据包 → 导出报告**。
每一步都说明要勾哪些功能、填什么、在哪里看结果，可以直接对着自己的赛题操作。

第一次使用请先看[安装与启动]({{ '/manual/install/' | relative_url }})，确认 `tshark` 已就绪。

## 0. 开始之前

- 只分析**合法获得**的抓包或日志：CTF 题目、授权演练或自己的实验流量。
- 建议每道题单独跑一次任务；Fnet 会为每次分析建立独立输出目录，互不覆盖。
- 不确定该勾什么时，先跑默认的“关键字检测 + HTTP数据提取”；输入是文本日志时
  会自动改跑 4 项日志功能。

<a id="find-flag"></a>
## 1. 找 flag：先跑默认两项

多数 CTF 流量题可以先靠默认勾选拿到线索。

1. 打开 `http://127.0.0.1:8765`，把 pcap / pcapng 或 `.log` 文本日志拖进左侧上传区。
2. 保持默认勾选：**关键字检测**（`checkBox_10`）与 **HTTP数据提取**（`checkBox_30`）。
3. 点右上角“开始分析”，等待状态变为“完成”。
4. 切到“分析结果”页，在搜索框输入 `flag`，或按类别筛选 `flag`、`credential`、`file`。
5. 找到命中行后，点击“帧 N”查看该数据包的前后文与完整解码；需要留档时导出 pcapng 片段。
6. 从“文件”菜单导出 Markdown / HTML 报告，或到“产出文件”页下载哈希、还原文件等交付物。

没有结果时，按顺序补查：

- 在“通用分析设置”里添加题目提示的关键字（支持正则，`;` 分隔）。
- 用“专项功能”菜单运行 **深度 flag 扫描**（`text_scan.deep`），它会检查重组流、解密正文和二进制载荷。
- 确认协议是否走非默认端口：运行 `protocols.detect` 做端口/协议识别。

<a id="web"></a>
## 2. Web 题：HTTP、Webshell 与 Shiro

先勾选：

- **HTTP数据提取**（`checkBox_30`）：请求/响应配对、URI、Host、状态码、Cookie、Basic 认证。
- **HTTP下载文件分析**（`checkBox_32`）：导出响应体、识别文件类型并计算 MD5。
- **shiro流量解密**（`checkBox_42`）：解 `rememberMe` Cookie。

如果题目是 Webshell：

1. 展开左侧“Webshell 解密设置”，填入连接密码或密钥。
2. 用“专项功能”菜单运行 **Webshell 解密**（`webshell.decrypt`），或命令行：
   `--features webshell.decrypt --param webshell_password=你的密码`。
3. 在“分析结果”里看还原出的命令、请求参数与命令输出。
4. 不确定变体时把 `webshell_mode` 设为 `auto`，让 Fnet 依次尝试冰蝎、哥斯拉、蚁剑等格式。

如果题目是 Shiro：

1. 在“Shiro 解密设置”里确认 Cookie 名（默认 `rememberMe`）。
2. 有密钥就填 Base64 密钥并选择 `CBC` / `GCM`；没有密钥时保持自动遍历内置密钥表。
3. 解密后的反序列化内容会写入日志和产出文件，可继续用 Webshell / Java 反编译相关功能分析。

<a id="sql"></a>
## 3. SQL 盲注：还原注入结果

展开“SQL 盲注设置”：

| 设置 | 作用 |
| --- | --- |
| SQL 正则 | 从请求中提取比较字符，例如 `substr(...,1,1)='a'` |
| 成功条件 | 响应里代表“条件为真”的特征文本 |
| 时间阈值 | 时间盲注的判定秒数，默认 1 秒 |
| 已保存日志 | 只有分析离线盲注日志时才需要 |

按题型勾选：

- **SQL盲注流量分析**（`checkBox_26`）：布尔 / 时间盲注。
- **SQL二分盲注增强**（`checkBox_46`）：二分法逐字符推断。
- **SQL盲注日志分析**（`checkBox_34`）：从日志文件回推内容。

结果会以还原出的字符或字符串出现在“分析结果”和日志中。

<a id="tls"></a>
## 4. 加密流量：TLS / QUIC 解密

1. 从“设置”菜单上传 **TLS keylog**（`SSLKEYLOGFILE` 格式）或服务器私钥。
2. 勾选 **TLS流量解密**（`checkBox_24`）。
3. 解密成功后，同一任务会继续还原 HTTP/2、gRPC、WebSocket、HTTP/3 正文和明文凭据。
4. 命令行等价写法：

```bash
python3 -m fnet -C capture.pcapng --features checkBox_24 \
  --param tls_keylog=/path/to/sslkeys.log
```

解密没有结果时先查三件事：

- TLS 1.3 / ECDHE 套件必须有 keylog，私钥解不了。
- keylog 是否覆盖了这次连接的握手。
- 走 QUIC 的流量同样需要 keylog，不是私钥。

<a id="credentials"></a>
## 5. 内网与凭据：NTLM、Kerberos、WinRM

| 勾选 | 用途 |
| --- | --- |
| **NTLM HASH提取**（`checkBox_39`） | 从 NTLMSSP 认证中提取 NetNTLM 哈希（hashcat 格式） |
| **Kerberos解析破解**（`checkBox_45`） | 提取 AS-REQ / AS-REP / TGS-REP 并生成 hashcat 哈希；有 keytab、账号口令或原始密钥时还能解密响应、解析 PAC 与用户时间线 |
| **WINRM流量解密**（`checkBox_43`） | 用 NTLM hash 或密码还原 WinRM 认证与命令 |

```bash
python3 -m fnet -C krb5.pcap --features checkBox_45 --keytab /etc/krb5.keytab
python3 -m fnet -C krb5.pcap --features checkBox_45 \
  --kerberos-password 'P@ssw0rd'
```

分析完成后在“分析结果”页按类别筛选 `hash`、`credential`、`auth`，可以直接复制或导出 CSV。
需要跨协议汇总时，用“专项功能”菜单运行 **多协议凭据提取**（`protocols.credentials`）和
**凭据关联**（`forensics.correlate`），输出会按账号 / 主机聚合。

<a id="batch"></a>
## 6. 批量分析与赛后复盘

- **批量**：一次拖入多个抓包或日志，自动进入“批量队列”；可以暂停、调整顺序、取消单个任务。
- **重跑**：在“任务历史”里找到旧任务，一键沿用原参数重跑。
- **续跑**：运行中可暂停，任务停在功能边界；点“继续”或 `--resume <job-id>` 从断点接着跑。
- **对比**：在“任务历史”里对比两个任务，查看新增/消失的凭据、哈希与 flag；
  命令行用 `--compare <base> <target>`。
- **脚本**：`--json` 输出任务、findings、统计与产出，方便接入流水线。
- **分享**：报告和 CSV 可能包含明文凭据，分享前先脱敏。

## 7. 日志分析：不依赖 tshark

Ceph、syslog、sshd、Apache、JSON Lines、CSV 等文本日志可以直接作为输入：

```bash
python3 -m fnet -C ceph.log
python3 -m fnet -C /var/log/auth.log --features checkBox_61,checkBox_63
```

1. 命令行或 WebUI 选择 `.log` / `.txt` / `.jsonl` / `.csv` 文件；检测到日志后
   会自动勾选“日志分析”分类的 4 项功能。
2. 先看“日志概览与时间线”：确认格式、时间范围、级别与来源分布，以及时间桶是否出现突增。
3. 再看“日志字段与实体统计”和“日志失败与异常检测”：按客户端/账号/IP 找出
   失败次数、失败率异常或低频异常字段值的实体。
4. 用“日志IOC与敏感信息”提取 flag、凭据、哈希、URL、域名与 IP 清单。
5. 结果同样进入“分析结果”和 `findings.json`，产出包含 `log_fields.csv`、
   `log_entities.csv`、`log_anomalies.csv` 与 `log_iocs.csv`。

日志记录没有数据包帧号，定位时以日志行号与原始文本为准；需要旁证抓包时，
再用 `checkBox_54` 把 Suricata/Zeek 日志与已有流量任务关联。

## 一页速查

| 你的目标 | 建议勾选 / 运行 |
| --- | --- |
| 快速找 flag | 关键字检测 + `text_scan.deep` |
| Web 题 | HTTP数据提取、HTTP下载文件分析、shiro流量解密、`webshell.decrypt` |
| SQL 盲注 | SQL盲注流量分析 / SQL二分盲注增强 / SQL盲注日志分析 |
| 文本日志 | 日志概览与时间线、字段与实体统计、失败与异常检测、IOC与敏感信息 |
| 加密流量 | TLS流量解密（先上传 keylog 或私钥） |
| 域环境 / 内网 | NTLM HASH提取、Kerberos解析破解、WINRM流量解密、`protocols.credentials` |
| 无线 / 硬件 | 无线流量暴力破解、蓝牙流量分析、USB 键盘 / 鼠标、EV3 |
| 工控 | Modbus、S7comm、IEC 104、MQTT、MMS、OMRON、GOOSE |
| 批量复盘 | 批量队列 + 任务历史 + 合并报告 |

需要逐项查看功能说明时，翻[功能清单]({{ '/manual/features/' | relative_url }})；想写脚本批量跑，
看[命令行]({{ '/manual/cli/' | relative_url }})。
