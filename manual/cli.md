---
layout: page
title: 命令行
permalink: /manual/cli/
description: Fnet 无界面用法：参数、功能选择、参数传递、批处理与退出码。
---

命令行和 WebUI 共用同一套分析与产出。加 `-C` 就不会启动 WebUI，日志直接打印到
终端，适合批量处理、脚本和没有图形界面的机器。第一次使用建议先跟着
[实战教程]({{ '/manual/tutorial/' | relative_url }})走一遍。

## 基本用法

```bash
python3 -m fnet -C capture.pcapng                    # 只跑默认勾选项
python3 -m fnet -C capture.pcapng --all              # 全部 37 个功能
python3 -m fnet -C capture.pcapng --features checkBox_10,http.extract
```

输出结构：

```
任务 3f9c2a | capture.pcapng | 2 个功能
输出目录: /home/you/.cache/fnet/jobs/3f9c2a
--------------------------------------------------------------
[10:24:01] 开始分析 ...
...
--------------------------------------------------------------
报告: .../report.txt
Markdown 报告: .../report.md
HTML 报告: .../report.html
结构化结果: .../findings.json
结果 CSV: .../findings.csv
共记录 42 条结构化结果（WebUI 的“分析结果”页可排序筛选）
```

## 参数一览

| 参数 | 说明 |
| --- | --- |
| `capture` | 要分析的 pcap / pcapng / cap / dmp / etl 文件 |
| `-C`, `--cli` | 不启动 WebUI，直接在终端运行 |
| `--features a,b` | 逗号分隔的功能，可写复选框编号或功能名 |
| `--all` | 运行全部 37 个功能 |
| `--param KEY=VALUE` | 传给功能的参数，可重复 |
| `--config PATH` | 使用指定的 `config.ini` |
| `--list-features` | 列出全部功能（`*` 为默认勾选） |
| `--list-tools` | 列出依赖的外部工具 |
| `--doctor` | 检查 tshark / java / hashcat 等环境 |
| `--version` | 显示版本 |
| `--host` / `--port` | 仅 WebUI 模式：监听地址与端口 |
| `--no-browser` | 仅 WebUI 模式：不自动打开浏览器 |

`--features` 支持两种写法，混用也可以：

- 复选框编号：`checkBox_10`、`checkBox_24`
- 功能名：`http.extract`、`tls.decrypt`、`protocols.smb2`

带点的功能名即使没有复选框也能直接运行，例如
`--features protocols.redis,forensics.correlate`。

## 传递功能参数

`--param` 把值传给所有功能，各功能只读取自己认识的键。常用键：

| 参数 | 用于 | 示例 |
| --- | --- | --- |
| `tls_keylog` | TLS 解密 | `--param tls_keylog=/path/sslkeys.log` |
| `tls_private_key` | TLS 解密（非前向保密套件） | `--param tls_private_key=/path/server.pem` |
| `tls_key_passphrase` | 带口令的私钥 | `--param tls_key_passphrase=secret` |
| `shiro_key` | Shiro | `--param shiro_key=kPH+bIxk5D2deZiIxcaaaA==` |
| `shiro_mode` | Shiro | `auto` 或 `diy` |
| `webshell_password` | Webshell | `--param webshell_password=pass` |
| `webshell_mode` | Webshell | `auto` / `behinder` / `godzilla` 等 |
| `sql_success` | SQL 盲注 | 成功响应的特征文本 |
| `sql_regex` | SQL 盲注 | 自定义提取正则 |
| `keywords` | 关键字检测 | `--param keywords="flag{;ctf"` |
| `wordlist` | 字典类功能 | 自定义字典路径 |

`--param` 的值写成 `true` / `false` 会被解析为布尔值。

## 批处理

```bash
#!/usr/bin/env bash
set -u
for pcap in samples/*.pcapng; do
  echo "== $pcap"
  python3 -m fnet -C "$pcap" --all \
    --param tls_keylog="$HOME/keys/sslkeys.log" || echo "  失败: $?"
done
```

每个任务有独立目录，互不覆盖。需要把配置、缓存与日志隔离到别处时：

```bash
FNET_HOME=/tmp/fnet-batch python3 -m fnet -C a.pcapng --all
```

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 任务完成 |
| `1` | 任务失败（查看输出目录里的报告与日志） |
| `2` | 参数或输入有误（文件不存在、功能名未知等） |
| `130` | 被 Ctrl+C 取消 |

单个功能失败不会让整个任务以 `1` 退出——任务继续跑完，失败原因记在日志里。
脚本里如果需要“严格失败”，可以检查输出目录中的报告与 `findings.json`。

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `FNET_HOME` | 把配置、缓存、日志集中到指定目录 |
| `FNET_ASSETS` | 覆盖内置资源目录（字典、密钥表、默认配置） |
| `FNET_TOOLS` | 追加便携工具目录（tshark、foremost 等） |

## 与 WebUI 的选择

- 只分析一个包、想看图表或整理报告 → 用 WebUI
- 批量跑样例、接入流水线、在无图形界面的机器上 → 用命令行
- 两者可以同时用：命令行跑出的任务同样记录在任务历史里
