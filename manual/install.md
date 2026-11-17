---
layout: page
title: 安装与启动
permalink: /manual/install/
description: 安装 Fnet：tshark 依赖、可选工具、启动 WebUI、配置目录与第一次分析。
---

## 系统要求

| 项目 | 要求 |
| --- | --- |
| Python | 3.10 及以上 |
| 协议解析 | `tshark`（Wireshark 自带） |
| 第三方 Python 包 | 运行时**不需要**，全部使用标准库 |
| 磁盘 | 约 10 MB 源码；分析产出写入用户缓存目录 |

`tshark` 是唯一必需的依赖，Fnet 自己不解析协议，只负责组织分析流程与呈现结果。

### 安装 tshark

```bash
# Debian / Ubuntu
sudo apt install tshark

# Fedora
sudo dnf install wireshark-cli

# macOS
brew install wireshark

# Arch
sudo pacman -S wireshark-cli
```

Windows 安装 [Wireshark](https://www.wireshark.org/download.html) 时勾选命令行工具，
并把安装目录（默认 `C:\Program Files\Wireshark`）加入 `PATH`。装完用
`tshark -v` 确认能输出版本号。

如果 `tshark` 不在 `PATH` 中，可以在 `config.ini` 的 `[paths]` 段写入绝对路径：

```ini
[paths]
tshark = C:\Program Files\Wireshark\tshark.exe
```

## 获取并启动

```bash
git clone https://github.com/fyfhcgch/Fnet
cd Fnet
python3 -m fnet
```

默认监听 `127.0.0.1:8765` 并自动打开浏览器。常用参数：

```bash
python3 -m fnet --no-browser          # 不自动打开浏览器
python3 -m fnet --port 9000           # 换端口
python3 -m fnet --host 0.0.0.0        # 监听所有网卡（注意安全）
python3 -m fnet capture.pcapng        # 启动后预选抓包
```

也可以安装成命令：

```bash
python3 -m pip install .
fnet
```

<p class="note">
  WebUI 只绑定本机回环地址，每次启动生成随机 token，写操作需要携带 token。
  除非在隔离环境，不要把 <code>--host</code> 改成 <code>0.0.0.0</code>。
</p>

## 第一次分析

<ol class="steps">
  <li>
    打开 <code>http://127.0.0.1:8765</code>，把 pcap / pcapng 拖到左侧虚线框，
    或在下方的输入框里填写本机路径后点“使用”。
  </li>
  <li>
    左侧已按 13 个分类列出 37 个功能，默认勾选“关键字检测”和“HTTP数据提取”。
    不确定时可以先点“全选”，或只勾与本题相关的功能。
  </li>
  <li>
    点击右上角“开始分析”，日志与进度会实时滚动；随时可以“取消”，已完成的产出保留。
  </li>
  <li>
    在“分析结果”页查看凭据、哈希、flag、导出文件等汇总，支持搜索、排序、
    按帧号下钻与导出 CSV。
  </li>
  <li>
    在“产出文件”页下载报告与还原的文件，或从“文件”菜单导出 Markdown / HTML 报告。
  </li>
</ol>

同一次分析也可以完全在终端完成：

```bash
python3 -m fnet -C capture.pcapng                       # 只跑默认勾选项
python3 -m fnet -C capture.pcapng --all                 # 跑全部 37 个功能
python3 -m fnet -C capture.pcapng --features checkBox_10,webshell.decrypt
```

## 输出与配置在哪

| 内容 | Linux | Windows / macOS |
| --- | --- | --- |
| 配置文件 | `~/.config/fnet/config.ini` | `%APPDATA%\Fnet\config.ini` 等 |
| 任务产出 | `~/.cache/fnet/jobs/<job-id>/` | 对应用户目录下的 `cache/jobs/` |
| 日志 | `~/.local/state/fnet/logs/` | 对应用户目录下的 `logs/` |

每个任务目录包含 `report.txt`、`report.md`、`report.html`、`findings.json`、
`findings.csv` 以及各功能导出的文件。想让配置、缓存、日志集中到某个目录时，
用环境变量隔离：

```bash
FNET_HOME=/tmp/fnet-dev python3 -m fnet --no-browser
```

## 常用配置项

配置文件是普通 INI，改完重启生效：

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `max_upload_mb` | `1024` | WebUI 上传大小上限 |
| `tshark_timeout` | `600` | 单次 tshark 调用超时（秒） |
| `tshark_retry` | `1` | 超时或失败后的重试次数 |
| `tshark_cache` | `1` | 按抓包与字段集缓存解析结果 |
| `tshark_max_rows` | `2000000` | 单次提取的最大行数 |
| `tshark_max_field_kb` | `256` | 单个字段的最大字节数 |

## 可选工具

缺失时对应功能会降级并在日志里给出提示，不影响其它分析：

| 工具 | 用途 |
| --- | --- |
| `java` | 反编译、部分 Webshell / 序列化分析 |
| `hashcat` / `john` | 哈希与握手包破解 |
| `foremost` / `binwalk` | 文件分离与固件提取 |
| `aircrack-ng` / `hcxtools` | Wi-Fi 握手处理与 22000 格式 |
| `pcapfix` | 修复损坏的 pcap |
| `etl2pcapng` | Windows ETL 转 pcapng |
| `pyrdp-player` | RDP 会话回放 |
| `wireshark` | 从日志帧号直接跳转到 Wireshark |

用下面的命令查看本机检测结果：

```bash
python3 -m fnet --doctor
python3 -m fnet --list-tools
```
