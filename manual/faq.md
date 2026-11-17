---
layout: page
title: 常见问题
permalink: /manual/faq/
description: Fnet 常见问题：tshark、上传与内存、TLS/Webshell 解密、端口、结果为空与数据安全。
---

## 启动与环境

### 提示“未找到 tshark”，功能都不可用

Fnet 不自己解析协议，必须能找到 `tshark`：

```bash
tshark -v                 # 确认已安装且在 PATH
python3 -m fnet --doctor  # 查看各外部工具的检测结果
```

Windows 把 `C:\Program Files\Wireshark` 加入 `PATH`；或在 `config.ini` 里写绝对路径：

```ini
[paths]
tshark = /usr/bin/tshark
```

### 端口 8765 被占用

```bash
python3 -m fnet --port 9000
```

或在 `config.ini` 里修改 `port`。启动失败时终端会直接给出换端口的提示。

### 浏览器打不开或页面空白

- 确认终端里打印的监听地址与端口，手动访问 `http://127.0.0.1:8765/`
- 页面由本机服务渲染，刷新前确认服务仍在运行
- 如果是远程机器，用 SSH 端口转发：`ssh -L 8765:127.0.0.1:8765 user@host`

## 上传与性能

### 上传大文件报错或占用内存过高

上传大小上限由 `max_upload_mb` 控制（默认 1024）。目前上传会把内容先读入内存，
超大抓包建议先用 `editcap` 按时间或包数切分，再放进批量队列：

```bash
editcap -c 200000 big.pcapng part.pcapng
```

上传大小可以在 `config.ini` 的 `max_upload_mb` 中调整；超大抓包建议先切分再分析。

### 分析很慢

- 先只勾选相关功能，“全选”适合小包
- 启用 `tshark_cache` 后，同一抓包与字段集不会重复解析
- 调大 `tshark_timeout` 只影响超时，不会提速；字段与行数上限可按机器调整
- 批量队列的并发数不要超过机器核数

### 想清空历史与缓存

任务产出在 `~/.cache/fnet/jobs/`，可以按任务目录删除；删除前先确认没有要保留的报告。
用 `FNET_HOME=/tmp/fnet-scratch` 可以把临时分析与日常数据分开。

## 解密类功能

### TLS 解密没有结果

按顺序检查：

1. **TLS 1.3 / ECDHE 套件**必须有 keylog（`SSLKEYLOGFILE` 格式），私钥解不了
2. keylog 必须覆盖当前连接的握手；配置里可以放多个文件，Fnet 会按行合并去重
3. 私钥方式只适用于 RSA 密钥交换的旧套件，带口令的 PEM 需要填 `tls_key_passphrase`
4. QUIC / HTTP/3 同样需要 keylog
5. 日志会汇报 keylog 覆盖率与密钥选择依据，可据此判断缺哪一段

WebUI 在“设置”菜单上传 keylog 或私钥；命令行用
`--param tls_keylog=...`、`--param tls_private_key=...`。

### Webshell 解不出明文

- 确认密码 / 密钥正确，且与流量中的变体一致（冰蝎 4.x 是自定义密钥协商）
- 用 `webshell_filter` 缩小到相关 HTTP 请求，避免在大量无关流量里错过配对
- 哥斯拉的 `AES_BASE64`、`AES_RAW`、`XOR` 变体可在 `webshell_mode` 中指定

### Shiro 解密失败

- `shiro_mode=diy` 时必须提供正确的 Base64 密钥
- 注意 `CBC` 与 `GCM` 的区别，必要时手动切换加密方式
- Cookie 名不是 `rememberMe` 时，修改 `shiro_remember`

### SQL 盲注没有还原出内容

- `sql_regex` 必须能匹配到比较运算的字符与结果
- 布尔盲注要填“成功条件”（响应中的特征文本）；时间盲注要设置合适的阈值
- 二分盲注用 `checkBox_46`，普通布尔/时间盲注用 `checkBox_26`

## 结果与界面

### 勾了功能但结果为空

先看日志里该功能是否报了“未找到字段 / 无匹配流量”：

- 抓包里确实没有对应协议（检查显示过滤器或 `tshark -r x.pcap -q -z io,phs`）
- 协议走的是非默认端口：运行 `protocols.detect` 先做特征识别
- 可选工具缺失：功能会降级执行，日志里会给出安装提示

### 帧号点击后没有跳到 Wireshark

“打开 Wireshark”需要本机可执行的 `wireshark`；没有安装时仍可导出 pcapng 片段，
用任意工具打开。路径可在 `config.ini` 的 `[paths]` 中指定。

### 报告里的中文或表格错乱

HTML 报告是自包含的，直接用浏览器打开或打印成 PDF；Markdown 报告建议用支持
GFM 表格的渲染器。报告内容来自抓包，分享前请先脱敏。

## 安全与数据

### Fnet 会把抓包上传到云端吗

不会。WebUI 只绑定 `127.0.0.1`，分析全部在本机完成；除非你主动修改监听地址，
外部无法访问。

### 分析流量包会执行其中的代码吗

不会。Fnet 只读取协议字段，所有解析由 `tshark` 完成；Webshell 与内存马分析只做
解密和反编译，不运行样本。

### 遇到问题怎么反馈

欢迎在 [GitHub Issues](https://github.com/fyfhcgch/Fnet/issues) 提问或提交功能建议。提问时请附上：

- Fnet 版本（`python3 -m fnet --version`）
- 操作系统与 `tshark -v` 输出
- 出错的功能、关键日志行或脱敏后的截图

请勿上传包含真实凭据、隐私或未授权流量的抓包；需要提供样例时先脱敏或使用自己构造的小包。
