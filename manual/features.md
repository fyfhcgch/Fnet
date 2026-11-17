---
layout: page
title: 功能清单
permalink: /manual/features/
description: Fnet 37 项分析功能与附加处理器的用途、复选框编号和依赖。
---

Fnet 有 **37 个复选框功能**，按 **13 个分类**组织；另有若干不带复选框的深度
处理器，用 `--features` 或“专项功能”菜单调用。★ 表示默认勾选。

想按赛题类型挑选功能，可以直接看文末的[选择建议](#选择建议)。

## 文本与关键字（1）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| 关键字检测 | `checkBox_10` ★ | 在 HTTP/TCP/UDP 载荷中匹配 `flag{...}`、自定义正则与 Base64/Hex/URL/ASCII 编码关键词 |

参数：`keywords`（`;` 分隔的正则）、`post_only`、`auto_regex`、`decode`、`max_hits`。

## HTTP / Web（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| HTTP数据提取 | `checkBox_30` ★ | 请求/响应配对、URI、Host、状态码、User-Agent、Cookie、Basic 认证，并提取响应正文 |
| HTTP下载文件分析 | `checkBox_32` | 导出响应体，识别文件类型（magic + 扩展名）并计算 MD5 |

## Webshell / Shiro（1）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| shiro流量解密 | `checkBox_42` | `rememberMe` 的 AES-CBC/ECB/GCM 解密，自动遍历内置密钥表，也支持手动密钥 |

Webshell 解密（冰蝎 3.x/4.x、哥斯拉、蚁剑、菜刀、内存马）没有复选框：
在“Webshell 解密设置”里填密码，或用 `--features webshell.decrypt` 运行。

## SQL 注入（3）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| SQL盲注流量分析 | `checkBox_26` | 按正则与成功条件还原布尔 / 时间盲注的字符 |
| SQL二分盲注增强 | `checkBox_46` | 针对二分法盲注，按字符区间推断结果 |
| SQL盲注日志分析 | `checkBox_34` | 从已保存的盲注日志回推注入内容 |

## C2 / 远控（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| Cobalt Strike流量分析 | `checkBox_15` | beacon 元数据与任务解密，需要 `.cobaltstrike.beacon_keys` |
| WINRM流量解密 | `checkBox_43` | 用 NTLM hash 或密码还原 WinRM 认证与命令 |

## 认证与凭据（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| NTLM HASH提取 | `checkBox_39` | 从 NTLMSSP 认证中提取 NetNTLM 哈希（hashcat 格式） |
| Kerberos解析破解 | `checkBox_45` | 提取 AS-REQ/AS-REP/TGS-REP，生成 hashcat 13100/18200 哈希 |

## 协议流量（10）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| TCP流分析 | `checkBox_33` | TCP 流重组、会话统计与内容提取（输出可能较多） |
| UDP流分析 | `checkBox_35` | UDP 会话与载荷提取 |
| DNS流量分析 | `checkBox_23` | 查询记录、长域名告警与标签解码（疑似 DNS 隧道） |
| ICMP流量分析 | `checkBox_20` | ICMP 载荷中的隐藏数据与长度异常 |
| FTP流量分析 | `checkBox_27` | 账号密码、命令与传输的文件 |
| SMTP流量分析 | `checkBox_28` | 邮件会话、发件人 / 收件人与正文 |
| Telnet流量分析 | `checkBox_19` | Telnet 会话内容还原 |
| MYSQL数据分析 | `checkBox_37` | 查询、登录信息与 schema |
| ARP协议分析 | `checkBox_44` | IP/MAC 冲突、免费 ARP 与异常字段 |
| 4G/5G通信协议分析 | `checkBox_41` | GTP 隧道与错误 TEID 检测 |

## 工控协议（7）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| 工控协议modbus分析 | `checkBox_11` | 功能码、地址与异常帧 |
| 工控协议s7comm分析 | `checkBox_14` | S7comm 读写请求 |
| 工控协议iec60870分析 | `checkBox_12` | IEC 60870-5-104 类型标识与传送原因 |
| 工控协议mqtt分析 | `checkBox_13` | MQTT 主题与消息 |
| 工控协议mms分析 | `checkBox_29` | MMS 会话概览 |
| 工控协议omron分析 | `checkBox_22` | OMRON FINS 会话概览 |
| 工控协议goose分析 | `checkBox_38` | GOOSE 报文概览 |

## USB / 外设（3）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| USB-键盘流量分析 | `checkBox_16` | HID 键盘按键还原 |
| USB-鼠标流量分析 | `checkBox_17` | HID 鼠标轨迹还原 |
| EV3数据提取 | `checkBox_40` | LEGO EV3 蓝牙数据还原 |

## 无线与蓝牙（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| 无线流量暴力破解 | `checkBox_18` | WPA/WPA2 握手字典破解，需要 `aircrack-ng` |
| 蓝牙流量分析 | `checkBox_21` | Bluetooth / BTHCI 协议概览 |

## TLS / 加密（1）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| TLS流量解密 | `checkBox_24` | keylog 或私钥解密，继续还原 HTTP/2、gRPC、WebSocket、HTTP/3 与明文凭据 |

QUIC 识别与解密由该项自动调用（`tls.quic`），不需要额外勾选。

## 杂项（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| SCSI传输数据提取 | `checkBox_36` | SCSI 读写数据提取 |
| IPID数据分析 | `checkBox_31` | IP ID 字段的隐蔽信道分析，通常关闭 |

## RDP 重放（1）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| RDP流量重放 | `checkBox_47` | 用私钥或 keylog 解密 RDP 会话并生成重放文件，需要 `pyrdp-player` |

## 附加深度处理器

这些处理器没有复选框，用 `--features` 或“专项功能”菜单调用：

| Handler | 用途 |
| --- | --- |
| `protocols.credentials` | 依次运行 Redis、MongoDB、PostgreSQL、LDAP、SMB2、WebSocket、HTTP/2 提取器 |
| `protocols.detect` | 非默认端口的协议特征探测，输出 `protocol_detection.csv` |
| `protocols.redis` | RESP2/RESP3、ACL、集群重定向、Pub/Sub、Lua 脚本 |
| `protocols.mongodb` | OP_MSG、BSON、SCRAM 认证与 GridFS 还原 |
| `protocols.postgres` | 扩展查询、COPY 数据与二进制参数 |
| `protocols.http2` | HPACK 还原、流与优先级、gRPC、DATA 正文重组 |
| `protocols.ldap` | StartTLS、SASL、AD 属性与批量查询 |
| `protocols.smb2` | 共享与文件读写、DFS、命名管道、加密识别 |
| `text_scan.deep` | 对重组流、解密正文与二进制载荷统一扫描 flag，带来源与置信度 |
| `forensics.correlate` | 跨协议凭据按账号/主机聚合，输出 `credentials_correlated.csv` |
| `forensics.timeline` | 登录、文件读写、提权与横向移动的时间线 |

```bash
python3 -m fnet -C capture.pcapng --features protocols.credentials
python3 -m fnet -C capture.pcapng --features text_scan.deep
```

完整参数、输出文件名与字段说明见 [功能规格]({{ '/docs/FEATURES.html' | relative_url }})。

## 选择建议

| 场景 | 建议勾选 |
| --- | --- |
| 只想快速找 flag | 关键字检测 + `text_scan.deep` |
| Web 题 | HTTP数据提取、HTTP下载文件分析、shiro流量解密、SQL 盲注系列、`webshell.decrypt` |
| 内网 / 域环境 | NTLM HASH提取、Kerberos解析破解、WINRM流量解密、`protocols.*`、`forensics.*` |
| 无线 / 硬件 | 无线流量暴力破解、蓝牙流量分析、USB 键盘/鼠标、EV3 |
| 工控 | 按协议勾选 Modbus / S7comm / IEC104 / MQTT / MMS / OMRON / GOOSE |
| 加密流量 | TLS流量解密（先在“设置”里上传 keylog 或私钥） |
