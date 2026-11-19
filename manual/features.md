---
layout: page
title: 功能清单
permalink: /manual/features/
description: Fnet 54 项分析功能与附加处理器的用途、复选框编号和依赖。
---

Fnet 有 **54 个复选框功能**，按 **14 个分类**组织；另有若干不带复选框的深度
处理器，用 `--features` 或“专项功能”菜单调用。★ 表示默认勾选。抓包
（pcap/pcapng）与文本日志（`.log`/`.txt`/`.jsonl`/`.csv`）都是合法输入，
日志任务默认勾选“日志分析”分类。

想按赛题类型挑选功能，可以直接看文末的[选择建议](#选择建议)。

## 日志分析（4）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| 日志概览与时间线 | `checkBox_61` ★ | 识别 Ceph / syslog / sshd / Apache / JSON Lines / CSV 与通用 KV 格式，输出时间范围、级别与来源分布、字段覆盖率与事件时间线 |
| 日志字段与实体统计 | `checkBox_62` ★ | 按客户端、账号、IP、网段、主机等维度统计活动量、成功次数/成功率、失败次数/失败率与活跃时段；网段维度 IPv4 默认按 /24（IPv6 固定 /64）聚合，并输出“网段成功统计”汇总 |
| 日志失败与异常检测 | `checkBox_63` ★ | 失败/认证错误关键字、失败率异常实体、事件突增时间桶与低频异常字段值 |
| 日志IOC与敏感信息 | `checkBox_64` ★ | 提取 flag、凭据、哈希、URL、域名、邮箱、密钥标识与公网/内网 IP 清单 |

参数：`log_fail_regex`、`log_fail_threshold`（默认 3）、`log_fail_ratio`
（默认 0.5）、`log_success_regex`（自定义“成功”口径正则，命中即计一次成功；
未提供时“未命中失败关键字”即视为成功）、`log_subnet_prefix`（网段维度的
IPv4 前缀，8–32，默认 24，非法时回退 24；IPv6 固定 /64）。这 4 项是**日志
输入**的默认勾选；抓包任务默认仍是关键字检测与
HTTP 数据提取。关键字检测在日志输入上会自动改用内置扫描，只保留 flag/编码
规则与用户自定义关键字。

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

## C2 / 远控（4）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| Cobalt Strike流量分析 | `checkBox_15` | beacon 元数据与任务解密，需要 `.cobaltstrike.beacon_keys` |
| WINRM流量解密 | `checkBox_43` | 用 NTLM hash 或密码还原 WinRM 认证与命令 |
| Meterpreter会话分析 | `checkBox_55` | Meterpreter/metsvc TCP TLV 会话识别，提取命令 ID、字符串参数与时间线 |
| Sliver/meterpreter C2扩展 | `checkBox_56` | Sliver HTTP/DNS/mTLS beacon 识别（v1.6 ChaCha20-Poly1305 与签名前缀/gzip、v1.5/旧版 AES-GCM 回退、密钥交换、流量编码器）与 meterpreter staging/AES-128/256-CBC wire 分析；`sliver_session_key`（32/16 字节 hex）/ `meterpreter_symkey`（16=AES-128、32=AES-256 hex）解密会话载荷，`sliver_dns_domain` 指定已知 DNS beacon 域名 |

## 认证与凭据（4）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| NTLM HASH提取 | `checkBox_39` | 从 NTLMSSP 认证中提取 NetNTLM 哈希（hashcat 格式） |
| Kerberos解析破解 | `checkBox_45` | 提取 AS-REQ/AS-REP/TGS-REP，生成 18200/13100/19800/19900 哈希；可用 keytab、账号口令或原始密钥解密响应（19600/19700），解析 PAC、NTLM 哈希与用户时间线 |
| NTLM密码离线验证 | `checkBox_58` | 无 hashcat 时用挑战/响应离线验证或受控枚举 NetNTLMv2 密码（默认不强攻） |
| SMB密码候选生成 | `checkBox_60` | 从账号/域名/共享/文件名与弱口令字典派生候选，供 NTLM 验证与 SMB3 解密复用 |

## 协议流量（17）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| TCP流分析 | `checkBox_33` | TCP 流重组、会话统计与内容提取（输出可能较多） |
| UDP流分析 | `checkBox_35` | UDP 会话与载荷提取 |
| DNS流量分析 | `checkBox_23` | 查询记录、长域名检测；按域名分块按序重组（Base64/Base32/Hex），输出隧道时间线与解码文件 |
| ICMP流量分析 | `checkBox_20` | ICMP 载荷中的隐藏数据；按源/目的/ID 重组分块隧道、时间线与解码落盘 |
| FTP流量分析 | `checkBox_27` | 账号密码、命令与传输的文件 |
| SMTP流量分析 | `checkBox_28` | SMTP/IMAP/POP3 命令与凭据、发件人 / 收件人 / 邮箱、MIME 头、正文与附件还原（附件落盘并计算 MD5/SHA256） |
| Telnet流量分析 | `checkBox_19` | Telnet 会话内容还原 |
| MYSQL数据分析 | `checkBox_37` | `mysql_native_password` / `caching_sha2_password` 握手、查询、结果集、`LOAD DATA LOCAL INFILE` 上传文件与 `LOAD_FILE()` 读取内容 |
| ARP协议分析 | `checkBox_44` | IP/MAC 冲突、免费 ARP 与异常字段 |
| 4G/5G通信协议分析 | `checkBox_41` | GTP 隧道与错误 TEID 检测 |
| LDAP流量分析 | `checkBox_48` | LDAP 绑定凭据/SASL 机制、查询 base/filter、条目属性（AD 账号等）与 StartTLS 告警 |
| SMB流量分析 | `checkBox_49` | SMB2/3 共享与会话、NTLM 身份、文件读写还原落盘、加密/压缩告警 |
| MongoDB流量分析 | `checkBox_50` | OP_MSG 命令与集合、SCRAM 认证交换、GridFS 文件还原落盘 |
| PostgreSQL流量分析 | `checkBox_51` | 查询语句与参数、结果摘要、明文口令消息与 COPY 数据 |
| Redis流量分析 | `checkBox_52` | RESP 命令、AUTH/ACL 凭据、敏感键读取与写入值摘要（支持非标准端口） |
| SSH流量分析 | `checkBox_53` | SSH 版本交换、KEXINIT 算法协商、userauth 用户名/方法/口令与爆破时间线 |
| SMB加密链路智能串联 | `checkBox_57` | NTLM 账号 → 候选密码注入/离线验证 → SMB3 解密 → 导出文件 → 熵识别 → flag，候选耗尽时回退提示 hashcat |

## 工控协议（7）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| 工控协议modbus分析 | `checkBox_11` | 功能码、地址与异常帧；写操作统计与寄存器隐蔽通道检测（ASCII 隐写自动解码） |
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
| 无线流量暴力破解 | `checkBox_18` | WPA/WPA2 握手与 PMKID 识别、hashcat 22000 命令；已知 PSK 时用 `--wpa-psk` 解密 802.11 数据帧并把明文送回 HTTP/DNS/凭据分析 |
| 蓝牙流量分析 | `checkBox_21` | Bluetooth / BTHCI 协议概览 |

## TLS / 加密（2）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| TLS流量解密 | `checkBox_24` | keylog 或私钥解密，继续还原 HTTP/2、gRPC、WebSocket、HTTP/3 与明文凭据 |
| OpenSSL加密文件分析 | `checkBox_59` | 识别 `Salted__`/`U2FsdGVkX1` Base64 信封与高熵文件；支持 EVP_BytesToKey/PBKDF2、`-iter`/`-saltlen`/`-md sha256`、`-a/-A` Base64、`-z`、原始 key/IV 解密并自动扫 flag；自动生成/明文工件（如 `c2_README.txt`、`findings.*`、`report*.md`、`job.json`）会被跳过 |

QUIC 识别与解密由 `checkBox_24` 自动调用（`tls.quic`），不需要额外勾选。

`openssl_file` 参数：`path`、`password`、`password_file`（首个非空行，口令不回显）、
`cipher`、`salt`/`salt_hex`/`nosalt`、`kdf`（`evp`/`pbkdf2`/`auto`）、`digest` 或 `md`、
`iter`/`iterations`、`saltlen`、`base64`、`zlib`、`key`/`key_hex`、`iv`/`iv_hex`、`nopad`。
OpenSSL 3.0+ 用 `-S` 指定的盐不再写入文件头，解密须再次传入 `salt`/`salt_hex`；
1.1.1 及更早版本写入 `Salted__` 头，两者均支持。默认摘要自 1.1.0 起为 `sha256`，
`-pbkdf2` 默认 10000 次迭代，`-saltlen` 默认 8（最大 16），`-a/-A` 为 Base64。
`-z` 会把整个 `Salted__` 信封包进 zlib（先 inflate 再识别信封），显式 `zlib=true`
强制该路径；自动模式也会先尝试 inflate。

## 杂项（3）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| SCSI传输数据提取 | `checkBox_36` | SCSI 读写数据提取 |
| IPID数据分析 | `checkBox_31` | IP ID 字段的隐蔽信道分析，通常关闭 |
| 日志证据关联 | `checkBox_54` | 导入 Suricata eve.json / Zeek 日志，归一化并与流量发现按 IP/端口关联 |

## RDP 重放（1）

| 功能 | 复选框 | 说明 |
| --- | --- | --- |
| RDP流量重放 | `checkBox_47` | 用私钥或 keylog 解密 RDP 会话并生成重放文件，需要 `pyrdp-player` |

## 高级功能（命令行调用）

这些功能没有复选框，适合进阶分析；可以在“专项功能”菜单里运行，也可以在命令行用
`--features` 直接调用：

| 功能名 | 用途 |
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

这些功能也可以和复选框功能写在同一次任务里，例如：

```bash
python3 -m fnet -C capture.pcapng --features checkBox_30,protocols.credentials
```

参数怎么传、怎么批量跑，见[命令行]({{ '/manual/cli/' | relative_url }})。

## 自定义规则

“设置 → 自定义规则…”或 `--rules` 可以导入逐行正则或 YARA 子集
（`strings` / `condition`、`any/all/N of them`、`$a and $b`）。命中结果写入
findings 的“自定义规则”类别，包含规则名、帧号、协议与片段，并参与报告、
CSV 导出与任务对比。WebUI 导入的路径保存在 `paths.rules_file`，后续任务
自动沿用。

## 选择建议

| 场景 | 建议勾选 |
| --- | --- |
| 只想快速找 flag | 关键字检测 + `text_scan.deep` |
| 日志审计 / 应急 | 日志概览与时间线、字段与实体统计、失败与异常检测、IOC与敏感信息 |
| Web 题 | HTTP数据提取、HTTP下载文件分析、shiro流量解密、SQL 盲注系列、`webshell.decrypt` |
| 内网 / 域环境 | NTLM HASH提取、Kerberos解析破解、WINRM流量解密、`protocols.*`、`forensics.*` |
| 无线 / 硬件 | 无线流量暴力破解、蓝牙流量分析、USB 键盘/鼠标、EV3 |
| 工控 | 按协议勾选 Modbus / S7comm / IEC104 / MQTT / MMS / OMRON / GOOSE |
| 加密流量 | TLS流量解密（先在“设置”里上传 keylog 或私钥） |
