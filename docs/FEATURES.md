# 功能说明

Fnet 共 **46 个分析功能**、**13 个分类**。WebUI 侧栏按分类折叠展示；CLI 用
复选框编号（`checkBox_10`）或 handler（`text_scan.keyword_scan`）选择。

```bash
python3 -m fnet --list-features          # 带 * 的是默认勾选
python3 -m fnet -C x.pcap --features checkBox_10,http.extract
```

所有功能都可以在 WebUI 中运行；标记“需要”的工具缺失时，功能仍会执行并给出
明确提示，不会影响其它功能。

## 文本与关键字

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_10` ★ | `text_scan.keyword_scan` | 关键字检测 | 在 HTTP/TCP/UDP 等载荷中匹配 `regmatch`、`flag{...}`、常见编码（Base64/Hex/URL/数字 ASCII）；短关键字使用词边界避免误报 |

参数：`keywords`（自定义正则，`;` 分隔）、`post_only`（只看 POST）、
`auto_regex`、`decode`、`max_hits`。

## HTTP / Web

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_30` ★ | `http.extract` | HTTP数据提取 | 请求/响应配对、URI、Host、状态码、User-Agent、Cookie、Basic 认证；提取响应正文与文件 |
| `checkBox_32` | `http.export_files` | HTTP下载文件分析 | 导出响应体，识别文件类型（含 magic/扩展名）并计算 MD5 |

## Webshell / Shiro

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_42` | `webshell.shiro` | shiro流量解密 | `rememberMe` Cookie 的 AES-CBC/ECB/GCM 解密；自动遍历 `shiro_keys.txt`，支持手动密钥 |

参数：`shiro_mode=auto|diy`、`shiro_key`（Base64/16/24/32 字节）、
`shiro_remember`（默认 `rememberMe`）。

Webshell 解密不是独立复选框，而是通过 WebUI 的“Webshell 解密设置”或 CLI
`--features webshell.decrypt` 调用：

```bash
python3 -m fnet -C x.pcap --features webshell.decrypt \
  --param webshell_mode=auto --param webshell_password=pass
```

支持明文/Base64 载荷识别，以及哥斯拉（Godzilla，AES_BASE64/AES_RAW/XOR）、
冰蝎（Behinder 3.x/4.x）、蚁剑（AntSword）、菜刀（Caidao）、天蝎（Tianxie）
等常见变体；规则表位于 `fnet/utils/webshell.py`，密钥推导与解密按规则选择。
请求与响应会按会话配对，响应中的命令、回显、文件操作与 flag 会被结构化；
冰蝎 4.x 的二进制 POST、Godzilla/Behinder 内存马常见 Servlet 容器类名
（`StandardContext`、`FilterDef`、`内存马` 等）会作为告警写入结构化结果。
对 Java class 载荷还会解析常量池，尽量还原 Filter/Servlet/Listener 注册信息。
内存马特征使用强弱标记阈值，普通业务类名不再单独触发告警。

## SQL 注入

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_26` | `sql.blind` | SQL盲注流量分析 | 按正则从 URI/正文提取比较对，结合成功条件还原布尔盲注 |
| `checkBox_46` | `sql.binary` | SQL二分盲注增强 | 对 `> N` / `< N` 形式的二分盲注按区间推断字符 |
| `checkBox_34` | `sql.log_analysis` | SQL盲注日志分析 | 读取已保存的盲注日志（文件或粘贴文本）还原结果 |

参数：`sql_success`（成功响应特征）、`sql_compare=contains|status|length`、
`sql_time_threshold`（时间盲注阈值，秒）、`sql_regex`、`sql_reverse`
（颠倒索引）、`sql_char`（查询值为字符）、`sql_log`/`sql_log_text`。

## C2 / 远控

| 复选框 | Handler | 功能 | 需要 | 说明 |
| --- | --- | --- | --- | --- |
| `checkBox_15` | `cs.analyze` | Cobalt Strike流量分析 | `cryptography` | 解析 beacon 元数据/任务，使用 `.cobaltstrike.beacon_keys` 解密 |
| `checkBox_43` | `winrm.decrypt` | WINRM流量解密 | — | 从 NTLM 认证还原 WinRM 凭据；支持 hash 或明文密码 |
| `checkBox_55` | `meterpreter.analyze` | Meterpreter会话分析 | — | Meterpreter/metsvc TCP TLV 会话识别：命令 ID、字符串参数、异常与命令时间线；不认识的 TLV type 显示 hex |
| `checkBox_56` | `c2ext.analyze` | Sliver/meterpreter C2扩展 | — | Sliver HTTP/DNS/mTLS beacon 识别（URI 扩展名分类、改良 Base32/Base58 解码、证书画像）与 meterpreter staging/XOR 加密传输分析；有会话密钥时解密会话载荷 |

Meterpreter 参数：无（自动按 TLV 结构识别，metsvc 默认端口 31337，
反向连接端口不定）。输出 `meterpreter_timeline.csv`。

C2 扩展参数：`sliver_session_key`（Sliver 会话 AES-256 密钥，hex）、
`meterpreter_symkey`（meterpreter AES-256 对称密钥，hex）、
`sliver_dns_domain`（已知 DNS beacon 域名，逗号分隔）。

WinRM 参数：`winrm_auth=hash|password`、`winrm_ntlm`、`winrm_password`。
CS 参数：`cobaltstrike_keys`（keys 文件路径）。

## 认证与凭据

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_39` | `ntlm.extract` | NTLM HASH提取 | 从 HTTP/SMB/WinRM 的 NTLMSSP 消息提取账号、域、主机与 NetNTLMv1/v2 哈希，输出 hashcat/john 格式 |
| `checkBox_45` | `kerberos.parse` | Kerberos解析破解 | 解析 AS-REQ/AS-REP/TGS-REP，生成 hashcat 18200/13100/19800/19900/19600/19700 哈希；可用 keytab、账号密码或原始密钥解密响应并解析 PAC、NTLM 哈希与用户时间线 |

NTLM 输出可直接用于：

```bash
hashcat -m 5600 ntlm_hashes.txt wordlist.txt   # NetNTLMv2
hashcat -m 5500 ntlm_hashes.txt wordlist.txt   # NetNTLMv1
```

## 协议流量

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_23` | `flows.dns` | DNS流量分析 | 查询/响应、长标签检测；按域名分块按序重组（Base64/Base32/Hex）、隧道时间线、解码数据落盘与 flag 提取 |
| `checkBox_20` | `flows.icmp` | ICMP流量分析 | ICMP 载荷、长度分布；按源/目的/ID 重组分块隧道、时间线与解码落盘 |
| `checkBox_19` | `flows.telnet` | Telnet流量分析 | Telnet 会话内容还原 |
| `checkBox_27` | `flows.ftp` | FTP流量分析 | USER/PASS、命令、数据通道与传输文件 |
| `checkBox_28` | `flows.smtp` | SMTP流量分析 | SMTP/IMAP/POP3 命令与凭据、发件人/收件人/邮箱、MIME 头、正文与附件还原（附件落盘并计算 MD5/SHA256） |
| `checkBox_37` | `flows.mysql` | MYSQL数据分析 | `mysql_native_password`/`caching_sha2_password` 握手认证、查询、结果集、`LOAD DATA LOCAL INFILE` 上传文件与 `LOAD_FILE()` 读取内容 |
| `checkBox_41` | `flows.gtp` | 4G/5G通信协议分析 | GTP 隧道、TEID 与异常检测 |
| `checkBox_35` | `flows.udp` | UDP流分析 | UDP 会话与载荷；输出可能较多 |
| `checkBox_33` | `flows.tcp` | TCP流分析 | TCP 流重组、会话统计与内容提取 |
| `checkBox_44` | `arp.analyze` | ARP协议分析 | IP/MAC 冲突、免费 ARP 与异常字段 |
| `checkBox_48` | `ldap.analyze` | LDAP流量分析 | LDAP 绑定凭据/SASL 机制、查询 base/filter、条目属性（AD 账号等）与 StartTLS 告警 |
| `checkBox_49` | `smb.analyze` | SMB流量分析 | SMB2/3 共享与会话、NTLM 身份、文件读写还原落盘、加密/压缩告警 |
| `checkBox_50` | `mongodb.analyze` | MongoDB流量分析 | OP_MSG 命令与集合、SCRAM 认证交换、GridFS 文件还原落盘 |
| `checkBox_51` | `postgres.analyze` | PostgreSQL流量分析 | 查询语句与参数、结果摘要、明文口令消息与 COPY 数据 |
| `checkBox_52` | `redis.analyze` | Redis流量分析 | RESP 命令、AUTH/ACL 凭据、敏感键读取与写入值摘要（支持非标准端口） |
| `checkBox_53` | `ssh.analyze` | SSH流量分析 | SSH 版本交换、KEXINIT 算法协商、userauth 用户名/方法/口令与爆破时间线 |

### 扩展协议处理器（无复选框）

以下处理器没有对应的复选框，可在 WebUI 的“专项功能”菜单
运行，或用 `--features` 直接调用：

| Handler | 功能 | 说明 |
| --- | --- | --- |
| `protocols.credentials` | 多协议凭据提取 | 依次运行 Redis、MongoDB、PostgreSQL、LDAP、SMB2、WebSocket、HTTP/2 提取器，输出命令、查询、认证信息与 flag |
| `protocols.redis` | Redis 深度解析 | RESP2/RESP3 命令、AUTH/HELLO/requirepass、ACL、集群 MOVED/ASK、Pub/Sub、EVAL/EVALSHA 脚本与键值，输出 `redis_commands.txt` |
| `protocols.mongodb` | MongoDB 深度解析 | OP_MSG/OP_QUERY/OP_REPLY 等消息、BSON 文档、SCRAM 认证、GridFS 分块还原，输出 `mongodb_queries.txt` 与 `gridfs_*` |
| `protocols.postgres` | PostgreSQL 深度解析 | 启动包/SSLRequest、简单与扩展查询（Parse/Bind/Execute）、MD5/SASL 认证、二进制参数、COPY 数据，输出 `postgres_queries.txt` 与 `postgres_copy_*` |
| `protocols.detect` | 端口/协议自动识别 | 对非默认端口做特征探测（Redis/MongoDB/PostgreSQL/LDAP/SMB2/HTTP2），输出 `protocol_detection.csv`；后续提取器自动复用探测结果，并支持置信度阈值与忽略列表 |
| `protocols.http2` | HTTP/2 深度解析 | 帧解析、HPACK 静态/动态表还原、流与优先级、gRPC/Protobuf 识别、DATA 正文重组；输出 `http2_streams.txt` 与 `http2_body_*` |
| `protocols.ldap` | LDAP 深度解析 | BER 解码、StartTLS、SASL/简单绑定、AD 属性、批量查询与 DN/过滤器结果；输出 `ldap_queries.txt` 与 `ldap_objects.txt` |
| `protocols.smb2` | SMB2/3 文件访问与认证 | 还原共享/文件名、读写操作与状态码、DFS 路径与命名管道，关联 NTLM 账号，导出文件内容与 `smb2_files.txt`/`smb2_pipes.txt`/`smb2_dfs.txt` |
| `text_scan.deep` | 深度 flag 扫描 | 对重组流、解密正文、导出文件与二进制载荷统一扫描 flag/编码，抑制占位符并保留来源帧与置信度 |
| `forensics.correlate` | 跨协议凭据关联 | 汇总 NTLM、LDAP、Basic、FTP、Redis、数据库等来源，按账号/主机聚合去重，输出 `credentials_correlated.csv`，支持白名单与最短密钥过滤 |
| `forensics.timeline` | 认证时间线 | 输出登录成功/失败、文件读写、提权与横向移动事件的时间线，写入 `auth_timeline.txt` |

```bash
python3 -m fnet -C capture.pcapng --features protocols.credentials
python3 -m fnet -C capture.pcapng --features protocols.redis
python3 -m fnet -C capture.pcapng --features protocols.mongodb
python3 -m fnet -C capture.pcapng --features protocols.postgres
python3 -m fnet -C capture.pcapng --features protocols.http2
python3 -m fnet -C capture.pcapng --features protocols.ldap
python3 -m fnet -C capture.pcapng --features protocols.smb2
python3 -m fnet -C capture.pcapng --features text_scan.deep
```

Redis/MongoDB/PostgreSQL/HTTP/2/LDAP/SMB2 会先用 `tcp.seq` 把每个方向重组为完整
字节流，再解析协议消息，因此跨包、乱序和重传的命令不会被截断；重组结果保留帧号
映射，丢包或截断会在日志中告警。Redis 直接解析 RESP，MongoDB/PostgreSQL/LDAP/
SMB2 在自有解析未取得消息时回退到 `tshark` 字段；HTTP/2 使用内置帧解析与 HPACK
表，WebSocket 会按流/方向增量解析帧，支持分片与续帧重组、`permessage-deflate`
解压、掩码与二进制帧导出。非默认端口由 `protocols.detect` 先探测再交给对应提取器，
探测结果带有置信度，可用 `protocol_min_confidence` 与 `protocol_ignore` 调整。

## 工控协议

| 复选框 | Handler | 功能 |
| --- | --- | --- |
| `checkBox_29` | `ics.summary` | MMS 会话概览 |
| `checkBox_11` | `ics.modbus` | Modbus 功能码、地址、写操作与异常帧 |
| `checkBox_12` | `ics.iecd` | IEC 60870-5-104 类型标识/传送原因 |
| `checkBox_13` | `ics.mqtt` | MQTT 主题与消息（自动尝试 Hex/Base64 解码） |
| `checkBox_22` | `ics.omron` | OMRON FINS 会话 |
| `checkBox_14` | `ics.s7comm` | S7comm 读写请求 |
| `checkBox_38` | `ics.goose` | GOOSE 报文概览 |

## USB / 外设

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_16` | `usb.keyboard` | USB-键盘流量分析 | HID 键盘按键还原为文本，输出 `usb_keyboard.txt` |
| `checkBox_17` | `usb.mouse` | USB-鼠标流量分析 | HID 鼠标轨迹，输出 `usb_mouse.csv` |
| `checkBox_40` | `misc.ev3` | EV3数据提取 | LEGO EV3 蓝牙数据还原 |

## 无线与蓝牙

| 复选框 | Handler | 功能 | 需要 | 说明 |
| --- | --- | --- | --- | --- |
| `checkBox_21` | `flows.bluetooth` | 蓝牙流量分析 | — | Bluetooth/BTHCI 概览 |
| `checkBox_18` | `wifi.crack` | 无线流量暴力破解 | 可选 `aircrack-ng`/`hcxtools`/`hashcat` | 识别 EAPOL 握手与 PMKID，生成 hashcat 22000 命令并可按需破解 |

Wi-Fi 处理器默认只做识别和取证，不会自动跑大字典：

- 按 BSSID/STA 关联 EAPOL 消息，标注 M1-M4 完整度与可用于破解的完整握手；
- 发现 PMKID 时按 AP/STA 去重，写入 `wifi_pmkid.hc22000`，并生成
  `wifi_hashcat.txt`（`hcxpcapngtool` / `hashcat -m 22000` 命令）；
- 识别 WPA3/SAE 握手并给出可用的分析路径；没有 `hcxpcapngtool` 时会提示安装
  并保留等价命令；
- 只有传入 `wifi_crack=1`（aircrack-ng）或 `wifi_run=1`（hashcat）才真正
  执行破解；
- 参数：`wordlist`（默认 `fnet/assets/wordlists/wifi_top2000.txt`）。
- 已知 PSK 时传入 `--wpa-psk <口令|64 位 PMK>`：处理器用 SSID 派生 PMK、
  由 M1/M2 nonce 派生 CCMP PTK，解密 802.11 数据帧并写出
  `wifi_decrypted_<bssid>_<sta>.pcap`，再把明文重新送入 HTTP/DNS/认证头
  分析，形成“破解 → 取证”的链路。

## TLS / 加密

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_24` | `tls.decrypt` | TLS流量解密 | 用 NSS keylog 或 RSA 私钥解密 TLS/QUIC，提取证书链、明文 HTTP、HTTP/2/gRPC、WebSocket 与 HTTP/3，并为每个 Client Hello 计算 JA3/JA4 指纹 |

`tls.decrypt` 会顺带调用 `tls.quic` 识别 QUIC v1/v2 连接：输出版本、SNI、
ALPN、包类型与帧号到 `quic_connections.csv`；配置 keylog 后继续解密 HTTP/3
头与正文。`tls.quic` 也可以从 CLI 或特殊功能中单独选择。

参数：`tls_keylog`（`SSLKEYLOGFILE` 格式）、`tls_private_key`（PEM 私钥）与
`tls_key_passphrase`（带口令 PEM 的口令）。WebUI 的“设置 → 上传 TLS keylog /
私钥…”会保存到 `<cache>/keys` 并写入配置；未显式配置时处理器会自动选用该目录
中的密钥。配置值、上传文件与目录中发现的多个 keylog 会按行合并去重后一起交给
`tshark`，便于匹配不同连接或轮换后的密钥；日志会给出 keylog 覆盖率与 TLS 1.3
KeyUpdate 提示。私钥仅适用于非前向保密套件：处理器会用证书链 SPKI 匹配私钥，
按匹配到的服务端 `IP:端口` 自动选择，带口令 PEM 会先经 `openssl` 解密；当本机
`tshark` 已移除 `tls.keys_list` 时会明确提示改用 keylog。解密后的明文会继续做
凭据/Cookie/JWT、表单、HTTP/2 与 WebSocket 分析与文件清单提取，分别写入
`tls_decrypted_http.csv`、`tls_http2.csv`、`tls_websocket.txt` 与
`tls_http_objects.csv`。另外，处理器会为每个 Client Hello 按 Salesforce JA3 与
FoxIO JA4+ 规范计算 JA3/JA4 指纹（纯 stdlib 实现，见 `fnet/utils/tlsdeep.py`），
并在“TLS 握手”表中追加 JA3/JA4 列、记录 `tls_fingerprint` 发现、输出
`tls_fingerprints.csv`（含匹配到的 Server Hello 的 JA4S/JA3S）。在没有 keylog
（或 keylog 解不出该连接）时，处理器还会用 RFC 9001 的 QUIC Initial 已知保护密钥
（纯 stdlib 实现于 `fnet/utils/tlsdeep.py`）直接解出 Initial 包中的 Client Hello，
输出“无需 keylog 的 Initial 元数据提取”日志、`tls_fingerprint` 发现与
`quic_initial_fingerprints.csv`（SNI/ALPN/JA3/JA4，JA4 使用 QUIC 的 `q` 前缀）。

## 杂项

| 复选框 | Handler | 功能 | 说明 |
| --- | --- | --- | --- |
| `checkBox_36` | `misc.scsi` | SCSI传输数据提取 | 从 SCSI/存储流量提取读写数据 |
| `checkBox_31` | `misc.ipid` | IPID数据分析 | IP ID 隐蔽信道/异常分析（通常关闭） |
| `checkBox_54` | `forensics.log_import` | 日志证据关联 | 导入 Suricata eve.json / Zeek TSV 日志（`log_path` 文件或 `log_text` 粘贴），归一化为统一事件模型并与流量发现按 IP/端口关联；告警签名计入结构化结果，输出 `log_import_events.csv` |

日志证据关联不是 pcap 解析功能：它只读取导入的日志并与当前任务已有的
findings 做交集，任务没有 findings 时照常归一化日志。识别不出格式时
会提示需要 eve.json（JSON Lines）或带 `#fields` 头的 Zeek 日志。

## RDP 重放

| 复选框 | Handler | 功能 | 需要 | 说明 |
| --- | --- | --- | --- | --- |
| `checkBox_47` | `rdp.handler` | RDP流量重放 | `pyrdp-player` | 用私钥或 keylog 解密 RDP 会话，生成重放文件；可选自动启动播放器 |

参数：`rdp_private_key`、`rdp_keylog`、`server_ip`、`port`、
`player_path`、`launch_player`。

## 分析报告

每个任务结束会自动生成三种报告：

- `report.txt`：纯文本，与终端日志一致，适合 grep；
- `report.md`：带概要、功能清单、关键发现、完整日志、产出文件与参数的 Markdown；
- `report.html`：自包含样式，可离线打开，也可用浏览器打印为 PDF。

WebUI 的“文件 → 导出分析报告…”可以勾选章节（`summary`、`features`、
`findings`、`log`、`artifacts`、`params`），“任务历史”每一行也提供 HTML
下载。对应接口为 `GET /api/report`，详见 [`WEBUI.md`](WEBUI.md)。

## 结构化结果

除了人读日志，功能处理器会把值得汇总的发现写成结构化记录：类别（flag、
凭据、哈希、HTTP、Webshell、SQL、DNS、文件、协议、自定义规则等）、级别、帧号、功能、
摘要与详情。任务结束时落盘为：

- `findings.json`：完整记录，供 WebUI、脚本或二次处理使用；
- `findings.csv`：UTF-8 CSV，可直接用表格软件打开。

当前会产出结果的功能包括关键字检测、HTTP 提取与文件导出、NTLM、Kerberos、
SQL 盲注、DNS、FTP/MySQL、Shiro 与 Webshell 解密等。WebUI 的“分析结果”
页支持按类别/级别筛选、关键字搜索、点击表头排序、复制与导出 CSV；
`GET /api/findings?job=<id>` 返回同样的数据，报告中的“关键发现”章节也会
优先使用这张表。

## 菜单里的非复选框动作

WebUI 的“工具/统计/文件”菜单还提供：

- 一键导出所有文件、分离所有文件、修复流量包、ETL 转 pcapng；
- 端口扫描统计、HTTP URI 统计、IP 会话统计、协议分层统计、时间线统计；
- 多协议凭据提取（Redis/MongoDB/PostgreSQL/LDAP/WebSocket/HTTP2）、SMB2 文件/认证分析、
  协议自动识别、跨协议凭据关联与认证时间线；
- CyberChef 打开、TLS keylog / 私钥 / CS keys / 字典 / Java / RDP 设置；
- 识别 HTTP 登录成功的账号密码。

这些动作通过 `POST /api/action` 执行，和任务一样受 token 保护。详见
[`WEBUI.md`](WEBUI.md)。
