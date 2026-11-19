---
layout: default
title: Fnet — 面向 CTF 与流量取证的流量分析工具箱
description: 把 pcap 或文本日志拖进浏览器，勾选需要的检查项，得到 flag、凭据、还原文件与解密流量。本地运行、纯标准库、抓包解析交给 tshark。
---

<div class="hero">
  <h1>Fnet</h1>
  <p class="tagline">面向 CTF 与流量取证的开源流量分析工具箱</p>
  <p class="lead">
    把 pcap / pcapng 或文本日志拖进浏览器，勾选要查的项，就能拿到 flag、凭据、
    还原的文件和解密后的流量。全部在本机运行，不需要第三方 Python 包，抓包解析
    交给 tshark，日志分析则由内置解析器完成。
  </p>
  <p class="cta-row">
    <a class="btn" href="{{ '/manual/tutorial/' | relative_url }}">开始实战</a>
    <a class="btn ghost" href="{{ '/manual/install/' | relative_url }}">安装与启动</a>
    <a class="btn ghost" href="{{ '/manual/features/' | relative_url }}">浏览 54 项功能</a>
    <a class="btn ghost" href="https://github.com/fyfhcgch/Fnet">GitHub 仓库</a>
    {%- if site.version %}
    <span class="badge version-badge">v{{ site.version }}</span>
    {%- endif %}
  </p>
</div>

## 2.21.3 更新

- **文本日志直接分析**：`.log` / `.txt` / `.jsonl` / `.csv` 可直接作为输入，内置解析器
  识别 Ceph、syslog、sshd、Apache 与通用 KV 等格式，新增“日志分析”分类（4 项功能），
  输出概览时间线、实体画像、失败异常与 IOC/敏感信息；日志分析不依赖 tshark。
- **Python 3.10 兼容**：日志证据时间戳解析统一处理 `+0000`/`+00`/`Z` 偏移，并保留非 UTC 时区的原始偏移，修复 CI 上时间窗关联失效。
- **测试可移植性**：路径契约测试不再依赖本机才存在的 `/tmp/opencode` 临时目录。

## 2.21.2 更新

- **OpenSSL 加密文件深度分析**：新增纯标准库 `enc` 信封核心，支持
  `Salted__`/Base64、`-md`、PBKDF2/`-iter`/`-saltlen`、显式 `-S`、`-K/-iv`、
  外层/内层 zlib，以及 AES-128/192/256 的 CBC/CTR/ECB 解密。
- **降噪与可操作结果**：生成的 README/报告/明文工件不再进入分析结果；命中时
  给出编码、salt、cipher、KDF、摘要、迭代数与 flag 细节，解密结果落盘。
- **真实 CLI 校验**：新增 `openssl enc` 样本生成器与兼容性测试，覆盖 1.1+/3.x/4.x
  常见配方；CLI `--all` 帮助改为按功能注册表动态显示数量。

## 2.21.1 更新

- **Sliver 现代传输解密**：支持 v1.6 ChaCha20-Poly1305、74 字节 minisign 签名前缀跳过与 gzip 透明解压；兼容 v1.5 与旧版 AES-GCM，并识别 Age/TOTP/RSA 密钥交换及多种流量编码器。
- **Meterpreter 线协议增强**：严格解析现代/旧版 XOR 头、TLV 与 staging，支持 AES-128/256-CBC 密钥解密；结果改为带命令号、GUID、加密与解密状态的线索，消除空信息与截图式伪头误报。
- **C2 参数与文档**：`sliver_session_key` 接受 32/16 字节，`meterpreter_symkey` 接受 32/16 字节；功能清单同步更新，继续沿用 `checkBox_56`。

## 2.21.0 更新

- **SMB 加密链路智能串联**：NTLM 账号 → 候选密码注入/离线验证 → SMB3 解密 →
  导出文件 → 熵识别疑似加密 → 提示 flag，一条命令自动串联；候选耗尽自动回退
  并提示 hashcat，缺模块时优雅降级不崩溃；WebUI 的 SMB3 解密对话框会按链路
  查到的账号、密码与会话密钥自动填入。
- **NTLM 密码离线验证**：无 hashcat 也能用捕获的挑战/响应直接验证或受控枚举
  NetNTLMv2 密码（默认不强攻），命中输出口令、未命中提示 hashcat -m 5600/5500。
- **OpenSSL 加密文件分析**：按字节熵识别疑似加密/压缩文件；内置 `EVP_BytesToKey`
  + AES-CTR/CBC/ECB OpenSSL 兼容解密（`openssl enc` 场景），解密后自动扫 flag。
- **密码候选生成**：从账号/域名/共享/文件名与弱口令字典派生候选，支持路径字典
  与受控暴力枚举，供 NTLM 验证与 SMB3 解密复用。

## 2.20.0 更新

- **协议补齐**：LDAP、SMB2/3、MongoDB、PostgreSQL、Redis、SSH 六个会话级功能
  注册为独立复选框（会话级共 46 项），统一输出命令、查询、凭据、文件与爆破时间线。
- **C2 与取证**：Sliver（HTTP/DNS/mTLS beacon）与 meterpreter（staging、XOR 线
  格式、AES 加密包）识别解密；导入 Suricata `eve.json` 与 Zeek 日志，按 IP/
  端口/时间与流量发现做旁证关联。
- **QUIC 无 keylog 取证**：纯标准库实现 RFC 9001 Initial 密钥派生与 AES-GCM
  解密，无 keylog 也能取出 ClientHello、SNI、版本协商与连接 ID。
- **可选加速层**：自动探测 CUDA → CPU JIT → 纯 Python 并静默回退；关键字扫描
  与 GCM 校验吞吐分别提升至 96× 与 131×，核心零依赖不变。
- **结果可交付**：findings 支持人工标注与误报标记，报告三格式同步渲染，任务
  对比的 diff 纳入标注差异。
- **工程**：`jobs.py` 按分片/断点/findings 拆分，Windows CI 转门禁，示例夹具
  补齐 USB、蓝牙与 RDP，发布走 PyPI Trusted Publishing。

## 2.19.0 更新

- **大包更稳**：关键字检测按帧区间分块扫描，1 GB 抓包峰值内存约 150 MB；
  multipart 上传流式落盘，不再整包读入内存。
- **断点与分片**：任务在功能边界暂停/继续（WebUI 与 `--resume`），无状态功能
  可用 `--shards N` 按帧区间并行。
- **实时抓包**：选择网卡与 BPF 过滤器直接抓包，停止后可立即送入分析。
- **对比与规则**：任务历史可对比两个任务的 findings diff；支持逐行正则与
  YARA 子集规则，命中写入结果与报告。
- **可编程**：`--json` 输出任务、findings、统计与产出；`--compare` 对比任务。
- **协议深化**：DNS/ICMP 隧道重组、Kerberos keytab/口令解密与 PAC、
  SMTP/IMAP/POP3 附件、MySQL 结果集与 LOAD DATA/LOAD_FILE、WPA PSK 解密取证。
- **界面**：中文 / English 切换、上传进度与取消、暂停/继续。

<p class="shot">
  <img src="{{ '/assets/images/webui.webp' | relative_url }}"
       alt="Fnet WebUI：左侧 54 个功能的勾选面板，右侧分析结果表格">
</p>
<p class="shot-caption">真实界面截图：暖夜主题下的分析结果页</p>

## 为什么用它

<div class="feature-grid why-grid">
  <div class="card">
    <h3>一条命令，本地可用</h3>
    <p>Python 3.10+ 与 tshark 就够，无数据库、无云端、无第三方依赖，断网也能分析。</p>
  </div>
  <div class="card">
    <h3>按赛题组织功能</h3>
    <p>54 个分析功能分成 14 类：从 flag 扫描、文本日志、HTTP 与 Webshell，到工控、无线、TLS 解密。</p>
  </div>
  <div class="card">
    <h3>结果能带走</h3>
    <p>凭据、哈希、flag、导出文件汇总成可排序表格，可导出 CSV 与 Markdown / HTML 报告。</p>
  </div>
  <div class="card">
    <h3>大包与长任务</h3>
    <p>分块扫描与流式上传控制内存；任务可暂停/续跑，无状态功能按帧区间分片。</p>
  </div>
  <div class="card">
    <h3>可复盘、可对比</h3>
    <p>任务历史一键重跑，对比两个任务的 findings diff；实时抓包后直接送入分析。</p>
  </div>
  <div class="card">
    <h3>可编程</h3>
    <p><code>--json</code> 输出任务与 findings，<code>--rules</code> 导入正则/YARA 子集，
       <code>--compare</code> 与 WebUI 共用同一实现。</p>
  </div>
</div>

## 三分钟上手

<ol class="steps">
  <li>
    <strong>装依赖</strong>：Python 3.10+ 与 <code>tshark</code>。
    <pre><code>sudo apt install tshark        # Debian / Ubuntu
brew install wireshark         # macOS</code></pre>
  </li>
  <li>
    <strong>启动 WebUI</strong>：
    <pre><code>git clone https://github.com/fyfhcgch/Fnet
cd Fnet
python3 -m fnet</code></pre>
    浏览器会自动打开 <code>http://127.0.0.1:8765</code>。
  </li>
  <li>
    <strong>上传抓包或日志并运行</strong>：拖入 pcap / pcapng / 日志文件 →
    左侧勾选功能 → “开始分析”，结果与日志会实时出现在右侧。
  </li>
  <li>
    <strong>拿走结论</strong>：在“分析结果”页筛选、复制或导出 CSV，或从“产出文件”
    下载报告与还原的文件。
  </li>
</ol>

<p class="note">
  <strong>无界面也能用：</strong>
  <code>python3 -m fnet -C capture.pcapng --features checkBox_10,webshell.decrypt</code>，
  结果与报告路径会直接打印在终端。详见<a href="{{ '/manual/cli/' | relative_url }}">命令行手册</a>。
</p>

## 跟着实战走

不知道先勾什么？按你的题型直接进入对应教程：

<div class="feature-grid tutorial-grid">
  <a class="card tutorial-card" href="{{ '/manual/tutorial/#find-flag' | relative_url }}">
    <h3>找 flag</h3>
    <p>默认两项、结果筛选、帧定位与深度扫描。</p>
  </a>
  <a class="card tutorial-card" href="{{ '/manual/tutorial/#web' | relative_url }}">
    <h3>Web / Webshell</h3>
    <p>HTTP 提取、下载文件、冰蝎哥斯拉与 Shiro 解密。</p>
  </a>
  <a class="card tutorial-card" href="{{ '/manual/tutorial/#tls' | relative_url }}">
    <h3>TLS 解密</h3>
    <p>上传 keylog 或私钥，继续还原 HTTP/2 与明文凭据。</p>
  </a>
  <a class="card tutorial-card" href="{{ '/manual/tutorial/#credentials' | relative_url }}">
    <h3>凭据提取</h3>
    <p>NTLM、Kerberos、WinRM 与跨协议账号关联。</p>
  </a>
</div>

## 功能一览

按场景选择，勾选后会在同一次任务里依次执行；缺失的可选工具只会让对应功能降级。

<div class="feature-grid">
  <div class="card">
    <span class="badge">4 项</span>
    <h3>日志分析</h3>
    <p>Ceph / syslog / sshd / Apache / JSONL / CSV 等文本日志：格式识别、时间线、实体失败率、异常突增与 IOC 提取，无需 tshark。</p>
  </div>
  <div class="card">
    <span class="badge">1 项</span>
    <h3>文本与关键字</h3>
    <p>flag 与自定义正则扫描，支持十六进制、Base64 / Hex / URL 编码关键词；大包按帧区间分块扫描。</p>
  </div>
  <div class="card">
    <span class="badge">2 项</span>
    <h3>HTTP / Web</h3>
    <p>请求响应配对、Cookie 与 Basic 认证，导出下载文件并计算 MD5。</p>
  </div>
  <div class="card">
    <span class="badge">1 项</span>
    <h3>Webshell / Shiro</h3>
    <p>Shiro rememberMe 自动或手动密钥解密，配合 Webshell 变体还原命令输出。</p>
  </div>
  <div class="card">
    <span class="badge">3 项</span>
    <h3>SQL 注入</h3>
    <p>布尔、时间与二分盲注的字符还原，也能从已保存的盲注日志回推内容。</p>
  </div>
  <div class="card">
    <span class="badge">2 项</span>
    <h3>C2 / 远控</h3>
    <p>Cobalt Strike beacon 解密与 WinRM 凭据还原。</p>
  </div>
  <div class="card">
    <span class="badge">4 项</span>
    <h3>认证与凭据</h3>
    <p>NTLM 哈希与 Kerberos 票据；keytab/口令/原始密钥解密、PAC 与用户时间线，输出 hashcat 格式；无 hashcat 时也可离线验证 NetNTLMv2 密码并派生 SMB 密码候选。</p>
  </div>
  <div class="card">
    <span class="badge">17 项</span>
    <h3>协议流量</h3>
    <p>TCP / UDP / DNS / ICMP / FTP / SMTP / Telnet / MySQL / ARP / GTP / LDAP / SMB / MongoDB / PostgreSQL / Redis / SSH；DNS/ICMP 隧道重组、邮件附件、MySQL 结果集与 LOAD，数据库与 SSH 会话凭据还原；SMB 加密链路智能串联。</p>
  </div>
  <div class="card">
    <span class="badge">7 项</span>
    <h3>工控协议</h3>
    <p>Modbus、S7comm、IEC 60870-5-104、MQTT、MMS、OMRON FINS 与 GOOSE。</p>
  </div>
  <div class="card">
    <span class="badge">3 项</span>
    <h3>USB / 外设</h3>
    <p>USB HID 键盘按键与鼠标轨迹还原，以及 LEGO EV3 蓝牙数据。</p>
  </div>
  <div class="card">
    <span class="badge">2 项</span>
    <h3>无线与蓝牙</h3>
    <p>WPA/WPA2 握手与 PMKID；已知 PSK 时解密数据帧，把明文送回 HTTP/DNS/凭据分析。</p>
  </div>
  <div class="card">
    <span class="badge">1 项</span>
    <h3>TLS / 加密</h3>
    <p>keylog 与私钥解密 TLS/QUIC，继续还原 HTTP/2、WebSocket、HTTP/3 与明文凭据。</p>
  </div>
  <div class="card">
    <span class="badge">2 项</span>
    <h3>杂项</h3>
    <p>SCSI 传输数据提取与 IP ID 隐蔽信道分析。</p>
  </div>
  <div class="card">
    <span class="badge">1 项</span>
    <h3>RDP 重放</h3>
    <p>用私钥或 keylog 解密 RDP 会话并生成可回放的会话文件。</p>
  </div>
</div>

<a class="btn ghost" href="{{ '/manual/features/' | relative_url }}">查看完整功能清单与依赖</a>

## 用户教程

<ul class="manual-list">
  <li>
    <a href="{{ '/manual/install/' | relative_url }}">
      <strong>安装与启动</strong>
      <span>系统依赖、可选工具、配置目录与第一次分析</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/tutorial/' | relative_url }}">
      <strong>实战教程</strong>
      <span>找 flag、Web 题、TLS 解密、凭据提取与批量复盘</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/webui/' | relative_url }}">
      <strong>WebUI 使用</strong>
      <span>上传进度、暂停/继续、语言切换、任务对比、实时抓包、报告与历史</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/features/' | relative_url }}">
      <strong>功能清单</strong>
      <span>54 项功能的作用、复选框编号与所需工具</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/cli/' | relative_url }}">
      <strong>命令行</strong>
      <span>JSON 输出、规则、分片、续跑、任务对比与批处理</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/faq/' | relative_url }}">
      <strong>常见问题</strong>
      <span>tshark 缺失、解密无结果、大文件内存与上传</span>
    </a>
  </li>
</ul>

## 适用场景

- **CTF 流量题**：flag 扫描、隐写与编码、协议还原、Webshell 与盲注流量。
- **日志取证**：Ceph / syslog / sshd / Web 访问日志的失败统计、异常实体与 IOC 提取。
- **应急与取证**：凭据与哈希提取、文件还原、认证时间线、跨协议账号关联。
- **教学与演练**：本地跑通完整分析链路，报告可直接交付或打印成 PDF。

<p class="note">
  请仅在合法的教学、竞赛与授权测试中使用。Fnet 不会执行流量包或日志中的任何代码；
  抓包的协议解析由 <code>tshark</code> 完成，文本日志由内置解析器读取。
</p>
