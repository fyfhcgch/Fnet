---
layout: default
title: Fnet — 面向 CTF 与流量取证的流量分析工具箱
description: 把 pcap 拖进浏览器，勾选需要的检查项，得到 flag、凭据、还原文件与解密流量。本地运行、纯标准库、协议解析交给 tshark。
---

<div class="hero">
  <h1>Fnet</h1>
  <p class="tagline">面向 CTF 与流量取证的开源流量分析工具箱</p>
  <p class="lead">
    把 pcap / pcapng 拖进浏览器，勾选要查的项，就能拿到 flag、凭据、还原的文件和
    解密后的流量。全部在本机运行，不需要第三方 Python 包，协议解析交给 tshark。
  </p>
  <p class="cta-row">
    <a class="btn" href="{{ '/manual/tutorial/' | relative_url }}">开始实战</a>
    <a class="btn ghost" href="{{ '/manual/install/' | relative_url }}">安装与启动</a>
    <a class="btn ghost" href="{{ '/manual/features/' | relative_url }}">浏览 37 项功能</a>
    <a class="btn ghost" href="https://github.com/fyfhcgch/Fnet">GitHub 仓库</a>
  </p>
</div>

<p class="shot">
  <img src="{{ '/assets/images/webui.webp' | relative_url }}"
       alt="Fnet WebUI：左侧 37 个功能的勾选面板，右侧分析结果表格">
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
    <p>37 个分析功能分成 13 类：从 flag 扫描、HTTP 与 Webshell，到工控、无线、TLS 解密。</p>
  </div>
  <div class="card">
    <h3>结果能带走</h3>
    <p>凭据、哈希、flag、导出文件汇总成可排序表格，可导出 CSV 与 Markdown / HTML 报告。</p>
  </div>
  <div class="card">
    <h3>批量与回看</h3>
    <p>多包排队分析、任务历史一键重跑、统计图表与会话拓扑，赛后复盘不用重来一遍。</p>
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
    <strong>上传抓包并运行</strong>：拖入 pcap → 左侧勾选功能 → “开始分析”，
    结果与日志会实时出现在右侧。
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
    <span class="badge">1 项</span>
    <h3>文本与关键字</h3>
    <p>flag 与自定义正则扫描，支持十六进制、Base64 / Hex / URL 编码关键词。</p>
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
    <span class="badge">2 项</span>
    <h3>认证与凭据</h3>
    <p>NTLM 哈希与 Kerberos 票据提取，直接生成 hashcat 可用的格式。</p>
  </div>
  <div class="card">
    <span class="badge">10 项</span>
    <h3>协议流量</h3>
    <p>TCP / UDP / DNS / ICMP / FTP / SMTP / Telnet / MySQL / ARP / GTP 会话与载荷。</p>
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
    <p>WPA/WPA2 握手字典破解，蓝牙 / BTHCI 协议概览。</p>
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
      <span>上传、勾选、结果表格、帧定位、历史、批量与报告</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/features/' | relative_url }}">
      <strong>功能清单</strong>
      <span>37 项功能的作用、复选框编号与所需工具</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/cli/' | relative_url }}">
      <strong>命令行</strong>
      <span>无界面运行、参数传递、批处理与退出码</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/faq/' | relative_url }}">
      <strong>常见问题</strong>
      <span>tshark 缺失、解密无结果、大文件与内存</span>
    </a>
  </li>
</ul>

## 适用场景

- **CTF 流量题**：flag 扫描、隐写与编码、协议还原、Webshell 与盲注流量。
- **应急与取证**：凭据与哈希提取、文件还原、认证时间线、跨协议账号关联。
- **教学与演练**：本地跑通完整分析链路，报告可直接交付或打印成 PDF。

<p class="note">
  请仅在合法的教学、竞赛与授权测试中使用。Fnet 不会执行流量包中的任何代码，
  所有协议解析由 <code>tshark</code> 完成。
</p>
