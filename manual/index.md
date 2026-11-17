---
layout: page
title: 使用手册
permalink: /manual/
description: Fnet 使用手册：安装、WebUI、功能清单、命令行与常见问题。
---

Fnet 有两条使用路径：**WebUI** 适合交互式分析、看图表和整理报告，**命令行**适合
脚本化与批量处理。两者共用同一套功能与输出目录。

## 从哪里开始

| 你的情况 | 建议阅读 |
| --- | --- |
| 第一次使用 | [安装与启动]({{ '/manual/install/' | relative_url }}) → [WebUI 使用]({{ '/manual/webui/' | relative_url }}) |
| 手上有一个 pcap，想知道该勾哪些功能 | [功能清单]({{ '/manual/features/' | relative_url }}) |
| 想写脚本批量跑赛题 | [命令行]({{ '/manual/cli/' | relative_url }}) |
| 跑不出结果、报错、解密失败 | [常见问题]({{ '/manual/faq/' | relative_url }}) |
| 想加一个协议或功能 | [CONTRIBUTING.md](https://github.com/fyfhcgch/Fnet/blob/master/CONTRIBUTING.md) |

## 手册目录

<ul class="manual-list">
  <li>
    <a href="{{ '/manual/install/' | relative_url }}">
      <strong>安装与启动</strong>
      <span>系统依赖、可选工具、配置目录、第一次分析</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/webui/' | relative_url }}">
      <strong>WebUI 使用</strong>
      <span>界面分区、上传与批量、结果表格、帧定位、报告</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/features/' | relative_url }}">
      <strong>功能清单</strong>
      <span>37 项功能按 13 个分类的作用、编号与依赖</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/cli/' | relative_url }}">
      <strong>命令行</strong>
      <span>参数、功能选择、参数传递、批处理与退出码</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/faq/' | relative_url }}">
      <strong>常见问题</strong>
      <span>tshark、解密、内存、端口与浏览器问题</span>
    </a>
  </li>
</ul>

## 深入文档

手册讲“怎么用”，下面这些文档讲“为什么这样实现”，主要面向二次开发：

- [功能规格与参数]({{ '/docs/FEATURES.html' | relative_url }})：每个功能的输入、输出文件与可选参数
- [WebUI 与 HTTP API]({{ '/docs/WEBUI.html' | relative_url }})：接口、批量任务、报告与远程访问
- [架构说明]({{ '/docs/ARCHITECTURE.html' | relative_url }})：对象图、任务模型与扩展点
- [安全说明]({{ '/docs/SECURITY.html' | relative_url }})：威胁模型与漏洞反馈方式
