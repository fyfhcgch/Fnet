---
layout: page
title: 用户教程
permalink: /manual/
description: Fnet 用户教程：从安装、实战分析到 WebUI、功能与命令行。
---

Fnet 有两条使用路径：**WebUI** 适合交互式分析、看图表和整理报告，**命令行**适合
脚本化与批量处理。两者共用同一套功能与输出目录。

## 从哪里开始

| 你的情况 | 建议阅读 |
| --- | --- |
| 第一次使用 | [安装与启动]({{ '/manual/install/' | relative_url }}) → [实战教程]({{ '/manual/tutorial/' | relative_url }}) |
| 手上有一个 pcap，想直接跟着做 | [实战教程]({{ '/manual/tutorial/' | relative_url }}) |
| 想按题型查该勾哪些功能 | [功能清单]({{ '/manual/features/' | relative_url }}) |
| 想批量跑赛题或写脚本 | [命令行]({{ '/manual/cli/' | relative_url }}) |
| 跑不出结果、报错、解密失败 | [常见问题]({{ '/manual/faq/' | relative_url }}) |

## 教程目录

<ul class="manual-list">
  <li>
    <a href="{{ '/manual/install/' | relative_url }}">
      <strong>安装与启动</strong>
      <span>系统依赖、可选工具、配置目录、第一次分析</span>
    </a>
  </li>
  <li>
    <a href="{{ '/manual/tutorial/' | relative_url }}">
      <strong>实战教程</strong>
      <span>找 flag、Web 题、SQL 盲注、TLS 解密、凭据与批量复盘</span>
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
      <span>56 项功能按 14 个分类的作用、编号与依赖</span>
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

## 建议阅读顺序

第一次使用按 **安装与启动 → 实战教程 → WebUI 使用** 的顺序走一遍；功能清单和命令行
可以当作需要时再翻的参考。所有页面都只讲怎么用 Fnet 完成分析。
