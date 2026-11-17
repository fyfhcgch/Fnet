# 性能基准

本文件由 `scripts/bench.py` 生成，请勿手工编辑。每次发布前重新运行：

```bash
python3 scripts/bench.py --sizes 10,100,1000 --features default
```

## 运行环境

| 项目 | 值 |
| --- | --- |
| fnet | 2.19.0 |
| python | 3.14.10 |
| platform | Linux-7.3.4-zen2-2-zen-x86_64-with-glibc2.44 |
| cpu_count | 24 |
| tshark | TShark (Wireshark) 4.7.4. |
| generated | 2026-11-17 11:34:46 |

## 方法

- 抓包由脚本用标准库直接写出 pcap（1200 字节 UDP 包，含 DNS、明文与二进制载荷），不依赖 scapy。
- 每个功能在独立子进程中运行，只提交该功能，`tshark_cache=0`，因此耗时包含 tshark 解析成本。
- 峰值 RSS 取 `resource.getrusage(RUSAGE_SELF).ru_maxrss`；`RUSAGE_CHILDREN` 单独列出，表示 tshark 等外部工具的最大 RSS。
- 计时包含任务创建、报告与结构化结果落盘，单位为秒。同一台机器上重复运行会有 ±10% 波动。

## 结果

### 10.0 MB（实际 10,485,841 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 1.85 s | 254.9 MB | 161.4 MB | 210 |
| `checkBox_30` | done | 524 ms | 150.3 MB | 155.7 MB | 0 |
| **合计** | | **2.38 s** | | | |

### 100.0 MB（实际 104,858,628 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 4.13 s | 150.5 MB | 152.0 MB | 0 |
| `checkBox_30` | done | 1.51 s | 150.1 MB | 309.9 MB | 0 |
| **合计** | | **5.64 s** | | | |

### 1000.0 MB（实际 1,048,576,532 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 36.96 s | 150.4 MB | 152.1 MB | 0 |
| `checkBox_30` | done | 8.52 s | 149.8 MB | 1082.5 MB | 0 |
| **合计** | | **45.47 s** | | | |

## 加速层基准（scripts/bench_accel.py）

> 本节由 `scripts/bench_accel.py` 生成，请勿手工编辑数字；重新运行：
> `python3 scripts/bench_accel.py`。

### 背景

`fnet/utils/accel.py` 提供可选加速层，探测顺序为 **cuda（cupy → numba.cuda）
→ cpu-jit（numba njit）→ 纯 Python 快速路径**，任何一步失败（缺库、无 GPU、
驱动异常）都静默回退，分析功能永不因缺依赖不可用；`pyproject.toml` 的
`accel` extras 仅承载 `numba` / `cupy-cuda12x`，运行时必需依赖保持为空。
加速实现与纯 Python 基线**逐字节一致**，由 `tests/test_accel.py` 断言
（GPU 用例无 GPU 时 skip）。接入的两个热点：

a) **`printable_ratio`**——关键字/flag 扫描（`text_scan.keyword_scan` /
   `flag_deep`）对每个解码视图的逐字节可打印统计，
   `fnet/utils/pcap.py:printable_ratio` 委托到 accel；
b) **AES-GCM GHASH**——QUIC Initial 无 keylog 解密
   （`fnet/utils/quicinit.py` 调用侧注入）的 GF(2^128) 乘法链；
   `fnet/utils/crypto.py` 只读不改。

### 实测环境

| 项目 | 值 |
| --- | --- |
| fnet | 2.19.0 |
| python | 3.14.10 |
| platform | Linux-7.3.4-zen2-2-zen-x86_64-with-glibc2.44 |
| cpu_count | 24 |
| 后端 | cuda（cupy，NVIDIA GeForce RTX 5060 Laptop GPU，驱动 CUDA 13.5） |
| extras | numba 0.68.1（cp314 wheel）、cupy-cuda12x 14.2.0 |

### 热点 a）：printable_ratio（关键字扫描编码变换，16 MiB，64 KiB 分块）

| 实现 | 耗时 | 吞吐 | 相对基线 |
| --- | ---: | ---: | ---: |
| 现状基线（纯 Python sum 循环） | 532 ms | 30.1 MiB/s | - |
| accel CPU（translate 快速路径，无需 extras） | 22 ms | 731.7 MiB/s | 24.32x |
| accel CPU-JIT（numba njit） | 6 ms | 2,888.7 MiB/s | 96.03x |
| accel CUDA（cupy 并行归约） | 25 ms | 644.4 MiB/s | 21.42x |

结论：装上 `accel` extras 后，该热点在 cpu-jit 后端约 **96 倍**；即使完全不
装第三方库，stdlib 的 translate 快速路径也有约 **24 倍**。GPU 路径受 PCIe
传输与逐块 kernel 启动开销影响，64 KiB 分块下略慢于 njit。

### 热点 b）：AES-GCM 解密 / GHASH（1024 KiB 密文）

| 实现 | 耗时 | 吞吐 | 相对基线 |
| --- | ---: | ---: | ---: |
| 现状基线（crypto.aes_gcm_decrypt 完整解密） | 3,518 ms | 0.3 MiB/s | - |
| ├ 仅 GHASH（现状逐位乘法） | 832 ms | 1.2 MiB/s | 4.23x |
| ├ 仅 GHASH（CPU 表驱动） | 78 ms | 12.8 MiB/s | 45.18x |
| ├ 仅 GHASH（CPU-JIT njit） | 27 ms | 37.4 MiB/s | 131.59x |
| ├ 仅 GHASH（CUDA 并行） | 112 ms | 9.0 MiB/s | 31.50x |
| accel 完整解密（自动后端） | 2,797 ms | 0.4 MiB/s | 1.26x |

结论：

- GHASH 乘法链本身加速 **45 倍**（CPU 表驱动，零依赖）/ **131 倍**
  （numba njit）；完整解密只提升 **~1.25 倍**，因为 AES-CTR keystream
  （纯 Python AES 块加密）占完整解密耗时约 3/4 且保持现状——GPU 化 AES
  本体是后续扩展点。
- QUIC Initial 包载荷通常仅 ~1.2 KiB，低于 JIT/CUDA 门槛
  （`_JIT_GCM_MIN_BYTES=4096`、`_CUDA_GCM_MIN_BYTES=65536`），实际走 CPU
  表驱动路径，单包解密仍比现状快约 45 倍（GHASH 部分）。
- **GPU GHASH 的已知瓶颈**：当前单 kernel 内 H^1..H^n 幂预计算由 0 号线程
  串行完成（约 128 次域乘法/块），4 MiB 起吞吐稳定在 ~8.8 MiB/s，低于
  njit 的 ~37 MiB/s。改用并行前缀（H^(2^k) 重复平方 + 按位组合）后 GPU
  才有望超越 CPU；在此之前 cuda 后端对大包 GCM 属于“比基线快但不如
  cpu-jit”的中间档。实测方法：`python3 scripts/bench_accel.py --gcm-kb 4096`。

### GPU 分支的验证方式与限制

- **逐字节一致性**：`tests/test_accel.py::CudaBackendTest` 在有 GPU 的机器
  上真实运行 cupy 与 numba.cuda 两条 GHASH 路径及 cupy 的
  printable_ratio，断言与 `crypto._ghash` / 纯 Python 基线逐位一致；
  无 GPU 时该类自动 skip，CPU 回退路径必须全绿。
- **静默回退**：`DetectTest` / `PrintableRatioTest` /
  `GcmConsistencyTest` 用 mock 注入“库缺失 / GPU 抛异常”场景，断言
  `detect()` 不抛异常、结果回退到现状实现且原因写入 `detail`。
- **手动复验（换卡/换驱动时）**：
  1. `python3 -m unittest tests.test_accel -v` — `CudaBackendTest` 应执行
     而非 skip 且全绿；
  2. `python3 scripts/bench_accel.py` — 输出的 CUDA 行应标注吞吐且
     `仅 GHASH（CUDA 并行）` 与基线结果经脚本内断言一致；
  3. `FNET_HOME=/tmp/fnet-accel python3 -m fnet -C tests/data/quic.pcap
     --features webshell.decrypt,checkBox_10` — 加速开启与
     `--features` 前后对比 `findings.json` 无差异。
- **限制**：GPU 分支覆盖 cupy（CUDA 12/13 wheel）与 numba.cuda；未在
  非 x86_64、多 GPU、受限容器（如无 `/dev/nvidia*`）环境验证——这些场景
  走探测失败→静默回退路径。

