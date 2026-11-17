"""可选加速层：CUDA（cupy / numba.cuda）与 Numba CPU JIT，不可用时静默回退。

设计红线（对应 docs/PERFORMANCE.md 的加速章节）：

* **运行时零第三方依赖不变**：accel 只有在 ``pyproject.toml`` 的 ``accel``
  extras 装了 cupy / numba 时才启用；探测不到时 ``backend()`` 返回
  ``"cpu"``，所有加速入口自动走纯 Python 快速路径，分析功能永不因缺依赖
  不可用。
* **绝不抛异常中断分析**：探测、GPU 调用、JIT 编译的任何错误都被捕获并
  记录原因（``detect().detail``），然后回退到纯 Python 实现。
* **逐字节一致**：每个加速实现与现状纯 Python 实现（``fnet.utils.crypto``、
  ``fnet.utils.pcap.printable_ratio``）的输出逐字节/逐位一致，由
  ``tests/test_accel.py`` 断言。

探测顺序（``detect``，按收益排序）：

1. cupy（CUDA）        → ``backend() == "cuda"``，provider ``cupy``；
2. numba.cuda（CUDA）  → ``backend() == "cuda"``，provider ``numba.cuda``；
3. numba CPU njit      → ``backend() == "cpu-jit"``（无 GPU 也能装、能跑）；
4. 纯 Python 快速路径  → ``backend() == "cpu"``。

已接入的热点（收益排序，仅做前两个，其余留扩展点）：

a) **关键字扫描的编码变换内层热点** ``printable_ratio``：关键字/flag 扫描
   （``fnet.features.text_scan`` / ``flag_deep``）对每个解码视图都要逐字节
   统计可打印占比，原实现是一条 Python 级 ``sum()`` 循环。CPU 快速路径用
   ``bytes.translate`` + ``count``（纯标准库、C 速度）；cpu-jit 后端用
   numba njit 单遍计数；CUDA 路径用 cupy 并行归约。
   ``fnet.utils.pcap.printable_ratio`` 委托到这里。

b) **QUIC Initial 的 AES-GCM 解密**（``fnet.utils.quicinit`` 调用侧注入）：
   GHASH 是 128 步/块的 GF(2^128) 乘法链。CPU 表驱动路径把固定乘数 H 的
   乘法预计算成 16×256 字节表（每块 ~16 次查表异或）；cpu-jit 路径用
   numba njit 编译整条 GHASH 链；CUDA 路径把 GHASH 展开成
   ``X_i · H^(n-i)`` 的并行形式逐块求积后 XOR 归约。
   ``fnet/utils/crypto.py`` 是并行会话的在制文件，本模块**只读取**其
   AES 块加密，不做任何修改；加速关闭/不可用时直接调用
   ``crypto.aes_gcm_decrypt``，行为与现状完全一致。

GPU 分支的正确性由“与 CPU 实现逐字节一致”的单元测试保证
（本机无 GPU 时 skip），手动验证步骤见 docs/PERFORMANCE.md。

扩展点（收益预计较低，暂未接入）：GCM 的 CTR keystream 并行化（需要在
GPU 上实现 AES 本体）、``codec.xor`` 逐字节变换、RC4 等。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from fnet.utils.crypto import aes_encrypt_block

__all__ = [
    "AccelStatus", "detect", "backend", "enabled", "set_enabled", "reset",
    "printable_ratio", "aes_gcm_decrypt",
]

# ---------------------------------------------------------------------------
# 探测状态
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AccelStatus:
    """一次加速栈探测的结果；``backend`` 为 ``"cuda"``/``"cpu-jit"``/``"cpu"``。"""

    backend: str
    provider: str          # "cupy" / "numba.cuda" / "numba" / ""
    device: str            # GPU 名称或 CPU 描述
    detail: str            # 探测过程说明，含不可用原因

    @property
    def accelerated(self) -> bool:
        return self.backend != "cpu"


_lock = threading.Lock()
_status: AccelStatus | None = None
_enabled = True


def detect(*, refresh: bool = False) -> AccelStatus:
    """探测加速栈（进程内缓存）。任何失败都归入“不可用”，绝不抛异常。"""
    global _status
    if _status is not None and not refresh:
        return _status
    with _lock:
        if _status is not None and not refresh:
            return _status
        try:
            _status = _probe()
        except Exception as exc:                     # noqa: BLE001 — 探测永不中断
            _status = AccelStatus("cpu", "", "纯 Python",
                                  f"探测过程异常：{type(exc).__name__}: {exc}")
        return _status


def backend() -> str:
    """当前生效的后端：``"cuda"`` / ``"cpu-jit"`` / ``"cpu"``。"""
    if not _enabled:
        return "cpu"
    return detect().backend


def enabled() -> bool:
    """加速总开关是否打开（``set_enabled(False)`` 后所有入口走现状实现）。"""
    return _enabled


def set_enabled(value: bool) -> None:
    """打开/关闭加速（测试与故障排查用；关闭后行为与未引入本模块一致）。"""
    global _enabled
    _enabled = bool(value)


def reset() -> None:
    """清空探测缓存并恢复开关（测试辅助）。"""
    global _status
    with _lock:
        _status = None
    set_enabled(True)


def _probe() -> AccelStatus:
    """按收益顺序逐个尝试 cupy → numba.cuda → numba njit → 纯 Python。"""
    notes: list[str] = []

    # 1) cupy（CUDA）
    try:
        import cupy
    except Exception as exc:                         # noqa: BLE001
        notes.append(f"cupy 不可用：{type(exc).__name__}: {exc}")
    else:
        try:
            if cupy.cuda.runtime.getDeviceCount() < 1:
                notes.append("cupy 已安装但没有可见的 GPU 设备")
            else:
                props = cupy.cuda.runtime.getDeviceProperties(0)
                name = props.get("name") if isinstance(props, dict) else None
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                return AccelStatus("cuda", "cupy", str(name or "CUDA GPU"),
                                   "; ".join(notes) or "cupy 探测成功")
        except Exception as exc:                     # noqa: BLE001 — 驱动/显存错误
            notes.append(f"cupy GPU 初始化失败：{type(exc).__name__}: {exc}")

    # 2) numba.cuda（CUDA）
    try:
        from numba import cuda
    except Exception as exc:                         # noqa: BLE001
        notes.append(f"numba.cuda 不可用：{type(exc).__name__}: {exc}")
    else:
        try:
            if not cuda.is_available():
                notes.append("numba.cuda 报告无可用 GPU")
            else:
                name = cuda.get_current_device().name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", "replace")
                return AccelStatus("cuda", "numba.cuda", str(name or "CUDA GPU"),
                                   "; ".join(notes) or "numba.cuda 探测成功")
        except Exception as exc:                     # noqa: BLE001
            notes.append(f"numba.cuda GPU 初始化失败：{type(exc).__name__}: {exc}")

    # 3) numba CPU njit（无需 GPU）
    try:
        import numba
    except Exception as exc:                         # noqa: BLE001
        notes.append(f"numba 不可用：{type(exc).__name__}: {exc}")
    else:
        return AccelStatus("cpu-jit", "numba",
                           f"CPU JIT (numba {numba.__version__})",
                           "; ".join(notes) or "numba njit 探测成功")

    # 4) 纯 Python 快速路径
    return AccelStatus("cpu", "", "纯 Python",
                       "; ".join(notes) or "未检测到加速栈")


# ---------------------------------------------------------------------------
# 热点 a)：关键字扫描的 printable_ratio（fnet.utils.pcap 委托到这里）
# ---------------------------------------------------------------------------
#: CUDA 路径的最小数据量（字节）：小数据跨主机传输得不偿失。
_CUDA_MIN_BYTES = 64 * 1024

#: numba njit 路径的最小数据量（字节）：JIT 首次编译约 1s，小块不值。
_JIT_MIN_BYTES = 4096

#: 与 fnet.utils.pcap.printable_ratio 完全同义的现状基线（纯 Python 循环）。
_PRINTABLE_TABLE = bytes(
    1 if (32 <= value < 127 or value in (9, 10, 13)) else 0
    for value in range(256))


def printable_ratio(data: bytes) -> float:
    """可打印字节占比（关键字/flag 扫描的内层热点，后端自动分派）。

    与 ``fnet.utils.pcap.printable_ratio`` 逐位一致（含空输入返回 0.0）；
    加速路径任何异常都静默回退到纯 Python 基线。实测（见
    docs/PERFORMANCE.md）：numba njit 单遍计数 > translate > 纯 Python
    循环，故 cpu-jit 后端在数据量足够时走 njit 路径。
    """
    data = bytes(data or b"")
    if not data:
        return 0.0
    if not _enabled:
        return _printable_ratio_baseline(data)
    status = detect()
    if status.backend == "cuda" and len(data) >= _CUDA_MIN_BYTES:
        try:
            return _printable_ratio_cuda(data)
        except Exception:                            # noqa: BLE001 — 静默回退
            pass
    if status.backend == "cpu-jit" and len(data) >= _JIT_MIN_BYTES:
        try:
            return _printable_ratio_jit(data)
        except Exception:                            # noqa: BLE001 — 静默回退
            pass
    return _printable_ratio_fast(data)


def _printable_ratio_baseline(data: bytes) -> float:
    """现状实现（逐字节 ``sum`` 循环），作为基准与最终回退。"""
    if not data:
        return 0.0
    good = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return good / len(data)


def _printable_ratio_fast(data: bytes) -> float:
    """CPU 快速路径：``bytes.translate`` + ``count``（纯标准库、C 速度）。"""
    return data.translate(_PRINTABLE_TABLE).count(1) / len(data)


def _printable_ratio_jit(data: bytes) -> float:
    """numba njit 路径（仅跑分对比用；对该热点收益通常不如 translate）。"""
    import numpy as np

    return _jit_count_printable()(np.frombuffer(data, dtype=np.uint8)) / len(data)


def _printable_ratio_cuda(data: bytes) -> float:
    """CUDA 路径：并行掩码归约。按探测到的 provider 选择 cupy / numba.cuda。"""
    if detect().provider == "numba.cuda":
        return _printable_ratio_cuda_numba(data)
    return _printable_ratio_cuda_cupy(data)


def _printable_ratio_cuda_cupy(data: bytes) -> float:
    """CUDA 路径（cupy）：GPU 掩码归约。结果与纯 Python 基线逐位一致。"""
    import cupy
    import numpy as np

    arr = cupy.asarray(np.frombuffer(data, dtype=np.uint8))
    mask = ((arr >= 32) & (arr < 127)) | (arr == 9) | (arr == 10) | (arr == 13)
    return int(mask.sum()) / len(data)


def _printable_ratio_cuda_numba(data: bytes) -> float:
    """CUDA 路径（numba.cuda）：网格归约到原子计数器。"""
    import numpy as np
    from numba import cuda

    arr = np.frombuffer(data, dtype=np.uint8)
    d_arr = cuda.to_device(arr)
    out = cuda.to_device(np.zeros(1, dtype=np.int64))
    threads = 256
    blocks = (len(data) + threads - 1) // threads
    _numba_count_printable()[blocks, threads](d_arr, out)
    return int(out.copy_to_host()[0]) / len(data)


# ---------------------------------------------------------------------------
# 热点 b)：AES-GCM 解密（quicinit 调用侧注入；crypto.py 只读不改）
# ---------------------------------------------------------------------------
_GCM_R = 0xE1000000000000000000000000000000
_GCM_MASK = (1 << 128) - 1
#: GF(2^128) 里 x 的逆元（x^-1 = x^127 + x^6 + x + 1），用于“乘法表”方向的
#: 模约简：``crypto`` 的整型约定是 MSB ↔ x^0，字节内各位的指数随字节值
#: 位序递减，查表分解需要 ×x^-1 方向的移位（见 _shl8_reduce/_table_mul）。
_GCM_R_INV = 0xC2000000000000000000000000000001

#: CUDA 路径对 GHASH 输入量的门槛；numba JIT 首次编译 ~1s，门槛更低。
_CUDA_GCM_MIN_BYTES = 64 * 1024
_JIT_GCM_MIN_BYTES = 4096

#: 每个固定乘数 H 的 16×256 GF(2^128) 乘法表缓存（CPU 表驱动路径）。
_ghash_tables: dict[int, tuple] = {}
_GHASH_TABLE_CAP = 64


def _gf128_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法（与 ``fnet.utils.crypto._gf128_mul`` 同语义的本地副本）。"""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_R
        else:
            v >>= 1
    return z


def _shl8_reduce(x: int) -> int:
    """GF(2^128) 元素乘 x^-8 并做模约简，用于建表。

    ``crypto`` 的整型约定 MSB ↔ x^0 下，×x 是整型右移（LSB 溢出异或 R），
    而按字节查表分解需要 ×x^-1（整型左移，MSB 溢出异或 x^-1 常数）——
    见 _GCM_R_INV 的说明与 tests/test_accel.py 的一致性断言。
    """
    for _ in range(8):
        bit = (x >> 127) & 1
        x = ((x << 1) & _GCM_MASK) ^ (_GCM_R_INV if bit else 0)
    return x


def _tables_for_h(h: int) -> tuple:
    """构建/取回固定乘数 ``h`` 的字节乘法表：``tables[t][v] = v·x^(-8t)·h``。"""
    tables = _ghash_tables.get(h)
    if tables is None:
        current = tuple(_gf128_mul(v, h) for v in range(256))
        built = [current]
        for _ in range(15):
            current = tuple(_shl8_reduce(v) for v in current)
            built.append(current)
        tables = tuple(built)
        if len(_ghash_tables) >= _GHASH_TABLE_CAP:
            _ghash_tables.clear()
        _ghash_tables[h] = tables
    return tables


def _table_mul(x: int, tables: tuple) -> int:
    """查表乘法：从最低字节开始 16 次查表异或。

    整型第 t 字节（LSB 起）的位 j 对应系数 x^(127-8t-j)，即
    ``byte_t · x^(-8t)``，故按 LSB→MSB 依次取表（tables[t] 已含
    ×x^(-8t) 因子，见 _shl8_reduce）。
    """
    z = 0
    for table in tables:
        z ^= table[x & 0xFF]
        x >>= 8
    return z


def _ghash_table(h: int, aad: bytes, ciphertext: bytes) -> int:
    """表驱动 GHASH：与 ``crypto._ghash`` 输出一致（含长度块），乘法换查表。"""
    tables = _tables_for_h(h)
    y = 0
    for data in (aad, ciphertext):
        for i in range(0, len(data), 16):
            y ^= int.from_bytes(data[i:i + 16].ljust(16, b"\x00"), "big")
            y = _table_mul(y, tables)
    length = (len(aad) * 8) << 64 | (len(ciphertext) * 8)
    return _table_mul(y ^ length, tables)


def _ctr32(counter: bytes) -> bytes:
    """GCM 计数器 +1（低 32 位回绕），与 ``crypto._ctr32`` 一致。"""
    prefix, last = counter[:12], int.from_bytes(counter[12:], "big")
    return prefix + ((last + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def aes_gcm_decrypt(data: bytes, key: bytes, iv: bytes,
                    aad: bytes = b"", tag_len: int = 16,
                    check_tag: bool = True) -> tuple[bytes, bool]:
    """AES-GCM 解密（``data = ciphertext || tag``），后端自动分派。

    返回 ``(明文, tag_valid)``，与 ``fnet.utils.crypto.aes_gcm_decrypt`` 的
    输出逐字节一致；加速关闭/不可用或加速路径抛出任何异常时直接调用后者，
    行为与现状完全一致。
    """
    if not _enabled:
        return _py_gcm_decrypt(data, key, iv, aad, tag_len)
    status = detect()
    ghash = None
    if status.backend == "cuda":
        ghash_input = len(aad) + max(len(data) - tag_len, 0)
        if ghash_input >= _CUDA_GCM_MIN_BYTES:
            ghash = _ghash_cuda
    elif status.backend == "cpu-jit":
        ghash_input = len(aad) + max(len(data) - tag_len, 0)
        if ghash_input >= _JIT_GCM_MIN_BYTES:
            ghash = _ghash_jit
    try:
        if ghash is not None:
            return _gcm_decrypt_generic(data, key, iv, aad, tag_len, ghash)
        return _gcm_decrypt_generic(data, key, iv, aad, tag_len, _ghash_table)
    except Exception:                                # noqa: BLE001 — 静默回退
        return _py_gcm_decrypt(data, key, iv, aad, tag_len)


def _py_gcm_decrypt(data: bytes, key: bytes, iv: bytes,
                    aad: bytes = b"", tag_len: int = 16) -> tuple[bytes, bool]:
    """现状实现（``fnet.utils.crypto.aes_gcm_decrypt`` 的只读直调）。"""
    from fnet.utils.crypto import aes_gcm_decrypt as impl
    return impl(data, key, iv, aad, tag_len)


def _gcm_decrypt_generic(data: bytes, key: bytes, iv: bytes, aad: bytes,
                         tag_len: int, ghash) -> tuple[bytes, bool]:
    """GCM 解密通用骨架：与 ``crypto.aes_gcm_decrypt`` 同构，GHASH 可插拔。

    keystream（AES-CTR）仍走 ``crypto.aes_encrypt_block``——GPU 化 AES 本体
    属于后续扩展点，这里保证与现状逐字节一致优先。
    """
    if len(data) < tag_len:
        return b"", False
    ciphertext, tag = data[:-tag_len], data[-tag_len:]
    h = int.from_bytes(aes_encrypt_block(b"\x00" * 16, key), "big")
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        j0 = ghash(h, b"", iv).to_bytes(16, "big")
    counter = j0
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        counter = _ctr32(counter)
        stream = aes_encrypt_block(counter, key)
        out += bytes(a ^ b for a, b in zip(ciphertext[i:i + 16], stream))
    expected = (int.from_bytes(aes_encrypt_block(j0, key), "big")
                ^ ghash(h, aad, ciphertext)).to_bytes(16, "big")[:tag_len]
    return bytes(out), (expected == tag)


# ---------------------------------------------------------------------------
# numba CPU JIT 路径（backend == "cpu-jit"）
# ---------------------------------------------------------------------------
_jit_cache: dict[str, object] = {}


def _jit_funcs() -> tuple:
    """惰性编译 numba njit 内核（首次调用 ~1s；失败由调用方捕获回退）。

    njit 函数体里引用的 ``np`` 是闭包自由变量，numba 会把它冻结为编译期
    常量；uint64 常量必须显式 ``np.uint64``，否则 numba 会把无符号运算
    提升为浮点导致结果错误。
    """
    funcs = _jit_cache.get("funcs")
    if funcs is not None:
        return funcs
    import numpy as np
    from numba import njit

    @njit
    def _count_printable(arr):                       # pragma: no cover — JIT
        count = 0
        for i in range(arr.size):
            b = arr[i]
            if 32 <= b < 127 or b == 9 or b == 10 or b == 13:
                count += 1
        return count

    @njit
    def _gmul_jit(x_hi, x_lo, h_hi, h_lo):           # pragma: no cover — JIT
        """GF(2^128) 乘法：128 位大端整数按 (hi, lo) 两个 uint64 表示。"""
        one = np.uint64(1)
        r_hi = np.uint64(0xE100000000000000)
        z_hi = np.uint64(0)
        z_lo = np.uint64(0)
        v_hi = np.uint64(h_hi)
        v_lo = np.uint64(h_lo)
        for i in range(127, -1, -1):
            if i >= 64:
                if ((x_hi >> np.uint64(i - 64)) & one) != 0:
                    z_hi = z_hi ^ v_hi
                    z_lo = z_lo ^ v_lo
            elif ((x_lo >> np.uint64(i)) & one) != 0:
                z_hi = z_hi ^ v_hi
                z_lo = z_lo ^ v_lo
            carry = (v_lo & one) != 0
            n_lo = (v_lo >> one) | (v_hi << np.uint64(63))
            n_hi = v_hi >> one
            if carry:
                n_hi = n_hi ^ r_hi
            v_hi = n_hi
            v_lo = n_lo
        return z_hi, z_lo

    @njit
    def _ghash_chain_jit(blocks, h_hi, h_lo):        # pragma: no cover — JIT
        """GHASH 串行链：blocks 为 (hi, lo) 交错的原生 uint64 数组。"""
        y_hi = np.uint64(0)
        y_lo = np.uint64(0)
        for j in range(blocks.shape[0] // 2):
            y_hi = y_hi ^ blocks[2 * j]
            y_lo = y_lo ^ blocks[2 * j + 1]
            y_hi, y_lo = _gmul_jit(y_hi, y_lo, h_hi, h_lo)
        return y_hi, y_lo

    funcs = (_count_printable, _ghash_chain_jit)
    _jit_cache["funcs"] = funcs
    return funcs


def _jit_count_printable():
    return _jit_funcs()[0]


# ---------------------------------------------------------------------------
# numba.cuda kernel（provider == "numba.cuda" 时的 CUDA 路径）
# ---------------------------------------------------------------------------
_numba_cuda_cache: dict[str, object] = {}


def _numba_count_printable():
    """惰性编译可打印字节计数的 numba.cuda kernel（原子加归约）。"""
    kernel = _numba_cuda_cache.get("count")
    if kernel is not None:
        return kernel
    from numba import cuda

    @cuda.jit
    def _count(arr, out):                            # pragma: no cover — GPU
        i = cuda.grid(1)
        if i < arr.size:
            b = arr[i]
            if 32 <= b < 127 or b == 9 or b == 10 or b == 13:
                cuda.atomic.add(out, 0, 1)

    _numba_cuda_cache["count"] = _count
    return _count


def _numba_ghash_kernel():
    """惰性编译 numba.cuda 并行 GHASH kernel（与 cupy 版同一算法）。"""
    kernel = _numba_cuda_cache.get("ghash")
    if kernel is not None:
        return kernel
    import numpy as np
    from numba import cuda

    @cuda.jit(device=True)
    def _gf128_mul_dev(x_hi, x_lo, h_hi, h_lo):      # pragma: no cover — GPU
        """GF(2^128) 乘法：(hi, lo) 两个 uint64 表示的 128 位大端整数。"""
        one = np.uint64(1)
        r_hi = np.uint64(0xE100000000000000)
        z_hi = np.uint64(0)
        z_lo = np.uint64(0)
        v_hi = np.uint64(h_hi)
        v_lo = np.uint64(h_lo)
        for i in range(127, -1, -1):
            if i >= 64:
                if ((x_hi >> np.uint64(i - 64)) & one) != 0:
                    z_hi = z_hi ^ v_hi
                    z_lo = z_lo ^ v_lo
            elif ((x_lo >> np.uint64(i)) & one) != 0:
                z_hi = z_hi ^ v_hi
                z_lo = z_lo ^ v_lo
            carry = (v_lo & one) != 0
            n_lo = (v_lo >> one) | (v_hi << np.uint64(63))
            n_hi = v_hi >> one
            if carry:
                n_hi = n_hi ^ r_hi
            v_hi = n_hi
            v_lo = n_lo
        return z_hi, z_lo

    @cuda.jit
    def _ghash(blocks, n, h_hi, h_lo, powers, products):  # pragma: no cover
        # 0 号线程串行预计算 H^1..H^n（可再用并行前缀优化）。
        tx = cuda.threadIdx.x
        if tx == 0:
            p_hi = np.uint64(h_hi)
            p_lo = np.uint64(h_lo)
            for k in range(n):
                powers[2 * k] = p_hi
                powers[2 * k + 1] = p_lo
                p_hi, p_lo = _gf128_mul_dev(p_hi, p_lo, h_hi, h_lo)
        cuda.syncthreads()
        # 第 j 块贡献 X_j · H^(n-j)，幂索引 e-1 = n-j-1。
        for j in range(tx, n, cuda.blockDim.x):
            e = n - j
            z_hi, z_lo = _gf128_mul_dev(
                blocks[2 * j], blocks[2 * j + 1],
                powers[2 * (e - 1)], powers[2 * (e - 1) + 1])
            products[2 * j] = z_hi
            products[2 * j + 1] = z_lo

    _numba_cuda_cache["ghash"] = _ghash
    return _ghash


def _blocks_u64(data: bytes):
    """把字节串补齐到 16 的倍数并切成 (hi, lo) 交错的原生 uint64 数组。"""
    import numpy as np

    data = bytes(data)
    pad = -len(data) % 16
    if pad:
        data += b"\x00" * pad
    # ">u8" 按大端解释每 8 字节，astype 转为原生序（数值不变）
    return np.ascontiguousarray(np.frombuffer(data, dtype=">u8").astype(np.uint64))


def _ghash_jit(h: int, aad: bytes, ciphertext: bytes) -> int:
    """numba njit GHASH：把 Python 级串行乘法链编译成机器码。

    与 ``crypto._ghash`` 一致：aad 块在前、密文块在后，最后追加 16 字节
    长度块 ``len(aad)*8 << 64 | len(ct)*8``。
    """
    import numpy as np

    combined = _ghash_input_padded(aad, ciphertext)
    length = ((len(aad) * 8) << 64 | (len(ciphertext) * 8)).to_bytes(16, "big")
    blocks = _blocks_u64(combined + length)
    _chain = _jit_funcs()[1]
    y_hi, y_lo = _chain(blocks, np.uint64(h >> 64),
                        np.uint64(h & 0xFFFFFFFFFFFFFFFF))
    return (int(y_hi) << 64) | int(y_lo)


# ---------------------------------------------------------------------------
# CUDA 路径（backend == "cuda"）：GHASH 并行化
# ---------------------------------------------------------------------------
_CUDA_THREADS = 256
_ghash_cuda_kernel_cache: dict[str, object] = {}


def _ghash_cuda(h: int, aad: bytes, ciphertext: bytes) -> int:
    """CUDA 并行 GHASH：``GHASH = ⊕_i X_i · H^(n-i)``（逐块独立求积 + XOR 归约）。

    单 kernel：0 号线程把 H^1..H^n 串行预计算进全局内存（GF(2^128) 移位-
    约简乘法），``__syncthreads`` 后所有线程并行计算各块的乘积，最后 XOR
    归约。keystream（AES-CTR）仍在 CPU 侧（见 ``_gcm_decrypt_generic``），
    GPU 化 AES 本体是后续扩展点。按 provider 选择 cupy / numba.cuda。
    """
    if detect().provider == "numba.cuda":
        return _ghash_cuda_numba(h, aad, ciphertext)
    return _ghash_cuda_cupy(h, aad, ciphertext)


def _ghash_cuda_cupy(h: int, aad: bytes, ciphertext: bytes) -> int:
    """CUDA 并行 GHASH（cupy RawKernel 实现，C 源码见 ``_cuda_ghash_kernel``）。"""
    import cupy
    import numpy as np

    combined = _ghash_input_padded(aad, ciphertext)
    length = ((len(aad) * 8) << 64 | (len(ciphertext) * 8)).to_bytes(16, "big")
    combined += length
    n = len(combined) // 16
    kernel = _cuda_ghash_kernel()
    blocks = cupy.asarray(_blocks_u64(combined))
    powers = cupy.zeros(2 * n, dtype=cupy.uint64)
    products = cupy.zeros(2 * n, dtype=cupy.uint64)
    kernel((1,), (_CUDA_THREADS,),
           (blocks, np.uint64(n), np.uint64(h >> 64),
            np.uint64(h & 0xFFFFFFFFFFFFFFFF), powers, products))
    host = cupy.asnumpy(products).reshape(n, 2)
    reduced = np.bitwise_xor.reduce(host, axis=0)
    return (int(reduced[0]) << 64) | int(reduced[1])


def _ghash_cuda_numba(h: int, aad: bytes, ciphertext: bytes) -> int:
    """CUDA 并行 GHASH（numba.cuda 实现，与 cupy 版同一算法）。"""
    import numpy as np
    from numba import cuda

    combined = _ghash_input_padded(aad, ciphertext)
    length = ((len(aad) * 8) << 64 | (len(ciphertext) * 8)).to_bytes(16, "big")
    combined += length
    n = len(combined) // 16
    blocks = cuda.to_device(_blocks_u64(combined))
    powers = cuda.device_array(2 * n, dtype=np.uint64)
    products = cuda.device_array(2 * n, dtype=np.uint64)
    _numba_ghash_kernel()[1, _CUDA_THREADS](
        blocks, np.uint64(n), np.uint64(h >> 64),
        np.uint64(h & 0xFFFFFFFFFFFFFFFF), powers, products)
    host = products.copy_to_host().reshape(n, 2)
    reduced = np.bitwise_xor.reduce(host, axis=0)
    return (int(reduced[0]) << 64) | int(reduced[1])


def _ghash_input_padded(aad: bytes, ciphertext: bytes) -> bytes:
    """GHASH 输入拼接：aad 与 ciphertext 各自独立补齐到 16 字节倍数。

    注意必须分别补零（与 ``crypto._ghash`` 的 ``blocks()`` 一致）——先拼
    接再补零会移动块边界，导致与基线结果不一致。
    """
    return (bytes(aad) + b"\x00" * (-len(aad) % 16)
            + bytes(ciphertext) + b"\x00" * (-len(ciphertext) % 16))


def _cuda_ghash_kernel():
    """惰性编译 GHASH 并行 kernel（RawKernel C 源码见下）。"""
    kernel = _ghash_cuda_kernel_cache.get("kernel")
    if kernel is not None:
        return kernel
    import cupy

    source = r"""
extern "C" __device__ void gf128_mul(unsigned long long* x_hi,
                                     unsigned long long* x_lo,
                                     unsigned long long h_hi,
                                     unsigned long long h_lo) {
    /* GF(2^128) 乘法：128 位大端整数按 (hi, lo) 表示，移位-约简算法，
       与 fnet.utils.crypto._gf128_mul 语义一致（GCM 的 R = 0xE1<<120）。 */
    unsigned long long z_hi = 0ULL, z_lo = 0ULL;
    unsigned long long v_hi = h_hi, v_lo = h_lo;
    for (int i = 127; i >= 0; --i) {
        unsigned long long bit = (i >= 64) ? ((x_hi[0] >> (i - 64)) & 1ULL)
                                           : ((x_lo[0] >> i) & 1ULL);
        if (bit) { z_hi ^= v_hi; z_lo ^= v_lo; }
        unsigned long long carry = v_lo & 1ULL;
        unsigned long long n_lo = (v_lo >> 1) | (v_hi << 63);
        unsigned long long n_hi = v_hi >> 1;
        if (carry) n_hi ^= 0xE100000000000000ULL;
        v_hi = n_hi;
        v_lo = n_lo;
    }
    x_hi[0] = z_hi;
    x_lo[0] = z_lo;
}

extern "C" __global__ void ghash_parallel(const unsigned long long* blocks,
                                          unsigned long long n,
                                          unsigned long long h_hi,
                                          unsigned long long h_lo,
                                          unsigned long long* powers,
                                          unsigned long long* products) {
    /* 0 号线程串行预计算 H^1..H^n；n 很大时这一步是瓶颈（单线程 ~10 万次
       乘法/MB），可通过并行前缀（重复平方 + 按位组合）进一步优化。 */
    if (threadIdx.x == 0) {
        unsigned long long p_hi = h_hi, p_lo = h_lo;   /* H^1 */
        for (unsigned long long k = 0; k < n; ++k) {
            powers[2 * k] = p_hi;
            powers[2 * k + 1] = p_lo;
            gf128_mul(&p_hi, &p_lo, h_hi, h_lo);       /* p = p * H */
        }
    }
    __syncthreads();
    /* 乘积并行：第 j 块贡献 X_j · H^(n-j)，幂索引 e-1 = n-j-1。 */
    for (unsigned long long j = threadIdx.x; j < n; j += blockDim.x) {
        unsigned long long x_hi = blocks[2 * j];
        unsigned long long x_lo = blocks[2 * j + 1];
        unsigned long long e = n - j;
        unsigned long long v_hi = powers[2 * (e - 1)];
        unsigned long long v_lo = powers[2 * (e - 1) + 1];
        unsigned long long z_hi = 0ULL, z_lo = 0ULL;
        for (int i = 127; i >= 0; --i) {
            unsigned long long bit = (i >= 64) ? ((x_hi >> (i - 64)) & 1ULL)
                                               : ((x_lo >> i) & 1ULL);
            if (bit) { z_hi ^= v_hi; z_lo ^= v_lo; }
            unsigned long long carry = v_lo & 1ULL;
            unsigned long long n_lo = (v_lo >> 1) | (v_hi << 63);
            unsigned long long n_hi = v_hi >> 1;
            if (carry) n_hi ^= 0xE100000000000000ULL;
            v_hi = n_hi;
            v_lo = n_lo;
        }
        products[2 * j] = z_hi;
        products[2 * j + 1] = z_lo;
    }
}
"""
    kernel = cupy.RawKernel(source, "ghash_parallel")
    _ghash_cuda_kernel_cache["kernel"] = kernel
    return kernel
