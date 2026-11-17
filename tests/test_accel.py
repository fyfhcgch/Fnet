"""加速层单元测试：探测降级、后端一致性、静默回退、quicinit 注入一致性。

GPU 分支的验证方式：

* 本模块在有 CUDA GPU 的机器上真实运行 cupy / numba.cuda 两条 GPU 路径，
  并断言其结果与纯 Python 基线**逐字节/逐位一致**；
* 无 GPU 时（``accel.detect().backend != "cuda"``）GPU 用例自动 skip，
  CPU 回退路径必须全绿；
* GPU 存在但运行时不可用（被其他进程独占、驱动/显存/设备临时错误）属于
  环境问题：直接调用 CUDA kernel 的用例会 ``skipTest`` 而不是硬失败；
  一致性断言本身（逐字节/逐位相等）绝不放宽；
* 手动复验步骤（换卡/换驱动时）：见 docs/PERFORMANCE.md 加速章节。
"""
from __future__ import annotations

import random
import struct
import sys
import unittest
import warnings
from unittest import mock

from fnet.utils import accel
from fnet.utils import crypto
from fnet.utils import quicinit
from fnet.utils.pcap import printable_ratio as pcap_printable_ratio

# GPU 测试的单 block kernel 会触发 numba 的占用率告警，属预期行为。
try:
    from numba.core.errors import NumbaPerformanceWarning
    warnings.filterwarnings("ignore", category=NumbaPerformanceWarning)
except ImportError:
    pass

try:                                                  # 探测环境是否带 GPU
    _HAS_CUDA = accel.detect(refresh=True).backend == "cuda"
except Exception:                                     # pragma: no cover
    _HAS_CUDA = False

requires_cuda = unittest.skipUnless(_HAS_CUDA, "需要 CUDA GPU（无 GPU 环境自动 skip）")


#: CUDA 运行时错误里常见的字样（cupy / numba.cuda 抛出的多为 RuntimeError 子类）。
_CUDA_ERROR_HINTS = (
    "cuda", "gpu", "out of memory", "driver", "no device", "device-side",
)


def _is_cuda_env_error(exc: BaseException) -> bool:
    """探测异常是否来自 CUDA 运行环境（驱动/显存/设备），而非算法不一致。

    直接调用 GPU kernel 的用例不走 ``accel`` 的静默回退，GPU 被其他进程
    占用（``cudaErrorMemoryAllocation``/``CUDA driver version``等）时会抛
    环境性异常；这类情况应 skipTest。算法层面的 ``AssertionError``、
    ``ValueError`` 等一律返回 ``False``，照常失败。
    """
    for cls in type(exc).__mro__:
        module = getattr(cls, "__module__", "") or ""
        if module.startswith(("cupy", "numba.cuda")):
            return True
    if isinstance(exc, (AssertionError, ImportError)):
        return False
    if isinstance(exc, (RuntimeError, MemoryError, OSError)):
        text = str(exc).lower()
        return any(hint in text for hint in _CUDA_ERROR_HINTS)
    return False


def _rand(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(n))


# ---------------------------------------------------------------------------
# 探测与降级
# ---------------------------------------------------------------------------
class DetectTest(unittest.TestCase):
    """detect() 的探测顺序与降级路径。"""

    def tearDown(self) -> None:
        accel.reset()

    def test_missing_optional_libs_falls_back_silently(self):
        """cupy/numba 全部缺失（sys.modules 注入 None）→ 纯 Python，不抛异常。"""
        with mock.patch.dict(sys.modules, {"cupy": None, "numba": None}):
            status = accel.detect(refresh=True)
        self.assertEqual(status.backend, "cpu")
        self.assertFalse(status.accelerated)
        self.assertIn("cupy", status.detail)          # 不可用原因被记录
        self.assertEqual(accel.backend(), "cpu")

    def test_missing_cupy_only_numba_jit(self):
        """只缺 cupy 且 numba.cuda 也不可用时应降级到 numba njit（cpu-jit）。"""
        try:
            import numba                             # noqa: F401
        except ImportError:
            self.skipTest("本机未安装 numba")
        # cupy 缺失（sys.modules 注入 None）+ numba.cuda 属性置 None，
        # 使探测只能落到 CPU JIT 档。
        with mock.patch.dict(sys.modules, {"cupy": None}), \
             mock.patch.object(numba, "cuda", None):
            status = accel.detect(refresh=True)
        self.assertEqual(status.backend, "cpu-jit")
        self.assertIn("cupy", status.detail)

    def test_detect_never_raises_and_is_cached(self):
        """真实环境探测：返回合法状态且缓存生效。"""
        first = accel.detect(refresh=True)
        again = accel.detect()
        self.assertIs(first, again)
        self.assertIn(first.backend, ("cuda", "cpu-jit", "cpu"))
        self.assertIsInstance(first.detail, str)

    def test_detect_survives_broken_probe(self):
        """探测函数自身抛异常也被吞掉，绝不中断分析。"""
        with mock.patch.object(accel, "_probe", side_effect=OSError("探测炸了")):
            status = accel.detect(refresh=True)
        self.assertEqual(status.backend, "cpu")
        self.assertIn("探测", status.detail)


# ---------------------------------------------------------------------------
# 热点 a)：printable_ratio（关键字扫描编码变换路径）
# ---------------------------------------------------------------------------
class PrintableRatioTest(unittest.TestCase):
    """加速实现与纯 Python 基线逐位一致。"""

    def setUp(self) -> None:
        accel.reset()
        self.rng = random.Random(2026)

    def test_matches_pure_python(self):
        from fnet.utils.pcap import printable_ratio as _baseline
        sizes = (0, 1, 7, 64, 255, 4096, 70000)       # 70000 跨过 GPU 门槛
        for size in sizes:
            data = _rand(self.rng, size)
            self.assertEqual(accel.printable_ratio(data), _baseline(data),
                             f"size={size}")
        text = b"flag{accel_test}\t\n  plain text" * 33
        self.assertEqual(accel.printable_ratio(text), _baseline(text))
        self.assertEqual(accel.printable_ratio(b""), 0.0)

    def test_pcap_delegates_to_accel(self):
        """pcap.printable_ratio 委托 accel，两者始终相等。"""
        data = _rand(self.rng, 300)
        self.assertEqual(pcap_printable_ratio(data),
                         accel._printable_ratio_baseline(data))

    def test_disabled_matches_pure_python(self):
        """关闭加速后行为与现状纯 Python 实现完全一致。"""
        data = _rand(self.rng, 1000)
        accel.set_enabled(False)
        try:
            self.assertEqual(accel.printable_ratio(data),
                             accel._printable_ratio_baseline(data))
            self.assertEqual(accel.backend(), "cpu")
        finally:
            accel.set_enabled(True)

    def test_silent_fallback_on_gpu_error(self):
        """GPU 路径抛异常时静默回退，结果仍正确、不向调用方抛出。"""
        data = _rand(self.rng, accel._CUDA_MIN_BYTES + 16)
        expected = accel._printable_ratio_baseline(data)
        fake = accel.AccelStatus("cuda", "cupy", "模拟 GPU", "")
        with mock.patch.object(accel, "detect", return_value=fake), \
             mock.patch.object(accel, "_printable_ratio_cuda",
                               side_effect=RuntimeError("GPU 炸了")):
            self.assertEqual(accel.printable_ratio(data), expected)


# ---------------------------------------------------------------------------
# 热点 b)：AES-GCM（quicinit 解密路径）
# ---------------------------------------------------------------------------
class GcmConsistencyTest(unittest.TestCase):
    """加速 GCM 与 crypto.aes_gcm_decrypt 输出逐字节一致。"""

    def setUp(self) -> None:
        accel.reset()
        self.rng = random.Random(9001)

    def _cases(self):
        """覆盖空明文/非整块/跨 GPU 与 JIT 门槛/非 12 字节 IV 等边界。"""
        for ct_len, aad_len, iv_len in (
                (0, 0, 12), (5, 0, 12), (31, 20, 12), (13, 48, 12),
                (4096, 16, 12), (100000, 33, 16), (262145, 5, 12)):
            key = _rand(self.rng, 16)
            iv = _rand(self.rng, iv_len)
            aad = _rand(self.rng, aad_len)
            msg = _rand(self.rng, ct_len)
            enc = crypto.aes_gcm_encrypt(msg, key, iv, aad)
            yield key, iv, aad, enc

    def test_dispatch_matches_pure_python(self):
        """当前后端自动分派（表驱动/JIT/CUDA）与现状实现一致。"""
        for key, iv, aad, enc in self._cases():
            self.assertEqual(accel.aes_gcm_decrypt(enc, key, iv, aad),
                             crypto.aes_gcm_decrypt(enc, key, iv, aad),
                             f"ct={len(enc) - 16} aad={len(aad)}")

    def test_disabled_calls_pure_python_directly(self):
        """关闭加速 = 直接调用 crypto.aes_gcm_decrypt（现状完全一致）。"""
        for key, iv, aad, enc in self._cases():
            accel.set_enabled(False)
            try:
                self.assertEqual(accel.aes_gcm_decrypt(enc, key, iv, aad),
                                 crypto.aes_gcm_decrypt(enc, key, iv, aad))
            finally:
                accel.set_enabled(True)

    def test_table_ghash_matches_reference(self):
        """CPU 表驱动 GHASH 与 crypto._ghash 一致（含长度块）。"""
        for _ in range(30):
            h = int.from_bytes(_rand(self.rng, 16), "big")
            aad = _rand(self.rng, self.rng.randrange(0, 64))
            ct = _rand(self.rng, self.rng.randrange(0, 200))
            self.assertEqual(accel._ghash_table(h, aad, ct),
                             crypto._ghash(h, aad, ct))

    def test_table_mul_matches_reference(self):
        """查表乘法与逐位基线乘法一致（300 组随机值）。"""
        for _ in range(300):
            x = int.from_bytes(_rand(self.rng, 16), "big")
            h = int.from_bytes(_rand(self.rng, 16), "big")
            self.assertEqual(
                accel._table_mul(x, accel._tables_for_h(h)),
                accel._gf128_mul(x, h), hex(x))

    def test_silent_fallback_on_gpu_error(self):
        """GHASH 后端抛任何异常都静默回退到 crypto 纯 Python 实现。"""
        key = _rand(self.rng, 16)
        iv = _rand(self.rng, 12)
        aad = b"aad"
        msg = _rand(self.rng, 100000)                 # 跨过 CUDA 门槛
        enc = crypto.aes_gcm_encrypt(msg, key, iv, aad)
        expected = crypto.aes_gcm_decrypt(enc, key, iv, aad)
        with mock.patch.object(accel, "_ghash_cuda",
                               side_effect=RuntimeError("GPU 炸了")):
            self.assertEqual(accel.aes_gcm_decrypt(enc, key, iv, aad), expected)


class NumbaJitTest(unittest.TestCase):
    """numba njit GHASH 链（cpu-jit 后端）与基线一致。"""

    def setUp(self) -> None:
        try:
            import numba                             # noqa: F401
            import numpy                             # noqa: F401
        except ImportError:
            self.skipTest("本机未安装 numba/numpy")
        accel.reset()
        self.rng = random.Random(4242)

    def test_jit_ghash_matches_reference(self):
        for _ in range(10):
            h = int.from_bytes(_rand(self.rng, 16), "big")
            aad = _rand(self.rng, self.rng.randrange(0, 64))
            ct = _rand(self.rng, self.rng.randrange(0, 4096))
            self.assertEqual(accel._ghash_jit(h, aad, ct),
                             crypto._ghash(h, aad, ct))

    def test_jit_dispatch_matches_pure_python(self):
        """强制 cpu-jit 后端 + 大于 JIT 门槛的数据 → JIT 分派路径正确。"""
        fake = accel.AccelStatus("cpu-jit", "numba", "CPU JIT", "")
        key = _rand(self.rng, 16)
        iv = _rand(self.rng, 12)
        aad = _rand(self.rng, 20)
        msg = _rand(self.rng, accel._JIT_GCM_MIN_BYTES * 2)
        enc = crypto.aes_gcm_encrypt(msg, key, iv, aad)
        with mock.patch.object(accel, "detect", return_value=fake):
            self.assertEqual(accel.aes_gcm_decrypt(enc, key, iv, aad),
                             crypto.aes_gcm_decrypt(enc, key, iv, aad))


class CudaBackendTest(unittest.TestCase):
    """GPU 路径逐字节一致性（无 GPU 时自动 skip）。

    手动复验（换卡/换驱动时）：在目标机器上运行
    ``python3 -m unittest tests.test_accel -v``，本类用例应全部执行
    （仅 GPU 被占用/驱动异常这类环境错误会 skip），并通过即视为
    GPU 路径与纯 Python 基线一致。
    """

    def setUp(self) -> None:
        if not _HAS_CUDA:
            self.skipTest("需要 CUDA GPU")
        accel.reset()
        self.rng = random.Random(555)

    def _cuda_call(self, fn, *args):
        """直接执行 GPU kernel；环境性 CUDA 失败转成 skip，断言失败照常抛。"""
        try:
            return fn(*args)
        except (AssertionError, ImportError):
            raise
        except Exception as exc:
            if _is_cuda_env_error(exc):
                self.skipTest(f"CUDA 运行环境不可用（{type(exc).__name__}: {exc}）")
            raise

    def test_cuda_printable_ratio_matches_cpu(self):
        data = _rand(self.rng, accel._CUDA_MIN_BYTES + 32)
        self.assertEqual(self._cuda_call(accel._printable_ratio_cuda, data),
                         accel._printable_ratio_baseline(data))

    def test_cuda_ghash_matches_reference_both_providers(self):
        """cupy 与 numba.cuda 两条 GPU GHASH 都与 crypto._ghash 一致。"""
        env_errors: list[str] = []
        for _ in range(5):
            h = int.from_bytes(_rand(self.rng, 16), "big")
            aad = _rand(self.rng, self.rng.randrange(0, 64))
            ct = _rand(self.rng, self.rng.randrange(0, 65536))
            for fn in (accel._ghash_cuda_cupy, accel._ghash_cuda_numba):
                try:
                    self.assertEqual(fn(h, aad, ct), crypto._ghash(h, aad, ct))
                except ImportError:
                    pass                              # 未装 cupy 或 numba 其一
                except Exception as exc:
                    if not _is_cuda_env_error(exc):
                        raise
                    env_errors.append(f"{fn.__name__}: {type(exc).__name__}")
        if env_errors:
            self.skipTest("CUDA 运行环境不可用：" + ", ".join(env_errors))

    def test_cuda_gcm_dispatch_matches_pure_python(self):
        """强制 cuda 后端 → 走 GPU GHASH，结果与纯 Python 完全一致。"""
        fake = accel.AccelStatus("cuda", "cupy", "模拟", "")
        key = _rand(self.rng, 16)
        iv = _rand(self.rng, 12)
        aad = _rand(self.rng, 16)
        msg = _rand(self.rng, accel._CUDA_GCM_MIN_BYTES * 2 + 3)
        enc = crypto.aes_gcm_encrypt(msg, key, iv, aad)
        with mock.patch.object(accel, "detect", return_value=fake):
            self.assertEqual(accel.aes_gcm_decrypt(enc, key, iv, aad),
                             crypto.aes_gcm_decrypt(enc, key, iv, aad))


# ---------------------------------------------------------------------------
# quicinit 调用侧注入
# ---------------------------------------------------------------------------
def _varint(value: int) -> bytes:
    """QUIC 变长整数编码（借自 tests/test_quicinit.py 的镜像辅助）。"""
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", value | 0x4000)
    if value < 1 << 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def _seal_initial(version: int, dcid: bytes, scid: bytes, payload: bytes,
                  *, role: str = "client", pn: int = 0) -> bytes:
    """按 RFC 9001 §5.4 加封 Initial 长包头（与 quicinit 解密互为镜像）。"""
    keys = quicinit.initial_secrets(version, dcid)[role]
    type_bits = 1 if version in quicinit.QUIC_V2_VERSIONS else 0
    pn_len = 4
    first = 0xC0 | (type_bits << 4) | (pn_len - 1)
    header = (bytes([first]) + struct.pack("!I", version)
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + _varint(0))                            # 空令牌的长度 varint
    header += _varint(pn_len + len(payload) + 16) + pn.to_bytes(pn_len, "big")
    nonce = bytes(a ^ b for a, b in zip(keys["iv"], pn.to_bytes(12, "big")))
    packet = bytearray(header + crypto.aes_gcm_encrypt(payload, keys["key"],
                                                       nonce, header))
    sample = packet[len(header) - pn_len + 4:len(header) - pn_len + 20]
    mask = crypto.aes_encrypt_block(sample, keys["hp"])
    packet[0] ^= mask[0] & 0x0F
    for index in range(pn_len):
        packet[len(header) - pn_len + index] ^= mask[1 + index]
    return bytes(packet)


class QuicinitInjectionTest(unittest.TestCase):
    """quicinit 经 accel 注入 GCM：加速开/关输出完全一致。"""

    def setUp(self) -> None:
        accel.reset()
        self.rng = random.Random(31337)
        # 构造一个最小 TLS 1.3 ClientHello（SNI=accel.example.com）装入 CRYPTO 帧。
        sni = b"accel.example.com"
        sni_ext = struct.pack("!H", len(sni) + 3) + b"\x00" \
            + struct.pack("!H", len(sni)) + sni
        alpn_ext = struct.pack("!HH", 0, 5) + b"\x03h3"
        versions_ext = b"\x02\x03\x04\x03\x03"
        ext = (struct.pack("!HH", 0, len(sni_ext)) + sni_ext
               + struct.pack("!HH", 16, len(alpn_ext)) + alpn_ext
               + struct.pack("!HH", 43, len(versions_ext)) + versions_ext)
        body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01"
                + b"\x01\x00" + struct.pack("!H", len(ext)) + ext)
        hello = b"\x01" + struct.pack("!I", len(body))[1:] + body
        dcid = _rand(self.rng, 8)
        self.dcid = dcid
        self.packets = (
            _seal_initial(1, dcid, bytes(8),
                          b"\x06\x00" + _varint(len(hello)) + hello),
        )

    def test_decrypt_initial_same_with_and_without_accel(self):
        results = []
        for enabled in (True, False):
            accel.set_enabled(enabled)
            try:
                results.append(quicinit.decrypt_initial(self.packets[0]))
            finally:
                accel.set_enabled(True)
        self.assertIsNotNone(results[0])
        self.assertEqual(results[0], results[1])
        self.assertIn("accel.example.com", str(results[0]))

    def test_decrypt_output_unchanged_by_accel_presence(self):
        """加速栈不可用（强制 cpu 直调现状实现）时输出同样一致。"""
        with mock.patch.dict(sys.modules, {"cupy": None, "numba": None}):
            accel.detect(refresh=True)
        self.assertEqual(accel.backend(), "cpu")
        on = quicinit.decrypt_initial(self.packets[0])
        accel.reset()
        accel.set_enabled(False)
        try:
            off = quicinit.decrypt_initial(self.packets[0])
        finally:
            accel.set_enabled(True)
        self.assertEqual(on, off)

    def test_verify_retry_uses_accel_path(self):
        """Retry 完整性校验（RFC 9001 A.4 官方向量）开关一致且校验通过。"""
        retry = bytes.fromhex(
            "ff000000010008f067a5502a4262b5746f6b656e"
            "04a265ba2eff4d829058fb3f0f2496ba")
        odcid = bytes.fromhex("8394c8f03e515708")
        results = []
        for enabled in (True, False):
            accel.set_enabled(enabled)
            try:
                results.append(quicinit.verify_retry(retry, odcid))
            finally:
                accel.set_enabled(True)
        self.assertTrue(results[0]["integrity"])
        self.assertEqual(results[0], results[1])


if __name__ == "__main__":
    unittest.main()
