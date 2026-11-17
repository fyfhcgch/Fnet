"""PCAP-over-IP：TCP 监听接收 pcap/pcapng 字节流并自动创建分析任务。

工作方式（与 tulip / pkappa2 等 A&D CTF 工具的 PCAP-over-IP 输出兼容）：

1. 服务器监听 ``127.0.0.1:PORT``（地址可由 ``--host`` 或 config 覆盖，
   绝不默认绑定 0.0.0.0）；
2. 客户端连接后把完整 pcap 文件字节（从全局头开始）写入 socket，然后关闭；
3. 服务器按全局头魔数（``a1b2c3d4`` 及其字节序/纳秒变体、pcapng 的
   ``0x0a0d0d0a``）识别端序与格式，持续把字节流拼接为合法 pcap；
4. 连接关闭后落盘到 ``<cache>/pcap-over-ip/``（路径全部来自 ``fnet.paths``，
   不写死绝对路径），并复用 ``JobManager.submit`` 触发一次分析任务。

本模块是纯 stdlib 实现；``fnet/utils/pcap.py`` 面向 tshark 后处理，没有流式
重组辅助，所以这里自带最小解析器。
"""
from __future__ import annotations

import datetime as _dt
import secrets
import socket
import threading
from pathlib import Path

from fnet.features.registry import FEATURES
from fnet.logger import logger
from fnet.paths import CACHE_DIR

#: 全局头魔数 -> (端序说明, 格式)。0xa1b2c3d4 写入文件时的小端字节序是
#: ``d4 c3 b2 a1``，大端则是 ``a1 b2 c3 d4``；纳秒变体交换 0x3c/0x4d。
PCAP_MAGICS: dict[bytes, str] = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap-ns",
    b"\xa1\xb2\x3c\x4d": "pcap-ns",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}

#: pcap 全局头 24 字节；pcapng 最小块（SHB）28 字节。
PCAP_HEADER_LEN = 24
PCAPNG_HEADER_LEN = 28

#: 单个连接允许的最大字节数（防止内存被拖垮）。
DEFAULT_MAX_BYTES = 512 * 1024 * 1024


def detect_magic(head: bytes) -> str | None:
    """Return the stream format for a 4-byte magic, or ``None`` if unknown."""
    if not head or len(head) < 4:
        return None
    return PCAP_MAGICS.get(bytes(head[:4]))


class PcapStreamParser:
    """把 TCP 字节流拼回一个完整的 pcap/pcapng 文件。

    容错行为：

    * 收到 >= 4 字节仍识别不出魔数时立即判为坏流（``feed`` 抛出
      ``ValueError``），之后的所有 ``feed``/``finish`` 继续失败；
    * ``finish`` 时不足一个完整全局头（pcap 24 字节 / pcapng 28 字节）判为
      截断流；
    * 半包/分包（一次 ``feed`` 只到一部分字节）会一直缓存直到 EOF。
    """

    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.max_bytes = max(4, int(max_bytes))
        self._buf = bytearray()
        self._magic_checked = False
        self._broken: str | None = None
        self.kind = ""

    @property
    def broken(self) -> str | None:
        return self._broken

    @property
    def size(self) -> int:
        return len(self._buf)

    def feed(self, data: bytes | bytearray) -> None:
        if self._broken:
            raise ValueError(self._broken)
        if not data:
            return
        if len(self._buf) + len(data) > self.max_bytes:
            self._broken = f"数据流超过大小上限 {self.max_bytes} 字节"
            raise ValueError(self._broken)
        self._buf.extend(data)
        if not self._magic_checked:
            if len(self._buf) < 4:
                return  # 半包：魔数还没收齐，继续等
            kind = detect_magic(bytes(self._buf[:4]))
            if kind is None:
                head = bytes(self._buf[:8])
                self._broken = f"不是有效的 pcap/pcapng 数据流（魔数不识别: {head.hex()}）"
                raise ValueError(self._broken)
            self.kind = kind
            self._magic_checked = True

    def finish(self) -> bytes:
        """EOF 后校验并返回完整文件字节；无效流抛出 ``ValueError``。"""
        try:
            if self._broken:
                raise ValueError(self._broken)
            if not self._magic_checked:
                raise ValueError("数据流太短，缺少 pcap/pcapng 全局头")
            minimum = PCAPNG_HEADER_LEN if self.kind == "pcapng" else PCAP_HEADER_LEN
            if len(self._buf) < minimum:
                raise ValueError(
                    f"数据流不完整：只有 {len(self._buf)} 字节，不足 {self.kind} "
                    f"全局头所需的 {minimum} 字节")
        except ValueError as exc:
            self._broken = str(exc)
            raise
        return bytes(self._buf)


class PcapOverIPServer:
    """Threaded TCP listener; every connection yields one analysis job."""

    def __init__(self, runtime, port: int, host: str | None = None,
                 features: list[str] | None = None, params: dict | None = None,
                 shards: int = 1, on_job=None,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.runtime = runtime
        # 不写死 0.0.0.0：默认只监听回环，可用 --host / config 的 host 覆盖。
        self.host = str(host or (runtime.config.get("host") if runtime else "") or "127.0.0.1")
        self.port = int(port)
        self.features = list(features) if features else [
            feature.checkbox for feature in FEATURES if feature.default]
        self.params = dict(params or {})
        try:
            self.shards = max(1, int(shards or 1))
        except (TypeError, ValueError):
            self.shards = 1
        self.on_job = on_job
        self.max_bytes = max_bytes
        self.jobs = []
        self.errors: list[str] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(4)
        sock.settimeout(0.5)
        # port=0 时回填实际分配的端口。
        self.port = sock.getsockname()[1]
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop,
                                        name="fnet-pcapoip", daemon=True)
        self._thread.start()
        logger.good(f"PCAP-over-IP 监听 {self.host}:{self.port}，等待客户端连接")

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    # -- connection handling -------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                break
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle, args=(conn, addr),
                                      daemon=True)
            worker.start()

    def _handle(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
        parser = PcapStreamParser(max_bytes=self.max_bytes)
        try:
            conn.settimeout(600)
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    raise ValueError(f"接收超时（已收 {parser.size} 字节）")
                if not chunk:
                    break
                parser.feed(chunk)
        except (OSError, ValueError) as exc:
            message = f"PCAP-over-IP 接收失败 ({peer}): {exc}"
            logger.warn(message)
            self.errors.append(message)
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass
        try:
            data = parser.finish()
        except ValueError as exc:
            message = f"PCAP-over-IP 数据无效 ({peer}): {exc}"
            logger.warn(message)
            self.errors.append(message)
            return
        path = self._save(data, parser.kind, peer)
        if path is None:
            return
        self._submit(path)

    # -- persistence / analysis ----------------------------------------
    def _save(self, data: bytes, kind: str, peer: str) -> Path | None:
        directory = CACHE_DIR / "pcap-over-ip"
        directory.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        suffix = ".pcapng" if kind == "pcapng" else ".pcap"
        target = directory / f"pcapoip-{stamp}-{secrets.token_hex(3)}{suffix}"
        try:
            target.write_bytes(data)
        except OSError as exc:
            message = f"PCAP-over-IP 落盘失败 ({peer}): {exc}"
            logger.error(message)
            self.errors.append(message)
            return None
        logger.good(f"PCAP-over-IP 已保存: {target}（{len(data)} 字节，{kind}）")
        return target

    def _submit(self, path: Path):
        job = self.runtime.jobs.submit(str(path.resolve()), self.features,
                                       self.params, shards=self.shards)
        self.jobs.append(job)
        logger.good(f"PCAP-over-IP 任务已创建: {job.id} | {path.name}")
        if self.on_job is not None:
            try:
                self.on_job(job)
            except Exception as exc:  # noqa: BLE001 - callbacks must not kill the server
                logger.warn(f"PCAP-over-IP 回调失败: {exc}")
        return job
