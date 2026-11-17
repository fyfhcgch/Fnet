"""RDP session replay.

The handler decrypts an RDP conversation, converts it to a replayable file and
reports failures through the application logger.  Conversion runs inside a
job, paths are cross-platform, and long commands can be cancelled from the
WebUI.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from fnet.features.registry import FeatureContext
from fnet.tools.runner import find_tool, run


def find_executable(name: str, hint_path: str | None = None) -> str | None:
    if hint_path and Path(hint_path).is_file():
        return hint_path
    return find_tool(name)


def run_tshark_decryption(tshark: str, input_pcap: Path, key_file: Path,
                          server_ip: str | None, port: int,
                          output_pcap: Path, log, cancel=None) -> bool:
    try:
        head = key_file.read_text(errors="ignore")[:4000]
        is_keylog = "CLIENT_RANDOM" in head or "TRAFFIC_SECRET" in head
    except OSError as exc:
        log(f"无法读取密钥文件: {exc}", "error")
        return False

    ip = server_ip or "0.0.0.0"
    cmd = [tshark, "-r", str(input_pcap),
           "-d", f"tcp.port=={port},tls",
           "-o", f"tpkt.tcp.port:{port}",
           "-U", "OSI layer 7", "-F", "pcap", "-w", str(output_pcap)]
    if is_keylog:
        log("检测到 KeyLog 格式，使用 TLS keylog 解密", "info")
        cmd += ["-o", f"tls.keylog_file:{key_file}"]
    else:
        log("检测到私钥格式，使用 RSA 私钥解密", "info")
        cmd += ["-o", f"tls.keys_list:{ip},{port or 3389},tpkt,{key_file}"]

    log("导出解密后的 PDU 到: " + str(output_pcap))
    code, out = run(cmd, timeout=1800, cancel=cancel, echo=False)
    if code != 0:
        log("tshark 执行失败: " + out[-1500:], "error")
        return False
    if not output_pcap.exists() or output_pcap.stat().st_size == 0:
        log("导出文件为空：可能使用了 DHE/ECDHE 前向保密，需要 KeyLog 而非私钥", "warn")
        return False
    return True


def convert_pcap(input_pcap: Path, output_dir: Path, log,
                 cancel=None) -> Path | None:
    log("调用 PyRDP 将 PCAP 转换为回放文件", "info")
    try:
        import logging

        logging.getLogger("pyrdp").setLevel(logging.CRITICAL)
        from pyrdp.convert.PCAPConverter import PCAPConverter
    except ImportError:
        log("无法导入 PyRDP，请安装：pip install pyrdp-mitm", "error")
        return None

    try:
        converter = PCAPConverter(
            inputFile=str(input_pcap),
            outputPrefix=str(output_dir) + "/",
            format="replay",
            secrets=None,
            srcFilter=[],
            dstFilter=[],
            listOnly=False,
        )
        converter.process()
    except Exception as exc:  # noqa: BLE001 - library raises many types
        log(f"PyRDP 转换失败: {exc}", "error")
        return None

    for path in output_dir.iterdir():
        if path.suffix.lower() in (".pyrdp", ".replay"):
            log(f"生成回放文件: {path}", "good")
            return path
    log("PyRDP 未生成回放文件", "warn")
    return None


def replay_rdp_session(pcap_path: str, key_path: str, server_ip: str | None = None,
                       port: int = 3389, tshark_path: str | None = None,
                       player_path: str = "pyrdp-player",
                       output_root: str | Path | None = None,
                       log=print, launch_player: bool = False,
                       cancel=None) -> Path | None:
    tshark = find_executable("tshark", tshark_path)
    if not tshark:
        log("未找到 tshark", "error")
        return None
    pcap, key = Path(pcap_path), Path(key_path)
    if not pcap.exists():
        log(f"输入 PCAP 不存在: {pcap}", "error")
        return None
    if not key.exists():
        log(f"密钥文件不存在: {key}", "error")
        return None

    outdir = Path(output_root or "rdp_replay_output")
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    decrypted = outdir / f"{pcap.stem}_dec.pcap"

    if not run_tshark_decryption(tshark, pcap, key, server_ip, port,
                                 decrypted, log, cancel=cancel):
        return None
    replay = convert_pcap(decrypted, outdir, log, cancel=cancel)
    if replay and launch_player:
        player = find_executable(player_path)
        if not player:
            log(f"未找到播放器 {player_path!r}，回放文件已保存", "warn")
        else:
            import subprocess

            log("启动 PyRDP Player", "info")
            try:
                subprocess.Popen([player, str(replay)],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            except OSError as exc:
                log(f"启动播放器失败: {exc}", "warn")
    return replay


def handler(ctx: FeatureContext) -> None:
    params = ctx.params
    key = str(params.get("rdp_private_key")
              or ctx.config.get("rdp_private_key", "paths")
              or ctx.config.get("rdp_keylog", "paths") or "")
    if not key:
        ctx.report("请在设置中指定 RDP 私钥或 Key log 文件", "error")
        return
    ctx.report("RDP 重放：需要 PyRDP（pip install pyrdp-mitm）", "info")
    output = replay_rdp_session(
        pcap_path=ctx.pcap,
        key_path=key,
        server_ip=params.get("server_ip") or None,
        port=int(params.get("port") or 3389),
        tshark_path=params.get("tshark_path") or ctx.config.get("tshark"),
        player_path=params.get("player_path") or "pyrdp-player",
        output_root=ctx.output_dir / "rdp",
        log=ctx.report,
        launch_player=bool(params.get("launch_player")),
        cancel=ctx.cancel,
    )
    if output:
        ctx.report(f"RDP 回放文件: {output}", "good")
    ctx.set_progress(100)
