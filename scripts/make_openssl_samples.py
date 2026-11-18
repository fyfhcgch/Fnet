"""生成真实的 ``openssl enc`` 样本，供 CLI 兼容性验证使用。

仅在本脚本被手工运行时才会调用系统 ``openssl``；这里不是 Fnet 运行时代码，
不依赖 scapy / tshark，也不写入任何被 git 跟踪的二进制夹具。

用法::

    python3 scripts/make_openssl_samples.py
    python3 scripts/make_openssl_samples.py -o /tmp/opencode/openssl-samples

产物目录包含若干 ``*.bin``/``*.b64`` 文件及 ``manifest.json``（明文摘要、
口令、KDF 参数、预期 flag 等）。解密侧应能仅凭 manifest 还原这些样本。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_OUTPUT = Path("/tmp/opencode/openssl-samples")

# 固定口令/明文：便于重复生成与跨 OpenSSL 版本对比。
PASSWORD = "fnet-openssl-ctf"
EXPECTED_FLAG = "flag{opeNssl_3x_pBkdf2_r0cks}"
PLAINTEXT = (
    b"Fnet OpenSSL CLI compatibility sample\n"
    + EXPECTED_FLAG.encode("ascii") + b"\n"
    + b"tail line for padding checks\n"
)

ITER = 10000
KEY_HEX = "0123456789abcdef" * 4          # 32 字节 = AES-256
IV_HEX = "00112233445566778899aabbccddeeff"  # 16 字节 = AES 块大小

# 每个用例的 args 直接跟在 ``openssl enc`` 之后；输入/输出由本脚本追加。
CASES: list[dict] = [
    {
        "name": "01_aes256cbc_md5_nosalt.bin",
        "cipher": "aes-256-cbc", "kdf": "evp", "digest": "md5",
        "iter": None, "salt_len": 0, "base64": False, "zlib": False,
        "password": PASSWORD,
        "args": ["-aes-256-cbc", "-md", "md5", "-nosalt",
                 "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "02_aes256cbc_sha256_salt.bin",
        "cipher": "aes-256-cbc", "kdf": "evp", "digest": "sha256",
        "iter": None, "salt_len": 8, "base64": False, "zlib": False,
        "password": PASSWORD,
        "args": ["-aes-256-cbc", "-md", "sha256", "-salt",
                 "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "03_aes256cbc_pbkdf2_sha256.bin",
        "cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256",
        "iter": ITER, "salt_len": 8, "base64": False, "zlib": False,
        "password": PASSWORD,
        "args": ["-aes-256-cbc", "-pbkdf2", "-iter", str(ITER),
                 "-md", "sha256", "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "04_aes128ctr_md5_salt.bin",
        "cipher": "aes-128-ctr", "kdf": "evp", "digest": "md5",
        "iter": None, "salt_len": 8, "base64": False, "zlib": False,
        "password": PASSWORD,
        "args": ["-aes-128-ctr", "-md", "md5", "-salt",
                 "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "05_aes256cbc_pbkdf2_sha256_aA.b64",
        "cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256",
        "iter": ITER, "salt_len": 8, "base64": True, "zlib": False,
        "password": PASSWORD,
        "args": ["-aes-256-cbc", "-pbkdf2", "-iter", str(ITER),
                 "-md", "sha256", "-a", "-A", "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "06_aes256cbc_pbkdf2_sha256_z.bin",
        "cipher": "aes-256-cbc", "kdf": "pbkdf2", "digest": "sha256",
        "iter": ITER, "salt_len": 8, "base64": False, "zlib": True,
        "password": PASSWORD,
        "args": ["-aes-256-cbc", "-pbkdf2", "-iter", str(ITER),
                 "-md", "sha256", "-z", "-pass", f"pass:{PASSWORD}"],
    },
    {
        "name": "07_aes256cbc_rawkey_iv.bin",
        "cipher": "aes-256-cbc", "kdf": "raw", "digest": None,
        "iter": None, "salt_len": 0, "base64": False, "zlib": False,
        "password": "ignored",
        "args": ["-aes-256-cbc", "-K", KEY_HEX, "-iv", IV_HEX, "-nosalt",
                 "-pass", "pass:ignored"],
    },
]


def _manifest_entry(case: dict) -> dict:
    """把用例元数据整理成 manifest 条目（字段名供解密测试直接消费）。"""
    entry = {
        "filename": case["name"],
        "cipher": case["cipher"],
        "kdf": case["kdf"],
        "digest": case["digest"],
        "iter": case["iter"],
        "salt_len": case["salt_len"],
        "base64": case["base64"],
        "zlib": case["zlib"],
        "password": case["password"],
        "plaintext_sha256": hashlib.sha256(PLAINTEXT).hexdigest(),
        "expected_flag": EXPECTED_FLAG,
        "args": list(case["args"]),
    }
    if case["kdf"] == "raw":
        entry["key_hex"] = KEY_HEX
        entry["iv_hex"] = IV_HEX
    return entry


def generate(openssl: str, output: Path) -> dict:
    """运行全部用例；不支持的用例跳过而不是让整个脚本失败。"""
    output.mkdir(parents=True, exist_ok=True)
    version = subprocess.run(
        [openssl, "version"], capture_output=True, text=True,
        errors="replace", shell=False, check=False,
    ).stdout.strip() or "未知版本"

    manifest: dict = {
        "openssl_version": version,
        "password": PASSWORD,
        "plaintext_sha256": hashlib.sha256(PLAINTEXT).hexdigest(),
        "expected_flag": EXPECTED_FLAG,
        "samples": [],
    }
    skipped: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="fnet-openssl-samples-") as tmp:
        plain_path = Path(tmp) / "plain.bin"
        plain_path.write_bytes(PLAINTEXT)
        for case in CASES:
            dest = output / case["name"]
            cmd = [openssl, "enc", *case["args"],
                   "-in", str(plain_path), "-out", str(dest)]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace",
                shell=False, check=False,
            )
            if proc.returncode != 0:
                dest.unlink(missing_ok=True)
                reason = (proc.stderr or proc.stdout).strip().replace("\n", " ")
                print(f"跳过 {case['name']}（openssl 不支持或执行失败）：{reason}")
                skipped.append({"filename": case["name"], "reason": reason})
                continue
            manifest["samples"].append(_manifest_entry(case))
            print(f"生成 {dest.name}（{dest.stat().st_size} 字节）")

    (output / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {"manifest": manifest, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="生成真实 openssl enc 样本（手工运行，不写入仓库夹具）",
    )
    parser.add_argument("output", nargs="?", default=None,
                        help="输出目录（默认 /tmp/opencode/openssl-samples）")
    parser.add_argument("-o", "--output", dest="output_opt", default=None,
                        help="输出目录，覆盖位置参数")
    parser.add_argument("--strict", action="store_true",
                        help="任一用例被跳过时返回非零退出码")
    args = parser.parse_args(argv)

    output = Path(args.output_opt or args.output or DEFAULT_OUTPUT).expanduser()
    openssl = shutil.which("openssl")
    if openssl is None:
        print("未找到 openssl 命令，跳过全部样本生成。", file=sys.stderr)
        return 0

    result = generate(openssl, output)
    total = len(result["manifest"]["samples"])
    skip_count = len(result["skipped"])
    print(f"完成：生成 {total} 个样本，跳过 {skip_count} 个；输出目录 {output}")
    if args.strict and skip_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
