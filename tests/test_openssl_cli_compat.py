"""用真实 ``openssl enc`` 输出验证解密配方（可选 CLI 兼容性测试）。

运行::

    python3 -m unittest tests.test_openssl_cli_compat -v

样本在 tempfile 中即时生成，不依赖网络/tshark/第三方包，也不写入 git 夹具。
缺少 ``openssl`` 时整个模块跳过；核心暂未支持的扩展用例逐项跳过。
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from fnet.utils import openssl_enc
from scripts.make_openssl_samples import (
    CASES, EXPECTED_FLAG, PLAINTEXT, _manifest_entry,
)

OPENSSL = shutil.which("openssl")
if OPENSSL is None:
    raise unittest.SkipTest("未找到 openssl 命令，跳过 CLI 兼容性测试")

# 1/2/3/5 是必须支持的基线与 PBKDF2/Base64 路径；4/6/7 视核心能力可选。
REQUIRED = {
    "01_aes256cbc_md5_nosalt.bin",
    "02_aes256cbc_sha256_salt.bin",
    "03_aes256cbc_pbkdf2_sha256.bin",
    "05_aes256cbc_pbkdf2_sha256_aA.b64",
}
BASE64_NAME = "05_aes256cbc_pbkdf2_sha256_aA.b64"
FLAG_BYTES = EXPECTED_FLAG.encode("ascii")


def _generate_samples(root: Path) -> dict[str, dict]:
    """在临时目录调用真实 openssl CLI（参数数组，不使用 shell）。"""
    manifest: dict[str, dict] = {}
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    plain_path = work / "plain.bin"
    plain_path.write_bytes(PLAINTEXT)
    for case in CASES:
        dest = root / case["name"]
        proc = subprocess.run(
            [OPENSSL, "enc", *case["args"],
             "-in", str(plain_path), "-out", str(dest)],
            capture_output=True, text=True, errors="replace",
            shell=False, check=False,
        )
        if proc.returncode != 0:
            # 例如未编译 zlib / 禁用 md5：该样本不进入本次 manifest。
            continue
        entry = _manifest_entry(case)
        entry["path"] = str(dest)
        manifest[case["name"]] = entry
    return manifest


def _spec_from_manifest(entry: dict) -> dict:
    """把 manifest 条目翻译成显式规格，并带上常见键名别名。"""
    digest = entry["digest"]
    spec = {
        "cipher": entry["cipher"],
        "digest": digest,
        "md": digest,
        "kdf": entry["kdf"],
        "iter": entry["iter"],
        "iterations": entry["iter"],
        "pbkdf2": entry["kdf"] == "pbkdf2",
        "salt_len": entry["salt_len"],
        "nosalt": entry["salt_len"] == 0,
        "base64": entry["base64"],
        "zlib": entry["zlib"],
    }
    if entry.get("key_hex"):
        spec["key_hex"] = entry["key_hex"]
        spec["iv_hex"] = entry["iv_hex"]
    return spec


def _expected_shape(entry: dict) -> tuple[str, int]:
    """从 cipher 名推导期望的 mode / key_len（字节）。"""
    cipher = entry["cipher"].lower().replace("_", "-")
    mode = cipher.rsplit("-", 1)[-1]
    bits = next((int(part) for part in cipher.split("-") if part.isdigit()), 256)
    return mode, bits // 8


class OpenSslCliCompatTest(unittest.TestCase):
    """真实 OpenSSL 1.1+/3.x/4.x 输出的端到端解密验证。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="fnet-openssl-cli-")
        cls.root = Path(cls._tmp.name)
        cls.manifest = _generate_samples(cls.root)
        missing = REQUIRED - cls.manifest.keys()
        if missing:
            cls._tmp.cleanup()
            raise unittest.SkipTest(
                f"openssl 未能生成必需样本：{', '.join(sorted(missing))}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def _decrypt(self, data: bytes, entry: dict) -> dict | None:
        """只用 manifest 推导出的显式规格调用核心，不做口令/参数爆破。"""
        return openssl_enc.decrypt_envelope(
            data, entry["password"], spec=_spec_from_manifest(entry))

    def test_decrypt_real_openssl_samples(self) -> None:
        """逐个样本验证明文、flag 与配方形状。"""
        for name, entry in self.manifest.items():
            with self.subTest(sample=name):
                data = Path(entry["path"]).read_bytes()
                result = self._decrypt(data, entry)
                if result is None:
                    if name in REQUIRED:
                        self.fail(f"无法解密必需样本 {name}")
                    self.skipTest(f"核心暂不支持样本 {name} 的配方")

                plain = result.get("plaintext")
                self.assertIsNotNone(plain, "结果应包含 plaintext")
                if isinstance(plain, str):
                    plain = plain.encode("utf-8")
                self.assertIsInstance(plain, bytes)

                if entry["zlib"]:
                    # zlib 路径不同实现可能保留/剥除尾部换行，只断言 flag。
                    self.assertIn(FLAG_BYTES, plain)
                else:
                    self.assertEqual(plain, PLAINTEXT)

                recipe = result.get("recipe") or {}
                mode, key_len = _expected_shape(entry)
                self.assertEqual(recipe.get("mode"), mode)
                self.assertEqual(recipe.get("key_len"), key_len)

    def test_detect_envelope_base64(self) -> None:
        """Base64 样本应识别出 encoding=base64 与 Salted__ 标记。"""
        entry = self.manifest.get(BASE64_NAME)
        if entry is None:
            self.skipTest("openssl 未生成 Base64 样本")
        data = Path(entry["path"]).read_bytes()
        # b"Salted__" 的 Base64 前缀固定为 U2FsdGVkX1。
        self.assertTrue(data.startswith(b"U2FsdGVkX1"))
        env = openssl_enc.detect_envelope(data)
        self.assertIsNotNone(env)
        self.assertEqual(getattr(env, "encoding", None), "base64")

        marker = getattr(env, "marker", None)
        if marker is None:
            marker = getattr(env, "magic", None)
        self.assertIsNotNone(marker, "OpenSslEnvelope 应暴露 marker")
        text = (marker.decode("ascii", "replace")
                if isinstance(marker, bytes) else str(marker))
        self.assertTrue(
            text.startswith("U2FsdGVkX1") or text.startswith("Salted__"),
            f"意外的 OpenSSL 标记：{text!r}")
        salt = getattr(env, "salt", None)
        if salt is not None:
            self.assertEqual(len(salt), entry["salt_len"])
