"""Unit tests for fnet.plugins (tool registry behind the “工具” menu)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.plugins import BUILTIN_TOOLS, PluginManager, plugin_url


def make_manager(tmp: Path) -> PluginManager:
    return PluginManager(Config(tmp / "config.ini"))


class UserToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-plugins-"))
        self.manager = make_manager(self.tmp)

    def test_default_registry_is_empty(self):
        self.assertEqual(self.manager.user_tools(), {})

    def test_add_parses_command_with_shlex(self):
        self.manager.add("nmap", "nmap -sV --top-ports 100")
        self.assertEqual(self.manager.user_tools()["nmap"],
                         ["nmap", "-sV", "--top-ports", "100"])

    def test_add_preserves_quoted_argument(self):
        self.manager.add("echo", 'echo "hello world"')
        self.assertEqual(self.manager.user_tools()["echo"],
                         ["echo", "hello world"])

    def test_add_persists_to_config(self):
        self.manager.add("nmap", "nmap -sV")
        manager = make_manager(self.tmp)
        self.assertEqual(manager.user_tools()["nmap"], ["nmap", "-sV"])

    def test_add_overwrites_existing_tool(self):
        self.manager.add("nmap", "nmap -sV")
        self.manager.add("nmap", "nmap -sn")
        self.assertEqual(self.manager.user_tools()["nmap"], ["nmap", "-sn"])

    def test_remove(self):
        self.manager.add("nmap", "nmap -sV")
        self.assertTrue(self.manager.remove("nmap"))
        self.assertEqual(self.manager.user_tools(), {})
        self.assertFalse(self.manager.remove("nmap"))

    def test_corrupt_json_is_ignored(self):
        self.manager.config.set("execute_cmd", "{not json", "plugins")
        self.assertEqual(self.manager.user_tools(), {})

    def test_string_and_list_specs(self):
        self.manager.config.set(
            "execute_cmd",
            json.dumps({"a": "ls -la", "b": ["python3", "-V"]}),
            "plugins")
        tools = self.manager.user_tools()
        self.assertEqual(tools["a"], ["ls", "-la"])
        self.assertEqual(tools["b"], ["python3", "-V"])


class ToolListTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-plugins-"))
        self.manager = make_manager(self.tmp)

    def test_builtin_tools_are_listed_first(self):
        items = self.manager.as_list()
        self.assertEqual([item["key"] for item in items[:len(BUILTIN_TOOLS)]],
                         [tool["key"] for tool in BUILTIN_TOOLS])
        for item in items[:len(BUILTIN_TOOLS)]:
            self.assertEqual(item["source"], "builtin")

    def test_user_tools_are_appended(self):
        self.manager.add("mytool", "mytool --flag")
        items = self.manager.as_list()
        last = items[-1]
        self.assertEqual(last["key"], "mytool")
        self.assertEqual(last["source"], "user")
        self.assertEqual(last["kind"], "command")
        self.assertEqual(last["target"], "mytool --flag")


class RunToolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-plugins-"))
        self.manager = make_manager(self.tmp)

    def test_unregistered_key(self):
        self.assertEqual(self.manager.run("no-such-tool"),
                         "未注册的工具: no-such-tool")

    def test_runs_user_command_without_shell(self):
        self.manager.add("py", f'"{sys.executable}" -c print(123)')
        output = self.manager.run("py")
        self.assertEqual(output.strip(), "123")

    def test_appends_target_argument(self):
        script = self.tmp / "tool.py"
        script.write_text("import sys\nprint(' '.join(sys.argv[1:]))\n",
                          encoding="utf-8")
        self.manager.add("tool", f'"{sys.executable}" "{script}"')
        self.assertEqual(self.manager.run("tool", "a.pcap").strip(), "a.pcap")

    def test_nonzero_exit_is_reported(self):
        script = self.tmp / "fail.py"
        script.write_text("import sys\nprint('boom')\nsys.exit(3)\n",
                          encoding="utf-8")
        self.manager.add("fail", f'"{sys.executable}" "{script}"')
        output = self.manager.run("fail")
        self.assertIn("[退出码 3]", output)
        self.assertIn("boom", output)

    def test_cyberchef_opens_url_without_subprocess(self):
        with mock.patch("fnet.plugins.open_url") as open_url:
            output = self.manager.run("cyberchef")
        self.assertEqual(output, "已在浏览器中打开 CyberChef")
        open_url.assert_called_once_with("https://gchq.github.io/CyberChef/")


class PluginUrlTest(unittest.TestCase):
    def test_safe_characters_are_kept(self):
        url = "https://gchq.github.io/CyberChef/?a=1&b=2#anchor"
        self.assertEqual(plugin_url(url), url)

    def test_unsafe_characters_are_percent_encoded(self):
        self.assertEqual(plugin_url("http://h/空白 x"),
                         "http://h/%E7%A9%BA%E7%99%BD%20x")


if __name__ == "__main__":
    unittest.main()
