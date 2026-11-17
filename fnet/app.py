"""Application assembly: one place where the object graph is wired.

The WebUI, the CLI and the test suite all build the same :class:`FnetApp`
so behaviour cannot drift between front-ends.
"""
from __future__ import annotations

from dataclasses import dataclass

from fnet.config import Config, load_config
from fnet.jobs import JobManager
from fnet.logger import logger
from fnet.paths import USER_CONFIG, ensure_dirs
from fnet.plugins import PluginManager
from fnet.tools.runner import ToolBox
from fnet.webui.server import FnetApp


@dataclass
class Runtime:
    """Everything needed to drive an analysis session."""

    config: Config
    toolbox: ToolBox
    jobs: JobManager
    plugins: PluginManager
    app: FnetApp

    @property
    def token(self) -> str:
        return self.app.token


def build(config: Config | None = None) -> Runtime:
    ensure_dirs()
    config = config or load_config()
    toolbox = ToolBox(config)
    jobs = JobManager(config, toolbox)
    plugins = PluginManager(config)
    app = FnetApp(config, toolbox, jobs, plugins)
    logger.debug(f"配置: {config.path}")
    return Runtime(config, toolbox, jobs, plugins, app)


def build_from_file(path: str | None = None) -> Runtime:
    return build(Config(path) if path else None)


def describe_environment(runtime: Runtime) -> str:
    """Human readable summary printed on startup and by ``fnet --doctor``."""
    lines = [f"配置文件: {runtime.config.path or USER_CONFIG}"]
    for key in runtime.toolbox.TOOL_NAMES:
        availability = runtime.toolbox.path(key)
        lines.append(f"  {key:<14s} {'✓ ' + availability if availability else '✗ 未找到'}")
    return "\n".join(lines)
