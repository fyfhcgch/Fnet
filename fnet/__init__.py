"""Fnet - a cross-platform CTF network traffic analysis toolbox.

Fnet organises protocol extraction and decoding into one local WebUI and a
matching headless CLI.  Protocol parsing is delegated to ``tshark`` and the
analyser itself only uses the Python standard library, so it runs natively on
Linux, macOS and Windows.
"""
from __future__ import annotations

__version__ = "2.21.3"
__author__ = "Fnet contributors"
__license__ = "Apache-2.0"

APP_NAME = "Fnet"
APP_DISPLAY_NAME = "Fnet - CTF 流量分析工具箱"
