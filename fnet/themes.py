"""Colour themes exposed to the WebUI as CSS custom properties.

The palettes follow a warm neutral + terracotta tonal scale.  Keep the keys in
sync with the ``--*`` variables consumed by ``static/style.css``; ``on_accent``
is set from CSS (per ``data-theme``) so light/dark primary buttons stay legible.
"""
from __future__ import annotations

THEMES: dict[str, dict[str, str]] = {
    "dark": {
        "name": "暖夜",
        "bg": "#141312", "panel": "#1d1b1a", "panel2": "#262322",
        "text": "#e9e4e0", "muted": "#a39d98", "border": "#3a3532",
        "accent": "#e08a70", "accent2": "#7bd3a0", "danger": "#ff8a80",
        "warn": "#ffc07a", "input": "#171514", "log": "#100f0e",
    },
    "light": {
        "name": "暖昼",
        "bg": "#f7f4f1", "panel": "#fffdfb", "panel2": "#f1ece8",
        "text": "#221f1d", "muted": "#726b65", "border": "#ddd5cf",
        "accent": "#8f3d33", "accent2": "#2f7d52", "danger": "#b3261e",
        "warn": "#a35a00", "input": "#fffdfb", "log": "#fbf9f7",
    },
    "pink0": {
        "name": "浅樱",
        "bg": "#fdf4f4", "panel": "#fffafa", "panel2": "#f8e7e5",
        "text": "#3d2422", "muted": "#8f6f6a", "border": "#ecd0cc",
        "accent": "#a84a3e", "accent2": "#3f7d5c", "danger": "#b3261e",
        "warn": "#985300", "input": "#fffbfb", "log": "#fdf8f7",
    },
    "pink1": {
        "name": "暮玫",
        "bg": "#1b1618", "panel": "#241d20", "panel2": "#2e2428",
        "text": "#f2e5e3", "muted": "#b39a97", "border": "#48383c",
        "accent": "#e0897a", "accent2": "#7ec9b0", "danger": "#ff9a90",
        "warn": "#ffc780", "input": "#171214", "log": "#120e10",
    },
    "pink2blue": {
        "name": "莓紫",
        "bg": "#211a20", "panel": "#2b222a", "panel2": "#362b34",
        "text": "#f4e6ee", "muted": "#bda1b2", "border": "#4a3a46",
        "accent": "#f0a0b8", "accent2": "#8ad9c0", "danger": "#ff9aae",
        "warn": "#ffd08a", "input": "#1b151a", "log": "#171116",
    },
}

DEFAULT_THEME = "dark"


def theme_names() -> list[dict[str, str]]:
    return [{"key": key, "name": value["name"]} for key, value in THEMES.items()]


def css_variables(key: str) -> str:
    theme = THEMES.get(key, THEMES[DEFAULT_THEME])
    return "\n".join(f"  --{name}: {value};" for name, value in theme.items()
                     if name != "name")


def theme_by_name(name: str) -> str | None:
    for key, value in THEMES.items():
        if value["name"] == name or key == name:
            return key
    return None
