"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG_PATH = REPO_ROOT / "styx.yaml.example"


def example_config_text() -> str:
    return EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8")
