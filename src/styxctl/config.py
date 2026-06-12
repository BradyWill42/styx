"""Config loading helpers for Styx.

MVP1 does not require a config file, but this module is included so later
install/deploy phases can share the same loader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG_FILENAMES = ("styx.yaml", "styx.yml")


class ConfigError(RuntimeError):
    """Raised when a Styx config file cannot be loaded."""


def find_config(start: Path | None = None) -> Path | None:
    base = start or Path.cwd()
    for name in DEFAULT_CONFIG_FILENAMES:
        candidate = base / name
        if candidate.exists():
            return candidate
    return None


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    candidate = Path(path) if path is not None else find_config()
    if candidate is None:
        return {}
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Could not read config file {candidate}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse config file {candidate}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {candidate} must contain a YAML mapping at the top level")
    return data
