"""Shared styx.yaml setup for live self-hosted runner integration tests."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def prepare_styx_yaml(repo_root: Path | None = None) -> Path:
    """Copy the minimal runners config into styx.yaml (no /etc/styx override)."""
    root = repo_root or REPO_ROOT
    target = root / "styx.yaml"
    runners = root / "styx.yaml.runners"
    if not runners.is_file():
        raise FileNotFoundError(f"Missing minimal runner config: {runners}")
    target.write_text(runners.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Using {runners}")
    return target
