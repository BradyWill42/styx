"""Shared styx.yaml setup for live self-hosted runner integration tests."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def prepare_styx_yaml(repo_root: Path | None = None) -> Path:
    """Copy styx.yaml.example into styx.yaml for runner integration."""
    root = repo_root or REPO_ROOT
    target = root / "styx.yaml"
    example = root / "styx.yaml.example"
    if not example.is_file():
        raise FileNotFoundError(f"Missing config example: {example}")
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Using {example}")
    return target
