"""Tests for styx.yaml loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from styxctl.config import config_status, load_config, validate_config

EXAMPLE_CONFIG = Path(__file__).resolve().parent.parent / "styx.yaml.example"


def test_validate_empty_config_warns():
    issues = validate_config({})
    assert len(issues) == 1
    assert issues[0].level == "warning"
    assert config_status(issues) == "VALID_WITH_WARNINGS"


def test_validate_example_config(tmp_path):
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    issues = validate_config(config)
    assert config_status(issues) == "VALID"


def test_validate_rejects_wg0_interface(tmp_path):
    config = {
        "cluster": {"name": "styx", "mode": "dual-stack"},
        "network": {"mesh_ipv4": "10.0.0.0/16"},
        "wireguard": {"interface": "wg0", "port": 47800},
    }
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    issues = validate_config(load_config(config_path))
    assert config_status(issues) == "INVALID"
    assert any("wg0" in issue.message for issue in issues)


def test_validate_rejects_port_outside_reserved_range(tmp_path):
    config = {
        "cluster": {"name": "styx", "mode": "dual-stack"},
        "wireguard": {"interface": "Styx", "port": 51820},
    }
    issues = validate_config(config)
    assert config_status(issues) == "INVALID"
    assert any("reserved range" in issue.message for issue in issues)
