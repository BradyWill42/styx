"""Tests for styx.yaml loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml

from styxctl.config import (
    config_status,
    load_config,
    resolve_config,
    validate_config,
)
from styxctl.nodes import parse_nodes

from tests.support import example_config_text


def test_validate_empty_config_warns():
    issues = validate_config({})
    assert len(issues) == 1
    assert issues[0].level == "warning"
    assert config_status(issues) == "VALID_WITH_WARNINGS"


def test_validate_example_config(tmp_path):
    config_path = tmp_path / "styx.yaml"
    config_path.write_text(example_config_text(), encoding="utf-8")
    config = load_config(config_path)
    issues = validate_config(config)
    assert config_status(issues) == "VALID"


def test_resolve_config_applies_network_defaults():
    config = resolve_config({"cluster": {"name": "styx"}, "nodes": []})
    assert config["network"]["pod_ipv4"] == "10.2.0.0/16"
    assert config["wireguard"]["port"] == 47800
    assert config["gateway"]["ssh_port"] == 47810


def test_resolve_config_assigns_mesh_ips_from_node_order():
    config = resolve_config(
        {
            "cluster": {"name": "styx"},
            "nodes": [
                {"name": "a", "role": "init-server"},
                {"name": "b", "role": "server"},
            ],
        }
    )
    nodes = parse_nodes(config)
    assert nodes[0].ipv4 == "10.0.0.1"
    assert nodes[0].ipv6 == "fd00:cafe::1"
    assert nodes[1].ipv4 == "10.0.0.2"
    assert nodes[1].ipv6 == "fd00:cafe::2"


def test_resolve_config_keeps_explicit_mesh_ips():
    config = resolve_config(
        {
            "cluster": {"name": "styx"},
            "nodes": [{"name": "a", "role": "init-server", "ipv4": "10.0.0.99"}],
        }
    )
    nodes = parse_nodes(config)
    assert nodes[0].ipv4 == "10.0.0.99"
    assert nodes[0].ipv6 == "fd00:cafe::1"


def test_validate_rejects_wg0_interface(tmp_path):
    config = {
        "cluster": {"name": "styx", "mode": "dual-stack"},
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
