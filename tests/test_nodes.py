"""Tests for styx cluster node configuration."""

from __future__ import annotations

from styxctl.config import load_config
from styxctl.nodes import identify_local_node, parse_nodes, validate_nodes

from tests.support import EXAMPLE_CONFIG_PATH, make_inventory


def test_parse_nodes_from_example_config():
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    assert len(nodes) == 3
    assert nodes[0].name == "pistyx"
    assert nodes[0].role == "init-server"


def test_validate_nodes_requires_single_init_server():
    nodes = parse_nodes(
        {
            "nodes": [
                {"name": "a", "ipv4": "10.0.0.1", "role": "server"},
                {"name": "b", "ipv4": "10.0.0.2", "role": "server"},
            ]
        }
    )
    errors = validate_nodes(nodes)
    assert any("init-server" in error for error in errors)


def test_identify_local_node_by_current_ip():
    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    matched = identify_local_node(
        nodes,
        make_inventory(
            hostname="pistyx",
            detected_binaries={},
            detected_services={},
            firewall_backend={"preferred": "unknown"},
        ),
    )
    assert matched is not None
    assert matched.name == "pistyx"
    assert matched.role == "init-server"
