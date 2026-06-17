"""Tests for styx cluster node configuration."""

from __future__ import annotations

from styxctl.inventory import SystemInventory
from styxctl.nodes import identify_local_node, parse_nodes, validate_nodes
from styxctl.ports import PortScanResult

from tests.support import EXAMPLE_CONFIG_PATH


def _inventory(**overrides) -> SystemInventory:
    base = SystemInventory(
        generated_at="2026-01-01T00:00:00+00:00",
        hostname="pistyx",
        fqdn="pistyx.local",
        os_version="Test OS",
        architecture="x86_64",
        kernel_version="6.1.0",
        boot_time=None,
        current_user="tester",
        sudo_available=True,
        primary_lan_ip="10.0.0.1",
        bootstrap_ipv4="10.0.0.1",
        bootstrap_ipv6="fd00:cafe::1",
        default_route="default via 10.0.0.254",
        dns_resolvers=["10.0.0.2"],
        time_sync_status="System clock synchronized: yes",
        disk_usage="",
        memory_swap="",
        mounted_filesystems="",
        network_interfaces=[],
        interface_names=[],
        wireguard_interfaces=[],
        ports=PortScanResult(
            range_start=47800,
            range_end=47850,
            scanner="ss -H -lntup",
            command_available=True,
            returncode=0,
            timed_out=False,
            error=None,
            stdout="",
            stderr="",
            conflicts=[],
        ),
        detected_binaries={},
        detected_services={},
        detected_artifacts={key: [] for key in (
            "old_k3s_files",
            "old_kubelet_state",
            "old_cni_configs",
            "old_flannel_state",
            "old_cni_interfaces",
            "old_flannel_interfaces",
            "old_styx_interface_exact",
            "old_temporary_styx_files",
        )},
        cni_interfaces=[],
        firewall_backend={"preferred": "unknown"},
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_parse_nodes_from_example_config():
    from styxctl.config import load_config

    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    assert len(nodes) == 3
    assert nodes[0].name == "pistyx"
    assert nodes[0].role == "init-server"


def test_validate_nodes_requires_single_init_server():
    nodes = parse_nodes(
        {
            "nodes": [
                {
                    "name": "a",
                    "ipv4": "10.0.0.1",
                    "public_ipv4": "203.0.113.1",
                    "hostname": "a.duckdns.org",
                    "role": "server",
                },
                {
                    "name": "b",
                    "ipv4": "10.0.0.2",
                    "public_ipv4": "203.0.113.2",
                    "hostname": "b.duckdns.org",
                    "role": "server",
                },
            ]
        }
    )
    errors = validate_nodes(nodes)
    assert any("init-server" in error for error in errors)


def test_node_bootstrap_host_uses_public_ipv4():
    from styxctl.config import load_config
    from styxctl.nodes import node_bootstrap_host

    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    assert node_bootstrap_host(config, by_name["pistyx"]) == "203.0.113.10"


def test_identify_local_node_by_current_ip():
    from styxctl.config import load_config

    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    matched = identify_local_node(nodes, _inventory())
    assert matched is not None
    assert matched.name == "pistyx"
    assert matched.role == "init-server"
