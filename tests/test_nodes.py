"""Tests for styx cluster node configuration."""

from __future__ import annotations

from styxctl.inventory import SystemInventory
from styxctl.nodes import (
    all_node_tls_sans,
    identify_local_node,
    is_colocated,
    parse_nodes,
    site_entrypoint_for,
    sites_by_public_ip,
    validate_nodes,
    validate_nodes_warnings,
)
from styxctl.ports import PortScanResult

from tests.support import EXAMPLE_CONFIG_PATH


def _colocated_config(*, leader: str = "lan-elected", atlas_lan_ip: str | None = "192.168.1.11"):
    return {
        "cluster": {"leader": leader, "ssh_user": "ubuntu"},
        "gateway": {"ssh_port": 47810, "k3s_api_port": 47811},
        "dns": {
            "provider": "duckdns",
            "domain": "duckdns.org",
            "fixed_endpoints": {
                "pegasus": "pegasus",
                "atlas": "atlas",
                "thor": "thor",
            },
        },
        "nodes": [
            {
                "name": "pegasus",
                "public_ipv4": "71.104.114.70",
                "lan_ip": "192.168.1.10",
                "ipv4": "10.0.0.1",
                "ipv6": "fd00:cafe::1",
                "role": "init-server",
                "hostname": "pegasus.duckdns.org",
            },
            {
                "name": "atlas",
                "public_ipv4": "71.104.114.70",
                "lan_ip": atlas_lan_ip,
                "ipv4": "10.0.0.2",
                "ipv6": "fd00:cafe::2",
                "role": "server",
                "hostname": "atlas.duckdns.org",
            },
            {
                "name": "thor",
                "public_ipv4": "108.35.35.192",
                "ipv4": "10.0.0.3",
                "ipv6": "fd00:cafe::3",
                "role": "server",
                "hostname": "thor.duckdns.org",
            },
        ],
    }


def _inventory(**overrides) -> SystemInventory:
    base = SystemInventory(
        generated_at="2026-01-01T00:00:00+00:00",
        hostname="node-init",
        fqdn="node-init.local",
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
    assert nodes[0].name == "node-init"
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
    assert node_bootstrap_host(config, by_name["node-init"]) == "203.0.113.10"


def test_identify_local_node_by_current_ip():
    from styxctl.config import load_config

    config = load_config(EXAMPLE_CONFIG_PATH)
    nodes = parse_nodes(config)
    matched = identify_local_node(nodes, _inventory())
    assert matched is not None
    assert matched.name == "node-init"
    assert matched.role == "init-server"


def test_validate_nodes_allows_shared_public_ipv4_with_lan_elected():
    config = _colocated_config()
    nodes = parse_nodes(config)
    errors = validate_nodes(nodes, config)
    assert not any("duplicate bootstrap host" in error for error in errors)


def test_validate_nodes_rejects_shared_public_ipv4_without_election():
    config = _colocated_config(leader="static")
    nodes = parse_nodes(config)
    errors = validate_nodes(nodes, config)
    assert any("require local election" in error for error in errors)


def test_validate_nodes_rejects_duplicate_public_ipv4_without_colocation_support():
    nodes = parse_nodes(
        {
            "nodes": [
                {
                    "name": "a",
                    "ipv4": "10.0.0.1",
                    "public_ipv4": "203.0.113.1",
                    "hostname": "a.duckdns.org",
                    "role": "init-server",
                },
                {
                    "name": "b",
                    "ipv4": "10.0.0.2",
                    "public_ipv4": "203.0.113.1",
                    "hostname": "b.duckdns.org",
                    "role": "server",
                },
            ]
        }
    )
    errors = validate_nodes(nodes, {"cluster": {"leader": "static"}})
    assert any("duplicate bootstrap host" in error or "require local election" in error for error in errors)


def test_validate_nodes_requires_lan_ip_for_remote_colocated_nodes():
    config = _colocated_config(atlas_lan_ip=None)
    nodes = parse_nodes(config)
    errors = validate_nodes(nodes, config, require_lan_ip=True)
    assert any("nodes.atlas" in error and "lan_ip is required" in error for error in errors)


def test_validate_nodes_warnings_when_lan_ip_deferred_to_election():
    config = _colocated_config(atlas_lan_ip=None)
    nodes = parse_nodes(config)
    warnings = validate_nodes_warnings(nodes, config)
    assert any("nodes.atlas" in warning and "local election will fill it" in warning for warning in warnings)


def test_sites_by_public_ip_groups_colocated_nodes():
    nodes = parse_nodes(_colocated_config())
    sites = sites_by_public_ip(nodes)
    assert len(sites["71.104.114.70"]) == 2
    assert {node.name for node in sites["71.104.114.70"]} == {"pegasus", "atlas"}


def test_site_entrypoint_for_prefers_explicit_flag():
    nodes = parse_nodes(_colocated_config(leader="static"))
    nodes[1].site_entrypoint = True
    entrypoint = site_entrypoint_for(nodes[1], nodes)
    assert entrypoint is not None
    assert entrypoint.name == "atlas"


def test_site_entrypoint_for_falls_back_to_init_server():
    nodes = parse_nodes(_colocated_config())
    by_name = {node.name: node for node in nodes}
    entrypoint = site_entrypoint_for(by_name["atlas"], nodes)
    assert entrypoint is not None
    assert entrypoint.name == "pegasus"


def test_is_colocated_detects_shared_wan_site():
    nodes = parse_nodes(_colocated_config())
    by_name = {node.name: node for node in nodes}
    assert is_colocated(by_name["atlas"], nodes)
    assert not is_colocated(by_name["thor"], nodes)


def test_all_node_tls_sans_includes_explicit_lan_ip():
    nodes = parse_nodes(_colocated_config())
    sans = all_node_tls_sans(nodes)
    assert "192.168.1.10" in sans
    assert "192.168.1.11" in sans


def test_validate_nodes_allows_local_colocated_node_without_lan_ip():
    config = _colocated_config(atlas_lan_ip=None)
    nodes = parse_nodes(config)
    inventory = _inventory(
        hostname="atlas",
        fqdn="atlas.local",
        bootstrap_ipv4="192.168.1.11",
        bootstrap_ipv6=None,
        primary_lan_ip="192.168.1.11",
        network_interfaces=["eth0 UP 192.168.1.11/24"],
    )
    local_node = identify_local_node(nodes, inventory, config)
    assert local_node is not None
    errors = validate_nodes(nodes, config, inventory=inventory, local_node=local_node)
    assert not any("nodes.atlas" in error and "lan_ip is required" in error for error in errors)


def test_all_node_tls_sans_uses_auto_detected_lan_ip():
    config = _colocated_config(atlas_lan_ip=None)
    nodes = parse_nodes(config)
    inventory = _inventory(
        hostname="atlas",
        fqdn="atlas.local",
        bootstrap_ipv4="192.168.1.11",
        bootstrap_ipv6=None,
        primary_lan_ip="192.168.1.11",
        network_interfaces=["eth0 UP 192.168.1.11/24"],
    )
    local_node = identify_local_node(nodes, inventory, config)
    assert local_node is not None
    sans = all_node_tls_sans(nodes, config, inventory=inventory, local_node=local_node)
    assert "192.168.1.11" in sans

