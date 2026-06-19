"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from styxctl.inventory import SystemInventory
from styxctl.ports import PortScanResult

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG_PATH = REPO_ROOT / "styx.yaml.example"
HOMELAB_CONFIG_PATH = REPO_ROOT / "styx.yaml.homelab"

ARTIFACT_KEYS = (
    "old_k3s_files",
    "old_kubelet_state",
    "old_cni_configs",
    "old_flannel_state",
    "old_cni_interfaces",
    "old_flannel_interfaces",
    "old_styx_interface_exact",
    "old_temporary_styx_files",
)


def example_config_text() -> str:
    return EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8")


def homelab_config(*, leader: str = "lan-elected", atlas_lan_ip: str | None = "192.168.1.11") -> dict[str, Any]:
    """Homelab topology: pegasus + atlas co-located, thor remote."""
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


def empty_artifacts() -> dict[str, list[str]]:
    return {key: [] for key in ARTIFACT_KEYS}


def make_inventory(**overrides) -> SystemInventory:
    inventory = SystemInventory(
        generated_at="2026-01-01T00:00:00+00:00",
        hostname="test-node",
        fqdn="test-node.local",
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
        detected_binaries={
            "k3s": None,
            "kubectl": None,
            "wg": None,
            "ss": "/usr/bin/ss",
            "curl": "/usr/bin/curl",
        },
        detected_services={"k3s": {"active": "inactive", "enabled": "disabled"}},
        detected_artifacts=empty_artifacts(),
        cni_interfaces=[],
        firewall_backend={"preferred": "unknown", "binaries": {}, "services": {}},
    )
    for key, value in overrides.items():
        setattr(inventory, key, value)
    return inventory
