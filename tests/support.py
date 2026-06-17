"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from styxctl.inventory import SystemInventory
from styxctl.ports import PortScanResult

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG_PATH = REPO_ROOT / "styx.yaml.example"

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
