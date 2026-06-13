"""Shared test fixtures for styxctl."""

from __future__ import annotations

from styxctl.inventory import SystemInventory
from styxctl.ports import PortConflict, PortScanResult

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


def empty_port_scan(**overrides) -> PortScanResult:
    defaults = {
        "range_start": 47800,
        "range_end": 47850,
        "scanner": "ss -H -lntup",
        "command_available": True,
        "returncode": 0,
        "timed_out": False,
        "error": None,
        "stdout": "",
        "stderr": "",
        "conflicts": [],
    }
    defaults.update(overrides)
    return PortScanResult(**defaults)


def make_inventory(**overrides) -> SystemInventory:
    defaults = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "hostname": "test-node",
        "fqdn": "test-node.local",
        "os_version": "Test OS",
        "architecture": "x86_64",
        "kernel_version": "6.1.0",
        "boot_time": None,
        "current_user": "tester",
        "sudo_available": True,
        "primary_lan_ip": "10.0.0.1",
        "bootstrap_ipv4": "10.0.0.1",
        "bootstrap_ipv6": None,
        "default_route": "default via 10.0.0.254",
        "dns_resolvers": ["10.0.0.2"],
        "time_sync_status": "System clock synchronized: yes",
        "disk_usage": "",
        "memory_swap": "",
        "mounted_filesystems": "",
        "network_interfaces": [],
        "interface_names": [],
        "wireguard_interfaces": [],
        "ports": empty_port_scan(),
        "detected_binaries": {},
        "detected_services": {},
        "detected_artifacts": {key: [] for key in ARTIFACT_KEYS},
        "cni_interfaces": [],
        "firewall_backend": {"preferred": "unknown"},
    }
    defaults.update(overrides)
    return SystemInventory(**defaults)


def blocked_port_conflict() -> PortConflict:
    return PortConflict(
        protocol="udp",
        port=47800,
        process_name="old-styx",
        pid=123,
        systemd_unit="old-styx.service",
        command_line="/usr/bin/old-styx",
        safe_to_stop=True,
        raw="",
    )
