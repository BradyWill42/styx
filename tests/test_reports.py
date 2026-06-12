"""Tests for sysprep readiness evaluation and report rendering."""

from __future__ import annotations

from styxctl.inventory import SystemInventory
from styxctl.ports import PortConflict, PortScanResult
from styxctl.reports import build_report_data, evaluate_readiness, render_sysprep_text


def _empty_inventory(**overrides) -> SystemInventory:
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
        "ports": PortScanResult(
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
        "detected_binaries": {},
        "detected_services": {},
        "detected_artifacts": {
            "old_k3s_files": [],
            "old_kubelet_state": [],
            "old_cni_configs": [],
            "old_flannel_state": [],
            "old_cni_interfaces": [],
            "old_flannel_interfaces": [],
            "old_styx_interface_exact": [],
            "old_temporary_styx_files": [],
        },
        "cni_interfaces": [],
        "firewall_backend": {"preferred": "unknown"},
    }
    defaults.update(overrides)
    return SystemInventory(**defaults)


def test_evaluate_readiness_ready():
    status, warnings, blocking = evaluate_readiness(_empty_inventory())
    assert status == "READY"
    assert warnings == []
    assert blocking == []


def test_evaluate_readiness_blocked_on_critical_port():
    conflict = PortConflict(
        protocol="udp",
        port=47800,
        process_name="old-styx",
        pid=123,
        systemd_unit="old-styx.service",
        command_line="/usr/bin/old-styx",
        safe_to_stop=True,
        raw="",
    )
    inventory = _empty_inventory(
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
            conflicts=[conflict],
        )
    )
    status, warnings, blocking = evaluate_readiness(inventory)
    assert status == "BLOCKED"
    assert blocking
    assert not warnings


def test_evaluate_readiness_warns_on_non_critical_port():
    conflict = PortConflict(
        protocol="tcp",
        port=47830,
        process_name="debug",
        pid=456,
        systemd_unit=None,
        command_line=None,
        safe_to_stop=False,
        raw="",
    )
    inventory = _empty_inventory(
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
            conflicts=[conflict],
        )
    )
    status, warnings, blocking = evaluate_readiness(inventory)
    assert status == "READY_WITH_WARNINGS"
    assert warnings
    assert blocking == []


def test_build_and_render_report():
    report = build_report_data(_empty_inventory(), command="styxctl sysprep check local")
    text = render_sysprep_text(report)
    assert report["status"] == "READY"
    assert "Status: READY" in text
    assert "test-node" in text
    assert "47800/udp: free" in text
