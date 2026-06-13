"""Tests for sysprep readiness evaluation and report rendering."""

from __future__ import annotations

from styxctl.ports import PortConflict
from styxctl.reports import build_report_data, evaluate_readiness, render_sysprep_text

from tests.helpers import blocked_port_conflict, empty_port_scan, make_inventory


def test_evaluate_readiness_ready():
    status, warnings, blocking = evaluate_readiness(make_inventory())
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
    inventory = make_inventory(ports=empty_port_scan(conflicts=[conflict]))
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
    inventory = make_inventory(ports=empty_port_scan(conflicts=[conflict]))
    status, warnings, blocking = evaluate_readiness(inventory)
    assert status == "READY_WITH_WARNINGS"
    assert warnings
    assert blocking == []


def test_build_and_render_report():
    report = build_report_data(make_inventory(), command="styxctl sysprep check local")
    text = render_sysprep_text(report)
    assert report["status"] == "READY"
    assert "Status: READY" in text
    assert "test-node" in text
    assert "47800/udp: free" in text
