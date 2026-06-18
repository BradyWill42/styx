"""Tests for automatic network detection."""

from __future__ import annotations

from styxctl.network_detect import detect_lan_ipv4, is_private_ipv4

from tests.support import make_inventory


def test_is_private_ipv4_detects_rfc1918():
    assert is_private_ipv4("192.168.1.10")
    assert is_private_ipv4("10.0.0.1")
    assert not is_private_ipv4("203.0.113.10")


def test_detect_lan_ipv4_prefers_bootstrap_private_address():
    inventory = make_inventory(
        bootstrap_ipv4="192.168.1.10",
        primary_lan_ip="192.168.1.10",
        network_interfaces=["eth0 UP 192.168.1.10/24"],
    )
    assert detect_lan_ipv4(inventory) == "192.168.1.10"


def test_detect_lan_ipv4_falls_back_to_interface_scan():
    inventory = make_inventory(
        bootstrap_ipv4="203.0.113.10",
        primary_lan_ip="203.0.113.10",
        network_interfaces=["eth0 UP 192.168.50.4/24"],
    )
    assert detect_lan_ipv4(inventory) == "192.168.50.4"
