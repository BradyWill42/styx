"""Tests for the built-in Styx backbone network plan."""

from __future__ import annotations

from styxctl.network_plan import (
    DEFAULT_NETWORK,
    mesh_ipv4_for_node,
    mesh_ipv6_for_node,
)


def test_mesh_ip_assignment_uses_fixed_plan():
    assert mesh_ipv4_for_node(0) == "10.0.0.1"
    assert mesh_ipv4_for_node(2) == "10.0.0.3"
    assert mesh_ipv6_for_node(0) == "fd00:cafe::1"
    assert mesh_ipv6_for_node(2) == "fd00:cafe::3"


def test_default_network_contains_k3s_cidrs():
    assert DEFAULT_NETWORK["pod_ipv4"] == "10.2.0.0/16"
    assert DEFAULT_NETWORK["service_ipv4"] == "10.3.0.0/16"
