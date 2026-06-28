"""Pure IP-plan tests — no cluster, no network, no pithor."""

from styxctl.network_plan import (
    PISTYX_IPV4,
    PISTYX_IPV6,
    allocate_roadwarrior_ips,
    mesh_ipv4_for_node,
    mesh_ipv6_for_node,
    roadwarrior_ipv4_for_index,
)


def test_pistyx_reserved_addresses():
    assert PISTYX_IPV4 == "10.0.250.1"
    assert "250" in PISTYX_IPV6 and PISTYX_IPV6.endswith("::1")


def test_mesh_ipv4_is_index_plus_one():
    assert mesh_ipv4_for_node(0) == "10.0.0.1"
    assert mesh_ipv4_for_node(3) == "10.0.0.4"
    assert mesh_ipv6_for_node(0).startswith("fd00:cafe")


def test_roadwarrior_clients_start_after_pistyx():
    # .0 = network, .1 = pistyx (reserved), clients begin at .2
    assert roadwarrior_ipv4_for_index(0) == "10.0.250.2"
    assert roadwarrior_ipv4_for_index(0) != PISTYX_IPV4


def test_allocator_skips_issued_and_reserved():
    v4, _ = allocate_roadwarrior_ips({"10.0.250.2"}, set(), stack_mode="ipv4-only")
    assert v4 == "10.0.250.3"
    fresh, _ = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv4-only")
    assert fresh != PISTYX_IPV4


def test_allocator_prunes_by_stack_mode():
    v4, v6 = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv4-only")
    assert v4 is not None and v6 is None
    v4b, v6b = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv6-only")
    assert v4b is None and v6b is not None
    v4c, v6c = allocate_roadwarrior_ips(set(), set(), stack_mode="dual-stack")
    assert v4c is not None and v6c is not None
