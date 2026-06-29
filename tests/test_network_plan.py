"""Pure IP-plan tests — no cluster, no network, no pithor."""

from styxctl.network_plan import (
    PISTYX_IPV4,
    PISTYX_IPV6,
    allocate_roadwarrior_ips,
    client_ipv4_for_site,
    mesh_ipv4_for_node,
    mesh_ipv6_for_node,
    node_host_suffix_for_index,
    node_ipv4_for_site,
    node_ipv6_for_site,
    pistyx_ipv4_for_site,
    site_ipv4_for_host,
    site_ipv4_network,
    roadwarrior_ipv4_for_index,
)


def test_pistyx_reserved_addresses():
    assert PISTYX_IPV4 == "10.0.250.1"
    assert "250" in PISTYX_IPV6 and PISTYX_IPV6.endswith("::1")
    assert pistyx_ipv4_for_site(1) == "10.0.1.1"
    assert pistyx_ipv4_for_site(2) == "10.0.2.1"


def test_site_scoped_identity_keeps_host_suffix():
    assert site_ipv4_network(1) == "10.0.1.0/24"
    assert site_ipv4_for_host(1, 7) == "10.0.1.7"
    assert site_ipv4_for_host(2, 7) == "10.0.2.7"
    assert client_ipv4_for_site(0, site_index=1) == "10.0.1.2"
    assert client_ipv4_for_site(0, site_index=2) == "10.0.2.2"


def test_mesh_ipv4_is_index_plus_one():
    assert mesh_ipv4_for_node(0) == "10.0.0.1"
    assert mesh_ipv4_for_node(3) == "10.0.0.4"
    assert mesh_ipv6_for_node(0).startswith("fd00:cafe")


def test_pi_site_identity_uses_stable_reserved_suffix():
    assert node_host_suffix_for_index(0) == 10
    assert node_ipv4_for_site(0, site_index=1) == "10.0.1.10"
    assert node_ipv4_for_site(0, site_index=2) == "10.0.2.10"
    assert node_ipv4_for_site(3, site_index=1) == "10.0.1.13"
    assert node_ipv6_for_site(3, site_index=2) == "fd00:cafe:0:2::d"


def test_roadwarrior_clients_start_after_pistyx():
    # .0 = network, .1 = pistyx (reserved), clients begin at .2
    assert roadwarrior_ipv4_for_index(0) == "10.0.250.2"
    assert roadwarrior_ipv4_for_index(0) != PISTYX_IPV4


def test_allocator_skips_issued_and_reserved():
    v4, _ = allocate_roadwarrior_ips({"10.0.250.2"}, set(), stack_mode="ipv4-only")
    assert v4 == "10.0.250.3"
    fresh, _ = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv4-only")
    assert fresh != PISTYX_IPV4
    site_v4, _ = allocate_roadwarrior_ips({"10.0.1.2"}, set(), stack_mode="ipv4-only", site_index=1)
    assert site_v4 == "10.0.1.3"


def test_allocator_prunes_by_stack_mode():
    v4, v6 = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv4-only")
    assert v4 is not None and v6 is None
    v4b, v6b = allocate_roadwarrior_ips(set(), set(), stack_mode="ipv6-only")
    assert v4b is None and v6b is not None
    v4c, v6c = allocate_roadwarrior_ips(set(), set(), stack_mode="dual-stack")
    assert v4c is not None and v6c is not None
