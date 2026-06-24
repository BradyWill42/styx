"""Three-site connectivity: hub LAN election and cross-WAN SSH routing.

Topology:
- pegasus + atlas share public_ipv4 71.104.114.70 (same LAN, local election)
- thor has a distinct public_ipv4 and reaches the hub via WAN SSH
"""

from __future__ import annotations

import pytest

from styxctl.k3s_cluster import _node_plan_target_host, _node_ssh_connection, build_cluster_plan
from styxctl.lan_election import (
    LanElectionResult,
    LanElectionSettings,
    LanPeer,
    apply_lan_election_roles,
    elect_lan_leader,
    filter_peers_to_configured_nodes,
    resolve_lan_leadership,
    run_lan_election,
)
from styxctl.nodes import identify_local_node, is_colocated, parse_nodes, site_entrypoint_for, sites_by_public_ip

from tests.support import (
    HUB_PUBLIC_IPV4,
    THOR_PUBLIC_IPV4,
    homelab_three_node_config,
    make_inventory,
)


def _hub_peers(*, pegasus_strength: int = 9000, atlas_strength: int = 5000) -> list[LanPeer]:
    return [
        LanPeer("pegasus", "192.168.1.10", pegasus_strength, "pegasus", "styx"),
        LanPeer("atlas", "192.168.1.11", atlas_strength, "atlas", "styx"),
    ]


def _hub_election_result(
    config: dict,
    *,
    pegasus_strength: int = 9000,
    atlas_strength: int = 5000,
    local_node_name: str = "pegasus",
) -> LanElectionResult:
    peers = _hub_peers(pegasus_strength=pegasus_strength, atlas_strength=atlas_strength)
    leader = elect_lan_leader(peers)
    local_peer = next(peer for peer in peers if peer.node_name == local_node_name)
    return LanElectionResult(
        enabled=True,
        settings=LanElectionSettings(enabled=True),
        local_peer=local_peer,
        peers=peers,
        leader=leader,
        promote_to_init_server=True,
        previous_init_server=None,
        subnet="192.168.1.0/24",
    )


def _thor_inventory(**overrides):
    return make_inventory(
        hostname="thor",
        primary_lan_ip="10.50.0.5",
        bootstrap_ipv4="10.50.0.5",
        network_interfaces=["eth0  UP  10.50.0.5/24"],
        **overrides,
    )


def _pegasus_inventory(**overrides):
    return make_inventory(
        hostname="pegasus",
        primary_lan_ip="192.168.1.10",
        bootstrap_ipv4="192.168.1.10",
        network_interfaces=["eth0  UP  192.168.1.10/24"],
        **overrides,
    )


def _atlas_inventory(**overrides):
    return make_inventory(
        hostname="atlas",
        primary_lan_ip="192.168.1.11",
        bootstrap_ipv4="192.168.1.11",
        network_interfaces=["eth0  UP  192.168.1.11/24"],
        **overrides,
    )


def test_three_node_topology_groups_hub_and_remote_sites():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    sites = sites_by_public_ip(nodes)

    assert len(sites) == 2
    assert {node.name for node in sites[HUB_PUBLIC_IPV4]} == {"pegasus", "atlas"}
    assert [node.name for node in sites[THOR_PUBLIC_IPV4]] == ["thor"]
    assert is_colocated(nodes[0], nodes) is True
    assert is_colocated(nodes[2], nodes) is False


def test_hub_lan_election_peers_are_only_colocated_nodes():
    config = homelab_three_node_config()
    all_peers = _hub_peers() + [LanPeer("thor", "10.50.0.5", 7000, "thor", "styx")]

    filtered = filter_peers_to_configured_nodes(all_peers, config)

    assert {peer.node_name for peer in filtered} == {"pegasus", "atlas", "thor"}
    hub_only = [peer for peer in filtered if peer.node_name in {"pegasus", "atlas"}]
    leader = elect_lan_leader(hub_only)
    assert leader is not None
    assert leader.node_name == "pegasus"


def test_run_lan_election_on_hub_discovers_only_local_site_peers(monkeypatch):
    config = homelab_three_node_config()

    def fake_discover(settings, inventory, *, local_peer, subnet=None):
        assert local_peer.node_name == "pegasus"
        return _hub_peers()

    monkeypatch.setattr("styxctl.lan_election.discover_lan_peers", fake_discover)

    election = run_lan_election(config, _pegasus_inventory())

    assert election.enabled is True
    assert {peer.node_name for peer in election.peers} == {"pegasus", "atlas"}
    assert election.leader is not None
    assert election.leader.node_name == "pegasus"
    assert election.promote_to_init_server is True
    assert "thor" not in {peer.node_name for peer in election.peers}


def test_run_lan_election_on_thor_is_single_peer_site(monkeypatch):
    config = homelab_three_node_config()
    thor_peer = LanPeer("thor", "10.50.0.5", 7000, "thor", "styx")

    monkeypatch.setattr(
        "styxctl.lan_election.discover_lan_peers",
        lambda *args, **kwargs: [thor_peer],
    )

    election = run_lan_election(config, _thor_inventory())

    assert election.enabled is True
    assert [peer.node_name for peer in election.peers] == ["thor"]
    assert election.leader is not None
    assert election.leader.node_name == "thor"
    assert election.promote_to_init_server is False
    assert any("only one Styx peer on this LAN" in warning for warning in election.warnings)


def test_apply_lan_election_roles_marks_hub_leader_as_site_entrypoint():
    config = homelab_three_node_config()
    election = _hub_election_result(config)

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    by_name = {node.name: node for node in nodes}

    assert by_name["pegasus"].site_entrypoint is True
    assert by_name["atlas"].site_entrypoint is False
    assert by_name["thor"].site_entrypoint is not True
    assert site_entrypoint_for(by_name["atlas"], nodes, election_leader="pegasus").name == "pegasus"


@pytest.mark.parametrize(
    ("pegasus_strength", "atlas_strength", "expected_leader"),
    [
        (9000, 5000, "pegasus"),
        (5000, 9000, "atlas"),
    ],
)
def test_hub_lan_election_picks_strongest_colocated_leader(
    pegasus_strength: int,
    atlas_strength: int,
    expected_leader: str,
):
    config = homelab_three_node_config()
    election = _hub_election_result(
        config,
        pegasus_strength=pegasus_strength,
        atlas_strength=atlas_strength,
        local_node_name="atlas",
    )

    assert election.leader is not None
    assert election.leader.node_name == expected_leader

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    by_name = {node.name: node for node in nodes}
    assert by_name[expected_leader].site_entrypoint is True
    assert site_entrypoint_for(by_name["pegasus"], nodes, election_leader=expected_leader).name == expected_leader


def test_resolve_lan_leadership_from_atlas_applies_hub_roles(monkeypatch):
    config = homelab_three_node_config()

    def fake_discover(settings, inventory, *, local_peer, subnet=None):
        return _hub_peers(pegasus_strength=5000, atlas_strength=9000)

    monkeypatch.setattr("styxctl.lan_election.discover_lan_peers", fake_discover)

    effective, election = resolve_lan_leadership(config, _atlas_inventory())
    nodes = parse_nodes(effective)
    by_name = {node.name: node for node in nodes}

    assert election.leader is not None
    assert election.leader.node_name == "atlas"
    assert by_name["atlas"].role == "init-server"
    assert by_name["pegasus"].role == "server"
    assert by_name["atlas"].site_entrypoint is True


def test_thor_ssh_to_elected_hub_leader_uses_public_wan():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    thor_node = identify_local_node(nodes, _thor_inventory(), config)

    connection = _node_ssh_connection(
        by_name["pegasus"],
        nodes,
        "ubuntu",
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_leader="pegasus",
    )

    assert connection.jump is None
    assert connection.target == f"ubuntu@{HUB_PUBLIC_IPV4}"
    assert connection.port == 47810


@pytest.mark.parametrize("election_leader", ["pegasus", "atlas"])
def test_thor_ssh_to_elected_hub_leader_when_leader_is_entrypoint(election_leader: str):
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    thor_node = identify_local_node(nodes, _thor_inventory(), config)

    connection = _node_ssh_connection(
        by_name[election_leader],
        nodes,
        "ubuntu",
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_leader=election_leader,
    )

    assert connection.jump is None
    assert connection.target == f"ubuntu@{HUB_PUBLIC_IPV4}"


def test_thor_ssh_to_non_leader_hub_node_uses_jump_via_elected_leader():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    thor_node = identify_local_node(nodes, _thor_inventory(), config)

    connection = _node_ssh_connection(
        by_name["atlas"],
        nodes,
        "ubuntu",
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_leader="pegasus",
    )

    assert connection.jump == f"ubuntu@{HUB_PUBLIC_IPV4}"
    assert connection.target == "ubuntu@192.168.1.11"


def test_thor_ssh_to_pegasus_when_atlas_elected_uses_jump_via_hub_wan():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    thor_node = identify_local_node(nodes, _thor_inventory(), config)

    connection = _node_ssh_connection(
        by_name["pegasus"],
        nodes,
        "ubuntu",
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_leader="atlas",
    )

    assert connection.jump == f"ubuntu@{HUB_PUBLIC_IPV4}"
    assert connection.target == "ubuntu@192.168.1.10"


def test_hub_nodes_ssh_each_other_directly_on_lan():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    pegasus_node = identify_local_node(nodes, _pegasus_inventory(), config)

    connection = _node_ssh_connection(
        by_name["atlas"],
        nodes,
        "ubuntu",
        config,
        inventory=_pegasus_inventory(),
        local_node=pegasus_node,
        election_leader="pegasus",
    )

    assert connection.jump is None
    assert connection.target == "ubuntu@192.168.1.11"


def test_build_cluster_plan_hub_atlas_joins_via_lan():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    pegasus_node = identify_local_node(nodes, _pegasus_inventory(), config)
    election_lan_ips = {"pegasus": "192.168.1.10", "atlas": "192.168.1.11"}

    plan = build_cluster_plan(
        config,
        inventory=_pegasus_inventory(),
        local_node=pegasus_node,
        election_lan_ips=election_lan_ips,
        election_leader="pegasus",
    )
    by_name = {item.node.name: item for item in plan.nodes}

    assert by_name["atlas"].k3s_env["K3S_URL"] == "https://192.168.1.10:47811"
    assert by_name["thor"].k3s_env["K3S_URL"] == f"https://{HUB_PUBLIC_IPV4}:47811"


def test_build_cluster_plan_thor_target_uses_hub_wan():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    thor_node = identify_local_node(nodes, _thor_inventory(), config)
    election_lan_ips = {"pegasus": "192.168.1.10", "atlas": "192.168.1.11"}

    plan = build_cluster_plan(
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_lan_ips=election_lan_ips,
        election_leader="pegasus",
    )
    by_name = {item.node.name: item for item in plan.nodes}

    assert by_name["pegasus"].target_host == HUB_PUBLIC_IPV4
    assert by_name["atlas"].target_host == "ubuntu@192.168.1.11 via ubuntu@71.104.114.70"
    assert by_name["thor"].local_execution is True
    assert by_name["thor"].target_host == THOR_PUBLIC_IPV4


def test_node_plan_target_host_from_thor_to_elected_leader():
    config = homelab_three_node_config()
    nodes = parse_nodes(config)
    by_name = {node.name: node for node in nodes}
    thor_node = identify_local_node(nodes, _thor_inventory(), config)

    host = _node_plan_target_host(
        by_name["pegasus"],
        nodes,
        config,
        inventory=_thor_inventory(),
        local_node=thor_node,
        election_leader="pegasus",
    )

    assert host == HUB_PUBLIC_IPV4
