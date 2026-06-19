"""Tests for LAN leader election."""

from __future__ import annotations

from styxctl.config import load_config
from styxctl.lan_election import (
    LanElectionResult,
    LanElectionSettings,
    LanPeer,
    apply_lan_election_roles,
    compute_node_strength,
    elect_lan_leader,
    filter_peers_to_configured_nodes,
    local_lan_subnet,
    parse_interface_ipv4,
    parse_lan_election_settings,
    resolve_lan_leadership,
    run_lan_election,
)
from styxctl.nodes import parse_nodes

from styxctl.nodes import init_server_node, parse_nodes, site_entrypoint_for

from tests.support import EXAMPLE_CONFIG_PATH, homelab_config, make_inventory
from tests.test_nodes import _colocated_config


def test_parse_lan_election_settings_enabled():
    settings = parse_lan_election_settings(
        {
            "cluster": {
                "leader": "lan-elected",
                "lan_election": {"port": 47802, "collect_sec": 5},
            }
        }
    )
    assert settings.enabled is True
    assert settings.port == 47802
    assert settings.collect_sec == 5.0


def test_parse_lan_election_settings_static_default():
    settings = parse_lan_election_settings({"cluster": {"name": "styx"}})
    assert settings.enabled is False


def test_compute_node_strength_prefers_more_resources():
    strong = make_inventory(
        architecture="x86_64",
        detected_binaries={"k3s": "/usr/local/bin/k3s"},
        disk_usage="Filesystem      1K-blocks    Used Available Use% Mounted on\n/dev/root      50000000 1000000  48000000   3% /",
    )
    weak = make_inventory(architecture="armv7l", detected_binaries={})
    assert compute_node_strength(strong) > compute_node_strength(weak)


def test_elect_lan_leader_picks_strongest():
    peers = [
        LanPeer("alpha", "10.0.0.1", 1000, "alpha", "styx"),
        LanPeer("beta", "10.0.0.2", 5000, "beta", "styx"),
        LanPeer("gamma", "10.0.0.3", 3000, "gamma", "styx"),
    ]
    leader = elect_lan_leader(peers)
    assert leader is not None
    assert leader.node_name == "beta"


def test_elect_lan_leader_tiebreaks_by_name():
    peers = [
        LanPeer("zebra", "10.0.0.1", 1000, "zebra", "styx"),
        LanPeer("alpha", "10.0.0.2", 1000, "alpha", "styx"),
    ]
    leader = elect_lan_leader(peers)
    assert leader is not None
    assert leader.node_name == "zebra"


def test_local_lan_subnet_from_interfaces():
    inventory = make_inventory(
        primary_lan_ip="192.168.1.10",
        network_interfaces=[
            "eth0  UP  192.168.1.10/24  fe80::1/64",
            "lo    UNKNOWN  127.0.0.1/8",
        ],
    )
    subnet = local_lan_subnet(inventory)
    assert subnet is not None
    assert str(subnet) == "192.168.1.0/24"


def test_parse_interface_ipv4_skips_loopback():
    parsed = parse_interface_ipv4(["lo  UNKNOWN  127.0.0.1/8", "eth0  UP  10.0.0.5/24"])
    assert len(parsed) == 1
    assert parsed[0][0] == "10.0.0.5"


def test_apply_lan_election_roles_promotes_leader():
    config = load_config(EXAMPLE_CONFIG_PATH)
    election = run_lan_election(config, make_inventory())
    election.enabled = True
    election.promote_to_init_server = True
    election.leader = LanPeer("node-agent", "10.0.0.3", 9000, "node-agent", "styx")

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    roles = {node.name: node.role for node in nodes}
    assert roles["node-agent"] == "init-server"
    assert roles["node-init"] == "server"


def test_apply_lan_election_roles_sets_site_entrypoint_and_lan_ip():
    config = _colocated_config()
    config["nodes"][1]["lan_ip"] = None
    election = run_lan_election(config, make_inventory(hostname="pegasus", primary_lan_ip="192.168.1.10"))
    election.enabled = True
    election.leader = LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx")
    election.peers = [
        LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx"),
        LanPeer("atlas", "192.168.1.11", 5000, "atlas", "styx"),
    ]

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    by_name = {node.name: node for node in nodes}
    assert by_name["pegasus"].site_entrypoint is True
    assert by_name["atlas"].site_entrypoint is False
    assert by_name["atlas"].lan_ip == "192.168.1.11"


def test_run_lan_election_disabled_by_default():
    config = {"cluster": {"name": "styx", "leader": "static"}}
    election = run_lan_election(config, make_inventory())
    assert election.enabled is False


def test_discover_lan_peers_includes_local_peer_when_subnet_unknown():
    settings = LanElectionSettings(enabled=True, port=47902, collect_sec=0.2)
    local_peer = LanPeer("node-init", "10.0.0.1", 1000, "node-init", "styx")
    inventory = make_inventory(network_interfaces=[])
    from styxctl.lan_election import discover_lan_peers

    peers = discover_lan_peers(settings, inventory, local_peer=local_peer, subnet=None)
    assert len(peers) == 1
    assert peers[0].node_name == "node-init"


def test_filter_peers_to_configured_nodes():
    config = load_config(EXAMPLE_CONFIG_PATH)
    peers = [
        LanPeer("node-init", "192.168.1.10", 1000, "node-init", "styx"),
        LanPeer("node-server", "192.168.1.11", 5000, "node-server", "styx"),
        LanPeer("rogue", "192.168.1.12", 9000, "rogue", "styx"),
    ]
    filtered = filter_peers_to_configured_nodes(peers, config)
    names = {peer.node_name for peer in filtered}
    assert names == {"node-init", "node-server"}
    assert elect_lan_leader(filtered).node_name == "node-server"


def test_run_lan_election_ignores_unlisted_lan_peers():
    config = load_config(EXAMPLE_CONFIG_PATH)
    config["cluster"]["leader"] = "lan-elected"
    election = run_lan_election(
        config,
        make_inventory(hostname="node-init", primary_lan_ip="192.168.1.10", bootstrap_ipv4="192.168.1.10"),
    )
    assert election.enabled is True
    assert all(peer.node_name in {"node-init", "node-server", "node-agent"} for peer in election.peers)


def test_build_local_peer_requires_configured_node():
    config = load_config(EXAMPLE_CONFIG_PATH)
    from styxctl.lan_election import build_local_peer

    peer = build_local_peer(
        config,
        make_inventory(
            hostname="unknown-host",
            primary_lan_ip="192.168.1.99",
            bootstrap_ipv4="192.168.1.99",
            bootstrap_ipv6=None,
        ),
    )
    assert peer is None


def test_resolve_lan_leadership_keeps_config_when_static():
    config = load_config(EXAMPLE_CONFIG_PATH)
    config["cluster"]["leader"] = "static"
    effective, election = resolve_lan_leadership(config, make_inventory())
    assert election.enabled is False
    assert parse_nodes(effective)[0].role == "init-server"


def test_elect_lan_leader_with_colocated_hub_peers():
    """pegasus and atlas elect a hub leader on their shared LAN."""
    peers = [
        LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx"),
        LanPeer("atlas", "192.168.1.11", 5000, "atlas", "styx"),
    ]
    leader = elect_lan_leader(peers)
    assert leader is not None
    assert leader.node_name == "pegasus"


def test_resolve_lan_leadership_elects_hub_leader_between_init_server_and_agent():
    config = homelab_config()
    election = LanElectionResult(
        enabled=True,
        settings=LanElectionSettings(enabled=True),
        local_peer=LanPeer("atlas", "192.168.1.11", 5000, "atlas", "styx"),
        peers=[
            LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx"),
            LanPeer("atlas", "192.168.1.11", 5000, "atlas", "styx"),
        ],
        leader=LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx"),
        promote_to_init_server=True,
        previous_init_server=None,
        subnet="192.168.1.0/24",
    )

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    by_name = {node.name: node for node in nodes}

    assert set(by_name) == {"pegasus", "atlas"}
    assert by_name["pegasus"].role == "init-server"
    assert by_name["atlas"].role == "agent"
    assert by_name["pegasus"].site_entrypoint is True
    assert site_entrypoint_for(by_name["atlas"], nodes).name == "pegasus"


def test_run_lan_election_keeps_roles_when_only_one_hub_peer_responds():
    config = homelab_config()
    election = run_lan_election(
        config,
        make_inventory(hostname="pegasus", primary_lan_ip="192.168.1.10", bootstrap_ipv4="192.168.1.10"),
    )
    election.enabled = True
    election.peers = [LanPeer("pegasus", "192.168.1.10", 9000, "pegasus", "styx")]
    election.leader = election.peers[0]
    election.promote_to_init_server = False
    election.warnings = ["only one Styx peer on this LAN; keeping configured roles"]

    effective = apply_lan_election_roles(config, election)
    nodes = parse_nodes(effective)
    assert init_server_node(nodes).name == "pegasus"
