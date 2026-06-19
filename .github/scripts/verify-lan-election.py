#!/usr/bin/env python3
"""Verify LAN election results for the pegasus/atlas hub (init-server + agent)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HUB_RUNNERS = frozenset({"pegasus", "atlas"})
CONFIGURED_ROLES = {"pegasus": "init-server", "atlas": "agent"}
SHARED_PUBLIC_IP = "71.104.114.70"


def main() -> int:
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/styx/lan-election-plan.json")
    if not report_path.is_file():
        print(f"LAN election report not found: {report_path}", file=sys.stderr)
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    election = report.get("lan_election") or {}
    if not election.get("enabled"):
        print("LAN election is not enabled in report", file=sys.stderr)
        return 1

    leader = election.get("leader") or {}
    leader_name = leader.get("node_name")
    peer_names = {peer.get("node_name") for peer in election.get("peers", []) if peer.get("node_name")}

    print(f"LAN peers: {sorted(peer_names)}")
    print(f"Elected leader: {leader_name}")

    if not leader_name:
        print("No LAN leader was elected", file=sys.stderr)
        return 1

    if leader_name not in HUB_RUNNERS:
        print(
            f"Expected hub leader in {sorted(HUB_RUNNERS)}, got {leader_name!r}",
            file=sys.stderr,
        )
        return 1

    local_peer = election.get("local_peer") or {}
    local_name = local_peer.get("node_name")
    if local_name and local_name not in HUB_RUNNERS:
        print(f"Runner {local_name!r} is not part of the co-located hub", file=sys.stderr)
        return 1

    hub_peers = peer_names & HUB_RUNNERS
    if hub_peers != HUB_RUNNERS and len(hub_peers) < 1:
        print("No co-located hub peers were discovered", file=sys.stderr)
        return 1

    unexpected_peers = peer_names - HUB_RUNNERS
    if unexpected_peers:
        print(f"Unexpected LAN peers outside hub: {sorted(unexpected_peers)}", file=sys.stderr)
        return 1

    if len(hub_peers) >= 2 and not election.get("promote_to_init_server"):
        print("Expected role promotion when both hub peers are present", file=sys.stderr)
        return 1

    from styxctl.config import load_config
    from styxctl.lan_election import apply_lan_election_roles
    from styxctl.lan_election import LanElectionResult, LanElectionSettings, LanPeer
    from styxctl.nodes import parse_nodes

    config_path = Path("styx.yaml")
    if not config_path.is_file():
        print("styx.yaml not found for role verification", file=sys.stderr)
        return 1

    config = load_config(config_path)
    nodes_before = {node.name: node.role for node in parse_nodes(config)}
    for name, role in CONFIGURED_ROLES.items():
        if nodes_before.get(name) != role:
            print(
                f"Expected configured role {name}={role!r}, got {nodes_before.get(name)!r}",
                file=sys.stderr,
            )
            return 1

    election_result = LanElectionResult(
        enabled=True,
        settings=LanElectionSettings(enabled=True),
        local_peer=_peer_from_dict(election.get("local_peer")),
        peers=[_peer_from_dict(peer) for peer in election.get("peers", []) if peer],
        leader=_peer_from_dict(leader) if leader else None,
        promote_to_init_server=bool(election.get("promote_to_init_server")),
        previous_init_server=election.get("previous_init_server"),
        subnet=election.get("subnet"),
        warnings=list(election.get("warnings") or []),
    )
    effective = apply_lan_election_roles(config, election_result)
    roles_after = {node.name: node.role for node in parse_nodes(effective)}

    init_servers = [name for name, role in roles_after.items() if role == "init-server"]
    if len(init_servers) != 1:
        print(f"Expected exactly one init-server after election, got {init_servers}", file=sys.stderr)
        return 1

    if init_servers[0] != leader_name:
        print(
            f"Elected leader {leader_name!r} is not init-server after role apply "
            f"(roles={roles_after})",
            file=sys.stderr,
        )
        return 1

    non_leader = (HUB_RUNNERS - {leader_name}).pop()
    allowed_follower_roles = {"agent", "server"}
    if roles_after.get(non_leader) not in allowed_follower_roles:
        print(
            f"Expected follower {non_leader} to remain agent or demote to server, "
            f"got {roles_after.get(non_leader)!r}",
            file=sys.stderr,
        )
        return 1

    subnet = election.get("subnet")
    if subnet:
        print(f"LAN subnet: {subnet}")

    print(f"Configured roles: {CONFIGURED_ROLES}")
    print(f"Effective roles: {roles_after}")
    print(f"Hub site public IP: {SHARED_PUBLIC_IP}")
    print("LAN hub election check passed")
    return 0


def _peer_from_dict(data: dict | None) -> LanPeer | None:
    if not data:
        return None
    return LanPeer(
        node_name=str(data["node_name"]),
        lan_ip=str(data["lan_ip"]),
        strength=int(data["strength"]),
        hostname=str(data["hostname"]),
        cluster_name=str(data["cluster_name"]),
    )


if __name__ == "__main__":
    raise SystemExit(main())
