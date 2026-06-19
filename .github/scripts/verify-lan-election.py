#!/usr/bin/env python3
"""Verify LAN election results for co-located hub runners (pegasus/atlas)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

COLOCATED_HUB = frozenset({"pegasus", "atlas"})
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

    if leader_name not in COLOCATED_HUB:
        print(
            f"Expected hub leader in {sorted(COLOCATED_HUB)}, got {leader_name!r}",
            file=sys.stderr,
        )
        return 1

    local_peer = election.get("local_peer") or {}
    local_name = local_peer.get("node_name")
    if local_name and local_name not in COLOCATED_HUB:
        print(f"Runner {local_name!r} is not part of the co-located hub", file=sys.stderr)
        return 1

    # When thor is offline it cannot appear as a LAN peer; hub nodes still elect locally.
    hub_peers = peer_names & COLOCATED_HUB
    if len(hub_peers) < 1:
        print("No co-located hub peers were discovered", file=sys.stderr)
        return 1

    if len(hub_peers) >= 2 and not election.get("promote_to_init_server"):
        print("Expected role promotion when multiple hub peers are present", file=sys.stderr)
        return 1

    subnet = election.get("subnet")
    if subnet:
        print(f"LAN subnet: {subnet}")

    print(f"Hub site public IP: {SHARED_PUBLIC_IP}")
    print("LAN hub election check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
