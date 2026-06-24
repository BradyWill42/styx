#!/usr/bin/env python3
"""Verify pegasus and atlas saw the same live LAN election result."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HUB_RUNNERS = ("pegasus", "atlas")
REQUIRED_HUB_PEERS = frozenset({"pegasus", "atlas"})


def _election_from_artifact(base: Path, runner: str) -> dict | None:
    for path in sorted(base.glob(f"**/{runner}.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        election = payload.get("lan_election")
        if election:
            return election
    for path in sorted(base.glob(f"**/{runner}-lan-election.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        election = payload.get("lan_election")
        if election:
            return election
    return None


def main() -> int:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("runner-artifacts")
    elections: dict[str, dict] = {}

    for runner in HUB_RUNNERS:
        election = _election_from_artifact(base, runner)
        if election is None:
            print(f"Missing LAN election data for {runner}", file=sys.stderr)
            return 1
        elections[runner] = election

    leaders: dict[str, str | None] = {}
    peer_sets: dict[str, set[str]] = {}

    for runner, election in elections.items():
        leader = (election.get("leader") or {}).get("node_name")
        peers = {
            peer.get("node_name")
            for peer in election.get("peers", [])
            if peer.get("node_name")
        }
        leaders[runner] = leader
        peer_sets[runner] = peers
        print(f"{runner}: peers={sorted(peers)} leader={leader}")

    for runner in HUB_RUNNERS:
        hub_peers = peer_sets[runner] & REQUIRED_HUB_PEERS
        if hub_peers != REQUIRED_HUB_PEERS:
            print(
                f"{runner} did not discover both hub peers "
                f"(saw {sorted(hub_peers)}, need {sorted(REQUIRED_HUB_PEERS)})",
                file=sys.stderr,
            )
            return 1

    if leaders.get("pegasus") != leaders.get("atlas"):
        print(
            f"Leader mismatch: pegasus={leaders.get('pegasus')!r} "
            f"atlas={leaders.get('atlas')!r}",
            file=sys.stderr,
        )
        return 1

    print("Hub LAN election consensus check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
