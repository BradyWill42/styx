#!/usr/bin/env python3
"""Generate a styx.yaml for CI from the live GitHub runner labels.

The runner labels are the single source of truth: each online, name-labeled runner
becomes a node (name = runner name, role = its role label), with exactly one init-server
chosen. Cluster-level settings (cluster:, dns:) come from the template (styx.yaml.example);
the template's own example `nodes:` list is ignored.

Hostnames are intentionally omitted: colocated runners are discovered via the LAN scan, so
no DuckDNS name is needed for CI. A remote node would need a name->DuckDNS hostname map
(not derivable from a label) — out of scope while the fleet is colocated.
"""

from __future__ import annotations

import json
import sys

import yaml

ROLE_LABELS = ("init-server", "server", "agent")


def derive_nodes(runners_json: dict) -> list[dict]:
    """Map online, name-labeled runners to cluster nodes, choosing one init-server."""
    online: list[tuple[str, set[str]]] = []
    for runner in runners_json.get("runners", []):
        if runner.get("status") != "online":
            continue
        labels = {label.get("name") for label in runner.get("labels", [])}
        name = runner.get("name")
        if not name or name not in labels:
            continue  # must be targetable by its own name label
        capabilities = labels & set(ROLE_LABELS)
        if capabilities:
            online.append((name, capabilities))
    online.sort()

    # Exactly one init-server. Prefer an init-server-only runner so dual-capable runners
    # (e.g. init-server+server) stay free to fill the server role.
    init_only = [name for name, caps in online if caps == {"init-server"}]
    init_capable = [name for name, caps in online if "init-server" in caps]
    chosen_init = (init_only or init_capable or [None])[0]

    nodes: list[dict] = []
    for name, caps in online:
        if name == chosen_init:
            role = "init-server"
        elif "agent" in caps:
            role = "agent"
        else:
            role = "server"  # plain server, or init-capable runner not chosen as init
        nodes.append({"name": name, "role": role})
    return nodes


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: generate_styx_config.py <runners.json> <template.yaml> <out.yaml>", file=sys.stderr)
        return 2
    runners_path, template_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(runners_path, encoding="utf-8") as handle:
        runners_json = json.load(handle)
    with open(template_path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    config["nodes"] = derive_nodes(runners_json)
    if not config["nodes"]:
        print("error: no online, name-labeled runners to build nodes from", file=sys.stderr)
        return 1

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("# AUTO-GENERATED for CI from live runner labels — do not edit.\n")
        yaml.safe_dump(config, handle, sort_keys=False, default_flow_style=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
