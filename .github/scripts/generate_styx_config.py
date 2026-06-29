#!/usr/bin/env python3
"""Generate a styx.yaml for CI from the live GitHub runner labels.

The runner labels are the source of truth for online node membership and role selection.
Cluster-level settings come from the template. For online runners whose names appear in the
template `nodes:` list, CI also preserves optional metadata such as DuckDNS hostname,
explicit site index, and SSH user.
"""

from __future__ import annotations

import json
import sys

import yaml

ROLE_LABELS = ("init-server", "server", "agent")
PRESERVED_NODE_KEYS = (
    "hostname",
    "public_ipv4",
    "public_ipv6",
    "lan_ip",
    "site_index",
    "site_entrypoint",
    "ssh_user",
    "user",
)


def _template_nodes_by_name(template_config: dict) -> dict[str, dict]:
    raw_nodes = template_config.get("nodes")
    if not isinstance(raw_nodes, list):
        return {}
    indexed: dict[str, dict] = {}
    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            indexed[name.strip()] = item
    return indexed


def derive_nodes(runners_json: dict, template_config: dict | None = None) -> list[dict]:
    """Map online, name-labeled runners to cluster nodes, choosing one init-server."""
    template_nodes = _template_nodes_by_name(template_config or {})
    online: list[tuple[str, set[str]]] = []
    for runner in runners_json.get("runners", []):
        if runner.get("status") != "online":
            continue
        labels = {label.get("name") for label in runner.get("labels", [])}
        name = runner.get("name")
        if not name or name not in labels:
            continue
        capabilities = labels & set(ROLE_LABELS)
        if capabilities:
            online.append((name, capabilities))
    online.sort()

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
            role = "server"
        node = {"name": name, "role": role}
        template_node = template_nodes.get(name, {})
        for key in PRESERVED_NODE_KEYS:
            value = template_node.get(key)
            if value is not None:
                node[key] = value
        nodes.append(node)
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

    config["nodes"] = derive_nodes(runners_json, config)
    if not config["nodes"]:
        print("error: no online, name-labeled runners to build nodes from", file=sys.stderr)
        return 1

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("# AUTO-GENERATED for CI from live runner labels - do not edit.\n")
        yaml.safe_dump(config, handle, sort_keys=False, default_flow_style=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
