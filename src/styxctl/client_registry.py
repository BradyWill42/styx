"""Automatic client registration - persist a roadwarrior into styx.yaml's `clients:` block.

A client is only accepted by a leader's pistyx PoP once it is a registered peer. The manual flow
is "add the client under `clients:` then `styxctl mesh up`"; this module automates the first half
so `styxctl client config <name> --register` records the peer (name + public key + stable host
suffix) and the next `mesh up` renders it onto every leader's PoP.

The `clients:` block is treated as a machine-managed section: we regenerate just that block and
splice it back in, preserving every other line/comment in the file (and writing a ``.bak`` first).
The list-mutation, suffix allocation, and block splice are pure and unit-tested; only
``register_client`` touches disk.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def _client_suffix_bounds() -> tuple[int, int]:
    from .network_plan import PISTYX_HOST_SUFFIX, SITE_CLIENT_OFFSET

    return SITE_CLIENT_OFFSET, PISTYX_HOST_SUFFIX - 1


def _valid_client_suffix(suffix: int) -> bool:
    low, high = _client_suffix_bounds()
    return isinstance(suffix, int) and not isinstance(suffix, bool) and low <= suffix <= high


def validate_client_suffix(suffix: int) -> int:
    """Validate that a client suffix lives in the client band (.64-.253)."""
    low, high = _client_suffix_bounds()
    if not _valid_client_suffix(suffix):
        raise ValueError(f"client host_suffix must be between {low} and {high}")
    return suffix


def next_client_suffix(used: set[int]) -> int:
    """Lowest free client host suffix: starts at the client band (.64), stays below pistyx (.254)."""
    from .network_plan import PISTYX_HOST_SUFFIX, SITE_CLIENT_OFFSET

    suffix = SITE_CLIENT_OFFSET
    while suffix in used:
        suffix += 1
    if suffix >= PISTYX_HOST_SUFFIX:
        raise ValueError("client address space exhausted (.64-.253)")
    return suffix


def _sorted_clients(clients: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(clients, key=lambda c: (c.get("host_suffix", 0), c.get("name", "")))


def merge_client(
    clients: list[dict[str, Any]],
    name: str,
    public_key: str,
    *,
    suffix: int | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Add or update a client. Re-registering an existing name rotates its key, keeps its suffix
    (unless an explicit ``suffix`` is given). Returns the new list + the client's host suffix."""
    merged = [dict(c) for c in clients]
    used_by_suffix = {
        c["host_suffix"]: c.get("name")
        for c in merged
        if isinstance(c.get("host_suffix"), int) and not isinstance(c.get("host_suffix"), bool)
    }
    used = set(used_by_suffix)
    if suffix is not None:
        suffix = validate_client_suffix(suffix)
        owner = used_by_suffix.get(suffix)
        if owner is not None and owner != name:
            raise ValueError(f"host_suffix {suffix} is already used by client {owner}")

    for client in merged:
        if client.get("name") == name:
            client["public_key"] = public_key
            if suffix is not None:
                client["host_suffix"] = suffix
            elif not _valid_client_suffix(client.get("host_suffix")):
                client["host_suffix"] = next_client_suffix(used)
            return _sorted_clients(merged), int(client["host_suffix"])

    if suffix is not None:
        chosen = suffix
    else:
        chosen = next_client_suffix(used)
    merged.append({"name": name, "public_key": public_key, "host_suffix": chosen})
    return _sorted_clients(merged), chosen


def render_clients_block(clients: list[dict[str, Any]]) -> str:
    """Render the managed ``clients:`` YAML block (name + public_key + host_suffix per entry)."""
    lines = ["clients:"]
    for client in _sorted_clients(clients):
        lines.append(f"  - name: {client['name']}")
        lines.append(f'    public_key: "{client["public_key"]}"')
        lines.append(f"    host_suffix: {client['host_suffix']}")
    return "\n".join(lines) + "\n"


def _is_top_level_key(line: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][\w-]*\s*:", line))


def replace_clients_block(text: str, block: str) -> str:
    """Splice ``block`` in as the file's ``clients:`` section, preserving all other content.

    Replaces an existing top-level ``clients:`` section (from its line to the next top-level key
    or EOF); if none exists, appends the block at EOF after a blank line.
    """
    block = block.rstrip("\n") + "\n"
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(r"^clients\s*:", ln)), None)
    if start is None:
        base = text.rstrip("\n")
        joiner = "\n\n" if base else ""
        return f"{base}{joiner}{block}"
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if _is_top_level_key(lines[j]):
            end = j
            break
    rebuilt = lines[:start] + block.rstrip("\n").split("\n") + lines[end:]
    return "\n".join(rebuilt) + "\n"


def existing_clients_from_doc(doc: Any) -> list[dict[str, Any]]:
    """Normalize a parsed styx.yaml's ``clients:`` into [{name, public_key, host_suffix}]."""
    from .wireguard_mesh import _host_suffix_from_client

    raw = doc.get("clients") if isinstance(doc, dict) else None
    raw = raw if isinstance(raw, list) else []
    clients: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        pub = item.get("public_key")
        if not isinstance(name, str) or not isinstance(pub, str) or not pub.strip():
            continue
        clients.append(
            {
                "name": name,
                "public_key": pub.strip(),
                "host_suffix": _host_suffix_from_client(item, index),
            }
        )
    return clients


def register_client(
    name: str,
    public_key: str,
    *,
    config_path: str | Path | None = None,
    suffix: int | None = None,
) -> tuple[dict[str, Any], int]:
    """Persist a client into styx.yaml's ``clients:`` block (writes a ``.bak`` first)."""
    import yaml

    from .config import find_config

    if not isinstance(name, str) or not name.strip():
        return {"status": "ERROR", "message": "client name is required to register"}, 1
    if not isinstance(public_key, str) or not public_key.strip():
        return {"status": "ERROR", "message": "client public key is required to register"}, 1

    candidate = Path(config_path) if config_path is not None else find_config()
    if candidate is None:
        return {"status": "ERROR", "message": "no styx.yaml found to register the client into"}, 1
    path = Path(candidate)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"status": "ERROR", "message": f"could not read {path}: {exc}"}, 1
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return {"status": "ERROR", "message": f"could not parse {path}: {exc}"}, 1

    clients = existing_clients_from_doc(doc)
    try:
        merged, chosen = merge_client(clients, name.strip(), public_key.strip(), suffix=suffix)
    except ValueError as exc:
        return {"status": "ERROR", "message": str(exc)}, 1
    new_text = replace_clients_block(text, render_clients_block(merged))

    backup = path.with_name(path.name + ".bak")
    try:
        backup.write_text(text, encoding="utf-8")
        path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return {"status": "ERROR", "message": f"could not write {path}: {exc}"}, 1

    return {
        "status": "OK",
        "client": name.strip(),
        "host_suffix": chosen,
        "config_path": str(path),
        "backup_path": str(backup),
        "message": (
            f"registered {name.strip()} (host_suffix {chosen}) in {path.name}; "
            "run `styxctl mesh up` to render it onto every leader's pistyx PoP"
        ),
    }, 0
