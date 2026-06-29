#!/usr/bin/env python3
"""Stage 1: local prerequisites on each self-hosted runner (no port 22)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import (
    REPO_ROOT,
    configure_styx_gateway,
    fail_check,
    pass_check,
    exit_from_checks,
    prepare_styx_yaml,
    port_listening,
    run,
    run_styxctl,
    runner_name,
)


def main() -> int:
    name = runner_name()
    print(f"=== Stage 1 - prerequisites: {name} ===")
    config_path = prepare_styx_yaml(REPO_ROOT)

    checks: list[dict[str, object]] = []

    from styxctl.bootstrap_config import load_operational_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.inventory import collect_inventory
    from styxctl.nodes import identify_local_node, parse_nodes

    inventory = collect_inventory()
    config = load_operational_config(config_path, inventory=inventory)
    nodes = parse_nodes(config)
    local_node = identify_local_node(nodes, inventory, config)
    if local_node is None:
        local_node = next((node for node in nodes if node.name == name), None)

    if local_node is None:
        fail_check(
            checks,
            "runner_identity",
            f"host {inventory.hostname!r} is not listed in styx.yaml nodes",
        )
    else:
        pass_check(checks, "runner_identity", f"node {local_node.name} (role: {local_node.role})")

    code, output = run(["sudo", "-n", "true"])
    if code != 0:
        fail_check(checks, "passwordless_sudo", output or "sudo -n failed")
    else:
        pass_check(checks, "passwordless_sudo")

    for binary in ("python3", "ssh", "curl"):
        code, output = run(["bash", "-lc", f"command -v {binary}"])
        if code != 0:
            fail_check(checks, f"binary_{binary}", f"{binary} not found")
        else:
            pass_check(checks, f"binary_{binary}", output.splitlines()[-1] if output else binary)

    code, output = run_styxctl("sysprep", "check", "local", timeout=180.0)
    if code not in (0, 1):
        fail_check(checks, "sysprep_check", output or f"exit {code}")
    else:
        try:
            report_dir = next((REPO_ROOT / "reports/styx").iterdir())
            report = json.loads((report_dir / "sysprep-report.json").read_text(encoding="utf-8"))
            status = report.get("status")
        except (StopIteration, OSError, json.JSONDecodeError) as exc:
            fail_check(checks, "sysprep_check", f"could not read sysprep report: {exc}")
        else:
            if status in {"READY", "READY_WITH_WARNINGS"}:
                pass_check(checks, "sysprep_check", f"status={status}")
            elif status == "BLOCKED":
                fail_check(checks, "sysprep_check", f"host BLOCKED: {output[-500:]}")
            else:
                fail_check(checks, "sysprep_check", f"unexpected status {status!r}")

    gateway = parse_gateway_ports(config)
    ok, detail = configure_styx_gateway(config_path)
    if ok:
        pass_check(checks, "gateway_configure", detail)
    else:
        fail_check(checks, "gateway_configure", detail)

    if port_listening(gateway.ssh):
        pass_check(checks, "gateway_listen_local", f"port {gateway.ssh}")
    else:
        fail_check(checks, "gateway_listen_local", f"port {gateway.ssh} not accepting connections")

    config = load_operational_config(config_path, inventory=inventory)
    if local_node is not None:
        local_node = next((node for node in parse_nodes(config) if node.name == local_node.name), local_node)
        if local_node.public_ipv4:
            pass_check(checks, "local_public_ipv4", local_node.public_ipv4)
        else:
            fail_check(checks, "local_public_ipv4", "not discovered (curl ifconfig.me)")

    return exit_from_checks(name, "prerequisites", checks)


if __name__ == "__main__":
    raise SystemExit(main())
