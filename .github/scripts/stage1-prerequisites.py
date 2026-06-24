#!/usr/bin/env python3
"""Stage 1: local prerequisites on each self-hosted runner (ports, sysprep, config)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import (
    BOOTSTRAP_SSH_PORT,
    REPO_ROOT,
    configure_styx_gateway,
    fail_check,
    pass_check,
    exit_from_checks,
    prepare_styx_yaml,
    port_listening,
    run,
    run_ssh_probe,
    run_styxctl,
    runner_name,
)


def main() -> int:
    name = runner_name()
    print(f"=== Stage 1 — prerequisites: {name} ===")
    config_path = prepare_styx_yaml(REPO_ROOT)

    checks: list[dict[str, object]] = []

    from styxctl.bootstrap_config import load_operational_config
    from styxctl.config import config_status, validate_config
    from styxctl.gateway import parse_gateway_ports
    from styxctl.inventory import collect_inventory
    from styxctl.nodes import identify_local_node, node_ssh_user, parse_nodes

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
    elif local_node.name != name:
        fail_check(
            checks,
            "runner_identity",
            f"GitHub runner {name!r} != styx node {local_node.name!r}",
        )
    else:
        pass_check(checks, "runner_identity", f"node {local_node.name}")

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

    if local_node is not None:
        for peer in nodes:
            if peer.name == local_node.name:
                continue
            user = node_ssh_user(peer)
            target = f"{user}@{peer.name}"
            ok, detail = run_ssh_probe(
                target,
                "echo styx-bootstrap-ok",
                port=BOOTSTRAP_SSH_PORT,
                timeout=20.0,
            )
            check_name = f"bootstrap_ssh_{peer.name}"
            if ok and "styx-bootstrap-ok" in detail:
                pass_check(checks, check_name, f"port {BOOTSTRAP_SSH_PORT} {target}")
            else:
                fail_check(checks, check_name, detail or f"port {BOOTSTRAP_SSH_PORT} {target}")

    config = load_operational_config(config_path, inventory=inventory)
    nodes = parse_nodes(config)
    for node in nodes:
        label = node.public_ipv4 or "missing"
        lan = f" lan={node.lan_ip}" if node.lan_ip else ""
        if node.public_ipv4:
            pass_check(checks, f"node_{node.name}_public_ipv4", f"{label}{lan}")
        else:
            fail_check(checks, f"node_{node.name}_public_ipv4", "not discovered (need bootstrap SSH + curl)")

    issues = validate_config(config, inventory=inventory)
    status = config_status(issues)
    if status == "INVALID":
        errors = [f"{issue.path}: {issue.message}" for issue in issues if issue.level == "error"]
        fail_check(checks, "config_validate", "; ".join(errors[:5]) or status)
    else:
        pass_check(checks, "config_validate", status)

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

    return exit_from_checks(name, "prerequisites", checks)


if __name__ == "__main__":
    raise SystemExit(main())
