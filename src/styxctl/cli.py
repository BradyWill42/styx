"""Typer CLI entry point for styxctl."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from typer._completion_shared import get_completion_script

from . import __version__
from .config import (
    ConfigError,
    config_status,
    find_config,
    format_config_summary,
    load_config,
    validate_config,
)
from .inventory import collect_inventory
from .install import (
    run_cluster_doctor,
    run_install_cluster,
    run_install_doctor,
    run_install_local,
    run_install_plan_preview,
    run_lan_election_preview,
    run_lan_election_status,
)
from .install_report import render_install_text, save_install_report
from .dns_publish import deploy_dns, render_dns_report_text
from .cluster_status import run_doctor, run_status
from .wireguard_mesh import (
    apply_local,
    client_config,
    ensure_egress_keypair,
    ensure_local_keypair,
    ensure_pistyx_identity,
    mesh_plan,
    mesh_up,
    pistyx_info,
    render_mesh_report_text,
    stage_pistyx_key,
)
from .uninstall import (
    apply_cluster_uninstall_plan,
    apply_uninstall_plan,
    build_cluster_uninstall_plan,
    build_uninstall_plan,
    render_cluster_uninstall_text,
    render_uninstall_text,
)
from .ports import PORT_BLOCKS, PORT_PLAN, check_reserved_ports, port_purpose
from .remediation import (
    apply_port_clear,
    apply_safe_sysprep,
    build_port_clear_plan,
    build_safe_sysprep_plan,
    render_remediation_summary,
)
from .reports import (
    build_report_data,
    load_saved_report,
    load_saved_report_text,
    render_sysprep_text,
    save_report_bundle,
)

console = Console()

app = typer.Typer(
    name="styxctl",
    help="Prepare, install, and manage Styx nodes.",
    no_args_is_help=True,
)
sysprep_app = typer.Typer(help="Prepare hosts safely before Styx installation.", no_args_is_help=True)
sysprep_check_app = typer.Typer(help="Read-only sysprep checks.", no_args_is_help=True)
sysprep_safe_app = typer.Typer(help="Known-safe local cleanup before install.", no_args_is_help=True)
sysprep_safe_plan_app = typer.Typer(help="Preview safe local cleanup without changing the host.", no_args_is_help=True)
sysprep_safe_apply_app = typer.Typer(help="Apply safe local cleanup without confirmation.", no_args_is_help=True)
sysprep_reset_app = typer.Typer(help="Interactive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
sysprep_nuke_app = typer.Typer(help="Destructive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
ports_app = typer.Typer(help="Inspect the Styx reserved port range.", no_args_is_help=True)
ports_check_app = typer.Typer(help="Check Styx reserved ports.", no_args_is_help=True)
ports_list_app = typer.Typer(help="List the Styx reserved port plan.", no_args_is_help=True)
ports_clear_app = typer.Typer(help="Clear safe Styx reserved port conflicts.", no_args_is_help=True)
ports_clear_plan_app = typer.Typer(help="Preview safe port cleanup without changing the host.", no_args_is_help=True)
ports_clear_apply_app = typer.Typer(help="Apply safe port cleanup without confirmation.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect and validate styx.yaml.", no_args_is_help=True)
report_app = typer.Typer(help="Inspect saved sysprep reports.", no_args_is_help=True)
install_app = typer.Typer(help="Install Styx prerequisites on local gateway nodes.", no_args_is_help=True)
install_status_app = typer.Typer(help="Show local install status.", no_args_is_help=True)
install_doctor_app = typer.Typer(help="Diagnose local install health.", no_args_is_help=True)
install_plan_app = typer.Typer(help="Preview install plans without changing the host.", no_args_is_help=True)
install_apply_app = typer.Typer(help="Apply install plans without confirmation.", no_args_is_help=True)
completion_app = typer.Typer(help="Shell completion helpers.", no_args_is_help=True)
uninstall_app = typer.Typer(help="Remove Styx config and k3s from local nodes.", no_args_is_help=True)
uninstall_plan_app = typer.Typer(help="Preview uninstall plan without changing the host.", no_args_is_help=True)
uninstall_apply_app = typer.Typer(help="Apply uninstall plan without confirmation.", no_args_is_help=True)
deploy_app = typer.Typer(help="Deploy Styx cluster workloads (MVP3).", no_args_is_help=True)
deploy_dns_app = typer.Typer(help="Publish cluster DNS to DuckDNS from inside k3s.", no_args_is_help=True)
mesh_app = typer.Typer(help="Build and inspect the Styx WireGuard backbone mesh.", no_args_is_help=True)
mesh_pistyx_app = typer.Typer(help="Inspect and move the movable pistyx egress.", no_args_is_help=True)
client_app = typer.Typer(help="Generate roadwarrior client configs (connect to a chosen site).", no_args_is_help=True)


@app.callback()
def main() -> None:
    """styxctl command root."""


@app.command("version")
def version() -> None:
    """Print the styxctl version."""
    console.print(__version__)


def _confirm_or_exit(planned_count: int, yes: bool) -> None:
    if planned_count == 0:
        console.print("[green]Nothing to do.[/green]")
        return
    if yes:
        return
    if not typer.confirm(f"Apply {planned_count} planned action(s)?", default=False):
        console.print("No changes were made.")
        raise typer.Exit(code=0)


def _run_remediation(
    *,
    title: str,
    build_plan,
    apply_plan,
    dry_run: bool,
    yes: bool,
) -> None:
    inventory = collect_inventory()
    if dry_run:
        result = build_plan(inventory)
        result.dry_run = True
        console.print(render_remediation_summary(result, title=title))
        return

    plan = build_plan(inventory)
    console.print(render_remediation_summary(plan, title=f"{title} (preview)"))
    _confirm_or_exit(len(plan.planned), yes)
    if not plan.planned:
        return

    result = apply_plan(inventory, dry_run=False)
    console.print(render_remediation_summary(result, title=f"{title} (results)"))
    console.print("[bold green]Re-run recommended:[/bold green] styxctl sysprep check local")


@sysprep_check_app.command("local")
def sysprep_check_local() -> None:
    """Run the read-only MVP1 sysprep check on this machine."""
    inventory = collect_inventory()
    report = build_report_data(inventory, command="styxctl sysprep check local")
    text = render_sysprep_text(report)
    paths = save_report_bundle(report, text)

    console.print(text)
    console.print(f"[bold green]Reports saved[/bold green]")
    console.print(f"  JSON: {paths['json']}")
    console.print(f"  Text: {paths['text']}")

    if report["status"] == "BLOCKED":
        console.print("[yellow]Hint:[/yellow] try `styxctl sysprep safe plan local` to preview safe cleanup.")
        raise typer.Exit(code=1)


@sysprep_check_app.command("all")
def sysprep_check_all() -> None:
    """Future: run sysprep checks across all nodes."""
    console.print("MVP4 placeholder: no remote checks were run.")


@sysprep_check_app.command("node")
def sysprep_check_node() -> None:
    """Future: run sysprep check on one named node."""
    console.print("MVP4 placeholder: no remote node check was run.")


@sysprep_safe_plan_app.command("local")
def sysprep_safe_plan_local() -> None:
    """Preview known-safe Styx/k3s cleanup without changing the host."""
    _run_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
        apply_plan=apply_safe_sysprep,
        dry_run=True,
        yes=False,
    )


@sysprep_safe_apply_app.command("local")
def sysprep_safe_apply_local() -> None:
    """Apply known-safe Styx/k3s cleanup without confirmation."""
    _run_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
        apply_plan=apply_safe_sysprep,
        dry_run=False,
        yes=True,
    )


@sysprep_safe_app.command("local")
def sysprep_safe_local() -> None:
    """Stop/disable known-safe Styx/k3s leftovers and clear safe reserved-port conflicts."""
    _run_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
        apply_plan=apply_safe_sysprep,
        dry_run=False,
        yes=False,
    )


def _not_implemented_future(command_name: str, milestone: str) -> None:
    console.print(f"{command_name} is not implemented in {milestone}.")
    console.print("No changes were made.")


@sysprep_reset_app.command("local")
def sysprep_reset_local() -> None:
    """Future: interactive reset of known Styx/k3s/CNI leftovers."""
    _not_implemented_future("styxctl sysprep reset local", "MVP3")


@sysprep_nuke_app.command("local")
def sysprep_nuke_local() -> None:
    """Future: destructive force-clear with confirmation."""
    _not_implemented_future("styxctl sysprep nuke local", "MVP3")


@ports_check_app.command("local")
def ports_check_local() -> None:
    """Read-only check of occupied ports in 47800-47850."""
    scan = check_reserved_ports()
    table = Table(title="Styx Reserved Port Conflicts")
    table.add_column("Protocol")
    table.add_column("Port")
    table.add_column("Process")
    table.add_column("PID")
    table.add_column("Systemd Unit")
    table.add_column("Safe To Stop")
    table.add_column("Purpose")

    if scan.conflicts:
        for conflict in scan.conflicts:
            table.add_row(
                conflict.protocol,
                str(conflict.port),
                conflict.process_name or "unknown",
                str(conflict.pid or "unknown"),
                conflict.systemd_unit or "unknown",
                "yes" if conflict.safe_to_stop else "no",
                port_purpose(conflict.port),
            )
    else:
        table.add_row("-", "47800-47850", "free", "-", "-", "-", "no conflicts found")

    console.print(table)
    if scan.error:
        console.print(f"[yellow]Warning:[/yellow] {scan.error}")


@ports_list_app.command("local")
def ports_list_local() -> None:
    """List the Styx reserved port plan."""
    table = Table(title="Styx Reserved Port Plan")
    table.add_column("Port(s)")
    table.add_column("Protocol")
    table.add_column("Purpose")

    for port in sorted(PORT_PLAN):
        item = PORT_PLAN[port]
        table.add_row(str(port), item["protocol"], item["purpose"])

    for purpose, start, end in PORT_BLOCKS:
        table.add_row(f"{start}-{end}", "any", purpose)

    console.print(table)


@ports_clear_plan_app.command("local")
def ports_clear_plan_local() -> None:
    """Preview safe Styx reserved port cleanup without changing the host."""
    _run_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
        apply_plan=apply_port_clear,
        dry_run=True,
        yes=False,
    )


@ports_clear_apply_app.command("local")
def ports_clear_apply_local() -> None:
    """Clear safe Styx reserved port conflicts without confirmation."""
    _run_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
        apply_plan=apply_port_clear,
        dry_run=False,
        yes=True,
    )


@ports_clear_app.command("local")
def ports_clear_local() -> None:
    """Clear only safe Styx reserved port conflicts in 47800-47850."""
    _run_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
        apply_plan=apply_port_clear,
        dry_run=False,
        yes=False,
    )


@config_app.command("show")
def config_show() -> None:
    """Show the active Styx config summary."""
    config_path = find_config()
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(format_config_summary(config, config_path))


@config_app.command("validate")
def config_validate() -> None:
    """Validate styx.yaml structure for Styx."""
    config_path = find_config()
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    issues = validate_config(config, inventory=collect_inventory())
    status = config_status(issues)
    console.print(f"Config status: {status}")
    if config_path:
        console.print(f"Config file: {config_path}")
    else:
        console.print("Config file: not found")

    if issues:
        for issue in issues:
            color = "red" if issue.level == "error" else "yellow"
            console.print(f"[{color}]{issue.level.upper()}[/{color}] {issue.path}: {issue.message}")
    else:
        console.print("[green]No issues found.[/green]")

    if status == "INVALID":
        raise typer.Exit(code=1)


@report_app.command("show")
def report_show_local(
    hostname: str | None = typer.Argument(None, help="Hostname report directory to display."),
) -> None:
    """Show the latest saved local sysprep report."""
    try:
        console.print(load_saved_report_text(hostname=hostname), end="")
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        console.print("Run `styxctl sysprep check local` first.")
        raise typer.Exit(code=1) from exc


@report_app.command("json")
def report_json_local(
    hostname: str | None = typer.Argument(None, help="Hostname report directory to display."),
) -> None:
    """Print the latest saved local sysprep report as JSON."""
    try:
        report = load_saved_report(hostname=hostname)
        console.print_json(data=report)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        console.print("Run `styxctl sysprep check local` first.")
        raise typer.Exit(code=1) from exc


def _emit_completion(shell: str) -> None:
    typer.echo(
        get_completion_script(
            prog_name="styxctl",
            complete_var="_STYXCTL_COMPLETE",
            shell=shell,
        )
    )


@completion_app.command("bash")
def completion_bash() -> None:
    """Print bash completion script."""
    _emit_completion("bash")


@completion_app.command("zsh")
def completion_zsh() -> None:
    """Print zsh completion script."""
    _emit_completion("zsh")


@completion_app.command("fish")
def completion_fish() -> None:
    """Print fish completion script."""
    _emit_completion("fish")


@completion_app.command("install")
def completion_install() -> None:
    """Show install guidance for shell completion."""
    console.print("Typer can install completion for your active shell:")
    console.print("  styxctl --install-completion")
    console.print("Or print a script directly:")
    console.print("  styxctl completion bash")
    console.print("  styxctl completion zsh")
    console.print("  styxctl completion fish")


def _print_install_report(report: dict, *, exit_code: int) -> None:
    text = render_install_text(report)
    paths = save_install_report(report, text)
    console.print(text)
    console.print("[bold green]Reports saved[/bold green]")
    console.print(f"  JSON: {paths['json']}")
    console.print(f"  Text: {paths['text']}")
    if report.get("message"):
        console.print(report["message"])
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@install_app.command("local")
def install_local() -> None:
    """Install k3s and the Styx WireGuard foundation on this machine."""
    report, exit_code = run_install_local(dry_run=False, yes=False, config_path=None)
    if report.get("status") == "CONFIRMATION_REQUIRED":
        pending = report.get("pending_count", 0)
        console.print(render_install_text(report))
        if not typer.confirm(f"Apply {pending} planned install step(s)?", default=False):
            console.print("No changes were made.")
            raise typer.Exit(code=0)
        report, exit_code = run_install_local(dry_run=False, yes=True, config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_apply_app.command("local")
def install_apply_local() -> None:
    """Apply the local install plan without confirmation."""
    report, exit_code = run_install_local(dry_run=False, yes=True, config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_status_app.command("local")
def install_status_local() -> None:
    """Show local install status for k3s and Styx WireGuard."""
    health = run_install_doctor(config_path=None)
    table = Table(title="Styx Install Status")
    table.add_column("Component")
    table.add_column("State")

    table.add_row("k3s installed", "yes" if health.k3s_installed else "no")
    table.add_row("k3s active", "yes" if health.k3s_active else "no")
    table.add_row("k3s version", health.k3s_version or "unknown")
    table.add_row("kubectl", "available" if health.kubectl_available else "missing")
    table.add_row("wg binary", "available" if health.wg_binary else "missing")
    table.add_row("Styx interface", "up" if health.styx_interface_up else "down")
    table.add_row("47800/udp listening", "yes" if health.styx_port_listening else "no")
    table.add_row("wg0 preserved", "yes" if health.wg0_preserved else "no")
    table.add_row("config", f"{health.config_path or 'not found'} ({health.config_status})")
    table.add_row("critical ports", "clear" if health.critical_ports_clear else "conflicts")
    if health.cluster_node_count:
        table.add_row("cluster nodes configured", str(health.cluster_node_count))
        if health.local_node:
            table.add_row("local cluster node", health.local_node)

    console.print(table)
    if health.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for warning in health.warnings:
            console.print(f"  - {warning}")
    if health.issues:
        console.print("[red]Issues:[/red]")
        for issue in health.issues:
            console.print(f"  - {issue}")
        raise typer.Exit(code=1)


@install_doctor_app.command("local")
def install_doctor_local() -> None:
    """Diagnose local install health with actionable failures."""
    health = run_install_doctor(config_path=None)
    if health.healthy:
        console.print("[green]Install doctor: healthy enough for MVP3[/green]")
        return

    console.print("[red]Install doctor: blocking issues found[/red]")
    for issue in health.issues:
        console.print(f"  - {issue}")
    if not health.k3s_active:
        console.print("  action: check `sudo systemctl status k3s` and re-run `styxctl install apply local`")
    if not health.styx_interface_up:
        console.print("  action: verify /etc/wireguard/Styx.conf and run `sudo wg-quick up Styx`")
    if not health.wg0_preserved:
        console.print("  action: investigate wg0 changes before retrying install")
    raise typer.Exit(code=1)


@install_plan_app.command("local")
def install_plan_local() -> None:
    """Preview the local install plan without changing the host."""
    report, exit_code = run_install_plan_preview(config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_plan_app.command("cluster")
def install_plan_cluster() -> None:
    """Preview the k3s cluster install plan without changing nodes."""
    report, exit_code = run_install_cluster(dry_run=True, yes=False, config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_plan_app.command("lan")
def install_plan_lan() -> None:
    """Preview LAN leader election without changing the host."""
    report, exit_code = run_lan_election_preview(config_path=None)
    console.print_json(data=report)
    raise typer.Exit(code=exit_code)


@install_app.command("cluster")
def install_cluster() -> None:
    """Install and join all k3s nodes listed in styx.yaml using their configured IPs."""
    report, exit_code = run_install_cluster(dry_run=False, yes=False, config_path=None)
    if report.get("status") == "CONFIRMATION_REQUIRED":
        pending = report.get("pending_count", 0)
        console.print(render_install_text(report))
        if not typer.confirm(f"Apply k3s cluster setup to {pending} remote node(s)?", default=False):
            console.print("No changes were made.")
            raise typer.Exit(code=0)
        report, exit_code = run_install_cluster(dry_run=False, yes=True, config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_apply_app.command("cluster")
def install_apply_cluster() -> None:
    """Apply the k3s cluster install plan without confirmation."""
    report, exit_code = run_install_cluster(dry_run=False, yes=True, config_path=None)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_status_app.command("cluster")
def install_status_cluster() -> None:
    """Show k3s cluster node status for all configured IPs."""
    health = run_cluster_doctor(config_path=None)
    table = Table(title="Styx k3s Cluster Status")
    table.add_column("Node")
    table.add_column("Role")
    table.add_column("IPv4")
    table.add_column("IPv6")
    table.add_column("Reachable")
    table.add_column("k3s Active")

    for node in health.get("nodes", []):
        table.add_row(
            node.get("name", "unknown"),
            node.get("role", "unknown"),
            node.get("ipv4") or "-",
            node.get("ipv6") or "-",
            "yes" if node.get("reachable") else "no",
            "yes" if node.get("k3s_active") else "no",
        )

    console.print(table)
    kubectl_nodes = health.get("kubectl_nodes") or []
    if kubectl_nodes:
        console.print(f"kubectl nodes: {', '.join(kubectl_nodes)}")
    if health.get("issues"):
        console.print("[red]Issues:[/red]")
        for issue in health["issues"]:
            console.print(f"  - {issue}")
        raise typer.Exit(code=1)


@install_status_app.command("lan")
def install_status_lan() -> None:
    """Show LAN peers and elected leader for this subnet."""
    election = run_lan_election_status(config_path=None)
    table = Table(title="Styx LAN Leader Election")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("enabled", "yes" if election.get("enabled") else "no")
    table.add_row("subnet", election.get("subnet") or "-")
    leader = election.get("leader") or {}
    table.add_row("leader", leader.get("node_name") or "-")
    table.add_row("leader strength", str(leader.get("strength") or "-"))
    table.add_row("promote to init-server", "yes" if election.get("promote_to_init_server") else "no")
    if election.get("previous_init_server"):
        table.add_row("previous init-server", election["previous_init_server"])
    console.print(table)

    peers = election.get("peers") or []
    if peers:
        peer_table = Table(title="LAN Peers")
        peer_table.add_column("Node")
        peer_table.add_column("LAN IP")
        peer_table.add_column("Strength")
        peer_table.add_column("Hostname")
        for peer in peers:
            peer_table.add_row(
                peer.get("node_name", "-"),
                peer.get("lan_ip", "-"),
                str(peer.get("strength", "-")),
                peer.get("hostname", "-"),
            )
        console.print(peer_table)

    if election.get("warnings"):
        console.print("[yellow]Warnings:[/yellow]")
        for warning in election["warnings"]:
            console.print(f"  - {warning}")


@install_doctor_app.command("cluster")
def install_doctor_cluster() -> None:
    """Diagnose k3s cluster health across all configured node IPs."""
    health = run_cluster_doctor(config_path=None)
    if health.get("healthy"):
        console.print("[green]Cluster doctor: all configured k3s nodes are healthy[/green]")
        return
    console.print("[red]Cluster doctor: blocking cluster issues found[/red]")
    for issue in health.get("issues", []):
        console.print(f"  - {issue}")
    console.print("  action: run `styxctl install apply local` on each node, then `styxctl install apply cluster`")
    raise typer.Exit(code=1)


def _print_uninstall_plan(plan, *, dry_run: bool, exit_code: int = 0) -> None:
    console.print(render_uninstall_text(plan, dry_run=dry_run))
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@uninstall_plan_app.command("local")
def uninstall_plan_local() -> None:
    """Preview what would be removed on this node without making any changes."""
    plan = build_uninstall_plan()
    _print_uninstall_plan(plan, dry_run=True)


@uninstall_apply_app.command("local")
def uninstall_apply_local() -> None:
    """Remove Styx config and k3s from this node without confirmation."""
    plan = build_uninstall_plan()
    applied = apply_uninstall_plan(plan)
    _print_uninstall_plan(
        applied,
        dry_run=False,
        exit_code=1 if any(step.status == "failed" for step in applied.steps) else 0,
    )


@uninstall_app.command("local")
def uninstall_local() -> None:
    """Remove Styx config and k3s from this node (shows plan, then confirms)."""
    plan = build_uninstall_plan()
    pending = [step for step in plan.steps if step.status == "pending"]
    _print_uninstall_plan(plan, dry_run=True)
    if not pending:
        console.print("[green]Nothing to uninstall.[/green]")
        return
    console.print(
        f"[cyan]{len(plan.preserved)} config(s)/service(s) will be preserved "
        f"(including /etc/styx/styx.yaml and wg0 when present).[/cyan]"
    )
    if not typer.confirm(f"Apply {len(pending)} uninstall step(s)?", default=False):
        console.print("No changes were made.")
        raise typer.Exit(code=0)
    applied = apply_uninstall_plan(plan)
    _print_uninstall_plan(applied, dry_run=False, exit_code=1 if any(s.status == "failed" for s in applied.steps) else 0)


@uninstall_plan_app.command("cluster")
def uninstall_plan_cluster() -> None:
    """Preview cluster-wide uninstall across all configured nodes."""
    plan = build_cluster_uninstall_plan()
    console.print(render_cluster_uninstall_text(plan, dry_run=True))


@uninstall_apply_app.command("cluster")
def uninstall_apply_cluster() -> None:
    """Remove Styx from all configured cluster nodes without confirmation."""
    plan = build_cluster_uninstall_plan()
    applied = apply_cluster_uninstall_plan(plan)
    console.print(render_cluster_uninstall_text(applied, dry_run=False))
    if any(node.status == "failed" for node in applied.nodes):
        raise typer.Exit(code=1)


@uninstall_app.command("cluster")
def uninstall_cluster() -> None:
    """Remove Styx from all configured cluster nodes (shows plan, then confirms)."""
    plan = build_cluster_uninstall_plan()
    console.print(render_cluster_uninstall_text(plan, dry_run=True))
    if not plan.nodes:
        console.print("[green]No cluster nodes configured.[/green]")
        return
    console.print(
        "[cyan]Persistent runner configs (/etc/styx/styx.yaml), wg0, and GitHub Actions "
        "runner registration are preserved on every node.[/cyan]"
    )
    if not typer.confirm(f"Apply uninstall to {len(plan.nodes)} cluster node(s)?", default=False):
        console.print("No changes were made.")
        raise typer.Exit(code=0)
    applied = apply_cluster_uninstall_plan(plan)
    console.print(render_cluster_uninstall_text(applied, dry_run=False))
    if any(node.status == "failed" for node in applied.nodes):
        raise typer.Exit(code=1)


@deploy_dns_app.command("plan")
def deploy_dns_plan() -> None:
    """Render the DuckDNS publisher manifest without applying it (no cluster access needed)."""
    report, exit_code = deploy_dns(dry_run=True, config_path=None)
    console.print(render_dns_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=exit_code)


@deploy_dns_app.command("apply")
def deploy_dns_apply() -> None:
    """Deploy the DuckDNS publisher to the cluster. Run on the init-server; reads $DUCKDNS_TOKEN."""
    report, exit_code = deploy_dns(dry_run=False, config_path=None)
    console.print(render_dns_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=exit_code)


def _render_cluster_health(health: dict[str, object]) -> None:
    table = Table(title="Styx Cluster Status")
    table.add_column("Node")
    table.add_column("Role")
    table.add_column("Reachable")
    table.add_column("k3s Active")
    for node in health.get("nodes", []):
        table.add_row(
            node.get("name", "?"),
            node.get("role", "?"),
            "yes" if node.get("reachable") else "no",
            "yes" if node.get("k3s_active") else "no",
        )
    console.print(table)
    kubectl_nodes = health.get("kubectl_nodes") or []
    if kubectl_nodes:
        console.print(f"kubectl nodes: {', '.join(kubectl_nodes)}")
    duckdns = (health.get("workloads") or {}).get("duckdns", {})
    state = "running" if duckdns.get("present") else "absent"
    console.print(f"DuckDNS publisher: {state} ({duckdns.get('detail', '-')})")
    if health.get("issues"):
        console.print("[red]Issues:[/red]")
        for issue in health["issues"]:
            console.print(f"  - {issue}")


@app.command("status")
def status_cmd() -> None:
    """Show cluster node health plus deployed Styx workloads."""
    health = run_status(config_path=None)
    _render_cluster_health(health)
    raise typer.Exit(code=1 if health.get("issues") else 0)


@app.command("doctor")
def doctor_cmd() -> None:
    """Diagnose cluster health and print remediation hints."""
    report, exit_code = run_doctor(config_path=None)
    _render_cluster_health(report)
    hints = report.get("hints") or []
    if hints:
        console.print("[yellow]Hints:[/yellow]")
        for hint in hints:
            console.print(f"  - {hint}")
    raise typer.Exit(code=exit_code)


@mesh_app.command("plan")
def mesh_plan_cmd() -> None:
    """Preview the hub-and-spoke mesh (topology + rendered configs); no cluster needed."""
    report, code = mesh_plan(config_path=None)
    console.print(render_mesh_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=code)


@mesh_app.command("up")
def mesh_up_cmd() -> None:
    """Bring up the Styx mesh: collect keys, wire peers, enable hub forwarding. Run on the init-server."""
    report, code = mesh_up(config_path=None)
    console.print(render_mesh_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=code)


@mesh_app.command("pubkey-local")
def mesh_pubkey_local_cmd(
    interface: str = typer.Option("", "--interface", help="WG interface name (default: config or 'Styx')"),
) -> None:
    """Ensure this node's WG keypair exists and print its public key (used by `mesh up`)."""
    if interface:
        config = {"wireguard": {"interface": interface}}
    else:
        found = find_config()
        config = load_config(found) if found else {}
    ok, result = ensure_local_keypair(config)
    if not ok:
        console.print(result, markup=False)
        raise typer.Exit(code=1)
    typer.echo(result)


@mesh_app.command("apply-local")
def mesh_apply_local_cmd(
    roster_b64: str = typer.Option(..., "--roster-b64", help="base64-encoded JSON roster"),
    local_name: str = typer.Option("", "--local-name", help="this node's name in the roster (from `mesh up`)"),
) -> None:
    """Render and install this node's mesh config from a roster (used by `mesh up`)."""
    import base64
    import json

    found = find_config()
    config = load_config(found) if found else {}
    roster = json.loads(base64.b64decode(roster_b64).decode())
    report, code = apply_local(roster, config, local_name=local_name or None)
    console.print(render_mesh_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=code)


@mesh_pistyx_app.command("show")
def mesh_pistyx_show_cmd() -> None:
    """Show the current pistyx holder, reserved overlay IP, and egress settings (render-only)."""
    report, code = pistyx_info(config_path=None)
    console.print(render_mesh_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=code)


@mesh_pistyx_app.command("pubkey-local")
def mesh_pistyx_pubkey_local_cmd() -> None:
    """Ensure the STABLE pistyx key exists locally and print its public key."""
    ok, result = ensure_pistyx_identity()
    if not ok:
        console.print(result, markup=False)
        raise typer.Exit(code=1)
    typer.echo(result)


@mesh_app.command("egress-pubkey-local")
def mesh_egress_pubkey_local_cmd(
    interface: str = typer.Option("StyxEgress", "--interface", help="egress WG interface name"),
) -> None:
    """Ensure this node's own StyxEgress keypair exists and print its public key (used by `mesh up`)."""
    ok, result = ensure_egress_keypair(interface)
    if not ok:
        console.print(result, markup=False)
        raise typer.Exit(code=1)
    typer.echo(result)


@mesh_app.command("stage-pistyx-key")
def mesh_stage_pistyx_key_cmd(
    key_b64: str = typer.Option(..., "--key-b64", help="base64-encoded stable pistyx private key"),
) -> None:
    """Write the pushed stable pistyx private key to local disk (used by `mesh up`)."""
    ok, detail = stage_pistyx_key(key_b64)
    if not ok:
        console.print(detail, markup=False)
        raise typer.Exit(code=1)
    typer.echo(detail)


@client_app.command("config")
def client_config_cmd(
    site: str = typer.Argument(..., help="entry site = the node name to home to (e.g. pegasus)"),
    name: str = typer.Option("", "--name", help="client name (default: <site>-client<index>)"),
    index: int = typer.Option(0, "--index", help="client slot; sets the roadwarrior IP offset"),
    render_only: bool = typer.Option(
        False, "--render-only", help="render the structure with placeholder keys (no wg/SSH)"
    ),
) -> None:
    """Generate a WireGuard config that homes to <site> by its DuckDNS name and egresses via pistyx."""
    report, code = client_config(site, name=name or None, index=index, render_only=render_only)
    if report.get("config"):
        typer.echo(report["config"])
    else:
        console.print(render_mesh_report_text(report), markup=False, soft_wrap=True)
    raise typer.Exit(code=code)


def _future_app(label: str, milestone: str) -> typer.Typer:
    future = typer.Typer(help=f"Future {label} commands ({milestone}).", no_args_is_help=True)

    @future.command("soon")
    def soon() -> None:  # pragma: no cover - simple placeholder
        _not_implemented_future(f"{label} commands", milestone)

    return future


sysprep_app.add_typer(sysprep_check_app, name="check")
sysprep_app.add_typer(sysprep_safe_app, name="safe")
sysprep_safe_app.add_typer(sysprep_safe_plan_app, name="plan")
sysprep_safe_app.add_typer(sysprep_safe_apply_app, name="apply")
sysprep_app.add_typer(sysprep_reset_app, name="reset")
sysprep_app.add_typer(sysprep_nuke_app, name="nuke")
ports_app.add_typer(ports_check_app, name="check")
ports_app.add_typer(ports_list_app, name="list")
ports_app.add_typer(ports_clear_app, name="clear")
ports_clear_app.add_typer(ports_clear_plan_app, name="plan")
ports_clear_app.add_typer(ports_clear_apply_app, name="apply")

install_app.add_typer(install_status_app, name="status")
install_app.add_typer(install_doctor_app, name="doctor")
install_app.add_typer(install_plan_app, name="plan")
install_app.add_typer(install_apply_app, name="apply")

uninstall_app.add_typer(uninstall_plan_app, name="plan")
uninstall_app.add_typer(uninstall_apply_app, name="apply")

app.add_typer(sysprep_app, name="sysprep")
app.add_typer(ports_app, name="ports")
app.add_typer(install_app, name="install")
app.add_typer(uninstall_app, name="uninstall")
deploy_app.add_typer(deploy_dns_app, name="dns")
app.add_typer(deploy_app, name="deploy")
mesh_app.add_typer(mesh_pistyx_app, name="pistyx")
app.add_typer(mesh_app, name="mesh")
app.add_typer(client_app, name="client")
# status + doctor are real top-level commands (see status_cmd / doctor_cmd above).
app.add_typer(_future_app("gateway", "MVP3"), name="gateway")
app.add_typer(_future_app("siem", "MVP4"), name="siem")
app.add_typer(config_app, name="config")
app.add_typer(report_app, name="report")
app.add_typer(completion_app, name="completion")


if __name__ == "__main__":
    app()
