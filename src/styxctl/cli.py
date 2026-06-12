"""Typer CLI entry point for styxctl."""

from __future__ import annotations

from pathlib import Path

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
from .install import run_install_cluster, run_install_doctor, run_install_local, run_install_plan_preview, run_cluster_doctor
from .install_report import render_install_text, save_install_report
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
sysprep_reset_app = typer.Typer(help="Interactive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
sysprep_nuke_app = typer.Typer(help="Destructive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
ports_app = typer.Typer(help="Inspect the Styx reserved port range.", no_args_is_help=True)
ports_check_app = typer.Typer(help="Check Styx reserved ports.", no_args_is_help=True)
ports_list_app = typer.Typer(help="List the Styx reserved port plan.", no_args_is_help=True)
ports_clear_app = typer.Typer(help="Clear safe Styx reserved port conflicts.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect and validate styx.yaml.", no_args_is_help=True)
report_app = typer.Typer(help="Inspect saved sysprep reports.", no_args_is_help=True)
install_app = typer.Typer(help="Install Styx prerequisites on local gateway nodes.", no_args_is_help=True)
install_status_app = typer.Typer(help="Show local install status.", no_args_is_help=True)
install_doctor_app = typer.Typer(help="Diagnose local install health.", no_args_is_help=True)
install_plan_app = typer.Typer(help="Preview the local install plan.", no_args_is_help=True)
completion_app = typer.Typer(help="Shell completion helpers.", no_args_is_help=True)


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
        console.print("[yellow]Hint:[/yellow] try `styxctl sysprep safe local --dry-run` to preview safe cleanup.")
        raise typer.Exit(code=1)


@sysprep_check_app.command("all")
def sysprep_check_all() -> None:
    """Future: run sysprep checks across all nodes."""
    console.print("MVP4 placeholder: no remote checks were run.")


@sysprep_check_app.command("node")
def sysprep_check_node() -> None:
    """Future: run sysprep check on one named node."""
    console.print("MVP4 placeholder: no remote node check was run.")


@sysprep_safe_app.command("local")
def sysprep_safe_local(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show planned actions without changing the host."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply planned actions without confirmation."),
) -> None:
    """Stop/disable known-safe Styx/k3s leftovers and clear safe reserved-port conflicts."""
    _run_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
        apply_plan=apply_safe_sysprep,
        dry_run=dry_run,
        yes=yes,
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


@ports_clear_app.command("local")
def ports_clear_local(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show planned actions without changing the host."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply planned actions without confirmation."),
) -> None:
    """Clear only safe Styx reserved port conflicts in 47800-47850."""
    _run_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
        apply_plan=apply_port_clear,
        dry_run=dry_run,
        yes=yes,
    )


@config_app.command("show")
def config_show(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Show the active Styx config summary."""
    config_path = Path(path) if path else find_config()
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(format_config_summary(config, config_path))


@config_app.command("validate")
def config_validate(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Validate styx.yaml structure for Styx."""
    config_path = Path(path) if path else find_config()
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    issues = validate_config(config)
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
    hostname: str | None = typer.Option(None, "--hostname", help="Hostname report directory to display."),
    json_output: bool = typer.Option(False, "--json", help="Print saved JSON instead of text report."),
) -> None:
    """Show the latest saved local sysprep report."""
    try:
        if json_output:
            report = load_saved_report(hostname=hostname)
            console.print_json(data=report)
        else:
            console.print(load_saved_report_text(hostname=hostname), end="")
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
def install_local(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show planned actions without changing the host."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply planned actions without confirmation."),
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Install k3s and the Styx WireGuard foundation on this machine."""
    report, exit_code = run_install_local(dry_run=dry_run, yes=yes, config_path=path)
    if report.get("status") == "CONFIRMATION_REQUIRED":
        pending = report.get("pending_count", 0)
        console.print(render_install_text(report))
        if not typer.confirm(f"Apply {pending} planned install step(s)?", default=False):
            console.print("No changes were made.")
            raise typer.Exit(code=0)
        report, exit_code = run_install_local(dry_run=False, yes=True, config_path=path)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_status_app.command("local")
def install_status_local(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Show local install status for k3s and Styx WireGuard."""
    health = run_install_doctor(config_path=path)
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
def install_doctor_local(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Diagnose local install health with actionable failures."""
    health = run_install_doctor(config_path=path)
    if health.healthy:
        console.print("[green]Install doctor: healthy enough for MVP3[/green]")
        return

    console.print("[red]Install doctor: blocking issues found[/red]")
    for issue in health.issues:
        console.print(f"  - {issue}")
    if not health.k3s_active:
        console.print("  action: check `sudo systemctl status k3s` and re-run `styxctl install local --yes`")
    if not health.styx_interface_up:
        console.print("  action: verify /etc/wireguard/Styx.conf and run `sudo wg-quick up Styx`")
    if not health.wg0_preserved:
        console.print("  action: investigate wg0 changes before retrying install")
    raise typer.Exit(code=1)


@install_plan_app.command("local")
def install_plan_local(
    dry_run: bool = typer.Option(True, "--dry-run/--apply", help="Preview mode is default for install plan."),
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Preview the local install plan without changing the host."""
    if not dry_run:
        console.print("install plan local only supports preview mode; use `styxctl install local`.")
        raise typer.Exit(code=1)
    report, exit_code = run_install_plan_preview(config_path=path)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_app.command("cluster")
def install_cluster(
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show planned cluster actions without changing nodes."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Join all configured nodes without confirmation."),
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Install and join all k3s nodes listed in styx.yaml using their configured IPs."""
    report, exit_code = run_install_cluster(dry_run=dry_run, yes=yes, config_path=path)
    if report.get("status") == "CONFIRMATION_REQUIRED":
        pending = report.get("pending_count", 0)
        console.print(render_install_text(report))
        if not typer.confirm(f"Apply k3s cluster setup to {pending} remote node(s)?", default=False):
            console.print("No changes were made.")
            raise typer.Exit(code=0)
        report, exit_code = run_install_cluster(dry_run=False, yes=True, config_path=path)
    gate = report.get("gate", {})
    if gate.get("message"):
        console.print(f"[red]Install blocked:[/red] {gate['message']}")
    _print_install_report(report, exit_code=exit_code)


@install_status_app.command("cluster")
def install_status_cluster(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Show k3s cluster node status for all configured IPs."""
    health = run_cluster_doctor(config_path=path)
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


@install_doctor_app.command("cluster")
def install_doctor_cluster(
    path: Path | None = typer.Option(None, "--path", help="Path to styx.yaml or styx.yml."),
) -> None:
    """Diagnose k3s cluster health across all configured node IPs."""
    health = run_cluster_doctor(config_path=path)
    if health.get("healthy"):
        console.print("[green]Cluster doctor: all configured k3s nodes are healthy[/green]")
        return
    console.print("[red]Cluster doctor: blocking cluster issues found[/red]")
    for issue in health.get("issues", []):
        console.print(f"  - {issue}")
    console.print("  action: run `styxctl install local --yes` on each node, then `styxctl install cluster --yes`")
    raise typer.Exit(code=1)


def _future_app(label: str, milestone: str) -> typer.Typer:
    future = typer.Typer(help=f"Future {label} commands ({milestone}).", no_args_is_help=True)

    @future.command("soon")
    def soon() -> None:  # pragma: no cover - simple placeholder
        _not_implemented_future(f"{label} commands", milestone)

    return future


sysprep_app.add_typer(sysprep_check_app, name="check")
sysprep_app.add_typer(sysprep_safe_app, name="safe")
sysprep_app.add_typer(sysprep_reset_app, name="reset")
sysprep_app.add_typer(sysprep_nuke_app, name="nuke")
ports_app.add_typer(ports_check_app, name="check")
ports_app.add_typer(ports_list_app, name="list")
ports_app.add_typer(ports_clear_app, name="clear")

install_app.add_typer(install_status_app, name="status")
install_app.add_typer(install_doctor_app, name="doctor")
install_app.add_typer(install_plan_app, name="plan")

app.add_typer(sysprep_app, name="sysprep")
app.add_typer(ports_app, name="ports")
app.add_typer(install_app, name="install")
app.add_typer(_future_app("deploy", "MVP3"), name="deploy")
app.add_typer(_future_app("status", "MVP3"), name="status")
app.add_typer(_future_app("doctor", "MVP3"), name="doctor")
app.add_typer(_future_app("client", "MVP4"), name="client")
app.add_typer(_future_app("gateway", "MVP3"), name="gateway")
app.add_typer(_future_app("siem", "MVP4"), name="siem")
app.add_typer(config_app, name="config")
app.add_typer(report_app, name="report")
app.add_typer(completion_app, name="completion")


if __name__ == "__main__":
    app()
