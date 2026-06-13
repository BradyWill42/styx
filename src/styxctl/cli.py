"""Typer CLI entry point for styxctl."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
)
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


def _group(help: str) -> typer.Typer:
    return typer.Typer(help=help, no_args_is_help=True)


app = _group("Prepare, install, and manage Styx nodes.")
sysprep_app = _group("Prepare hosts safely before Styx installation.")
sysprep_check_app = _group("Read-only sysprep checks.")
sysprep_safe_app = _group("Known-safe local cleanup before install.")
sysprep_reset_app = _group("Interactive cleanup modes. MVP3 placeholder.")
sysprep_nuke_app = _group("Destructive cleanup modes. MVP3 placeholder.")
ports_app = _group("Inspect the Styx reserved port range.")
ports_check_app = _group("Check Styx reserved ports.")
ports_list_app = _group("List the Styx reserved port plan.")
ports_clear_app = _group("Clear safe Styx reserved port conflicts.")
config_app = _group("Inspect and validate styx.yaml.")
report_app = _group("Inspect saved sysprep reports.")
install_app = _group("Install Styx prerequisites on local gateway nodes.")
install_status_app = _group("Show local install status.")
install_doctor_app = _group("Diagnose local install health.")
install_plan_app = _group("Preview install plans without changing the host.")
install_apply_app = _group("Apply install plans without confirmation.")
completion_app = _group("Shell completion helpers.")


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


def _add_remediation_commands(
    parent: typer.Typer,
    plan_app: typer.Typer,
    apply_app: typer.Typer,
    *,
    title: str,
    build_plan,
    apply_plan,
    helps: tuple[str, str, str],
) -> None:
    for app, help_text, dry_run, yes in (
        (plan_app, helps[1], True, False),
        (apply_app, helps[2], False, True),
        (parent, helps[0], False, False),
    ):
        def handler(dry_run: bool = dry_run, yes: bool = yes) -> None:
            _run_remediation(
                title=title,
                build_plan=build_plan,
                apply_plan=apply_plan,
                dry_run=dry_run,
                yes=yes,
            )

        handler.__doc__ = help_text
        app.command("local")(handler)


def _not_implemented_future(command_name: str, milestone: str) -> None:
    console.print(f"{command_name} is not implemented in {milestone}.")
    console.print("No changes were made.")


def _load_config_or_exit() -> tuple[dict[str, Any], Any]:
    config_path = find_config()
    try:
        return load_config(config_path), config_path
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _report_or_exit(exc: FileNotFoundError) -> None:
    console.print(f"[red]Error:[/red] {exc}")
    console.print("Run `styxctl sysprep check local` first.")
    raise typer.Exit(code=1) from exc


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


def _finish_install_report(report: dict, exit_code: int) -> None:
    if message := report.get("gate", {}).get("message"):
        console.print(f"[red]Install blocked:[/red] {message}")
    _print_install_report(report, exit_code=exit_code)


def _run_confirmed_install(
    run_fn: Callable[..., tuple[dict, int]],
    confirm_template: str,
) -> None:
    report, exit_code = run_fn(dry_run=False, yes=False, config_path=None)
    if report.get("status") == "CONFIRMATION_REQUIRED":
        pending = report.get("pending_count", 0)
        console.print(render_install_text(report))
        if not typer.confirm(confirm_template.format(pending=pending), default=False):
            console.print("No changes were made.")
            raise typer.Exit(code=0)
        report, exit_code = run_fn(dry_run=False, yes=True, config_path=None)
    _finish_install_report(report, exit_code)


@sysprep_check_app.command("local")
def sysprep_check_local() -> None:
    """Run the read-only MVP1 sysprep check on this machine."""
    inventory = collect_inventory()
    report = build_report_data(inventory, command="styxctl sysprep check local")
    text = render_sysprep_text(report)
    paths = save_report_bundle(report, text)

    console.print(text)
    console.print("[bold green]Reports saved[/bold green]")
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
    for column in ("Protocol", "Port", "Process", "PID", "Systemd Unit", "Safe To Stop", "Purpose"):
        table.add_column(column)

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


@config_app.command("show")
def config_show() -> None:
    """Show the active Styx config summary."""
    config, config_path = _load_config_or_exit()
    console.print(format_config_summary(config, config_path))


@config_app.command("validate")
def config_validate() -> None:
    """Validate styx.yaml structure for Styx."""
    config, config_path = _load_config_or_exit()
    issues = validate_config(config)
    status = config_status(issues)
    console.print(f"Config status: {status}")
    console.print(f"Config file: {config_path or 'not found'}")

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
        _report_or_exit(exc)


@report_app.command("json")
def report_json_local(
    hostname: str | None = typer.Argument(None, help="Hostname report directory to display."),
) -> None:
    """Print the latest saved local sysprep report as JSON."""
    try:
        console.print_json(data=load_saved_report(hostname=hostname))
    except FileNotFoundError as exc:
        _report_or_exit(exc)


@completion_app.command("install")
def completion_install() -> None:
    """Show install guidance for shell completion."""
    console.print("Typer can install completion for your active shell:")
    console.print("  styxctl --install-completion")
    console.print("Or print a script directly:")
    for shell in ("bash", "zsh", "fish"):
        console.print(f"  styxctl completion {shell}")


@install_app.command("local")
def install_local() -> None:
    """Install k3s and the Styx WireGuard foundation on this machine."""
    _run_confirmed_install(
        run_install_local,
        "Apply {pending} planned install step(s)?",
    )


@install_apply_app.command("local")
def install_apply_local() -> None:
    """Apply the local install plan without confirmation."""
    report, exit_code = run_install_local(dry_run=False, yes=True, config_path=None)
    _finish_install_report(report, exit_code)


@install_status_app.command("local")
def install_status_local() -> None:
    """Show local install status for k3s and Styx WireGuard."""
    health = run_install_doctor(config_path=None)
    table = Table(title="Styx Install Status")
    table.add_column("Component")
    table.add_column("State")

    rows = [
        ("k3s installed", "yes" if health.k3s_installed else "no"),
        ("k3s active", "yes" if health.k3s_active else "no"),
        ("k3s version", health.k3s_version or "unknown"),
        ("kubectl", "available" if health.kubectl_available else "missing"),
        ("wg binary", "available" if health.wg_binary else "missing"),
        ("Styx interface", "up" if health.styx_interface_up else "down"),
        ("47800/udp listening", "yes" if health.styx_port_listening else "no"),
        ("wg0 preserved", "yes" if health.wg0_preserved else "no"),
        ("config", f"{health.config_path or 'not found'} ({health.config_status})"),
        ("critical ports", "clear" if health.critical_ports_clear else "conflicts"),
    ]
    if health.cluster_node_count:
        rows.append(("cluster nodes configured", str(health.cluster_node_count)))
        if health.local_node:
            rows.append(("local cluster node", health.local_node))
    for label, value in rows:
        table.add_row(label, value)

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
    _finish_install_report(report, exit_code)


@install_plan_app.command("cluster")
def install_plan_cluster() -> None:
    """Preview the k3s cluster install plan without changing nodes."""
    report, exit_code = run_install_cluster(dry_run=True, yes=False, config_path=None)
    _finish_install_report(report, exit_code)


@install_app.command("cluster")
def install_cluster() -> None:
    """Install and join all k3s nodes listed in styx.yaml using their configured IPs."""
    _run_confirmed_install(
        run_install_cluster,
        "Apply k3s cluster setup to {pending} remote node(s)?",
    )


@install_apply_app.command("cluster")
def install_apply_cluster() -> None:
    """Apply the k3s cluster install plan without confirmation."""
    report, exit_code = run_install_cluster(dry_run=False, yes=True, config_path=None)
    _finish_install_report(report, exit_code)


@install_status_app.command("cluster")
def install_status_cluster() -> None:
    """Show k3s cluster node status for all configured IPs."""
    health = run_cluster_doctor(config_path=None)
    table = Table(title="Styx k3s Cluster Status")
    for column in ("Node", "Role", "IPv4", "IPv6", "Reachable", "k3s Active"):
        table.add_column(column)

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
    if kubectl_nodes := health.get("kubectl_nodes") or []:
        console.print(f"kubectl nodes: {', '.join(kubectl_nodes)}")
    if health.get("issues"):
        console.print("[red]Issues:[/red]")
        for issue in health["issues"]:
            console.print(f"  - {issue}")
        raise typer.Exit(code=1)


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


def _future_app(label: str, milestone: str) -> typer.Typer:
    future = _group(f"Future {label} commands ({milestone}).")

    @future.command("soon")
    def soon() -> None:  # pragma: no cover - simple placeholder
        _not_implemented_future(f"{label} commands", milestone)

    return future


def _completion_command(shell: str) -> Callable[[], None]:
    def handler() -> None:
        typer.echo(
            get_completion_script(
                prog_name="styxctl",
                complete_var="_STYXCTL_COMPLETE",
                shell=shell,
            )
        )

    handler.__doc__ = f"Print {shell} completion script."
    return handler


sysprep_safe_plan_app = _group("Preview safe local cleanup without changing the host.")
sysprep_safe_apply_app = _group("Apply safe local cleanup without confirmation.")
_add_remediation_commands(
    sysprep_safe_app,
    sysprep_safe_plan_app,
    sysprep_safe_apply_app,
    title="Styx Safe Sysprep Remediation",
    build_plan=build_safe_sysprep_plan,
    apply_plan=apply_safe_sysprep,
    helps=(
        "Stop/disable known-safe Styx/k3s leftovers and clear safe reserved-port conflicts.",
        "Preview known-safe Styx/k3s cleanup without changing the host.",
        "Apply known-safe Styx/k3s cleanup without confirmation.",
    ),
)

ports_clear_plan_app = _group("Preview safe port cleanup without changing the host.")
ports_clear_apply_app = _group("Apply safe port cleanup without confirmation.")
_add_remediation_commands(
    ports_clear_app,
    ports_clear_plan_app,
    ports_clear_apply_app,
    title="Styx Reserved Port Cleanup",
    build_plan=build_port_clear_plan,
    apply_plan=apply_port_clear,
    helps=(
        "Clear only safe Styx reserved port conflicts in 47800-47850.",
        "Preview safe Styx reserved port cleanup without changing the host.",
        "Clear safe Styx reserved port conflicts without confirmation.",
    ),
)

for shell in ("bash", "zsh", "fish"):
    completion_app.command(shell)(_completion_command(shell))

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

app.add_typer(sysprep_app, name="sysprep")
app.add_typer(ports_app, name="ports")
app.add_typer(install_app, name="install")
for label, milestone in (
    ("deploy", "MVP3"),
    ("status", "MVP3"),
    ("doctor", "MVP3"),
    ("client", "MVP4"),
    ("gateway", "MVP3"),
    ("siem", "MVP4"),
):
    app.add_typer(_future_app(label, milestone), name=label)
app.add_typer(config_app, name="config")
app.add_typer(report_app, name="report")
app.add_typer(completion_app, name="completion")


if __name__ == "__main__":
    app()
