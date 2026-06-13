"""Typer CLI entry point for styxctl."""

from __future__ import annotations

from pathlib import Path
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
    add_completion=False,
)
sysprep_app = typer.Typer(help="Prepare hosts safely before Styx installation.", no_args_is_help=True)
sysprep_check_app = typer.Typer(help="Read-only sysprep checks.", no_args_is_help=True)
sysprep_safe_app = typer.Typer(help="Known-safe local cleanup before install.", no_args_is_help=True)
sysprep_safe_preview_app = typer.Typer(help="Preview safe cleanup without changing the host.", no_args_is_help=True)
sysprep_reset_app = typer.Typer(help="Interactive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
sysprep_nuke_app = typer.Typer(help="Destructive cleanup modes. MVP3 placeholder.", no_args_is_help=True)
ports_app = typer.Typer(help="Inspect the Styx reserved port range.", no_args_is_help=True)
ports_check_app = typer.Typer(help="Check Styx reserved ports.", no_args_is_help=True)
ports_list_app = typer.Typer(help="List the Styx reserved port plan.", no_args_is_help=True)
ports_clear_app = typer.Typer(help="Clear safe Styx reserved port conflicts.", no_args_is_help=True)
ports_clear_preview_app = typer.Typer(help="Preview port cleanup without changing the host.", no_args_is_help=True)
config_app = typer.Typer(help="Inspect and validate styx.yaml.", no_args_is_help=True)
report_app = typer.Typer(help="Inspect saved sysprep reports.", no_args_is_help=True)
report_show_app = typer.Typer(help="Show saved sysprep reports.", no_args_is_help=True)
report_json_app = typer.Typer(help="Show saved sysprep reports as JSON.", no_args_is_help=True)
completion_app = typer.Typer(help="Shell completion helpers.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """styxctl command root."""


@app.command("version")
def version() -> None:
    """Print the styxctl version."""
    console.print(__version__)


def _confirm_or_exit(planned_count: int) -> None:
    if planned_count == 0:
        console.print("[green]Nothing to do.[/green]")
        raise typer.Exit(code=0)
    if not typer.confirm(f"Apply {planned_count} planned action(s)?", default=False):
        console.print("No changes were made.")
        raise typer.Exit(code=0)


def _preview_remediation(*, title: str, build_plan) -> None:
    inventory = collect_inventory()
    result = build_plan(inventory)
    result.dry_run = True
    console.print(render_remediation_summary(result, title=title))


def _load_config_or_exit() -> tuple[dict[str, Any], Path | None]:
    config_path = find_config()
    try:
        return load_config(config_path), config_path
    except ConfigError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _report_missing(exc: FileNotFoundError) -> None:
    console.print(f"[red]Error:[/red] {exc}")
    console.print("Run `styxctl sysprep check local` first.")
    raise typer.Exit(code=1) from exc


def _apply_remediation(*, title: str, build_plan, apply_plan) -> None:
    inventory = collect_inventory()
    plan = build_plan(inventory)
    console.print(render_remediation_summary(plan, title=f"{title} (preview)"))
    _confirm_or_exit(len(plan.planned))

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
        console.print("[yellow]Hint:[/yellow] try `styxctl sysprep safe preview local` to preview safe cleanup.")
        raise typer.Exit(code=1)


def _mvp4_placeholder(message: str) -> None:
    console.print(f"MVP4 placeholder: {message}")


@sysprep_check_app.command("all")
def sysprep_check_all() -> None:
    """Future: run sysprep checks across all nodes."""
    _mvp4_placeholder("no remote checks were run.")


@sysprep_check_app.command("node")
def sysprep_check_node() -> None:
    """Future: run sysprep check on one named node."""
    _mvp4_placeholder("no remote node check was run.")


@sysprep_safe_preview_app.command("local")
def sysprep_safe_preview_local() -> None:
    """Preview known-safe Styx/k3s cleanup on this machine."""
    _preview_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
    )


@sysprep_safe_app.command("local")
def sysprep_safe_local() -> None:
    """Apply known-safe Styx/k3s cleanup on this machine."""
    _apply_remediation(
        title="Styx Safe Sysprep Remediation",
        build_plan=build_safe_sysprep_plan,
        apply_plan=apply_safe_sysprep,
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


@ports_clear_preview_app.command("local")
def ports_clear_preview_local() -> None:
    """Preview safe reserved-port cleanup on this machine."""
    _preview_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
    )


@ports_clear_app.command("local")
def ports_clear_local() -> None:
    """Clear safe Styx reserved port conflicts on this machine."""
    _apply_remediation(
        title="Styx Reserved Port Cleanup",
        build_plan=build_port_clear_plan,
        apply_plan=apply_port_clear,
    )


@config_app.command("show")
def config_show() -> None:
    """Show the active Styx config summary from ./styx.yaml."""
    config, config_path = _load_config_or_exit()
    console.print(format_config_summary(config, config_path))


@config_app.command("validate")
def config_validate() -> None:
    """Validate ./styx.yaml structure for Styx."""
    config, config_path = _load_config_or_exit()

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


@report_show_app.command("local")
def report_show_local() -> None:
    """Show the latest saved local sysprep report."""
    try:
        console.print(load_saved_report_text(), end="")
    except FileNotFoundError as exc:
        _report_missing(exc)


@report_json_app.command("local")
def report_json_local() -> None:
    """Show the latest saved local sysprep report as JSON."""
    try:
        console.print_json(data=load_saved_report())
    except FileNotFoundError as exc:
        _report_missing(exc)


def _emit_completion(shell: str) -> None:
    typer.echo(
        get_completion_script(
            prog_name="styxctl",
            complete_var="_STYXCTL_COMPLETE",
            shell=shell,
        )
    )


def _completion_command(shell: str):
    def cmd() -> None:
        _emit_completion(shell)

    cmd.__doc__ = f"Print {shell} completion script."
    return cmd


for _shell in ("bash", "zsh", "fish"):
    completion_app.command(_shell)(_completion_command(_shell))


@completion_app.command("install")
def completion_install() -> None:
    """Show install guidance for shell completion."""
    console.print("Install a completion script directly:")
    console.print("  styxctl completion bash")
    console.print("  styxctl completion zsh")
    console.print("  styxctl completion fish")


def _future_app(label: str, milestone: str) -> typer.Typer:
    future = typer.Typer(help=f"Future {label} commands ({milestone}).", no_args_is_help=True)

    @future.command("soon")
    def soon() -> None:  # pragma: no cover - simple placeholder
        _not_implemented_future(f"{label} commands", milestone)

    return future


sysprep_app.add_typer(sysprep_check_app, name="check")
sysprep_safe_app.add_typer(sysprep_safe_preview_app, name="preview")
sysprep_app.add_typer(sysprep_safe_app, name="safe")
sysprep_app.add_typer(sysprep_reset_app, name="reset")
sysprep_app.add_typer(sysprep_nuke_app, name="nuke")
ports_app.add_typer(ports_check_app, name="check")
ports_app.add_typer(ports_list_app, name="list")
ports_clear_app.add_typer(ports_clear_preview_app, name="preview")
ports_app.add_typer(ports_clear_app, name="clear")
report_app.add_typer(report_show_app, name="show")
report_app.add_typer(report_json_app, name="json")

app.add_typer(sysprep_app, name="sysprep")
app.add_typer(ports_app, name="ports")
app.add_typer(_future_app("install", "MVP2"), name="install")
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
