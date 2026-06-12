"""Typer CLI entry point for styxctl."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table
from typer._completion_shared import get_completion_script

from . import __version__
from .inventory import collect_inventory
from .ports import PORT_BLOCKS, PORT_PLAN, check_reserved_ports, port_purpose
from .prerequisites import (
    render_prerequisites_text,
    run_prerequisites_install,
    save_prerequisites_report,
)
from .reports import build_report_data, render_sysprep_text, save_report_bundle

console = Console()

app = typer.Typer(
    name="styxctl",
    help="Prepare, install, and manage Styx nodes.",
    no_args_is_help=True,
)
sysprep_app = typer.Typer(help="Prepare hosts safely before Styx installation.", no_args_is_help=True)
sysprep_check_app = typer.Typer(help="Read-only sysprep checks.", no_args_is_help=True)
sysprep_safe_app = typer.Typer(help="Known-safe cleanup modes. MVP1 placeholder only.", no_args_is_help=True)
sysprep_reset_app = typer.Typer(help="Interactive cleanup modes. MVP1 placeholder only.", no_args_is_help=True)
sysprep_nuke_app = typer.Typer(help="Destructive cleanup modes. MVP1 placeholder only.", no_args_is_help=True)
ports_app = typer.Typer(help="Inspect the Styx reserved port range.", no_args_is_help=True)
ports_check_app = typer.Typer(help="Check Styx reserved ports.", no_args_is_help=True)
ports_list_app = typer.Typer(help="List the Styx reserved port plan.", no_args_is_help=True)
ports_clear_app = typer.Typer(help="Clear Styx reserved ports. MVP1 placeholder only.", no_args_is_help=True)
completion_app = typer.Typer(help="Shell completion helpers.", no_args_is_help=True)
install_app = typer.Typer(help="Install Styx prerequisites and platform components.", no_args_is_help=True)
install_prerequisites_app = typer.Typer(help="Install host prerequisites.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """styxctl command root."""


@app.command("version")
def version() -> None:
    """Print the styxctl version."""
    console.print(__version__)


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
        raise typer.Exit(code=1)


@sysprep_check_app.command("all")
def sysprep_check_all() -> None:
    """Future: run sysprep checks across all nodes."""
    console.print("MVP4 placeholder: no remote checks were run.")


@sysprep_check_app.command("node")
def sysprep_check_node() -> None:
    """Future: run sysprep check on one named node."""
    console.print("MVP4 placeholder: no remote node check was run.")


def _not_implemented_read_only(command_name: str) -> None:
    console.print(f"{command_name} is not implemented in MVP1.")
    console.print("No changes were made.")


@sysprep_safe_app.command("local")
def sysprep_safe_local() -> None:
    """Future: stop/disable known safe services only."""
    _not_implemented_read_only("styxctl sysprep safe local")


@sysprep_reset_app.command("local")
def sysprep_reset_local() -> None:
    """Future: interactive reset of known Styx/k3s/CNI leftovers."""
    _not_implemented_read_only("styxctl sysprep reset local")


@sysprep_nuke_app.command("local")
def sysprep_nuke_local() -> None:
    """Future: destructive force-clear with confirmation."""
    _not_implemented_read_only("styxctl sysprep nuke local")


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
def ports_clear_local() -> None:
    """Future: clear only Styx reserved ports."""
    _not_implemented_read_only("styxctl ports clear local")


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


@install_prerequisites_app.command("local")
def install_prerequisites_local(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Show the install plan without changing the host.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Proceed even when sysprep status is BLOCKED.",
    ),
    config: str | None = typer.Option(
        None,
        "--config",
        help="Path to styx.yaml for optional component selection.",
    ),
) -> None:
    """Install missing host prerequisites on this machine."""
    result = run_prerequisites_install(dry_run=dry_run, force=force, config_path=config)
    text = render_prerequisites_text(result)
    paths = save_prerequisites_report(result, text)

    console.print(text)
    console.print("[bold green]Reports saved[/bold green]")
    console.print(f"  JSON: {paths['json']}")
    console.print(f"  Text: {paths['text']}")

    if result.overall_status in {"BLOCKED", "FAILED"}:
        raise typer.Exit(code=1)


def _future_app(label: str) -> typer.Typer:
    future = typer.Typer(help=f"Future {label} commands.", no_args_is_help=True)

    @future.command("soon")
    def soon() -> None:  # pragma: no cover - simple placeholder
        console.print(f"{label} commands are not implemented yet. No changes were made.")

    return future


sysprep_app.add_typer(sysprep_check_app, name="check")
sysprep_app.add_typer(sysprep_safe_app, name="safe")
sysprep_app.add_typer(sysprep_reset_app, name="reset")
sysprep_app.add_typer(sysprep_nuke_app, name="nuke")
ports_app.add_typer(ports_check_app, name="check")
ports_app.add_typer(ports_list_app, name="list")
ports_app.add_typer(ports_clear_app, name="clear")

install_app.add_typer(install_prerequisites_app, name="prerequisites")

app.add_typer(sysprep_app, name="sysprep")
app.add_typer(ports_app, name="ports")
app.add_typer(install_app, name="install")
app.add_typer(_future_app("deploy"), name="deploy")
app.add_typer(_future_app("status"), name="status")
app.add_typer(_future_app("doctor"), name="doctor")
app.add_typer(_future_app("client"), name="client")
app.add_typer(_future_app("gateway"), name="gateway")
app.add_typer(_future_app("siem"), name="siem")
app.add_typer(_future_app("config"), name="config")
app.add_typer(_future_app("report"), name="report")
app.add_typer(completion_app, name="completion")


if __name__ == "__main__":
    app()
