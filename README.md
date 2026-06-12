# styxctl

`styxctl` is the control CLI for Styx: a k3s-native, dual-stack WireGuard mesh and access gateway platform.

MVP1 implements the safe, read-only local sysprep check:

```bash
styxctl sysprep check local
```

It collects local inventory, checks only the Styx reserved port range `47800-47850`, detects old k3s/CNI/Styx artifacts, prints a human-readable report, and automatically saves JSON and text reports.

## Install for local development

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Then run:

```bash
styxctl sysprep check local
```

Reports are saved automatically under:

```text
./reports/styx/<hostname>/sysprep-report.json
./reports/styx/<hostname>/sysprep-report.txt
```

## CLI style

The CLI is intentionally command-discovery-first instead of flag-heavy.

Expected discovery path:

```bash
styxctl <TAB>
styxctl sysprep <TAB>
styxctl sysprep check <TAB>
```

Implemented MVP1 command:

```bash
styxctl sysprep check local
```

Safe placeholders are present for the future sysprep modes:

```bash
styxctl sysprep safe local
styxctl sysprep reset local
styxctl sysprep nuke local
```

These placeholders do not change the host.

## Shell completion

Typer supports completion installation:

```bash
styxctl --install-completion
```

This scaffold also includes command-style helpers:

```bash
styxctl completion bash
styxctl completion zsh
styxctl completion fish
styxctl completion install
```

## Styx reserved ports

Only this range is checked by MVP1 sysprep:

```text
47800-47850
```

Important planned ports:

```text
47800/udp  Styx production WireGuard gateway
47801/tcp  Styx gateway health API
47802/tcp  Styx director API
47803/tcp  Styx status dashboard/API
47804/tcp  Styx node agent API
47805/tcp  Styx Ansible controller API
47806/tcp  Styx watchdog agent API
47807/tcp  Styx local diagnostics API
47808/tcp  Styx metrics exporter
47809      reserved

47810-47819  site/gateway testing
47820-47829  client/profile testing
47830-47839  development/debug
47840-47850  reserved future
```

The future WireGuard endpoint should use:

```ini
Endpoint = pistyx.duckdns.org:47800
```

## Safety rules

`styxctl sysprep check local` is read-only. It does not stop services, kill processes, edit files, delete directories, change networking, disable units, or remove interfaces.

It preserves existing LAN networking, SSH, `wg0`, MooseFS, DNS/BIND, Caddy, home directories, Ansible directories, non-Styx services, and custom scripts.

`wg0` is detected and reported as preserved. It is never removed by MVP1.

## Development checks

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m styxctl.cli --help
styxctl ports list local
styxctl ports check local
```

When `styxctl sysprep check local` reports `Status: BLOCKED`, the command exits with code `1` so scripts and CI can fail fast.

## GitHub-hosted smoke test

Every push and pull request runs a read-only sysprep check on a GitHub-hosted Ubuntu runner. In the Actions tab, open the **Sysprep check (GitHub-hosted)** job to see the live report output. Download the **sysprep-report-github-hosted** artifact to inspect the saved JSON and text reports.

This validates the full command path on real Linux, but it is not a substitute for running the check on your own gateway node.
