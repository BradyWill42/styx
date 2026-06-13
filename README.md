# styxctl

`styxctl` is the control CLI for Styx: a k3s-native, dual-stack WireGuard mesh and access gateway platform.

MVP1 covers local assessment and safe remediation on a single Linux gateway node.

## MVP1 workflow

```bash
styxctl sysprep check local
styxctl sysprep safe plan local
styxctl sysprep safe apply local
styxctl sysprep check local
```

Typical flow:

1. **Check** the node read-only
2. **Preview** safe cleanup with `sysprep safe plan local`
3. **Apply** safe cleanup with `sysprep safe apply local`
4. **Re-check** until status is `READY` or only non-blocking warnings remain

## Install for local development

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## MVP1 commands

### Assessment

```bash
styxctl sysprep check local
styxctl ports check local
styxctl ports list local
```

`sysprep check local` collects local inventory, checks Styx reserved ports `47800-47850`, detects old k3s/CNI/Styx artifacts, prints a report, and saves JSON/text output.

Reports are saved under:

```text
./reports/styx/<hostname>/sysprep-report.json
./reports/styx/<hostname>/sysprep-report.txt
```

Readiness status:

- `READY` — clear to proceed toward MVP2 install
- `READY_WITH_WARNINGS` — usable, but review warnings first
- `BLOCKED` — critical ports `47800-47808` are occupied; exits with code `1`

### Safe remediation

```bash
styxctl sysprep safe plan local
styxctl sysprep safe apply local
styxctl sysprep safe local
styxctl ports clear plan local
styxctl ports clear apply local
styxctl ports clear local
```

Safe remediation only acts on items already identified as safe:

- Styx/k3s/flannel/CNI processes marked `safe_to_stop`
- known leftover services such as `k3s.service` and `k3s-agent.service`
- old temporary Styx files under `/tmp/styx*` and `/var/tmp/styx*`

It never touches:

- `wg0`
- LAN networking, SSH, BIND, Caddy, MooseFS, home directories, or unrelated services
- unsafe port conflicts
- deeper k3s state directories (reserved for MVP3 reset)

Use `sysprep safe plan local` first. `sysprep safe local` asks for confirmation before changing the host; `sysprep safe apply local` skips the prompt.

### Config and reports

```bash
styxctl config show
styxctl config validate
styxctl report show
styxctl report json
```

Copy `styx.yaml.example` to `styx.yaml` when you want config validation before MVP2.

## MVP2 workflow

After MVP1 leaves the node `READY` or `READY_WITH_WARNINGS`:

```bash
cp styx.yaml.example styx.yaml
# Edit nodes: set each node's ipv4/ipv6 to its current LAN addresses
styxctl config validate
styxctl install plan local
styxctl install plan cluster
styxctl install local                 # asks for confirmation
styxctl install apply local             # prereqs + local k3s role on each node
styxctl install cluster                 # asks for confirmation
styxctl install apply cluster           # init + join all nodes by IP over SSH
styxctl install status local
styxctl install status cluster
styxctl install doctor local
styxctl install doctor cluster
```

Each node in `styx.yaml` uses its configured `ipv4` / `ipv6` as the k3s `--node-ip` values. The init-server node bootstraps the cluster with dual-stack pod/service CIDRs from the network plan; additional `server` and `agent` nodes join using their own current IPs.

MVP2 installs only the local foundation prerequisites:

- k3s server with cluster/service CIDRs from `styx.yaml`
- Styx WireGuard interface on `47800/udp` (interface name `Styx`, never `wg0`)
- supporting packages such as `iproute2`, WireGuard tools, and `curl`

Reports are saved under:

```text
./reports/styx/<hostname>/install-report.json
./reports/styx/<hostname>/install-report.txt
```

Install is blocked when:

- `styx.yaml` is missing or `INVALID`
- sysprep status is `BLOCKED` on ports `47800-47808`
- non-interactive sudo is unavailable for a mutating install

Use `install plan local` first. `install local` asks for confirmation before changing the host; `install apply local` skips the prompt.

`install status local` and `install doctor local` verify k3s, the `Styx` interface, `wg0` preservation, and critical port state. Exit code `0` means healthy enough for MVP3 deploy work.

## CLI style

The CLI is command-discovery-first:

```bash
styxctl <TAB>
styxctl sysprep <TAB>
styxctl sysprep check <TAB>
```

Future placeholders remain read-only:

```bash
styxctl sysprep reset local   # MVP3
styxctl sysprep nuke local    # MVP3
styxctl deploy soon           # MVP3
```

## Shell completion

```bash
styxctl --install-completion
styxctl completion bash
styxctl completion zsh
styxctl completion fish
```

## Styx reserved ports

Only this range is checked and cleaned by MVP1:

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

`styxctl sysprep check local` is read-only.

`sysprep safe local` and `ports clear local` are bounded remediation commands. They do not perform destructive resets, delete k3s data directories, or modify preserved infrastructure.

`styxctl install local` only installs k3s and the `Styx` WireGuard interface. It never modifies `wg0`, LAN networking, SSH, BIND, Caddy, MooseFS, or unrelated services.

`wg0` is detected and reported as preserved. It is never removed by MVP1 or modified by MVP2 install.

## Development checks

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m styxctl.cli --help
styxctl sysprep check local
styxctl sysprep safe plan local
styxctl config validate
styxctl install plan local
styxctl install apply local
styxctl report show
```

## GitHub-hosted smoke test

Every push and pull request runs a read-only sysprep check on a GitHub-hosted Ubuntu runner. In the Actions tab, open the **Sysprep check (GitHub-hosted)** job to see the live report output. Download the **sysprep-report-github-hosted** artifact to inspect the saved JSON and text reports.

This validates the full check path on real Linux, but it is not a substitute for running MVP1 on your own gateway node.
