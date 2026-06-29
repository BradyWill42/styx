"""Multi-node k3s cluster planning and remote orchestration for MVP2."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import os
import shutil
import subprocess
from typing import Any, Callable

from .inventory import SystemInventory
from .gateway import k3s_join_url, k3s_gateway_listen_args, parse_gateway_ports
from .lan_election import local_lan_subnet
from .nodes import (
    ClusterNode,
    all_node_tls_sans,
    init_server_node,
    is_colocated,
    node_bootstrap_host,
    node_effective_lan_ip,
    node_hostname,
    node_ssh_user,
    parse_nodes,
    site_entrypoint_for,
    sort_nodes_for_install,
)

K3S_TOKEN_PATH = "/var/lib/rancher/k3s/server/node-token"

RunResult = tuple[bool, str]


@dataclass(slots=True)
class SshConnection:
    target: str
    jump: str | None = None
    port: int = 47810


def _operator_on_lan(inventory: SystemInventory | None, lan_ip: str | None) -> bool:
    if inventory is None or not lan_ip:
        return False
    subnet = local_lan_subnet(inventory)
    if subnet is None:
        return False
    try:
        return ipaddress.ip_address(lan_ip) in subnet
    except ValueError:
        return False


def _init_join_host(
    init_node: ClusterNode,
    joining_node: ClusterNode,
    *,
    election_lan_ips: dict[str, str] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
) -> str | None:
    if (
        init_node.public_ipv4
        and joining_node.public_ipv4
        and init_node.public_ipv4 == joining_node.public_ipv4
    ):
        return node_effective_lan_ip(
            init_node,
            election_lan_ips=election_lan_ips,
            inventory=inventory,
            local_node=local_node,
        ) or init_node.public_ipv4
    return init_node.public_ipv4


def _init_ssh_host(
    init_node: ClusterNode,
    *,
    inventory: SystemInventory | None = None,
    election_lan_ips: dict[str, str] | None = None,
    local_node: ClusterNode | None = None,
) -> str | None:
    init_lan = node_effective_lan_ip(
        init_node,
        election_lan_ips=election_lan_ips,
        inventory=inventory,
        local_node=local_node,
    )
    if init_lan and _operator_on_lan(inventory, init_lan):
        return init_lan
    return init_node.public_ipv4


def _node_ssh_connection(
    node: ClusterNode,
    nodes: list[ClusterNode],
    fallback_user: str | None,
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
    gateway_ssh_port: int = 47810,
) -> SshConnection:
    user = node_ssh_user(node)
    entrypoint = site_entrypoint_for(
        node,
        nodes,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
    )
    lan_ip = node_effective_lan_ip(
        node,
        election_lan_ips=election_lan_ips,
        inventory=inventory,
        local_node=local_node,
    )

    # If the local node shares a public IP with the target, they are on the same LAN:
    # always reach it over the LAN IP, even when the target is the site entrypoint.
    # Bouncing out to the shared public IP relies on NAT hairpin/loopback, which is
    # usually closed and yields "connection refused".
    local_on_target_lan = (
        local_node is not None
        and local_node.public_ipv4 is not None
        and node.public_ipv4 is not None
        and local_node.public_ipv4 == node.public_ipv4
    )
    if local_on_target_lan and lan_ip:
        return SshConnection(target=f"{user}@{lan_ip}" if user else lan_ip, port=gateway_ssh_port)

    if not is_colocated(node, nodes) or (entrypoint is not None and node.name == entrypoint.name):
        host = (
            node_bootstrap_host(
                node,
                inventory=inventory,
                local_node=local_node,
            )
            or node.name
        )
        return SshConnection(target=f"{user}@{host}" if user else host, port=gateway_ssh_port)

    # Colocated nodes share a public IP — always connect directly over LAN, never via public IP.
    if lan_ip:
        return SshConnection(target=f"{user}@{lan_ip}" if user else lan_ip, port=gateway_ssh_port)

    # LAN IP unknown — fall back to ProxyJump through the site entrypoint.
    jump_host = entrypoint.public_ipv4 if entrypoint else node.public_ipv4
    jump_user = node_ssh_user(entrypoint) if entrypoint else user
    jump = f"{jump_user}@{jump_host}" if jump_user else jump_host
    final_host = node.name
    return SshConnection(
        target=f"{user}@{final_host}" if user else final_host,
        jump=jump,
        port=gateway_ssh_port,
    )


def _node_plan_target_host(
    node: ClusterNode,
    nodes: list[ClusterNode],
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> str:
    connection = _node_ssh_connection(
        node,
        nodes,
        None,
        config,
        inventory=inventory,
        local_node=local_node,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
    )
    if connection.jump:
        return f"{connection.target} via {connection.jump}"
    return connection.target.split("@", 1)[-1]


@dataclass(slots=True)
class ClusterNodePlan:
    node: ClusterNode
    role: str
    target_host: str
    node_ips: list[str]
    tls_sans: list[str]
    k3s_env: dict[str, str]
    k3s_args: list[str]
    command_display: str
    status: str = "pending"
    detail: str | None = None
    local_execution: bool = False
    ssh_port: int = 47810
    resolved_ipv4: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["node"] = self.node.to_dict()
        return data


@dataclass(slots=True)
class ClusterPlan:
    init_node: str
    nodes: list[ClusterNodePlan] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    join_url: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "init_node": self.init_node,
            "join_url": self.join_url,
            "warnings": list(self.warnings),
            "nodes": [item.to_dict() for item in self.nodes],
        }


def _k3s_network_args(config: dict[str, Any]) -> list[str]:
    cluster = config.get("cluster", {})
    network = config.get("network", {})
    mode = cluster.get("mode", "dual-stack")
    args: list[str] = []

    if mode in {"dual-stack", "ipv4-only"}:
        pod_ipv4 = network.get("pod_ipv4")
        service_ipv4 = network.get("service_ipv4")
        if isinstance(pod_ipv4, str):
            args.extend(["--cluster-cidr", pod_ipv4])
        if isinstance(service_ipv4, str):
            args.extend(["--service-cidr", service_ipv4])

    if mode in {"dual-stack", "ipv6-only"}:
        pod_ipv6 = network.get("pod_ipv6")
        service_ipv6 = network.get("service_ipv6")
        if isinstance(pod_ipv6, str):
            args.extend(["--cluster-cidr-v6", pod_ipv6])
        if isinstance(service_ipv6, str):
            args.extend(["--service-cidr-v6", service_ipv6])
    return args


def k3s_install_spec(
    config: dict[str, Any],
    node: ClusterNode,
    *,
    all_nodes: list[ClusterNode],
    join_url: str | None = None,
    join_token: str | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
) -> tuple[dict[str, str], list[str], str]:
    args = _k3s_network_args(config)
    args.extend(k3s_gateway_listen_args(config, server_role=node.role in {"init-server", "server"}))
    env: dict[str, str] = {}

    for ip in node.all_ips():
        args.extend(["--node-ip", ip])
    for san in all_node_tls_sans(
        all_nodes,
        config,
        election_lan_ips=election_lan_ips,
        inventory=inventory,
        local_node=local_node,
    ):
        args.extend(["--tls-san", san])

    # Distributed cluster, never node-local: keep the embedded etcd datastore (--cluster-init below)
    # AND disable k3s's local-path provisioner so PersistentVolumeClaims bind a DISTRIBUTED storage
    # class (Longhorn / MooseFS), never a node-local volume. Server-role nodes only.
    if node.role in {"init-server", "server"}:
        args.extend(["--disable", "local-storage"])

    if node.role == "init-server":
        env["INSTALL_K3S_EXEC"] = "server"
        args.append("--cluster-init")
        display = (
            "curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC='server' sh -s - "
            + " ".join(args)
        )
    elif node.role == "server":
        env["INSTALL_K3S_EXEC"] = "server"
        if join_url:
            env["K3S_URL"] = join_url
        if join_token:
            env["K3S_TOKEN"] = join_token
        display = (
            f"curl -sfL https://get.k3s.io | K3S_URL={join_url or '<init-url>'} "
            f"K3S_TOKEN=<token> INSTALL_K3S_EXEC='server' sh -s - "
            + " ".join(args)
        )
    else:
        env["INSTALL_K3S_EXEC"] = "agent"
        if join_url:
            env["K3S_URL"] = join_url
        if join_token:
            env["K3S_TOKEN"] = join_token
        display = (
            f"curl -sfL https://get.k3s.io | K3S_URL={join_url or '<init-url>'} "
            f"K3S_TOKEN=<token> INSTALL_K3S_EXEC='agent' sh -s - "
            + " ".join(args)
        )
    return env, args, display


def build_cluster_plan(
    config: dict[str, Any],
    *,
    local_node: ClusterNode | None = None,
    inventory: SystemInventory | None = None,
    join_url: str | None = None,
    join_token: str | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> ClusterPlan:
    nodes = parse_nodes(config)
    gateway = parse_gateway_ports(config)
    init_node = init_server_node(nodes)
    if init_node is None:
        return ClusterPlan(init_node="unknown", warnings=["no init-server node defined"])

    plans: list[ClusterNodePlan] = []
    warnings: list[str] = []
    default_join_url = join_url
    for node in sort_nodes_for_install(nodes):
        host = _node_plan_target_host(
            node,
            nodes,
            config,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        )
        if not host:
            warnings.append(f"node {node.name} has no bootstrap connectivity target")
            continue

        node_join_url = default_join_url
        if node.role != "init-server":
            join_host = _init_join_host(
                init_node,
                node,
                election_lan_ips=election_lan_ips,
                inventory=inventory,
                local_node=local_node,
            )
            if join_host:
                node_join_url = k3s_join_url(join_host, gateway)

        resolved = node.resolved_ipv4()
        env, args, display = k3s_install_spec(
            config,
            node,
            all_nodes=nodes,
            join_url=node_join_url if node.role != "init-server" else None,
            join_token=join_token if node.role != "init-server" else None,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
        )
        plans.append(
            ClusterNodePlan(
                node=node,
                role=node.role,
                target_host=host,
                node_ips=node.all_ips(),
                tls_sans=all_node_tls_sans(
                    nodes,
                    config,
                    election_lan_ips=election_lan_ips,
                    inventory=inventory,
                    local_node=local_node,
                ),
                k3s_env=env,
                k3s_args=args,
                command_display=display,
                local_execution=local_node is not None and local_node.name == node.name,
                ssh_port=gateway.ssh,
                resolved_ipv4=resolved,
            )
        )

    representative_join_url = default_join_url
    if representative_join_url is None and init_node:
        join_host = _init_ssh_host(
            init_node,
            inventory=inventory,
            election_lan_ips=election_lan_ips,
            local_node=local_node,
        )
        if join_host:
            representative_join_url = k3s_join_url(join_host, gateway)

    return ClusterPlan(
        init_node=init_node.name,
        nodes=plans,
        warnings=warnings,
        join_url=representative_join_url,
    )


def _ssh_target(
    node: ClusterNode,
    fallback_user: str | None,
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> SshConnection:
    nodes = parse_nodes(config)
    gateway = parse_gateway_ports(config)
    return _node_ssh_connection(
        node,
        nodes,
        fallback_user,
        config,
        inventory=inventory,
        local_node=local_node,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
        gateway_ssh_port=gateway.ssh,
    )


def _run_ssh_command(
    target: str,
    remote_command: str,
    *,
    port: int = 47810,
    jump: str | None = None,
    timeout: float = 900.0,
) -> RunResult:
    if shutil.which("ssh") is None:
        return False, "ssh command not found"
    use_sshpass = bool(os.environ.get("SSHPASS")) and shutil.which("sshpass") is not None
    command = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "LogLevel=ERROR",
    ]
    if use_sshpass:
        command.extend(["-o", "PreferredAuthentications=password", "-o", "BatchMode=no"])
    else:
        command.extend(["-o", "BatchMode=yes"])
    if jump:
        command.extend(["-J", f"{jump}:{port}"])
    command.extend([target, remote_command])
    if use_sshpass:
        command = ["sshpass", "-e", *command]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout} seconds"
    except OSError as exc:
        return False, str(exc)

    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return True, detail or "ok"
    return False, detail or f"ssh exit code {completed.returncode}"


def fetch_join_token_from_init(
    init_node: ClusterNode,
    *,
    config: dict[str, Any],
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> RunResult:
    gateway = parse_gateway_ports(config)
    connection = _ssh_target(
        init_node,
        ssh_user,
        config,
        inventory=inventory,
        local_node=local_node,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
    )
    run = runner or _run_ssh_command
    return run(
        connection.target,
        f"sudo cat {K3S_TOKEN_PATH}",
        port=connection.port,
        jump=connection.jump,
    )


def _remote_k3s_install_command(env: dict[str, str], args: list[str]) -> str:
    env_exports = " ".join(f"{key}='{value}'" for key, value in env.items())
    arg_text = " ".join(args)
    return f"curl -sfL https://get.k3s.io | {env_exports} sh -s - {arg_text}"


def apply_cluster_node_plan(
    plan: ClusterNodePlan,
    *,
    config: dict[str, Any],
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    inventory: SystemInventory | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> ClusterNodePlan:
    if plan.local_execution:
        plan.status = "skipped"
        plan.detail = "local node handled by install local"
        return plan

    connection = _ssh_target(
        plan.node,
        ssh_user,
        config,
        inventory=inventory,
        local_node=local_node,
        election_lan_ips=election_lan_ips,
        election_leader=election_leader,
    )
    remote_command = _remote_k3s_install_command(plan.k3s_env, plan.k3s_args)
    run = runner or _run_ssh_command
    ok, detail = run(
        connection.target,
        remote_command,
        port=connection.port,
        jump=connection.jump,
    )
    plan.status = "installed" if ok else "failed"
    plan.detail = detail
    return plan


def assess_cluster_nodes(
    config: dict[str, Any],
    *,
    inventory: SystemInventory | None = None,
    ssh_user: str | None = None,
    runner: Callable[..., RunResult] | None = None,
    local_node: ClusterNode | None = None,
    election_lan_ips: dict[str, str] | None = None,
    election_leader: str | None = None,
) -> dict[str, Any]:
    nodes = parse_nodes(config)
    gateway = parse_gateway_ports(config)
    init_node = init_server_node(nodes)
    results: list[dict[str, Any]] = []
    issues: list[str] = []
    run = runner or _run_ssh_command

    kubectl_nodes: list[str] = []
    if init_node:
        connection = _ssh_target(
            init_node,
            ssh_user,
            config,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        )
        ok, detail = run(
            connection.target,
            "sudo kubectl get nodes -o json",
            port=connection.port,
            jump=connection.jump,
        )
        if ok:
            try:
                payload = json.loads(detail)
                for item in payload.get("items", []):
                    name = item.get("metadata", {}).get("name")
                    ready = any(
                        condition.get("type") == "Ready" and condition.get("status") == "True"
                        for condition in item.get("status", {}).get("conditions", [])
                    )
                    kubectl_nodes.append(name or "unknown")
                    if not ready:
                        issues.append(f"kubectl reports node {name} not Ready")
            except json.JSONDecodeError:
                issues.append("could not parse kubectl get nodes output from init server")
        else:
            issues.append(f"could not query kubectl on init server: {detail}")

    for node in nodes:
        host = _node_plan_target_host(
            node,
            nodes,
            config,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        ) or node.name
        connection = _ssh_target(
            node,
            ssh_user,
            config,
            inventory=inventory,
            local_node=local_node,
            election_lan_ips=election_lan_ips,
            election_leader=election_leader,
        )
        ok, detail = run(
            connection.target,
            "sudo systemctl is-active k3s || sudo systemctl is-active k3s-agent",
            port=connection.port,
            jump=connection.jump,
        )
        resolved = node.resolved_ipv4()
        entry = {
            "name": node.name,
            "role": node.role,
            "hostname": node_hostname(node),
            "public_ipv4": node.public_ipv4,
            "ipv4": node.ipv4,
            "ipv6": node.ipv6,
            "resolved_ipv4": resolved,
            "reachable": ok,
            "k3s_active": detail.strip() == "active" if ok else False,
            "detail": detail,
        }
        results.append(entry)
        if not ok:
            issues.append(f"node {node.name} ({host}:{gateway.ssh}) is not reachable or k3s is not active")

    expected = {node.name for node in nodes}
    if kubectl_nodes and expected - set(kubectl_nodes):
        missing = ", ".join(sorted(expected - set(kubectl_nodes)))
        issues.append(f"cluster missing kubectl nodes: {missing}")

    healthy = not issues and len(results) == len(nodes) and all(item["k3s_active"] for item in results)
    return {
        "healthy": healthy,
        "init_node": init_node.name if init_node else None,
        "join_url": (
            k3s_join_url(
                _init_ssh_host(
                    init_node,
                    inventory=inventory,
                    election_lan_ips=election_lan_ips,
                    local_node=local_node,
                )
                or "",
                gateway,
            )
            if init_node
            and _init_ssh_host(
                init_node,
                inventory=inventory,
                election_lan_ips=election_lan_ips,
                local_node=local_node,
            )
            else None
        ),
        "kubectl_nodes": kubectl_nodes,
        "nodes": results,
        "issues": issues,
    }
