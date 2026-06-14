"""Gateway port-forward settings for cross-site Styx nodes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ports import RESERVED_PORT_END, RESERVED_PORT_START

DEFAULT_SSH_PORT = 47810
DEFAULT_K3S_API_PORT = 47811


@dataclass(frozen=True, slots=True)
class GatewayPorts:
    ssh: int = DEFAULT_SSH_PORT
    k3s_api: int = DEFAULT_K3S_API_PORT

    def validate(self) -> list[str]:
        errors: list[str] = []
        for label, port in (("gateway.ssh_port", self.ssh), ("gateway.k3s_api_port", self.k3s_api)):
            if not (RESERVED_PORT_START <= port <= RESERVED_PORT_END):
                errors.append(
                    f"{label}: port {port} must be within Styx reserved range "
                    f"{RESERVED_PORT_START}-{RESERVED_PORT_END}"
                )
        if self.ssh == self.k3s_api:
            errors.append("gateway: ssh_port and k3s_api_port must be different")
        return errors


def parse_gateway_ports(config: dict[str, Any]) -> GatewayPorts:
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        return GatewayPorts()

    ssh = gateway.get("ssh_port", DEFAULT_SSH_PORT)
    k3s_api = gateway.get("k3s_api_port", DEFAULT_K3S_API_PORT)
    if not isinstance(ssh, int):
        ssh = DEFAULT_SSH_PORT
    if not isinstance(k3s_api, int):
        k3s_api = DEFAULT_K3S_API_PORT
    return GatewayPorts(ssh=ssh, k3s_api=k3s_api)


def k3s_join_url(hostname: str, ports: GatewayPorts) -> str:
    return f"https://{hostname}:{ports.k3s_api}"
