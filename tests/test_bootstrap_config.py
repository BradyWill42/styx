from styxctl.bootstrap_config import _map_lan_ips_by_identity
from styxctl.nodes import ClusterNode


def _node(name: str) -> ClusterNode:
    return ClusterNode(name=name, role="agent", ipv4=None, ipv6=None)


def test_map_lan_ips_by_identity_matches_hostname_output_not_scan_order():
    nodes = [_node("pegasus"), _node("atlas"), _node("kraken")]
    local = nodes[0]
    responses = {
        "atlas@192.168.1.235": (True, "kraken\n"),
        "atlas@192.168.1.238": (True, "atlas\n"),
        "kraken@192.168.1.235": (True, "kraken\n"),
    }

    def runner(target: str, command: str) -> tuple[bool, str]:
        assert command == "hostname -s"
        return responses.get(target, (False, "permission denied"))

    mapped = _map_lan_ips_by_identity(
        nodes,
        local,
        ["192.168.1.235", "192.168.1.238"],
        port=47810,
        runner=runner,
    )

    assert mapped == {"atlas": "192.168.1.238", "kraken": "192.168.1.235"}
