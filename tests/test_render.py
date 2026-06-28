"""Pure WireGuard render tests — config text generation, no cluster/SSH/pithor."""

from styxctl.wireguard_mesh import (
    MeshMember,
    pistyx_clients,
    render_client_config,
    render_local_config,
    render_pistyx_pop,
)


def test_pistyx_pop_is_a_server_not_a_default_route():
    out = render_pistyx_pop(
        "<priv>",
        [{"name": "laptop", "public_key": "PUBKEY", "ipv4": "10.0.250.2", "ipv6": None}],
        listen_port=47801,
        mtu=1420,
        gateway_v4="10.0.250.1",
        gateway_v6="fd00:cafe:0:250::1",
        stack_mode="dual-stack",
    )
    assert "Address = 10.0.250.1/24" in out          # owns the client band
    assert "ListenPort = 47801" in out
    assert "MTU = 1420" in out
    assert "PublicKey = PUBKEY" in out
    assert "AllowedIPs = 10.0.250.2/32" in out         # routed by the client's /32
    # The PoP must NEVER carry a default route — that was the severing bug.
    assert "0.0.0.0/0" not in out


def test_pistyx_pop_with_no_clients_has_no_peers():
    out = render_pistyx_pop(
        "<priv>", [], listen_port=47801, mtu=1420,
        gateway_v4="10.0.250.1", gateway_v6="fd00:cafe:0:250::1",
    )
    assert "[Interface]" in out
    assert "[Peer]" not in out


def test_client_config_full_tunnels_to_pistyx():
    out = render_client_config(
        "laptop", "<priv>",
        pistyx_pubkey="PISTYXPUB", endpoint="pistyx.duckdns.org", port=47801,
        address_v4="10.0.250.2", address_v6="fd00:cafe:0:250::2", mtu=1420,
    )
    assert "Endpoint = pistyx.duckdns.org:47801" in out
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in out
    assert "PublicKey = PISTYXPUB" in out
    assert "PersistentKeepalive = 25" in out


def test_client_config_ipv4_only_prunes_v6():
    out = render_client_config(
        "laptop", "<priv>", pistyx_pubkey="P", endpoint="pistyx.duckdns.org", port=47801,
        address_v4="10.0.250.2", address_v6=None, mtu=1420,
    )
    assert "0.0.0.0/0" in out
    assert "::/0" not in out


def test_mesh_spoke_routes_supernet_to_hub():
    members = [
        MeshMember(name="pegasus", role="init-server", ipv4="10.0.0.1", ipv6=None,
                   public_key="HUB", endpoint="pipegasus.duckdns.org"),
        MeshMember(name="hydra", role="agent", ipv4="10.0.0.2", ipv6=None, public_key="SPOKE"),
    ]
    out = render_local_config(
        "hydra", "<priv>", members, "pegasus",
        listen_port=47800, route_v4="10.0.0.0/14", route_v6="fd00:cafe::/48",
    )
    assert "AllowedIPs = 10.0.0.0/14" in out
    assert "Endpoint = pipegasus.duckdns.org:47800" in out
    assert "PersistentKeepalive = 25" in out


def test_mesh_hub_has_per_spoke_peer_not_default_route():
    members = [
        MeshMember(name="pegasus", role="init-server", ipv4="10.0.0.1", ipv6=None, public_key="HUB"),
        MeshMember(name="hydra", role="agent", ipv4="10.0.0.2", ipv6=None, public_key="SPOKE"),
    ]
    out = render_local_config(
        "pegasus", "<priv>", members, "pegasus",
        listen_port=47800, route_v4="10.0.0.0/14", route_v6="fd00:cafe::/48",
    )
    assert "AllowedIPs = 10.0.0.2/32" in out   # routed by the spoke's /32
    assert "PublicKey = SPOKE" in out


def test_pistyx_clients_parses_and_skips_incomplete():
    cfg = {"clients": [
        {"name": "good", "public_key": "K", "ipv4": "10.0.250.2"},
        {"name": "no-key"},          # dropped: no public_key
        "not-a-dict",                 # dropped
    ]}
    clients = pistyx_clients(cfg)
    assert len(clients) == 1
    assert clients[0]["name"] == "good"
