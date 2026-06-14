from styxctl.inventory import boot_time_from_proc_stat, parse_ip_br_addr, parse_ip_route_src, parse_nameservers, parse_os_release
from styxctl.ports import extract_port, parse_ss_output, port_purpose


def test_parse_os_release_pretty_name():
    assert parse_os_release('NAME="Raspberry Pi OS"\nPRETTY_NAME="Raspberry Pi OS Bookworm"\n') == "Raspberry Pi OS Bookworm"


def test_parse_nameservers():
    assert parse_nameservers("# test\nnameserver 10.206.201.3\nnameserver fd00:cafe::53\n") == [
        "10.206.201.3",
        "fd00:cafe::53",
    ]


def test_parse_ip_route_src():
    output = "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.20 uid 1000"
    assert parse_ip_route_src(output) == "192.168.1.20"


def test_parse_ip_br_addr():
    lines, names = parse_ip_br_addr("lo UNKNOWN 127.0.0.1/8 ::1/128\neth0 UP 10.0.0.5/24\nwg0 UNKNOWN 10.206.201.8/24\n")
    assert names == ["lo", "eth0", "wg0"]
    assert len(lines) == 3


def test_boot_time_from_proc_stat():
    assert boot_time_from_proc_stat("cpu  1 2 3\nbtime 1710000000\n") == "2024-03-09T16:00:00+00:00"


def test_extract_port_formats():
    assert extract_port("0.0.0.0:47800") == 47800
    assert extract_port("*:47801") == 47801
    assert extract_port("[::]:47802") == 47802
    assert extract_port("[fe80::1%eth0]:47803") == 47803
    assert extract_port(":::47804") == 47804


def test_parse_ss_output_reserved_conflict():
    output = 'udp UNCONN 0 0 0.0.0.0:47800 0.0.0.0:* users:(("old-styx",pid=123,fd=6))\n'
    conflicts = parse_ss_output(output)
    assert len(conflicts) == 1
    assert conflicts[0].protocol == "udp"
    assert conflicts[0].port == 47800
    assert conflicts[0].process_name == "old-styx"
    assert conflicts[0].pid == 123
    assert conflicts[0].safe_to_stop is True


def test_parse_ss_output_ignores_non_styx_range():
    output = 'tcp LISTEN 0 4096 0.0.0.0:6443 0.0.0.0:* users:(("k3s",pid=999,fd=6))\n'
    assert parse_ss_output(output) == []


def test_port_purpose_block():
    assert port_purpose(47810) == "SSH gateway listen (MVP2 configures on Pi)"
    assert port_purpose(47811) == "k3s API gateway listen (MVP2 configures on Pi)"
    assert port_purpose(47830) == "spare / future"
