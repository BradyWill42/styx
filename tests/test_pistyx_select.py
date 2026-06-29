"""Pure tests for the fastest-site pistyx decision brain - no SSH, no cluster, no pithor."""

from styxctl.pistyx_select import (
    DEFAULT_HYSTERESIS_MS,
    parse_ping_rtt,
    rank_sites_by_consensus,
    rank_sites_by_rtt,
    select_consensus_site,
    select_fastest_site,
)


def test_parse_ping_rtt_iputils():
    out = "rtt min/avg/max/mdev = 12.3/18.7/25.1/4.2 ms"
    assert parse_ping_rtt(out) == 18.7


def test_parse_ping_rtt_busybox():
    out = "round-trip min/avg/max = 5.0/9.5/14.0 ms"
    assert parse_ping_rtt(out) == 9.5


def test_parse_ping_rtt_unreachable_or_garbage():
    assert parse_ping_rtt("100% packet loss") is None
    assert parse_ping_rtt("") is None
    assert parse_ping_rtt(None) is None


def test_rank_drops_unreachable_and_sorts_fastest_first():
    ranked = rank_sites_by_rtt({1: 30.0, 2: None, 3: 12.0, 4: -1})
    assert ranked == [(3, 12.0), (1, 30.0)]


def test_rank_tie_breaks_on_lower_site_index():
    assert rank_sites_by_rtt({2: 10.0, 1: 10.0}) == [(1, 10.0), (2, 10.0)]


def test_select_returns_none_when_all_unreachable():
    assert select_fastest_site({1: None, 2: None}) is None


def test_select_picks_fastest_when_no_current_holder():
    assert select_fastest_site({1: 40.0, 2: 10.0}, current_site=None) == 2


def test_select_moves_off_unreachable_current_site():
    assert select_fastest_site({1: None, 2: 50.0}, current_site=1) == 2


def test_select_stays_within_hysteresis():
    # current site (1) is only a few ms slower than the best; don't flap the DuckDNS record.
    assert select_fastest_site({1: 20.0, 2: 12.0}, current_site=1, hysteresis_ms=DEFAULT_HYSTERESIS_MS) == 1


def test_select_moves_when_beaten_beyond_hysteresis():
    assert select_fastest_site({1: 80.0, 2: 12.0}, current_site=1, hysteresis_ms=DEFAULT_HYSTERESIS_MS) == 2


def test_consensus_rank_favors_reachability_then_average_rtt():
    ranked = rank_sites_by_consensus({
        "phone": {1: 20.0, 2: 8.0, 3: None},
        "laptop": {1: 40.0, 2: None, 3: 2.0},
    })
    assert ranked == [
        {"site": 1, "reachable": 2, "avg_rtt_ms": 30.0},
        {"site": 3, "reachable": 1, "avg_rtt_ms": 2.0},
        {"site": 2, "reachable": 1, "avg_rtt_ms": 8.0},
    ]


def test_consensus_sticks_with_current_site_inside_hysteresis():
    samples = {"phone": {1: 25.0, 2: 18.0}}
    assert select_consensus_site(samples, current_site=1, hysteresis_ms=15.0) == 1


def test_consensus_moves_when_average_beats_hysteresis():
    samples = {"phone": {1: 70.0, 2: 18.0}}
    assert select_consensus_site(samples, current_site=1, hysteresis_ms=15.0) == 2


def test_consensus_moves_to_site_that_reaches_more_active_clients():
    samples = {
        "phone": {1: 10.0, 2: 40.0},
        "laptop": {1: None, 2: 80.0},
    }
    assert select_consensus_site(samples, current_site=1, hysteresis_ms=15.0) == 2
