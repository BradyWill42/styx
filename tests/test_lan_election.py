"""Regression tests for the lan_election df parser (the parts[5] IndexError fix)."""

from styxctl.lan_election import parse_root_avail_kb


def test_root_avail_parsed_from_full_df_row():
    df = "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 1000 400 600 40% /\n"
    assert parse_root_avail_kb(df) == 600 * 1024


def test_short_df_row_does_not_crash():
    # Regression: a '/'-leading line with <6 columns must not raise IndexError.
    df = "/dev/root 1000 400 600\n"
    assert parse_root_avail_kb(df) is None


def test_non_root_mountpoint_ignored():
    df = "/dev/sda1 1000 400 600 40% /boot\n"
    assert parse_root_avail_kb(df) is None


def test_empty_input():
    assert parse_root_avail_kb("") is None
