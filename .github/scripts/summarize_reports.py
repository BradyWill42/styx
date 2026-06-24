#!/usr/bin/env python3
"""Summarize all runner integration JSON reports in a directory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import REPORT_DIR, format_report


def main() -> int:
    report_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPORT_DIR
    if not report_dir.is_dir():
        print(f"No report directory: {report_dir}", file=sys.stderr)
        return 1

    reports = sorted(report_dir.glob("*-*.json"))
    if not reports:
        print(f"No reports under {report_dir}", file=sys.stderr)
        return 1

    total_failed = 0
    for path in reports:
        print(format_report(path), end="")
        data = json.loads(path.read_text(encoding="utf-8"))
        total_failed += int(data.get("failed", 0))

    print(f"=== total failed checks: {total_failed} ===")
    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
