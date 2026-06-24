#!/usr/bin/env python3
"""Print a human-readable summary of a runner integration stage report."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner_lib import print_report


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <runner> <stage>", file=sys.stderr)
        print("  stage: prerequisites | connectivity", file=sys.stderr)
        return 2
    return print_report(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(main())
