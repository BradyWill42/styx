"""Persist the movable ``pistyx.current_host`` decision in styx.yaml."""

from __future__ import annotations

import re
from pathlib import Path


def _is_top_level_key(line: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][\w-]*\s*:", line))


def set_pistyx_current_host_text(text: str, host: str) -> str:
    """Return ``text`` with top-level ``pistyx.current_host`` set to ``host``.

    Preserves the rest of the file verbatim. If no ``pistyx:`` block exists, appends one.
    """
    host = str(host).strip()
    block_line = f"  current_host: {host}"
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^pistyx\s*:", line)), None)
    if start is None:
        base = text.rstrip("\n")
        joiner = "\n\n" if base else ""
        return f"{base}{joiner}pistyx:\n{block_line}\n"

    # Normalize inline/empty forms like "pistyx: {}" into a block. The common config keeps
    # public_key under pistyx already; this path is mostly for minimal generated configs.
    if lines[start].strip() != "pistyx:":
        lines[start] = "pistyx:"

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if _is_top_level_key(lines[index]):
            end = index
            break

    for index in range(start + 1, end):
        if re.match(r"^\s+current_host\s*:", lines[index]):
            lines[index] = block_line
            return "\n".join(lines) + "\n"

    rebuilt = lines[: start + 1] + [block_line] + lines[start + 1 :]
    return "\n".join(rebuilt) + "\n"


def write_pistyx_current_host(host: str, *, config_path: str | Path) -> tuple[dict[str, str], int]:
    """Write ``pistyx.current_host`` to styx.yaml, saving ``.bak`` first."""
    if not isinstance(host, str) or not host.strip():
        return {"status": "ERROR", "message": "pistyx current_host is required"}, 1
    path = Path(config_path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"status": "ERROR", "message": f"could not read {path}: {exc}"}, 1

    new_text = set_pistyx_current_host_text(text, host.strip())
    backup = path.with_name(path.name + ".bak")
    try:
        backup.write_text(text, encoding="utf-8")
        path.write_text(new_text, encoding="utf-8")
    except OSError as exc:
        return {"status": "ERROR", "message": f"could not write {path}: {exc}"}, 1

    return {
        "status": "OK",
        "current_host": host.strip(),
        "config_path": str(path),
        "backup_path": str(backup),
        "message": f"set pistyx.current_host: {host.strip()} in {path.name}",
    }, 0
