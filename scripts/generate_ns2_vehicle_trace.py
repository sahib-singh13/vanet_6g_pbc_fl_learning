#!/usr/bin/env python3
"""Expand an ns-2 mobility trace to a larger deterministic vehicle count."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


NODE_RE = re.compile(r"\$node_\((\d+)\)")
SET_X_RE = re.compile(r"(\$node_\(\d+\)\s+set\s+X_\s+)([-+]?\d+(?:\.\d+)?)")
SET_Y_RE = re.compile(r"(\$node_\(\d+\)\s+set\s+Y_\s+)([-+]?\d+(?:\.\d+)?)")
SETDEST_RE = re.compile(
    r"(setdest\s+)([-+]?\d+(?:\.\d+)?)\s+([-+]?\d+(?:\.\d+)?)\s+([-+]?\d+(?:\.\d+)?)"
)


def fmt(value: float) -> str:
    text = f"{value:.2f}"
    return text.rstrip("0").rstrip(".")


def offset_for_extra(extra_index: int) -> tuple[float, float]:
    """Return a small lane-like offset so duplicate vehicles do not overlap."""
    column = extra_index % 10
    row = (extra_index // 10) % 10
    return (column - 4.5) * 2.0, (row - 2.0) * 2.0


def duplicate_line(line: str, source_id: int, new_id: int, dx: float, dy: float) -> str:
    out = line.replace(f"$node_({source_id})", f"$node_({new_id})")

    out = SET_X_RE.sub(lambda match: f"{match.group(1)}{fmt(float(match.group(2)) + dx)}", out)
    out = SET_Y_RE.sub(lambda match: f"{match.group(1)}{fmt(float(match.group(2)) + dy)}", out)

    def setdest_repl(match: re.Match[str]) -> str:
        x = fmt(float(match.group(2)) + dx)
        y = fmt(float(match.group(3)) + dy)
        speed = match.group(4)
        return f"{match.group(1)}{x} {y} {speed}"

    return SETDEST_RE.sub(setdest_repl, out)


def count_nodes(lines: list[str]) -> int:
    return len({int(match) for line in lines for match in NODE_RE.findall(line)})


def expand_trace(input_path: Path, output_path: Path, target_vehicles: int) -> int:
    lines = input_path.read_text(encoding="utf-8").splitlines(keepends=True)
    source_nodes = sorted({int(match) for line in lines for match in NODE_RE.findall(line)})
    if not source_nodes:
        raise ValueError(f"No node_(id) entries found in {input_path}")

    base_count = len(source_nodes)
    if target_vehicles < base_count:
        raise ValueError(
            f"Target vehicle count {target_vehicles} is smaller than base trace count {base_count}"
        )

    next_id = max(source_nodes) + 1
    source_to_duplicates: dict[int, list[tuple[int, float, float]]] = {node: [] for node in source_nodes}
    for extra_index in range(target_vehicles - base_count):
        source_id = source_nodes[extra_index % base_count]
        new_id = next_id + extra_index
        dx, dy = offset_for_extra(extra_index)
        source_to_duplicates[source_id].append((new_id, dx, dy))

    expanded: list[str] = []
    for line in lines:
        expanded.append(line)
        referenced_nodes = sorted({int(match) for match in NODE_RE.findall(line)})
        for source_id in referenced_nodes:
            for new_id, dx, dy in source_to_duplicates.get(source_id, []):
                expanded.append(duplicate_line(line, source_id, new_id, dx, dy))

    actual_count = count_nodes(expanded)
    if actual_count != target_vehicles:
        raise ValueError(f"Generated trace has {actual_count} vehicles, expected {target_vehicles}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("".join(expanded), encoding="utf-8")
    return actual_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a larger ns-2 mobility trace by duplicating nodes with small offsets."
    )
    parser.add_argument("--input", required=True, type=Path, help="Base ns-2 mobility trace")
    parser.add_argument("--output", required=True, type=Path, help="Output trace path")
    parser.add_argument("--target-vehicles", required=True, type=int, help="Desired vehicle count")
    args = parser.parse_args()

    try:
        count = expand_trace(args.input, args.output, args.target_vehicles)
    except Exception as exc:  # noqa: BLE001 - CLI should print a concise failure.
        print(f"Trace generation failed: {exc}", file=sys.stderr)
        return 1

    print(f"Generated {args.output} with {count} vehicles from {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
