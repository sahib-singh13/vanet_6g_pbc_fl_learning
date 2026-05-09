#!/usr/bin/env python3
"""Compare PBC against ECC baseline for VANET power and latency CSV outputs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable


POWER_METRICS = [
    ("total_energy_j", "Total energy (J)"),
    ("security_energy_j", "Security energy (J)"),
    ("comm_energy_j", "Communication energy (J)"),
    ("avg_total_power_w", "Average total power (W)"),
    ("avg_security_power_w", "Average security power (W)"),
    ("avg_comm_power_w", "Average communication power (W)"),
    ("avg_v2v_delay_ms", "Average V2V delay (ms)"),
    ("avg_v2i_uplink_ms", "Average V2I uplink delay (ms)"),
    ("avg_v2i_downlink_ms", "Average V2I downlink delay (ms)"),
    ("avg_v2i_rtt_ms", "Average V2I RTT (ms)"),
    ("avg_reg_delay_ms", "Average registration delay (ms)"),
    ("avg_kgc_rtt_ms", "Average KGC RTT (ms)"),
    ("avg_ta_rtt_ms", "Average TA RTT (ms)"),
    ("avg_sign_ms", "Average signing latency (ms)"),
    ("avg_aggregate_ms", "Average aggregation latency (ms)"),
    ("avg_verify_ms", "Average verification latency (ms)"),
    ("avg_partial_key_ms", "Average partial-key latency (ms)"),
]


def to_float(value: str | None) -> float:
    try:
        return float(value or "0")
    except ValueError:
        return 0.0


def read_last_row(path: Path) -> dict[str, str]:
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    return rows[-1] if rows else {}


def read_stage_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def sum_energy(rows: Iterable[dict[str, str]], stage_prefix: str | None = None) -> float:
    total = 0.0
    for row in rows:
        stage = row.get("stage", "")
        if stage_prefix is None or stage.startswith(stage_prefix):
            total += to_float(row.get("total_energy_j"))
    return total


def sum_latency(rows: Iterable[dict[str, str]], stage_prefix: str | None = None) -> float:
    total = 0.0
    for row in rows:
        stage = row.get("stage", "")
        if stage_prefix is None or stage.startswith(stage_prefix):
            total += to_float(row.get("total_latency_ms"))
    return total


def delta(pbc: float, ecc: float) -> tuple[float, str]:
    diff = pbc - ecc
    if ecc == 0.0:
        return diff, "NA"
    return diff, f"{(diff / ecc) * 100.0:.6f}"


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def fmt(value: float) -> str:
    return f"{value:.6f}"


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "network_label",
        "metric",
        "ecc_value",
        "pbc_value",
        "increment_abs",
        "increment_percent",
    ]
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, label: str, rows: list[dict[str, str]]) -> None:
    lines = [
        f"# PBC Increment Analysis: {label}",
        "",
        "This report compares PBC security against the ECC baseline.",
        "",
        "Formula:",
        "",
        "```text",
        "increment_abs = pbc_value - ecc_value",
        "increment_percent = 100 * (pbc_value - ecc_value) / ecc_value",
        "```",
        "",
        "Positive values mean PBC is higher than ECC. Negative values mean PBC is lower.",
        "",
        "## Power And Latency Increment Table",
        md_table(
            ["Metric", "ECC", "PBC", "Increment", "Increment %"],
            [
                [
                    row["metric"],
                    row["ecc_value"],
                    row["pbc_value"],
                    row["increment_abs"],
                    row["increment_percent"],
                ]
                for row in rows
            ],
        ),
        "",
    ]
    path.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--ecc-power", required=True, type=Path)
    parser.add_argument("--pbc-power", required=True, type=Path)
    parser.add_argument("--ecc-stages", required=True, type=Path)
    parser.add_argument("--pbc-stages", required=True, type=Path)
    parser.add_argument("--out-prefix", required=True, type=Path)
    args = parser.parse_args()

    ecc_power = read_last_row(args.ecc_power)
    pbc_power = read_last_row(args.pbc_power)
    ecc_stages = read_stage_rows(args.ecc_stages)
    pbc_stages = read_stage_rows(args.pbc_stages)

    rows: list[dict[str, str]] = []
    for key, label in POWER_METRICS:
        ecc_value = to_float(ecc_power.get(key))
        pbc_value = to_float(pbc_power.get(key))
        diff, pct = delta(pbc_value, ecc_value)
        rows.append(
            {
                "network_label": args.label,
                "metric": label,
                "ecc_value": fmt(ecc_value),
                "pbc_value": fmt(pbc_value),
                "increment_abs": fmt(diff),
                "increment_percent": pct,
            }
        )

    stage_metrics = [
        ("Total stage energy (J)", sum_energy(ecc_stages), sum_energy(pbc_stages)),
        ("Security-stage energy (J)", sum_energy(ecc_stages, None) - sum_energy(ecc_stages, "communication_"), sum_energy(pbc_stages, None) - sum_energy(pbc_stages, "communication_")),
        ("Communication-stage energy (J)", sum_energy(ecc_stages, "communication_"), sum_energy(pbc_stages, "communication_")),
        ("Total stage latency (ms)", sum_latency(ecc_stages), sum_latency(pbc_stages)),
        ("Security-stage latency (ms)", sum_latency(ecc_stages, None) - sum_latency(ecc_stages, "communication_"), sum_latency(pbc_stages, None) - sum_latency(pbc_stages, "communication_")),
        ("Communication-stage latency (ms)", sum_latency(ecc_stages, "communication_"), sum_latency(pbc_stages, "communication_")),
    ]
    for label, ecc_value, pbc_value in stage_metrics:
        diff, pct = delta(pbc_value, ecc_value)
        rows.append(
            {
                "network_label": args.label,
                "metric": label,
                "ecc_value": fmt(ecc_value),
                "pbc_value": fmt(pbc_value),
                "increment_abs": fmt(diff),
                "increment_percent": pct,
            }
        )

    csv_path = args.out_prefix.with_name(args.out_prefix.name + "_comparison.csv")
    md_path = args.out_prefix.with_name(args.out_prefix.name + "_comparison.md")
    write_csv(csv_path, rows)
    write_markdown(md_path, args.label, rows)
    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
