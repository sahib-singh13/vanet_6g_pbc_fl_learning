#!/usr/bin/env python3
"""Compare authentication-only VANET runs against authentication + FL runs."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Callable, Iterable

POWER_METRICS = [
    ("comm_energy_j", "Communication energy (J)"),
    ("avg_comm_power_w", "Average communication power (W)"),
    ("total_energy_j", "Total energy (J)"),
    ("avg_total_power_w", "Average total power (W)"),
    ("avg_v2v_delay_ms", "Average V2V delay (ms)"),
    ("avg_v2i_uplink_ms", "Average V2I uplink delay (ms)"),
    ("avg_v2i_downlink_ms", "Average V2I downlink delay (ms)"),
    ("avg_v2i_rtt_ms", "Average V2I RTT (ms)"),
    ("avg_reg_delay_ms", "Average registration delay (ms)"),
    ("avg_sign_ms", "Average signing latency (ms)"),
    ("avg_verify_ms", "Average verification latency (ms)"),
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


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def stage_sum(rows: Iterable[dict[str, str]], key: str, pred: Callable[[dict[str, str]], bool]) -> float:
    return sum(to_float(row.get(key)) for row in rows if pred(row))


def stage_count(rows: Iterable[dict[str, str]], pred: Callable[[dict[str, str]], bool]) -> int:
    return sum(int(to_float(row.get("count"))) for row in rows if pred(row))


def any_comm(row: dict[str, str]) -> bool:
    return row.get("stage", "").startswith("communication_")


def fl_comm(row: dict[str, str]) -> bool:
    return any_comm(row) and "fl_" in row.get("role", "")


def fl_compute(row: dict[str, str]) -> bool:
    return row.get("stage", "").startswith("fl_")


def pbc_compute(row: dict[str, str]) -> bool:
    return row.get("stage", "").startswith("pbc_")


def delta(fl_value: float, auth_value: float) -> tuple[float, str]:
    diff = fl_value - auth_value
    if auth_value == 0.0:
        return diff, "NA"
    return diff, f"{(diff / auth_value) * 100.0:.6f}"


def fmt(value: float) -> str:
    return f"{value:.6f}"


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def add_comparison(rows: list[dict[str, str]], label: str, metric: str, auth_value: float, fl_value: float) -> None:
    diff, pct = delta(fl_value, auth_value)
    rows.append(
        {
            "network_label": label,
            "metric": metric,
            "auth_only_value": fmt(auth_value),
            "auth_fl_value": fmt(fl_value),
            "overhead_abs": fmt(diff),
            "overhead_percent": pct,
        }
    )


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "network_label",
        "metric",
        "auth_only_value",
        "auth_fl_value",
        "overhead_abs",
        "overhead_percent",
    ]
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, label: str, rows: list[dict[str, str]], fl_round_rows: list[dict[str, str]]) -> None:
    completed_rounds = len(fl_round_rows)
    last_round = fl_round_rows[-1] if fl_round_rows else {}
    lines = [
        f"# FL + Authentication Overhead Analysis: {label}",
        "",
        "This report compares a PBC authentication-only VANET run against a PBC authentication plus federated learning run.",
        "",
        "Formula:",
        "",
        "```text",
        "overhead_abs = auth_fl_value - auth_only_value",
        "overhead_percent = 100 * (auth_fl_value - auth_only_value) / auth_only_value",
        "```",
        "",
        "Positive overhead means FL + authentication is higher than authentication only.",
        "",
        "## FL Completion",
        "",
        f"Completed FL rounds: `{completed_rounds}`",
        "",
    ]
    if last_round:
        lines.extend(
            [
                f"Last completed round: `{last_round.get('round', 'NA')}` at simulation time `{last_round.get('time', 'NA')}` seconds.",
                f"Updates sent/verified/rejected: `{last_round.get('updates_sent', 'NA')}` / `{last_round.get('updates_verified', 'NA')}` / `{last_round.get('updates_rejected', 'NA')}`.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "No completed FL round was recorded. Increase `--simTime` or reduce `--flParticipants`.",
                "",
            ]
        )
    lines.extend(
        [
            "## Communication And Delay Overhead",
            md_table(
                ["Metric", "Auth only", "Auth + FL", "Overhead", "Overhead %"],
                [
                    [
                        row["metric"],
                        row["auth_only_value"],
                        row["auth_fl_value"],
                        row["overhead_abs"],
                        row["overhead_percent"],
                    ]
                    for row in rows
                ],
            ),
            "",
            "## Interpretation",
            "",
            "The stage rows named `communication_*` represent analytical airtime and radio energy. Rows whose role contains `fl_` are FL-specific communication overhead.",
            "",
            "The rows named `fl_local_train`, `fl_mask_generate`, `fl_edge_aggregate`, and `fl_global_aggregate` represent the added FL computation delay. In the current ns-3 implementation, local training is synthetic and lightweight; real ML accuracy and training behavior remain in the Python baseline.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--auth-power", required=True, type=Path)
    parser.add_argument("--auth-stages", required=True, type=Path)
    parser.add_argument("--fl-power", required=True, type=Path)
    parser.add_argument("--fl-stages", required=True, type=Path)
    parser.add_argument("--fl-csv", required=True, type=Path)
    parser.add_argument("--out-prefix", required=True, type=Path)
    args = parser.parse_args()

    auth_power = read_last_row(args.auth_power)
    fl_power = read_last_row(args.fl_power)
    auth_stages = read_rows(args.auth_stages)
    fl_stages = read_rows(args.fl_stages)
    fl_round_rows = read_rows(args.fl_csv)

    rows: list[dict[str, str]] = []
    for key, name in POWER_METRICS:
        add_comparison(rows, args.label, name, to_float(auth_power.get(key)), to_float(fl_power.get(key)))

    stage_metrics = [
        ("Total communication-stage energy (J)", stage_sum(auth_stages, "total_energy_j", any_comm), stage_sum(fl_stages, "total_energy_j", any_comm)),
        ("Total communication-stage latency (ms)", stage_sum(auth_stages, "total_latency_ms", any_comm), stage_sum(fl_stages, "total_latency_ms", any_comm)),
        ("FL-only communication energy (J)", 0.0, stage_sum(fl_stages, "total_energy_j", fl_comm)),
        ("FL-only communication latency (ms)", 0.0, stage_sum(fl_stages, "total_latency_ms", fl_comm)),
        ("FL-only computation energy (J)", 0.0, stage_sum(fl_stages, "total_energy_j", fl_compute)),
        ("FL-only computation latency (ms)", 0.0, stage_sum(fl_stages, "total_latency_ms", fl_compute)),
        ("PBC-stage energy (J)", stage_sum(auth_stages, "total_energy_j", pbc_compute), stage_sum(fl_stages, "total_energy_j", pbc_compute)),
        ("PBC-stage latency (ms)", stage_sum(auth_stages, "total_latency_ms", pbc_compute), stage_sum(fl_stages, "total_latency_ms", pbc_compute)),
        ("FL communication events", 0.0, float(stage_count(fl_stages, fl_comm))),
        ("FL computation events", 0.0, float(stage_count(fl_stages, fl_compute))),
    ]
    for name, auth_value, fl_value in stage_metrics:
        add_comparison(rows, args.label, name, auth_value, fl_value)

    csv_path = args.out_prefix.with_name(args.out_prefix.name + "_comparison.csv")
    md_path = args.out_prefix.with_name(args.out_prefix.name + "_comparison.md")
    write_csv(csv_path, rows)
    write_markdown(md_path, args.label, rows, fl_round_rows)
    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
