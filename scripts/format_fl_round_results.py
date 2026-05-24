#!/usr/bin/env python3
"""Create per-round federated-learning power/latency summaries from FL CSV output."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


BASE_FIELDS = [
    "time",
    "round",
    "network_label",
    "security_mode",
    "selected_vehicles",
    "rsu_count",
    "updates_sent",
    "updates_verified",
    "updates_rejected",
    "verification_success_percent",
    "edge_aggregates_sent",
    "global_round_completed",
    "avg_local_train_ms",
    "avg_update_sign_ms",
    "avg_update_verify_ms",
    "avg_edge_aggregate_ms",
    "avg_global_aggregate_ms",
    "fl_security_energy_j",
    "fl_comm_energy_j",
    "fl_total_energy_j",
    "avg_fl_power_w",
    "model_download_bytes",
    "update_upload_bytes",
    "global_loss_proxy",
    "global_accuracy_proxy",
    "round_duration_s",
    "round_security_energy_delta_j",
    "round_comm_energy_delta_j",
    "round_total_energy_delta_j",
    "round_avg_power_delta_w",
]


def to_float(value: str | None, default: float = 0.0) -> float:
    try:
        return float(value or default)
    except (TypeError, ValueError):
        return default


def to_int(value: str | None, default: int = 0) -> int:
    try:
        return int(float(value or default))
    except (TypeError, ValueError):
        return default


def fmt(value: float, digits: int = 6) -> str:
    return f"{value:.{digits}f}"


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def enrich_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    enriched: list[dict[str, str]] = []
    previous_time = 0.0
    previous_security_energy = 0.0
    previous_comm_energy = 0.0
    previous_total_energy = 0.0

    for row in rows:
        current_time = to_float(row.get("time"))
        current_security_energy = to_float(row.get("fl_security_energy_j"))
        current_comm_energy = to_float(row.get("fl_comm_energy_j"))
        current_total_energy = to_float(row.get("fl_total_energy_j"))
        updates_sent = to_int(row.get("updates_sent"))
        updates_verified = to_int(row.get("updates_verified"))

        duration = max(0.0, current_time - previous_time)
        security_delta = current_security_energy - previous_security_energy
        comm_delta = current_comm_energy - previous_comm_energy
        total_delta = current_total_energy - previous_total_energy
        round_power = total_delta / duration if duration > 0.0 else 0.0
        success_percent = 100.0 * updates_verified / updates_sent if updates_sent > 0 else 0.0

        out = {field: row.get(field, "") for field in BASE_FIELDS}
        out["verification_success_percent"] = fmt(success_percent)
        out["round_duration_s"] = fmt(duration)
        out["round_security_energy_delta_j"] = fmt(security_delta)
        out["round_comm_energy_delta_j"] = fmt(comm_delta)
        out["round_total_energy_delta_j"] = fmt(total_delta)
        out["round_avg_power_delta_w"] = fmt(round_power)
        enriched.append(out)

        previous_time = current_time
        previous_security_energy = current_security_energy
        previous_comm_energy = current_comm_energy
        previous_total_energy = current_total_energy

    return enriched


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=BASE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def write_markdown(path: Path, rows: list[dict[str, str]], source_csv: Path) -> None:
    lines = [
        "# NR-Max PBC+FL Per-Round FL Power And Latency Report",
        "",
        f"Source CSV: `{source_csv}`",
        "",
    ]

    if not rows:
        lines.extend(
            [
                "No completed FL rounds were found.",
                "",
                "This usually means the simulation ended before a full FL round completed, or the FL CSV path was not written.",
                "",
            ]
        )
        path.write_text("\n".join(lines))
        return

    last = rows[-1]
    total_delta = sum(to_float(row["round_total_energy_delta_j"]) for row in rows)
    max_energy_round = max(rows, key=lambda row: to_float(row["round_total_energy_delta_j"]))
    avg_total_delta = total_delta / len(rows)

    lines.extend(
        [
            "## Completion Summary",
            md_table(
                ["Metric", "Value"],
                [
                    ["Completed FL rounds", str(len(rows))],
                    ["Last completed round", last.get("round", "")],
                    ["Last completion time (s)", last.get("time", "")],
                    ["Selected vehicles", last.get("selected_vehicles", "")],
                    ["RSU count", last.get("rsu_count", "")],
                    ["Last round updates sent", last.get("updates_sent", "")],
                    ["Last round updates verified", last.get("updates_verified", "")],
                    ["Last round updates rejected", last.get("updates_rejected", "")],
                    ["Last round verification success (%)", last.get("verification_success_percent", "")],
                    ["Cumulative FL security energy (J)", last.get("fl_security_energy_j", "")],
                    ["Cumulative FL communication energy (J)", last.get("fl_comm_energy_j", "")],
                    ["Cumulative FL total energy (J)", last.get("fl_total_energy_j", "")],
                    ["Average per-round total-energy delta (J)", fmt(avg_total_delta)],
                    ["Highest-energy round", max_energy_round.get("round", "")],
                    ["Highest round total-energy delta (J)", max_energy_round.get("round_total_energy_delta_j", "")],
                ],
            ),
            "",
            "## Full Per-Round Metrics",
            "",
            md_table(
                [
                    "Round",
                    "Time (s)",
                    "Selected",
                    "RSUs",
                    "Sent",
                    "Verified",
                    "Rejected",
                    "Success %",
                    "Local Train ms",
                    "Sign ms",
                    "Verify ms",
                    "Edge Agg ms",
                    "Global Agg ms",
                    "Cum Sec J",
                    "Cum Comm J",
                    "Cum Total J",
                    "Round Sec dJ",
                    "Round Comm dJ",
                    "Round Total dJ",
                    "Round Avg W",
                    "Model Bytes",
                    "Update Bytes",
                    "Loss",
                    "Accuracy",
                ],
                [
                    [
                        row.get("round", ""),
                        row.get("time", ""),
                        row.get("selected_vehicles", ""),
                        row.get("rsu_count", ""),
                        row.get("updates_sent", ""),
                        row.get("updates_verified", ""),
                        row.get("updates_rejected", ""),
                        row.get("verification_success_percent", ""),
                        row.get("avg_local_train_ms", ""),
                        row.get("avg_update_sign_ms", ""),
                        row.get("avg_update_verify_ms", ""),
                        row.get("avg_edge_aggregate_ms", ""),
                        row.get("avg_global_aggregate_ms", ""),
                        row.get("fl_security_energy_j", ""),
                        row.get("fl_comm_energy_j", ""),
                        row.get("fl_total_energy_j", ""),
                        row.get("round_security_energy_delta_j", ""),
                        row.get("round_comm_energy_delta_j", ""),
                        row.get("round_total_energy_delta_j", ""),
                        row.get("round_avg_power_delta_w", ""),
                        row.get("model_download_bytes", ""),
                        row.get("update_upload_bytes", ""),
                        row.get("global_loss_proxy", ""),
                        row.get("global_accuracy_proxy", ""),
                    ]
                    for row in rows
                ],
            ),
            "",
        ]
    )
    path.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fl-csv", required=True, type=Path)
    parser.add_argument("--out-prefix", required=True, type=Path)
    args = parser.parse_args()

    rows = enrich_rows(read_rows(args.fl_csv))
    structured_csv = args.out_prefix.with_name(args.out_prefix.name + "_structured.csv")
    report_md = args.out_prefix.with_name(args.out_prefix.name + "_report.md")
    write_csv(structured_csv, rows)
    write_markdown(report_md, rows, args.fl_csv)
    print(f"Wrote {structured_csv}")
    print(f"Wrote {report_md}")


if __name__ == "__main__":
    main()
