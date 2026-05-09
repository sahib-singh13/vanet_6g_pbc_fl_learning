#!/usr/bin/env python3
"""Create readable VANET security power/latency summaries from raw CSV files."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable


SECURITY_SETUP = {
    "cert_sign",
    "ecc_keygen",
    "pbc_pid2",
    "pbc_partial_key",
    "pbc_full_key",
}

SECURITY_MESSAGE = {
    "ecc_sign",
    "ecc_verify",
    "pbc_sign",
    "pbc_aggregate",
    "pbc_verify_aggregate",
}

SECTION_ORDER = {
    "total": 0,
    "security_setup": 1,
    "security_message": 2,
    "communication_tx": 3,
    "communication_rx": 4,
    "other": 5,
}


def to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def section_for(stage: str) -> str:
    if stage == "communication_tx":
        return "communication_tx"
    if stage == "communication_rx":
        return "communication_rx"
    if stage in SECURITY_SETUP:
        return "security_setup"
    if stage in SECURITY_MESSAGE:
        return "security_message"
    return "other"


def read_stage_rows(path: Path) -> list[dict[str, object]]:
    with path.open(newline="") as stream:
        rows = []
        for row in csv.DictReader(stream):
            count = to_int(row.get("count", "0"))
            total_latency_ms = to_float(row.get("total_latency_ms", "0"))
            total_energy_j = to_float(row.get("total_energy_j", "0"))
            rows.append(
                {
                    "network_label": row.get("network_label", ""),
                    "security_mode": row.get("security_mode", ""),
                    "section": section_for(row.get("stage", "")),
                    "stage": row.get("stage", ""),
                    "role": row.get("role", ""),
                    "count": count,
                    "avg_latency_ms": to_float(row.get("avg_latency_ms", "0")),
                    "total_latency_ms": total_latency_ms,
                    "total_energy_j": total_energy_j,
                    "avg_energy_mj_per_op": to_float(row.get("avg_energy_mj_per_op", "0")),
                }
            )
    return rows


def read_last_power_row(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    return rows[-1] if rows else {}


def aggregate(rows: Iterable[dict[str, object]], section: str, stage: str, role: str) -> dict[str, object]:
    selected = list(rows)
    count = sum(int(row["count"]) for row in selected)
    total_latency_ms = sum(float(row["total_latency_ms"]) for row in selected)
    total_energy_j = sum(float(row["total_energy_j"]) for row in selected)
    return {
        "network_label": selected[0]["network_label"] if selected else "",
        "security_mode": selected[0]["security_mode"] if selected else "",
        "section": section,
        "stage": stage,
        "role": role,
        "count": count,
        "avg_latency_ms": total_latency_ms / count if count else 0.0,
        "total_latency_ms": total_latency_ms,
        "total_energy_j": total_energy_j,
        "avg_energy_mj_per_op": (1000.0 * total_energy_j / count) if count else 0.0,
    }


def add_percentages(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    total_energy = sum(float(row["total_energy_j"]) for row in rows if row["section"] != "total")
    total_latency = sum(float(row["total_latency_ms"]) for row in rows if row["section"] != "total")
    for row in rows:
        row["energy_percent"] = (
            100.0 * float(row["total_energy_j"]) / total_energy if total_energy > 0 else 0.0
        )
        row["latency_percent"] = (
            100.0 * float(row["total_latency_ms"]) / total_latency if total_latency > 0 else 0.0
        )
    return rows


def build_structured_rows(raw_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    security_rows = [row for row in raw_rows if not str(row["stage"]).startswith("communication_")]
    tx_rows = [row for row in raw_rows if row["stage"] == "communication_tx"]
    rx_rows = [row for row in raw_rows if row["stage"] == "communication_rx"]
    communication_rows = tx_rows + rx_rows

    totals = [
        aggregate(raw_rows, "total", "overall_total", "all",),
        aggregate(security_rows, "total", "security_total", "all"),
        aggregate(communication_rows, "total", "communication_total", "all"),
        aggregate(tx_rows, "total", "communication_tx_total", "all"),
        aggregate(rx_rows, "total", "communication_rx_total", "all"),
    ]

    detailed = sorted(
        raw_rows,
        key=lambda row: (
            SECTION_ORDER.get(str(row["section"]), 99),
            -float(row["total_energy_j"]),
            str(row["stage"]),
            str(row["role"]),
        ),
    )
    return add_percentages(totals + detailed)


def write_structured_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames = [
        "network_label",
        "security_mode",
        "section",
        "stage",
        "role",
        "count",
        "avg_latency_ms",
        "total_latency_ms",
        "total_energy_j",
        "avg_energy_mj_per_op",
        "energy_percent",
        "latency_percent",
    ]
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            formatted = dict(row)
            for key in [
                "avg_latency_ms",
                "total_latency_ms",
                "total_energy_j",
                "avg_energy_mj_per_op",
                "energy_percent",
                "latency_percent",
            ]:
                formatted[key] = f"{float(formatted[key]):.6f}"
            writer.writerow(formatted)


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    output = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    output.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(output)


def fmt(value: object, digits: int = 3) -> str:
    return f"{float(value):.{digits}f}"


def write_markdown_report(path: Path, rows: list[dict[str, object]], power_row: dict[str, str]) -> None:
    network = str(rows[0]["network_label"]) if rows else ""
    mode = str(rows[0]["security_mode"]) if rows else ""
    totals = {str(row["stage"]): row for row in rows if row["section"] == "total"}
    security_rows = [row for row in rows if row["section"] in {"security_setup", "security_message"}]
    communication_rows = [row for row in rows if row["section"] in {"communication_tx", "communication_rx"}]
    detailed_rows = [row for row in rows if row["section"] != "total"]

    lines = [
        f"# VANET Security Power And Latency Report: {network} / {mode}",
        "",
        "## Overall Totals",
        md_table(
            ["Metric", "Value"],
            [
                ["Total energy (J)", fmt(totals["overall_total"]["total_energy_j"], 6)],
                ["Security energy (J)", fmt(totals["security_total"]["total_energy_j"], 6)],
                ["Communication energy (J)", fmt(totals["communication_total"]["total_energy_j"], 6)],
                ["Total stage latency (ms)", fmt(totals["overall_total"]["total_latency_ms"], 3)],
                ["Security latency total (ms)", fmt(totals["security_total"]["total_latency_ms"], 3)],
                ["Communication latency total (ms)", fmt(totals["communication_total"]["total_latency_ms"], 3)],
            ],
        ),
        "",
        "## Energy And Latency Distribution",
        md_table(
            [
                "Category",
                "Energy (J)",
                "Energy %",
                "Total Latency (ms)",
                "Latency %",
                "Avg Latency (ms)",
                "Count",
            ],
            [
                [
                    "Security",
                    fmt(totals["security_total"]["total_energy_j"], 6),
                    fmt(totals["security_total"]["energy_percent"], 2),
                    fmt(totals["security_total"]["total_latency_ms"], 3),
                    fmt(totals["security_total"]["latency_percent"], 2),
                    fmt(totals["security_total"]["avg_latency_ms"], 6),
                    str(totals["security_total"]["count"]),
                ],
                [
                    "Communication",
                    fmt(totals["communication_total"]["total_energy_j"], 6),
                    fmt(totals["communication_total"]["energy_percent"], 2),
                    fmt(totals["communication_total"]["total_latency_ms"], 3),
                    fmt(totals["communication_total"]["latency_percent"], 2),
                    fmt(totals["communication_total"]["avg_latency_ms"], 6),
                    str(totals["communication_total"]["count"]),
                ],
                [
                    "Communication TX",
                    fmt(totals["communication_tx_total"]["total_energy_j"], 6),
                    fmt(totals["communication_tx_total"]["energy_percent"], 2),
                    fmt(totals["communication_tx_total"]["total_latency_ms"], 3),
                    fmt(totals["communication_tx_total"]["latency_percent"], 2),
                    fmt(totals["communication_tx_total"]["avg_latency_ms"], 6),
                    str(totals["communication_tx_total"]["count"]),
                ],
                [
                    "Communication RX",
                    fmt(totals["communication_rx_total"]["total_energy_j"], 6),
                    fmt(totals["communication_rx_total"]["energy_percent"], 2),
                    fmt(totals["communication_rx_total"]["total_latency_ms"], 3),
                    fmt(totals["communication_rx_total"]["latency_percent"], 2),
                    fmt(totals["communication_rx_total"]["avg_latency_ms"], 6),
                    str(totals["communication_rx_total"]["count"]),
                ],
            ],
        ),
        "",
    ]

    if power_row:
        lines.extend(
            [
                "## Final Time-Series Row",
                md_table(
                    ["Metric", "Value"],
                    [
                        ["Simulation time (s)", power_row.get("time", "")],
                        ["Infected ratio", power_row.get("infected_ratio", "")],
                        ["Propagation distance", power_row.get("propagation_distance", "")],
                        ["Verification failures", power_row.get("verification_failures", "")],
                        ["Security energy (J)", power_row.get("security_energy_j", "")],
                        ["Communication energy (J)", power_row.get("comm_energy_j", "")],
                        ["Total energy (J)", power_row.get("total_energy_j", "")],
                        ["Avg total power (W)", power_row.get("avg_total_power_w", "")],
                        ["Avg security power (W)", power_row.get("avg_security_power_w", "")],
                        ["Avg communication power (W)", power_row.get("avg_comm_power_w", "")],
                        ["Avg V2V delay (ms)", power_row.get("avg_v2v_delay_ms", "")],
                        ["Avg V2I uplink delay (ms)", power_row.get("avg_v2i_uplink_ms", "")],
                        ["Avg V2I downlink delay (ms)", power_row.get("avg_v2i_downlink_ms", "")],
                        ["Avg V2I RTT delay (ms)", power_row.get("avg_v2i_rtt_ms", "")],
                        ["Avg registration delay (ms)", power_row.get("avg_reg_delay_ms", "")],
                        ["Avg KGC RTT (ms)", power_row.get("avg_kgc_rtt_ms", "")],
                        ["Avg TA RTT (ms)", power_row.get("avg_ta_rtt_ms", "")],
                        ["Avg sign latency (ms)", power_row.get("avg_sign_ms", "")],
                        ["Avg aggregate latency (ms)", power_row.get("avg_aggregate_ms", "")],
                        ["Avg verify latency (ms)", power_row.get("avg_verify_ms", "")],
                        ["Avg partial-key latency (ms)", power_row.get("avg_partial_key_ms", "")],
                    ],
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## Security Stages",
            md_table(
                [
                    "Section",
                    "Stage",
                    "Role",
                    "Count",
                    "Avg Latency (ms)",
                    "Total Latency (ms)",
                    "Latency %",
                    "Energy (J)",
                    "Avg Energy (mJ/op)",
                    "Energy %",
                ],
                [
                    [
                        str(row["section"]),
                        str(row["stage"]),
                        str(row["role"]),
                        str(row["count"]),
                        fmt(row["avg_latency_ms"], 3),
                        fmt(row["total_latency_ms"], 3),
                        fmt(row["latency_percent"], 2),
                        fmt(row["total_energy_j"], 6),
                        fmt(row["avg_energy_mj_per_op"], 6),
                        fmt(row["energy_percent"], 2),
                    ]
                    for row in security_rows
                ],
            ),
            "",
            "## Communication Stages",
            md_table(
                [
                    "Direction",
                    "Role/Category",
                    "Count",
                    "Avg Airtime (ms)",
                    "Total Airtime (ms)",
                    "Latency %",
                    "Energy (J)",
                    "Avg Energy (mJ/op)",
                    "Energy %",
                ],
                [
                    [
                        str(row["stage"]).replace("communication_", ""),
                        str(row["role"]),
                        str(row["count"]),
                        fmt(row["avg_latency_ms"], 6),
                        fmt(row["total_latency_ms"], 3),
                        fmt(row["latency_percent"], 2),
                        fmt(row["total_energy_j"], 6),
                        fmt(row["avg_energy_mj_per_op"], 6),
                        fmt(row["energy_percent"], 2),
                    ]
                    for row in communication_rows
                ],
            ),
            "",
            "## Top Energy Consumers",
        ]
    )

    top_rows = sorted(
        detailed_rows,
        key=lambda row: float(row["total_energy_j"]),
        reverse=True,
    )[:10]
    lines.append(
        md_table(
            ["Rank", "Stage", "Role", "Energy (J)", "Energy %", "Avg Latency (ms)", "Count"],
            [
                [
                    str(index),
                    str(row["stage"]),
                    str(row["role"]),
                    fmt(row["total_energy_j"], 6),
                    fmt(row["energy_percent"], 2),
                    fmt(row["avg_latency_ms"], 3),
                    str(row["count"]),
                ]
                for index, row in enumerate(top_rows, start=1)
            ],
        )
    )
    lines.extend(["", "## Top Latency Consumers"])
    top_latency_rows = sorted(
        detailed_rows,
        key=lambda row: float(row["total_latency_ms"]),
        reverse=True,
    )[:10]
    lines.append(
        md_table(
            [
                "Rank",
                "Stage",
                "Role",
                "Total Latency (ms)",
                "Latency %",
                "Avg Latency (ms)",
                "Count",
            ],
            [
                [
                    str(index),
                    str(row["stage"]),
                    str(row["role"]),
                    fmt(row["total_latency_ms"], 3),
                    fmt(row["latency_percent"], 2),
                    fmt(row["avg_latency_ms"], 6),
                    str(row["count"]),
                ]
                for index, row in enumerate(top_latency_rows, start=1)
            ],
        )
    )
    lines.append("")
    path.write_text("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-csv", required=True, type=Path)
    parser.add_argument("--power-csv", type=Path)
    parser.add_argument("--out-prefix", required=True, type=Path)
    args = parser.parse_args()

    raw_rows = read_stage_rows(args.stage_csv)
    structured_rows = build_structured_rows(raw_rows)
    power_row = read_last_power_row(args.power_csv)

    structured_csv = args.out_prefix.with_name(args.out_prefix.name + "_structured.csv")
    report_md = args.out_prefix.with_name(args.out_prefix.name + "_report.md")
    write_structured_csv(structured_csv, structured_rows)
    write_markdown_report(report_md, structured_rows, power_row)
    print(f"Wrote {structured_csv}")
    print(f"Wrote {report_md}")


if __name__ == "__main__":
    main()
