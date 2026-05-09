#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"

RESULT_DIR="${RESULT_DIR:-results/nr_max_150_four_modes}"
SIM_TIME="${SIM_TIME:-150}"
FL_ROUNDS="${FL_ROUNDS:-20}"
FL_PARTICIPANTS="${FL_PARTICIPANTS:-50}"
FL_MODEL_DIM="${FL_MODEL_DIM:-64}"
FL_ROUND_INTERVAL="${FL_ROUND_INTERVAL:-1.0}"
TRACE_PATH="${TRACE_PATH:-mobility_trace.tcl}"

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

run_case() {
  local case_name="$1"
  local security_mode="$2"
  local extra_args="$3"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running ${case_name} for ${SIM_TIME} simulated seconds..."
  ./ns3 run "vanet-security-nr --trace=${TRACE_PATH} --radioProfile=6g_nr_max --securityMode=${security_mode} --simTime=${SIM_TIME} --progressLog=true ${extra_args} --outCsv=${power_csv} --stageCsv=${stage_csv}"

  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --out-prefix "$RESULT_DIR/$case_name"
}

write_index() {
  local index="$RESULT_DIR/nr_max_150_four_modes_index.md"
  {
    printf '# NR-Max 150 Second Four-Mode Report Index\n\n'
    printf 'Simulation time: `%s` seconds\n\n' "$SIM_TIME"
    printf 'Radio profile: `6g_nr_max`\n\n'
    printf 'Trace: `%s`\n\n' "$TRACE_PATH"
    printf 'FL settings: `%s` rounds, `%s` participants, model dimension `%s`, round interval `%s` seconds\n\n' "$FL_ROUNDS" "$FL_PARTICIPANTS" "$FL_MODEL_DIM" "$FL_ROUND_INTERVAL"
    printf '## Case Mapping\n\n'
    printf '| Label | Case | Security | FL |\n'
    printf '| --- | --- | --- | --- |\n'
    printf '| nr-max | `nr_max_ecc` | ECC | disabled |\n'
    printf '| nr-max pbc | `nr_max_pbc` | PBC | disabled |\n'
    printf '| nr-max-fl | `nr_max_ecc_fl` | ECC | ECC-secured FL |\n'
    printf '| nr-max pbc+fl | `nr_max_pbc_fl` | PBC | PBC-secured FL |\n\n'
    printf '## Per-Case Reports\n\n'
    printf '| Case | Markdown report | Structured CSV | Power CSV | Stage CSV | FL rounds CSV |\n'
    printf '| --- | --- | --- | --- | --- | --- |\n'
    printf '| NR-max ECC | `%s/nr_max_ecc_report.md` | `%s/nr_max_ecc_structured.csv` | `%s/nr_max_ecc_power.csv` | `%s/nr_max_ecc_stages.csv` | - |\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '| NR-max PBC | `%s/nr_max_pbc_report.md` | `%s/nr_max_pbc_structured.csv` | `%s/nr_max_pbc_power.csv` | `%s/nr_max_pbc_stages.csv` | - |\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '| NR-max ECC + FL | `%s/nr_max_ecc_fl_report.md` | `%s/nr_max_ecc_fl_structured.csv` | `%s/nr_max_ecc_fl_power.csv` | `%s/nr_max_ecc_fl_stages.csv` | `%s/nr_max_ecc_fl_rounds.csv` |\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '| NR-max PBC + FL | `%s/nr_max_pbc_fl_report.md` | `%s/nr_max_pbc_fl_structured.csv` | `%s/nr_max_pbc_fl_power.csv` | `%s/nr_max_pbc_fl_stages.csv` | `%s/nr_max_pbc_fl_rounds.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '## Comparison Reports\n\n'
    printf '| Comparison | Markdown | CSV |\n'
    printf '| --- | --- | --- |\n'
    printf '| PBC vs ECC | `%s/nr_max_pbc_vs_ecc_comparison.md` | `%s/nr_max_pbc_vs_ecc_comparison.csv` |\n' "$RESULT_DIR" "$RESULT_DIR"
    printf '| ECC + FL vs ECC | `%s/nr_max_ecc_fl_vs_ecc_comparison.md` | `%s/nr_max_ecc_fl_vs_ecc_comparison.csv` |\n' "$RESULT_DIR" "$RESULT_DIR"
    printf '| PBC + FL vs PBC | `%s/nr_max_pbc_fl_vs_pbc_comparison.md` | `%s/nr_max_pbc_fl_vs_pbc_comparison.csv` |\n' "$RESULT_DIR" "$RESULT_DIR"
    printf '| PBC + FL vs ECC + FL | `%s/nr_max_pbc_fl_vs_ecc_fl_comparison.md` | `%s/nr_max_pbc_fl_vs_ecc_fl_comparison.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR"
    printf '## Quick Checks\n\n'
    printf 'The final periodic CSV row for each case is printed at the end of the script output. Each per-case Markdown report includes overall power, security/communication energy distribution, detailed stage latency, detailed stage energy, top energy consumers, and top latency consumers.\n'
  } > "$index"
}

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

if [[ ! -f "$TRACE_PATH" ]]; then
  echo "Trace file not found from ns-3 directory: $TRACE_PATH" >&2
  exit 1
fi

vehicle_count="$(grep -Eo 'node_\([0-9]+\)' "$TRACE_PATH" | sort -u | wc -l | tr -d '[:space:]')"
echo "Trace vehicle count: ${vehicle_count}"
if [[ "$vehicle_count" != "50" ]]; then
  echo "Warning: expected 50 vehicles, but trace reports ${vehicle_count}." >&2
fi

echo "Building VANET NR security scenario..."
./ns3 build vanet-security-nr

run_case "nr_max_ecc" "ecc" ""
run_case "nr_max_pbc" "pbc" ""

run_case "nr_max_ecc_fl" "ecc" \
  "--enableFl=true --flSecurityMode=ecc --flRounds=${FL_ROUNDS} --flParticipants=${FL_PARTICIPANTS} --flModelDim=${FL_MODEL_DIM} --flRoundInterval=${FL_ROUND_INTERVAL} --flCsv=${RESULT_DIR}/nr_max_ecc_fl_rounds.csv --flStageCsv=${RESULT_DIR}/nr_max_ecc_fl_stage_summary.csv"

run_case "nr_max_pbc_fl" "pbc" \
  "--enableFl=true --flSecurityMode=pbc --flRounds=${FL_ROUNDS} --flParticipants=${FL_PARTICIPANTS} --flModelDim=${FL_MODEL_DIM} --flRoundInterval=${FL_ROUND_INTERVAL} --flCsv=${RESULT_DIR}/nr_max_pbc_fl_rounds.csv --flStageCsv=${RESULT_DIR}/nr_max_pbc_fl_stage_summary.csv"

python3 "$REPO_ROOT/scripts/compare_security_power_modes.py" \
  --label "6g_nr_max" \
  --ecc-power "$RESULT_DIR/nr_max_ecc_power.csv" \
  --ecc-stages "$RESULT_DIR/nr_max_ecc_stages.csv" \
  --pbc-power "$RESULT_DIR/nr_max_pbc_power.csv" \
  --pbc-stages "$RESULT_DIR/nr_max_pbc_stages.csv" \
  --out-prefix "$RESULT_DIR/nr_max_pbc_vs_ecc"

python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
  --label "6g_nr_max_ecc" \
  --auth-power "$RESULT_DIR/nr_max_ecc_power.csv" \
  --auth-stages "$RESULT_DIR/nr_max_ecc_stages.csv" \
  --fl-power "$RESULT_DIR/nr_max_ecc_fl_power.csv" \
  --fl-stages "$RESULT_DIR/nr_max_ecc_fl_stages.csv" \
  --fl-csv "$RESULT_DIR/nr_max_ecc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/nr_max_ecc_fl_vs_ecc"

python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
  --label "6g_nr_max_pbc" \
  --auth-power "$RESULT_DIR/nr_max_pbc_power.csv" \
  --auth-stages "$RESULT_DIR/nr_max_pbc_stages.csv" \
  --fl-power "$RESULT_DIR/nr_max_pbc_fl_power.csv" \
  --fl-stages "$RESULT_DIR/nr_max_pbc_fl_stages.csv" \
  --fl-csv "$RESULT_DIR/nr_max_pbc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/nr_max_pbc_fl_vs_pbc"

python3 "$REPO_ROOT/scripts/compare_security_power_modes.py" \
  --label "6g_nr_max_fl" \
  --ecc-power "$RESULT_DIR/nr_max_ecc_fl_power.csv" \
  --ecc-stages "$RESULT_DIR/nr_max_ecc_fl_stages.csv" \
  --pbc-power "$RESULT_DIR/nr_max_pbc_fl_power.csv" \
  --pbc-stages "$RESULT_DIR/nr_max_pbc_fl_stages.csv" \
  --out-prefix "$RESULT_DIR/nr_max_pbc_fl_vs_ecc_fl"

write_index

echo
echo "Final periodic CSV rows:"
for case_name in nr_max_ecc nr_max_pbc nr_max_ecc_fl nr_max_pbc_fl; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Reports written under:"
echo "$NS3_DIR/$RESULT_DIR"
echo
echo "Open this first:"
echo "$NS3_DIR/$RESULT_DIR/nr_max_150_four_modes_index.md"
