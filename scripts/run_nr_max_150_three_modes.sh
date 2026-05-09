#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"

RESULT_DIR="${RESULT_DIR:-results/nr_max_150}"
SIM_TIME="${SIM_TIME:-150}"
FL_ROUNDS="${FL_ROUNDS:-20}"
FL_PARTICIPANTS="${FL_PARTICIPANTS:-50}"
FL_MODEL_DIM="${FL_MODEL_DIM:-64}"
FL_ROUND_INTERVAL="${FL_ROUND_INTERVAL:-1.0}"

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

run_case() {
  local case_name="$1"
  local security_mode="$2"
  local extra_args="$3"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running ${case_name} for ${SIM_TIME} simulated seconds..."
  ./ns3 run "vanet-security-nr --securityMode=${security_mode} --radioProfile=6g_nr_max --simTime=${SIM_TIME} --progressLog=true ${extra_args} --outCsv=${power_csv} --stageCsv=${stage_csv}"

  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --out-prefix "$RESULT_DIR/$case_name"
}

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

echo "Building VANET NR security scenario..."
./ns3 build vanet-security-nr

run_case "nr_max_ecc" "ecc" ""
run_case "nr_max_pbc" "pbc" ""

run_case "nr_max_pbc_fl" "pbc" \
  "--enableFl=true --flSecurityMode=pbc --flRounds=${FL_ROUNDS} --flParticipants=${FL_PARTICIPANTS} --flModelDim=${FL_MODEL_DIM} --flRoundInterval=${FL_ROUND_INTERVAL} --flCsv=${RESULT_DIR}/nr_max_pbc_fl_rounds.csv --flStageCsv=${RESULT_DIR}/nr_max_pbc_fl_stage_summary.csv"

python3 "$REPO_ROOT/scripts/compare_security_power_modes.py" \
  --label "6g_nr_max" \
  --ecc-power "$RESULT_DIR/nr_max_ecc_power.csv" \
  --ecc-stages "$RESULT_DIR/nr_max_ecc_stages.csv" \
  --pbc-power "$RESULT_DIR/nr_max_pbc_power.csv" \
  --pbc-stages "$RESULT_DIR/nr_max_pbc_stages.csv" \
  --out-prefix "$RESULT_DIR/nr_max"

python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
  --label "6g_nr_max" \
  --auth-power "$RESULT_DIR/nr_max_pbc_power.csv" \
  --auth-stages "$RESULT_DIR/nr_max_pbc_stages.csv" \
  --fl-power "$RESULT_DIR/nr_max_pbc_fl_power.csv" \
  --fl-stages "$RESULT_DIR/nr_max_pbc_fl_stages.csv" \
  --fl-csv "$RESULT_DIR/nr_max_pbc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/nr_max_pbc_fl"

{
  printf '# NR-Max 150 Second Run Index\n\n'
  printf 'Simulation time: `%s` seconds\n\n' "$SIM_TIME"
  printf 'Radio profile: `6g_nr_max`\n\n'
  printf 'FL settings: `%s` rounds, `%s` participants, model dimension `%s`, round interval `%s` seconds\n\n' "$FL_ROUNDS" "$FL_PARTICIPANTS" "$FL_MODEL_DIM" "$FL_ROUND_INTERVAL"
  printf '## Per-Case Reports\n\n'
  printf '- ECC: `%s/nr_max_ecc_report.md`\n' "$RESULT_DIR"
  printf '- PBC: `%s/nr_max_pbc_report.md`\n' "$RESULT_DIR"
  printf '- PBC + FL: `%s/nr_max_pbc_fl_report.md`\n\n' "$RESULT_DIR"
  printf '## Comparison Reports\n\n'
  printf '- PBC vs ECC: `%s/nr_max_comparison.md`\n' "$RESULT_DIR"
  printf '- PBC + FL vs PBC: `%s/nr_max_pbc_fl_comparison.md`\n\n' "$RESULT_DIR"
  printf '## Raw Data\n\n'
  printf '- Power CSV files: `%s/*_power.csv`\n' "$RESULT_DIR"
  printf '- Stage CSV files: `%s/*_stages.csv`\n' "$RESULT_DIR"
  printf '- FL round CSV: `%s/nr_max_pbc_fl_rounds.csv`\n' "$RESULT_DIR"
} > "$RESULT_DIR/nr_max_150_index.md"

echo
echo "Final periodic CSV rows:"
for case_name in nr_max_ecc nr_max_pbc nr_max_pbc_fl; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Reports written under:"
echo "$NS3_DIR/$RESULT_DIR"
echo
echo "Open this first:"
echo "$NS3_DIR/$RESULT_DIR/nr_max_150_index.md"
