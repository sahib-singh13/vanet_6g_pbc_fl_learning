#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"
RESULT_DIR="${RESULT_DIR:-results/power_pbc}"
SIM_TIME="${SIM_TIME:-5}"
CASE_ARGS=("$@")
RUN_CASES=()

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

run_case() {
  local case_name="$1"
  local program="$2"
  local args="$3"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running $case_name..."
  ./ns3 run "$program --securityMode=pbc --simTime=$SIM_TIME --progressLog=true $args --outCsv=$power_csv --stageCsv=$stage_csv"
  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --out-prefix "$RESULT_DIR/$case_name"
  RUN_CASES+=("$case_name")
}

run_lte_pbc() {
  run_case "lte_pbc" \
    "vanet-security-lte" \
    "--networkLabel=5g_lte --effectiveRateMbps=100"
}

run_nr_min_pbc() {
  run_case "nr_min_pbc" \
    "vanet-security-nr" \
    "--radioProfile=6g_nr_min"
}

run_nr_max_pbc() {
  run_case "nr_max_pbc" \
    "vanet-security-nr" \
    "--radioProfile=6g_nr_max"
}

print_usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_pbc_power_tests.sh [case ...]

Cases:
  lte          Run LTE PBC only
  nr-min       Run 6G minimum NR PBC only
  nr-max       Run 6G maximum NR PBC only
  all          Run LTE, 6G minimum, and 6G maximum

Examples:
  ./scripts/run_pbc_power_tests.sh lte
  ./scripts/run_pbc_power_tests.sh nr-min
  ./scripts/run_pbc_power_tests.sh nr-max
  SIM_TIME=20 ./scripts/run_pbc_power_tests.sh lte
EOF
}

run_named_case() {
  local requested="$1"
  case "$requested" in
    lte|lte-pbc|lte_pbc)
      run_lte_pbc
      ;;
    nr-min|nr_min|nr-min-pbc|nr_min_pbc|6g-min|6g_min)
      run_nr_min_pbc
      ;;
    nr-max|nr_max|nr-max-pbc|nr_max_pbc|6g-max|6g_max)
      run_nr_max_pbc
      ;;
    all)
      run_lte_pbc
      run_nr_min_pbc
      run_nr_max_pbc
      ;;
    -h|--help|help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown case: $requested" >&2
      print_usage >&2
      exit 1
      ;;
  esac
}

for requested_case in "${CASE_ARGS[@]}"; do
  case "$requested_case" in
    lte|lte-pbc|lte_pbc|nr-min|nr_min|nr-min-pbc|nr_min_pbc|6g-min|6g_min|nr-max|nr_max|nr-max-pbc|nr_max_pbc|6g-max|6g_max|all)
      ;;
    -h|--help|help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown case: $requested_case" >&2
      print_usage >&2
      exit 1
      ;;
  esac
done

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

echo "Building VANET LTE and NR security scenarios..."
./ns3 build vanet-security-lte vanet-security-nr

if ((${#CASE_ARGS[@]} == 0)); then
  run_named_case "all"
else
  for requested_case in "${CASE_ARGS[@]}"; do
    run_named_case "$requested_case"
  done
fi

echo
echo "Final periodic CSV rows:"
for case_name in "${RUN_CASES[@]}"; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Important PBC stage rows:"
for case_name in "${RUN_CASES[@]}"; do
  echo "$case_name:"
  grep -E "pbc_sign|pbc_aggregate|pbc_verify_aggregate|pbc_partial_key|communication_" \
    "$RESULT_DIR/${case_name}_stages.csv" || true
done

SUMMARY_CSV="$RESULT_DIR/final_pbc_power_summary.csv"
echo "case,total_energy_j,avg_total_power_w,security_energy_j,comm_energy_j" > "$SUMMARY_CSV"
for case_name in lte_pbc nr_min_pbc nr_max_pbc; do
  f="$RESULT_DIR/${case_name}_power.csv"
  if [[ -f "$f" ]]; then
    awk -F, -v case_name="$case_name" 'END {print case_name "," $14 "," $17 "," $12 "," $13}' "$f" >> "$SUMMARY_CSV"
  fi
done

echo
echo "Wrote summary from available case files: $SUMMARY_CSV"
cat "$SUMMARY_CSV"
