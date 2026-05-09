#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"
RESULT_DIR="${RESULT_DIR:-results/security_compare}"
SIM_TIME="${SIM_TIME:-5}"
CASE_ARGS=("$@")
RUN_CASES=()

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

print_usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_security_power_compare.sh [case ...]

Cases:
  lte-pbc       Run LTE with PBC security
  lte-ecc       Run LTE without PBC, using ECC baseline
  lte           Run LTE PBC and LTE ECC
  nr-min-pbc    Run 6G minimum NR with PBC security
  nr-min-ecc    Run 6G minimum NR without PBC, using ECC baseline
  nr-min        Run NR-min PBC and NR-min ECC
  all           Run LTE PBC/ECC and NR-min PBC/ECC

Examples:
  ./scripts/run_security_power_compare.sh lte-pbc
  ./scripts/run_security_power_compare.sh lte-ecc
  ./scripts/run_security_power_compare.sh nr-min-pbc
  ./scripts/run_security_power_compare.sh nr-min-ecc
  SIM_TIME=20 ./scripts/run_security_power_compare.sh lte
EOF
}

validate_case() {
  case "$1" in
    lte-pbc|lte_pbc|lte-ecc|lte_ecc|lte|nr-min-pbc|nr_min_pbc|nr-min-ecc|nr_min_ecc|nr-min|nr_min|all)
      ;;
    -h|--help|help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown case: $1" >&2
      print_usage >&2
      exit 1
      ;;
  esac
}

run_case() {
  local case_name="$1"
  local program="$2"
  local security_mode="$3"
  local args="$4"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running $case_name..."
  ./ns3 run "$program --securityMode=$security_mode --simTime=$SIM_TIME --progressLog=true $args --outCsv=$power_csv --stageCsv=$stage_csv"
  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --out-prefix "$RESULT_DIR/$case_name"
  RUN_CASES+=("$case_name")
}

run_lte_pbc() {
  run_case "lte_pbc" \
    "vanet-security-lte" \
    "pbc" \
    "--networkLabel=5g_lte --effectiveRateMbps=100"
}

run_lte_ecc() {
  run_case "lte_ecc" \
    "vanet-security-lte" \
    "ecc" \
    "--networkLabel=5g_lte --effectiveRateMbps=100"
}

run_nr_min_pbc() {
  run_case "nr_min_pbc" \
    "vanet-security-nr" \
    "pbc" \
    "--radioProfile=6g_nr_min"
}

run_nr_min_ecc() {
  run_case "nr_min_ecc" \
    "vanet-security-nr" \
    "ecc" \
    "--radioProfile=6g_nr_min"
}

run_comparison_if_available() {
  local label="$1"
  local prefix="$2"
  local ecc_power="$RESULT_DIR/${prefix}_ecc_power.csv"
  local pbc_power="$RESULT_DIR/${prefix}_pbc_power.csv"
  local ecc_stages="$RESULT_DIR/${prefix}_ecc_stages.csv"
  local pbc_stages="$RESULT_DIR/${prefix}_pbc_stages.csv"

  if [[ -f "$ecc_power" && -f "$pbc_power" && -f "$ecc_stages" && -f "$pbc_stages" ]]; then
    python3 "$REPO_ROOT/scripts/compare_security_power_modes.py" \
      --label "$label" \
      --ecc-power "$ecc_power" \
      --pbc-power "$pbc_power" \
      --ecc-stages "$ecc_stages" \
      --pbc-stages "$pbc_stages" \
      --out-prefix "$RESULT_DIR/${prefix}"
  fi
}

run_named_case() {
  case "$1" in
    lte-pbc|lte_pbc)
      run_lte_pbc
      ;;
    lte-ecc|lte_ecc)
      run_lte_ecc
      ;;
    lte)
      run_lte_pbc
      run_lte_ecc
      ;;
    nr-min-pbc|nr_min_pbc)
      run_nr_min_pbc
      ;;
    nr-min-ecc|nr_min_ecc)
      run_nr_min_ecc
      ;;
    nr-min|nr_min)
      run_nr_min_pbc
      run_nr_min_ecc
      ;;
    all)
      run_lte_pbc
      run_lte_ecc
      run_nr_min_pbc
      run_nr_min_ecc
      ;;
  esac
}

if ((${#CASE_ARGS[@]} == 0)); then
  print_usage
  exit 0
fi

for requested_case in "${CASE_ARGS[@]}"; do
  validate_case "$requested_case"
done

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

echo "Building VANET LTE and NR security scenarios..."
./ns3 build vanet-security-lte vanet-security-nr

for requested_case in "${CASE_ARGS[@]}"; do
  run_named_case "$requested_case"
done

run_comparison_if_available "5g_lte" "lte"
run_comparison_if_available "6g_nr_min" "nr_min"

echo
echo "Final periodic CSV rows:"
for case_name in "${RUN_CASES[@]}"; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Comparison reports available when both PBC and ECC runs exist:"
ls -1 "$RESULT_DIR"/*_comparison.md 2>/dev/null || true
