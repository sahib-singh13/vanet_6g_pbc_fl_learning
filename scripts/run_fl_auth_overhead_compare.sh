#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"
RESULT_DIR="${RESULT_DIR:-results/fl_auth_compare}"
SIM_TIME="${SIM_TIME:-30}"
FL_ROUNDS="${FL_ROUNDS:-3}"
FL_PARTICIPANTS="${FL_PARTICIPANTS:-10}"
FL_MODEL_DIM="${FL_MODEL_DIM:-16}"
CASE="${1:-lte}"

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/run_fl_auth_overhead_compare.sh [lte|nr-min]

Environment overrides:
  SIM_TIME=30
  FL_ROUNDS=3
  FL_PARTICIPANTS=10
  FL_MODEL_DIM=16
  RESULT_DIR=results/fl_auth_compare

Examples:
  ./scripts/run_fl_auth_overhead_compare.sh lte
  SIM_TIME=90 ./scripts/run_fl_auth_overhead_compare.sh lte
  SIM_TIME=90 ./scripts/run_fl_auth_overhead_compare.sh nr-min
USAGE
}

run_pair() {
  local label="$1"
  local prefix="$2"
  local program="$3"
  local common_args="$4"

  local auth_power="$RESULT_DIR/${prefix}_auth_power.csv"
  local auth_stages="$RESULT_DIR/${prefix}_auth_stages.csv"
  local fl_power="$RESULT_DIR/${prefix}_auth_fl_power.csv"
  local fl_stages="$RESULT_DIR/${prefix}_auth_fl_stages.csv"
  local fl_csv="$RESULT_DIR/${prefix}_auth_fl_rounds.csv"
  local fl_stage_summary="$RESULT_DIR/${prefix}_auth_fl_stage_summary.csv"

  echo
  echo "Running ${label} authentication-only baseline..."
  ./ns3 run "$program --securityMode=pbc --simTime=$SIM_TIME --progressLog=true $common_args --outCsv=$auth_power --stageCsv=$auth_stages"

  echo
  echo "Running ${label} authentication + federated learning..."
  ./ns3 run "$program --securityMode=pbc --enableFl=true --flSecurityMode=pbc --flRounds=$FL_ROUNDS --flParticipants=$FL_PARTICIPANTS --flModelDim=$FL_MODEL_DIM --simTime=$SIM_TIME --progressLog=true $common_args --outCsv=$fl_power --stageCsv=$fl_stages --flCsv=$fl_csv --flStageCsv=$fl_stage_summary"

  python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
    --label "$label" \
    --auth-power "$auth_power" \
    --auth-stages "$auth_stages" \
    --fl-power "$fl_power" \
    --fl-stages "$fl_stages" \
    --fl-csv "$fl_csv" \
    --out-prefix "$RESULT_DIR/${prefix}"

  echo
  echo "Report: $NS3_DIR/$RESULT_DIR/${prefix}_comparison.md"
  echo "CSV:    $NS3_DIR/$RESULT_DIR/${prefix}_comparison.csv"
}

case "$CASE" in
  -h|--help|help)
    usage
    exit 0
    ;;
  lte)
    PROGRAM="vanet-security-lte"
    LABEL="5g_lte"
    PREFIX="lte_pbc"
    COMMON_ARGS="--networkLabel=5g_lte --effectiveRateMbps=100"
    ;;
  nr-min|nr_min)
    PROGRAM="vanet-security-nr"
    LABEL="6g_nr_min"
    PREFIX="nr_min_pbc"
    COMMON_ARGS="--radioProfile=6g_nr_min"
    ;;
  *)
    echo "Unknown case: $CASE" >&2
    usage >&2
    exit 1
    ;;
esac

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

echo "Building VANET LTE/NR scenarios..."
./ns3 build vanet-security-lte vanet-security-nr

run_pair "$LABEL" "$PREFIX" "$PROGRAM" "$COMMON_ARGS"
