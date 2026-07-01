#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"

TARGET_VEHICLES="${TARGET_VEHICLES:-100}"
RESULT_DIR="${RESULT_DIR:-results/5g_lte_1000_pbc_fl_${TARGET_VEHICLES}v}"
SIM_TIME="${SIM_TIME:-1000}"
FL_ROUNDS="${FL_ROUNDS:-500}"
FL_PARTICIPANTS="${FL_PARTICIPANTS:-$TARGET_VEHICLES}"
FL_MODEL_DIM="${FL_MODEL_DIM:-64}"
FL_ROUND_INTERVAL="${FL_ROUND_INTERVAL:-1.0}"
MSG_INTERVAL="${MSG_INTERVAL:-1.0}"
BASE_TRACE_PATH="${BASE_TRACE_PATH:-mobility_trace.tcl}"
TRACE_PATH="${TRACE_PATH:-mobility_trace_${TARGET_VEHICLES}.tcl}"
NS3_CONFIGURE_ARGS="${NS3_CONFIGURE_ARGS:---enable-examples --build-profile=optimized}"
INDEX_NAME="${INDEX_NAME:-5g_lte_${SIM_TIME}_pbc_fl_${TARGET_VEHICLES}v_index.md}"
PBC_CMAKE_ARG="-DVANET_SECURITY_ENABLE_PBC=ON"
PBC_CMAKE_EXTRA_ARGS="${PBC_CMAKE_EXTRA_ARGS:-}"

if [[ -z "$PBC_CMAKE_EXTRA_ARGS" && -f /usr/local/lib/libpbc.so && -d /usr/local/include ]]; then
  PBC_CMAKE_EXTRA_ARGS="-DPBC_INCLUDE_DIR=/usr/local/include -DPBC_LIBRARY=/usr/local/lib/libpbc.so"
fi

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

configure_with_pbc() {
  ./ns3 configure "$@" $NS3_CONFIGURE_ARGS -- "$PBC_CMAKE_ARG" $PBC_CMAKE_EXTRA_ARGS
}

run_case() {
  local case_name="$1"
  local extra_args="$2"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running ${case_name} for ${SIM_TIME} simulated seconds..."
  ./ns3 run "vanet-security-lte --trace=${TRACE_PATH} --networkLabel=5g_lte --effectiveRateMbps=100 --securityMode=pbc --simTime=${SIM_TIME} --msgInterval=${MSG_INTERVAL} --progressLog=true ${extra_args} --outCsv=${power_csv} --stageCsv=${stage_csv}"

  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --sim-time "$SIM_TIME" \
    --out-prefix "$RESULT_DIR/$case_name"
}

write_index() {
  local index="$RESULT_DIR/$INDEX_NAME"
  {
    printf '# 5G LTE %s Second %s Vehicle PBC And PBC+FL Report Index\n\n' "$SIM_TIME" "$TARGET_VEHICLES"
    printf 'Simulation time: `%s` seconds\n\n' "$SIM_TIME"
    printf 'Target vehicles: `%s`\n\n' "$TARGET_VEHICLES"
    printf 'Base trace: `%s`\n\n' "$BASE_TRACE_PATH"
    printf 'Trace: `%s`\n\n' "$TRACE_PATH"
    printf 'Trace vehicle count: `%s`\n\n' "$vehicle_count"
    printf 'Network label: `5g_lte`\n\n'
    printf 'Program: `vanet-security-lte`\n\n'
    printf 'Security mode: `pbc`\n\n'
    printf 'Message interval: `%s` seconds\n\n' "$MSG_INTERVAL"
    printf 'Analytical effective rate: `100 Mbps`\n\n'
    printf 'FL settings: `%s` rounds, `%s` participants, model dimension `%s`, round interval `%s` seconds\n\n' "$FL_ROUNDS" "$FL_PARTICIPANTS" "$FL_MODEL_DIM" "$FL_ROUND_INTERVAL"
    printf 'Stage average power formula: `avg_stage_power_w = total_energy_j / %s`\n\n' "$SIM_TIME"
    printf '## Reports\n\n'
    printf '| Case | Markdown report | Structured CSV | Power CSV | Stage CSV | FL rounds CSV |\n'
    printf '| --- | --- | --- | --- | --- | --- |\n'
    printf '| 5G LTE PBC | `%s/5g_lte_pbc_report.md` | `%s/5g_lte_pbc_structured.csv` | `%s/5g_lte_pbc_power.csv` | `%s/5g_lte_pbc_stages.csv` | - |\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '| 5G LTE PBC + FL | `%s/5g_lte_pbc_fl_report.md` | `%s/5g_lte_pbc_fl_structured.csv` | `%s/5g_lte_pbc_fl_power.csv` | `%s/5g_lte_pbc_fl_stages.csv` | `%s/5g_lte_pbc_fl_rounds.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '## FL Round Reports\n\n'
    printf '| Report | Markdown | CSV |\n'
    printf '| --- | --- | --- |\n'
    printf '| Per-round PBC+FL power and latency | `%s/5g_lte_pbc_fl_rounds_report.md` | `%s/5g_lte_pbc_fl_rounds_structured.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR"
    printf '## Comparison\n\n'
    printf '| Comparison | Markdown | CSV |\n'
    printf '| --- | --- | --- |\n'
    printf '| PBC + FL vs PBC | `%s/5g_lte_pbc_fl_vs_pbc_comparison.md` | `%s/5g_lte_pbc_fl_vs_pbc_comparison.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR"
    printf 'Each per-case report includes total power/energy, security and communication power distribution, detailed stage energy, detailed stage latency, average stage power, top energy consumers, and top latency consumers.\n'
  } > "$index"
}

cd "$NS3_DIR"
mkdir -p "$RESULT_DIR"

if [[ ! -f "$TRACE_PATH" ]]; then
  if [[ "$TRACE_PATH" == "mobility_trace_${TARGET_VEHICLES}.tcl" && -f "$BASE_TRACE_PATH" && -f "$REPO_ROOT/scripts/generate_ns2_vehicle_trace.py" ]]; then
    echo "Generating ${TARGET_VEHICLES}-vehicle trace from ${BASE_TRACE_PATH}..."
    python3 "$REPO_ROOT/scripts/generate_ns2_vehicle_trace.py" \
      --input "$BASE_TRACE_PATH" \
      --output "$TRACE_PATH" \
      --target-vehicles "$TARGET_VEHICLES"
  else
    echo "Trace file not found from ns-3 directory: $TRACE_PATH" >&2
    exit 1
  fi
fi

vehicle_count="$(grep -Eo 'node_\([0-9]+\)' "$TRACE_PATH" | sort -u | wc -l | tr -d '[:space:]')"
echo "Trace vehicle count: ${vehicle_count}"
if [[ "$vehicle_count" != "$TARGET_VEHICLES" ]]; then
  echo "Warning: TARGET_VEHICLES=${TARGET_VEHICLES}, but trace reports ${vehicle_count} vehicles." >&2
fi
if ((FL_PARTICIPANTS > vehicle_count)); then
  echo "Warning: FL_PARTICIPANTS=${FL_PARTICIPANTS}, but trace has ${vehicle_count} vehicles. Simulator will cap selected vehicles to the trace count." >&2
fi

if [[ ! -f cmake-cache/CMakeCache.txt ]]; then
  echo "Configuring ns-3 with PBC enabled because this checkout has no cmake-cache/CMakeCache.txt..."
  configure_with_pbc
elif ! grep -q '^VANET_SECURITY_ENABLE_PBC:BOOL=ON$' cmake-cache/CMakeCache.txt; then
  echo "Reconfiguring ns-3 because VANET_SECURITY_ENABLE_PBC is not enabled in cmake-cache..."
  configure_with_pbc --force-refresh
fi

echo "Building VANET LTE security scenario..."
./ns3 build vanet-security-lte

run_case "5g_lte_pbc" ""

run_case "5g_lte_pbc_fl" \
  "--enableFl=true --flSecurityMode=pbc --flRounds=${FL_ROUNDS} --flParticipants=${FL_PARTICIPANTS} --flModelDim=${FL_MODEL_DIM} --flRoundInterval=${FL_ROUND_INTERVAL} --flCsv=${RESULT_DIR}/5g_lte_pbc_fl_rounds.csv --flStageCsv=${RESULT_DIR}/5g_lte_pbc_fl_stage_summary.csv"

python3 "$REPO_ROOT/scripts/format_fl_round_results.py" \
  --fl-csv "$RESULT_DIR/5g_lte_pbc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/5g_lte_pbc_fl_rounds"

python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
  --label "5g_lte_pbc" \
  --auth-power "$RESULT_DIR/5g_lte_pbc_power.csv" \
  --auth-stages "$RESULT_DIR/5g_lte_pbc_stages.csv" \
  --fl-power "$RESULT_DIR/5g_lte_pbc_fl_power.csv" \
  --fl-stages "$RESULT_DIR/5g_lte_pbc_fl_stages.csv" \
  --fl-csv "$RESULT_DIR/5g_lte_pbc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/5g_lte_pbc_fl_vs_pbc"

write_index

echo
echo "Final periodic CSV rows:"
for case_name in 5g_lte_pbc 5g_lte_pbc_fl; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Reports written under:"
echo "$NS3_DIR/$RESULT_DIR"
echo
echo "Open this first:"
echo "$NS3_DIR/$RESULT_DIR/$INDEX_NAME"
