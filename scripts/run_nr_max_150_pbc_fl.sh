#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS3_DIR="$REPO_ROOT/simulation_workspace/ns-allinone-3.44/ns-3.44"

RESULT_DIR="${RESULT_DIR:-results/nr_max_150_pbc_fl}"
SIM_TIME="${SIM_TIME:-150}"
FL_ROUNDS="${FL_ROUNDS:-20}"
FL_PARTICIPANTS="${FL_PARTICIPANTS:-50}"
FL_MODEL_DIM="${FL_MODEL_DIM:-64}"
FL_ROUND_INTERVAL="${FL_ROUND_INTERVAL:-1.0}"
TRACE_PATH="${TRACE_PATH:-mobility_trace.tcl}"
NS3_CONFIGURE_ARGS="${NS3_CONFIGURE_ARGS:---enable-examples --build-profile=optimized}"

export LSAN_OPTIONS="${LSAN_OPTIONS:-detect_leaks=0}"

run_case() {
  local case_name="$1"
  local extra_args="$2"
  local power_csv="$RESULT_DIR/${case_name}_power.csv"
  local stage_csv="$RESULT_DIR/${case_name}_stages.csv"

  echo
  echo "Running ${case_name} for ${SIM_TIME} simulated seconds..."
  ./ns3 run "vanet-security-nr --trace=${TRACE_PATH} --radioProfile=6g_nr_max --securityMode=pbc --simTime=${SIM_TIME} --progressLog=true ${extra_args} --outCsv=${power_csv} --stageCsv=${stage_csv}"

  python3 "$REPO_ROOT/scripts/format_pbc_power_results.py" \
    --power-csv "$power_csv" \
    --stage-csv "$stage_csv" \
    --out-prefix "$RESULT_DIR/$case_name"
}

write_index() {
  local index="$RESULT_DIR/nr_max_150_pbc_fl_index.md"
  {
    printf '# NR-Max 150 Second PBC And PBC+FL Report Index\n\n'
    printf 'Simulation time: `%s` seconds\n\n' "$SIM_TIME"
    printf 'Trace: `%s`\n\n' "$TRACE_PATH"
    printf 'Trace vehicle count: `%s`\n\n' "$vehicle_count"
    printf 'Radio profile: `6g_nr_max`\n\n'
    printf 'Security mode: `pbc`\n\n'
    printf 'FL settings: `%s` rounds, `%s` participants, model dimension `%s`, round interval `%s` seconds\n\n' "$FL_ROUNDS" "$FL_PARTICIPANTS" "$FL_MODEL_DIM" "$FL_ROUND_INTERVAL"
    printf '## NR-Max 6G Profile Used\n\n'
    printf '| Parameter | Value |\n'
    printf '| --- | --- |\n'
    printf '| Carrier frequency | `100e9` Hz (`100 GHz`) |\n'
    printf '| Bandwidth | `1000e6` Hz (`1 GHz`) |\n'
    printf '| Numerology | `mu=4` |\n'
    printf '| gNB TX power | `35 dBm` |\n'
    printf '| UE/vehicle TX power | `23 dBm` |\n'
    printf '| Analytical effective rate | `10000 Mbps` (`10 Gbps`) |\n'
    printf '| Scheduler | `NrMacSchedulerTdmaRR` |\n'
    printf '| RLC mode | `RLC_UM_ALWAYS` |\n'
    printf '| Channel factory | `UMa`, `Default`, `NYU` |\n'
    printf '| Channel update period | `100 ms` |\n'
    printf '| gNB antenna | `4 x 8` isotropic array |\n'
    printf '| UE antenna | `1 x 1` isotropic antenna |\n'
    printf '| V2V mode | `relay` fallback through BS relay when sidelink is unavailable |\n\n'
    printf '## Reports\n\n'
    printf '| Case | Markdown report | Structured CSV | Power CSV | Stage CSV | FL rounds CSV |\n'
    printf '| --- | --- | --- | --- | --- | --- |\n'
    printf '| NR-max PBC | `%s/nr_max_pbc_report.md` | `%s/nr_max_pbc_structured.csv` | `%s/nr_max_pbc_power.csv` | `%s/nr_max_pbc_stages.csv` | - |\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '| NR-max PBC + FL | `%s/nr_max_pbc_fl_report.md` | `%s/nr_max_pbc_fl_structured.csv` | `%s/nr_max_pbc_fl_power.csv` | `%s/nr_max_pbc_fl_stages.csv` | `%s/nr_max_pbc_fl_rounds.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR" "$RESULT_DIR"
    printf '## Comparison\n\n'
    printf '| Comparison | Markdown | CSV |\n'
    printf '| --- | --- | --- |\n'
    printf '| PBC + FL vs PBC | `%s/nr_max_pbc_fl_vs_pbc_comparison.md` | `%s/nr_max_pbc_fl_vs_pbc_comparison.csv` |\n\n' "$RESULT_DIR" "$RESULT_DIR"
    printf 'Each per-case report includes total power/energy, security and communication power distribution, detailed stage energy, detailed stage latency, top energy consumers, and top latency consumers.\n'
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
if ((FL_PARTICIPANTS > vehicle_count)); then
  echo "Warning: FL_PARTICIPANTS=${FL_PARTICIPANTS}, but trace has ${vehicle_count} vehicles. Simulator will cap selected vehicles to the trace count." >&2
fi

if [[ ! -f cmake-cache/CMakeCache.txt ]]; then
  echo "Configuring ns-3 because this checkout has no cmake-cache/CMakeCache.txt..."
  ./ns3 configure $NS3_CONFIGURE_ARGS
fi

echo "Building VANET NR security scenario..."
./ns3 build vanet-security-nr

run_case "nr_max_pbc" ""

run_case "nr_max_pbc_fl" \
  "--enableFl=true --flSecurityMode=pbc --flRounds=${FL_ROUNDS} --flParticipants=${FL_PARTICIPANTS} --flModelDim=${FL_MODEL_DIM} --flRoundInterval=${FL_ROUND_INTERVAL} --flCsv=${RESULT_DIR}/nr_max_pbc_fl_rounds.csv --flStageCsv=${RESULT_DIR}/nr_max_pbc_fl_stage_summary.csv"

python3 "$REPO_ROOT/scripts/compare_fl_auth_overhead.py" \
  --label "6g_nr_max_pbc" \
  --auth-power "$RESULT_DIR/nr_max_pbc_power.csv" \
  --auth-stages "$RESULT_DIR/nr_max_pbc_stages.csv" \
  --fl-power "$RESULT_DIR/nr_max_pbc_fl_power.csv" \
  --fl-stages "$RESULT_DIR/nr_max_pbc_fl_stages.csv" \
  --fl-csv "$RESULT_DIR/nr_max_pbc_fl_rounds.csv" \
  --out-prefix "$RESULT_DIR/nr_max_pbc_fl_vs_pbc"

write_index

echo
echo "Final periodic CSV rows:"
for case_name in nr_max_pbc nr_max_pbc_fl; do
  echo "$case_name:"
  tail -n 1 "$RESULT_DIR/${case_name}_power.csv"
done

echo
echo "Reports written under:"
echo "$NS3_DIR/$RESULT_DIR"
echo
echo "Open this first:"
echo "$NS3_DIR/$RESULT_DIR/nr_max_150_pbc_fl_index.md"
