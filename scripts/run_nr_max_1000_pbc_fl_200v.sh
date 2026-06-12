#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export TARGET_VEHICLES="${TARGET_VEHICLES:-200}"
export SIM_TIME="${SIM_TIME:-1000}"
export FL_ROUNDS="${FL_ROUNDS:-500}"
export FL_PARTICIPANTS="${FL_PARTICIPANTS:-$TARGET_VEHICLES}"
export MSG_INTERVAL="${MSG_INTERVAL:-1.0}"
export RELAY_AGGREGATION_WINDOW_MS="${RELAY_AGGREGATION_WINDOW_MS:-50}"
export RELAY_MAX_BATCH_SIZE="${RELAY_MAX_BATCH_SIZE:-32}"

exec "$SCRIPT_DIR/run_nr_max_1000_pbc_fl_100v.sh" "$@"
