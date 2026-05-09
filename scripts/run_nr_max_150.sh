#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export SIM_TIME="${SIM_TIME:-150}"
export RESULT_DIR="${RESULT_DIR:-results/power_pbc}"

exec "$REPO_ROOT/scripts/run_pbc_power_tests.sh" nr-max
