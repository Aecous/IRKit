#!/usr/bin/env bash
# Prepare a case from /logs then run one Claude session. Results land in /cases (host-mounted).
set -euo pipefail

: "${ANTHROPIC_BASE_URL:?set ANTHROPIC_BASE_URL}"
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY}"
BUDGET="${BUDGET:-8}"
BACKGROUND="${BACKGROUND:-}"
MODE="${MODE:-run}"   # doctor | prepare | run

cd /opt/irkit

if [ "$MODE" = "doctor" ]; then
  exec uv run irkit doctor
fi

PREP=$(uv run irkit investigate /logs --prepare-only --cases-dir /cases --background "$BACKGROUND")
echo "$PREP"
CASE_DIR=$(printf '%s' "$PREP" | uv run python -c 'import sys,json;print(json.load(sys.stdin)["case_dir"])')
echo "case_dir=$CASE_DIR"

if [ "$MODE" = "prepare" ]; then
  exit 0
fi

exec uv run python scripts/run_case.py "$CASE_DIR" --budget "$BUDGET"
