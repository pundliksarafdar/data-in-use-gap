#!/usr/bin/env bash
# Run the Crash Diagnostics Agent against the running victim container.
#
#   ./scripts/run-agent.sh [container] [logfile]
#
# Default log is the INJECTED one, to demonstrate the safeguard bypass. Pass
# logs/payments-api.log to show the safe (crash_only) baseline.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-payments-api}"
LOG="${2:-logs/payments-api.injected.log}"

PID="$(docker inspect --format '{{.State.Pid}}' "$NAME")"
if [[ -z "$PID" || "$PID" == "0" ]]; then
  echo "[run-agent] could not resolve host pid for container '$NAME'" >&2
  exit 1
fi

echo "[run-agent] container '$NAME' -> host pid $PID"
echo "[run-agent] ingesting log: $LOG"
echo

sudo python3 agent/agent.py --log "$LOG" --pid "$PID"

echo
echo "[run-agent] ----- report -----"
cat reports/report.txt
