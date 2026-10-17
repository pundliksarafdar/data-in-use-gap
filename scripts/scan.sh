#!/usr/bin/env bash
# Resolve the victim container's host PID and scan its memory for the canary.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-payments-api}"
PID="$(docker inspect --format '{{.State.Pid}}' "$NAME")"

if [[ -z "$PID" || "$PID" == "0" ]]; then
  echo "[scan] could not resolve host pid for container '$NAME'" >&2
  exit 1
fi

echo "[scan] container '$NAME' -> host pid $PID"
sudo python3 scanner/scan.py "$PID"
