#!/usr/bin/env bash
# Run the victim with container hardening applied. The demo's point is that
# none of these flags protect process memory from a privileged host observer.
#
# The canary is NOT baked into the image. It is injected at runtime via the
# environment (-e). In a real deployment these values come from your secret
# store / orchestrator and are kept out of the repo.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-payments-api}"

# Planted demo canaries (fake teaching values; see README "Safety scope").
# Overridable via env so nothing real is ever hardcoded in the repo.
DB_PASSWORD="${DB_PASSWORD:-DB_PASSWORD=Pr0d_c0nn_7f3a9c21}"
DEMO_MARKER="${DEMO_MARKER:-TDX_DEMO_CANARY_v1}"

docker rm -f "$NAME" >/dev/null 2>&1 || true

docker run -d --name "$NAME" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 32 \
  -e "DB_PASSWORD=$DB_PASSWORD" \
  -e "DEMO_MARKER=$DEMO_MARKER" \
  tdx-demo/victim:latest

echo "[run] started hardened container: $NAME"
echo "[run] canary injected via environment"
docker logs "$NAME"
