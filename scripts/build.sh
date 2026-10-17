#!/usr/bin/env bash
# Build the hardened victim image.
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -t tdx-demo/victim:latest victim/
echo "[build] built tdx-demo/victim:latest"
