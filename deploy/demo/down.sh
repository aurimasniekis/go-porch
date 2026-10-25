#!/usr/bin/env bash
# Stops the Porch demo stack and deletes everything it created: containers, the network, the named volumes (Porch
# data, the KEK, Caddy's CA) and deploy/demo/.state.
#
# Usage: deploy/demo/down.sh [--keep]
#   --keep   stop and remove containers only; keep volumes and .state so up.sh resumes the same installation.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
# shellcheck source=/dev/null # optional local settings
[[ -f .env ]] && { set -a; . ./.env; set +a; }
compose=(docker compose -f "$here/compose.yaml" --profile demo-app --profile init)

if [[ "${1:-}" == "--keep" ]]; then
  "${compose[@]}" down --remove-orphans
  exit 0
fi
"${compose[@]}" down --volumes --remove-orphans
rm -rf "$here/.state"
echo "demo stack removed (containers, network, volumes, .state). Images are kept; remove them with:"
echo "  docker image rm porch:local porch-demo-fakegoogle:local porch-demo-app:local"
