#!/usr/bin/env bash
# Runs the Playwright suite against a fresh development `porch serve` and the fake Google provider.
# Usage: scripts/e2e.sh [playwright args...]
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PUB=$(free_port); MGMT=$(free_port); IDP=$(free_port)
work=$(mktemp -d)
chmod 700 "$work"
cleanup() {
  for p in "${porch_pid:-}" "${idp_pid:-}" "${fwd_pid:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

if [[ "${E2E_SKIP_BUILD:-}" != 1 ]]; then
  (cd web && pnpm install --frozen-lockfile --silent && pnpm build >/dev/null)
  CGO_ENABLED=0 go build -o bin/porch ./cmd/porch
  go build -o bin/fakegoogle ./test/fakegoogle
  go build -o bin/demo-app ./examples/demo-app
  go build -o bin/fwdproxy ./test/fwdproxy
fi

cat > "$work/porch.yaml" <<YAML
mode: development
data_dir: $work/data
public_url: http://localhost:$PUB
http:
  listen: 127.0.0.1:$PUB
management:
  listen: 127.0.0.1:$MGMT
outbound:
  allow_cidrs: [127.0.0.1/32]
log:
  format: text
  level: warn
YAML
bin/fakegoogle -listen "127.0.0.1:$IDP" -issuer "http://127.0.0.1:$IDP" -client-id porch -client-secret porch-e2e-secret \
  -redirect-uris "http://localhost:$PUB/login/google/callback" >"$work/idp.log" 2>&1 &
idp_pid=$!
token=$(bin/porch admin setup-token -config "$work/porch.yaml" 2>/dev/null | grep -o 'porch_setup_[A-Za-z0-9_-]*')
bin/porch serve -config "$work/porch.yaml" >"$work/porch.log" 2>&1 &
porch_pid=$!
FWD=$(free_port)
bin/fwdproxy -listen "127.0.0.1:$FWD" -porch "http://127.0.0.1:$PUB" >"$work/fwd.log" 2>&1 &
fwd_pid=$!
for _ in $(seq 1 50); do bin/porch healthcheck --url "http://127.0.0.1:$MGMT/readyz" >/dev/null 2>&1 && break; sleep 0.2; done

export PORCH_E2E_URL="http://localhost:$PUB" PORCH_E2E_SETUP_TOKEN="$token" PORCH_E2E_IDP="http://127.0.0.1:$IDP"
export PORCH_E2E_MGMT="http://127.0.0.1:$MGMT" PORCH_E2E_DEMO_BIN="$root/bin/demo-app" PORCH_E2E_DEMO_PORT=$(free_port) PORCH_E2E_STATE="$work/e2e-state.json" PORCH_E2E_FWD="http://whoami.localhost:$FWD"
status=0
(cd web && pnpm exec playwright test "$@") || status=$?
if [[ $status -ne 0 ]]; then echo "--- porch log"; tail -50 "$work/porch.log"; echo "--- idp log"; tail -20 "$work/idp.log"; fi
exit $status
