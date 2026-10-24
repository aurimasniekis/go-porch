#!/usr/bin/env bash
# Acceptance demonstration: runs every automated suite that demonstrates the acceptance items of docs/PLAN.md against
# real binaries and prints one honest table. Items that were not exercised are reported as SKIPPED or NOT VERIFIED,
# never as passed.
#
# Usage: scripts/acceptance.sh [--quick] [--report FILE]
#   --quick   skip `make check` and the OpenID conformance suite
# Needs: Go, pnpm (web), Docker (MinIO drill, conformance), python3, curl; Terraform for the provider acceptance tests.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
quick=false; report=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --quick) quick=true ;;
    --report) report=$2; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
logs=$(mktemp -d); chmod 700 "$logs"
declare -a rows
row() { rows+=("| $1 | $2 | $3 | $4 |"); }
run() { # name logfile cmd...
  local name=$1 log=$2; shift 2
  printf '== %s ... ' "$name"
  if "$@" >"$log" 2>&1; then echo ok; return 0; else echo "FAILED (log: $log)"; return 1; fi
}

if ! $quick; then
  if run "make check" "$logs/check.log" make check; then row "Build" "make check (lint, race tests, drift, vuln, secrets, web, site)" PASS "make check"
  else row "Build" "make check" FAIL "$logs/check.log"; fi
else
  row "Build" "make check" SKIPPED "--quick"
fi

# Browser suite: setup, Google (fake) Workspace enrollment, backup login + lockout with Google still working,
# demo OIDC app, forward-auth, launcher, admin UI with axe + CSP, delegation, automation tokens.
if run "Playwright e2e" "$logs/e2e.log" scripts/e2e.sh; then
  n=$(grep -Eo '[0-9]+ passed' "$logs/e2e.log" | tail -1)
  for item in "Workspace (hd) enrollment via fake Google; consumer account refused|m2-login" \
              "Backup login: 1 failure locks for 6 h, Google login still works|m2-login" \
              "Demo OIDC app: sign-in, verified ID + RFC 9068 access token, refresh, logout|m3-demo-app" \
              "Forward-auth (whoami) with identity headers via launcher|m4-launcher" \
              "Delegated admin cannot grant Administrator (escalation refused in UI)|m5-authz-admin" \
              "Explain trace + simulator in the admin UI|m5-authz-admin" \
              "Admin UI WCAG 2.1 AA (axe) on every page and dialog, zero CSP violations|m5-*, m6-*" \
              "Automation token issued in UI, used as bearer, revoked|m6-automation"; do
    row "UI/e2e" "${item%%|*}" PASS "Playwright ${item##*|} ($n)"
  done
else
  row "UI/e2e" "Playwright suite" FAIL "$logs/e2e.log"
fi

# API scenario against a fresh real server.
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PUB=$(free_port); MGMT=$(free_port); work=$(mktemp -d); chmod 700 "$work"
cat >"$work/porch.yaml" <<YAML
mode: development
data_dir: $work/data
public_url: http://localhost:$PUB
http:
  listen: 127.0.0.1:$PUB
management:
  listen: 127.0.0.1:$MGMT
log:
  level: warn
YAML
CGO_ENABLED=0 go build -o bin/porch ./cmd/porch
token=$(bin/porch admin setup-token -config "$work/porch.yaml" 2>/dev/null | grep -o 'porch_setup_[A-Za-z0-9_-]*')
bin/porch serve -config "$work/porch.yaml" >"$logs/api-porch.log" 2>&1 & pid=$!
for _ in $(seq 1 60); do bin/porch healthcheck --url "http://127.0.0.1:$MGMT/readyz" >/dev/null 2>&1 && break; sleep 0.25; done
printf '== API scenario ... '
PORCH_URL="http://localhost:$PUB" PORCH_MGMT="http://127.0.0.1:$MGMT" PORCH_SETUP_TOKEN="$token" \
  python3 test/acceptance/api_scenario.py >"$logs/api.log" 2>&1; api_rc=$?
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "$work"
[[ $api_rc -eq 0 ]] && echo ok || echo "FAILED (log: $logs/api.log)"
while read -r status id text; do
  case $status in PASS|FAIL) row "API" "$text" "$status" "api_scenario.py $id" ;; esac
done <"$logs/api.log"

if command -v docker >/dev/null 2>&1; then
  if run "backup drill (MinIO)" "$logs/drill.log" scripts/backup-drill.sh; then
    row "Backups" "Encrypted backup to MinIO (versioning + object lock), verify, restore into a clean data dir, sessions invalidated, keys replaced" PASS "scripts/backup-drill.sh"
  else row "Backups" "Backup/restore drill" FAIL "$logs/drill.log"; fi
  if ! $quick && [[ -x test/conformance/run.sh ]]; then
    if run "OpenID conformance (Basic + Config OP)" "$logs/conformance.log" test/conformance/run.sh; then
      row "OIDC" "OpenID conformance suite Basic + Config OP (local run, not certification)" PASS "test/conformance"
    else row "OIDC" "OpenID conformance suite" FAIL "$logs/conformance.log (REVIEW/WARNING modules need a human; see test/conformance/README.md)"; fi
  else
    row "OIDC" "OpenID conformance suite" SKIPPED "--quick (last recorded run: test/conformance/results-*.md)"
  fi
else
  row "Backups" "Backup/restore drill" SKIPPED "Docker not available"
fi

tf=${TF_PROVIDER_DIR:-$root/../terraform-provider-porch}
if [[ -f $tf/go.mod ]] && command -v terraform >/dev/null 2>&1; then
  if (cd "$tf" && run "Terraform provider acceptance (TF_ACC)" "$logs/tf.log" env TF_ACC=1 TF_ACC_TERRAFORM_PATH="$(command -v terraform)" go test ./... -count=1); then
    row "Terraform" "Provider acceptance tests against a real porch (create/update/import/drift)" PASS "$tf (TF_ACC=1)"
  else row "Terraform" "Provider acceptance tests" FAIL "$logs/tf.log"; fi
else
  row "Terraform" "Provider acceptance tests" SKIPPED "provider repo or terraform CLI not found"
fi

row "Events" "Outbox → NATS JetStream through the go-pulse SDK (IDs, headers, dedupe)" "$(go test ./internal/events -run TestRelayJetStream -count=1 >/dev/null 2>&1 && echo PASS || echo FAIL)" "go test ./internal/events"
row "Events" "Events visible in a running pulsed (replay API)" "NOT VERIFIED" "pulsed + creds issuance not run"
row "External" "Real Google Workspace, real S3 providers, real Cloudflare" "NOT VERIFIED" "fakes/MinIO only"

{
  echo "# Porch acceptance $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "Commit: $(git rev-parse --short HEAD)$(git diff --quiet || echo ' (dirty)')"
  echo
  echo "| Area | Item | Result | Evidence |"
  echo "|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
} | tee "${report:-/dev/null}"
if printf '%s\n' "${rows[@]}" | grep -q '| FAIL |'; then exit 1; fi
