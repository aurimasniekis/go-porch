#!/usr/bin/env bash
# Verifies Porch's event relay against a real, running pulsed (not just embedded NATS): a throwaway pulse dev stack
# (compose project porch-pulse, own ports and volumes) from a local go-pulse checkout, a publish-only client for
# evt.porch.> issued through pulsed's admin API, and a development Porch whose outbox relay publishes to it.
#
#   1. events from Porch API changes appear in pulsed with subject, CloudEvents type, source and Porch's event ID;
#   2. Porch keeps working while pulse is stopped, and the events written meanwhile arrive after pulse returns;
#   3. restarting Porch does not publish anything twice.
#
# Usage: test/pulse/verify.sh            (PULSE_REPO defaults to ../pulse next to this repository)
#   KEEP=1  leave the porch-pulse stack running afterwards
# Needs Docker (compose v2), Go, python3 and curl. TEST ONLY: everything is throwaway.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
pulse_repo=$(cd "${PULSE_REPO:-$root/../pulse}" && pwd)
here="$root/test/pulse"
py() { python3 -I "$here/verify.py" "$@"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

export PULSE_DEV_NATS_PORT=${PULSE_DEV_NATS_PORT:-34322} PULSE_DEV_ADMIN_PORT=${PULSE_DEV_ADMIN_PORT:-38180}
export PULSE_DEV_METRICS_PORT=${PULSE_DEV_METRICS_PORT:-39564} PULSE_DEV_PUBLIC_PORT=${PULSE_DEV_PUBLIC_PORT:-38543}
export PULSE_DEV_ALLOY_PORT=${PULSE_DEV_ALLOY_PORT:-32445} PULSE_DEV_S3_PORT=${PULSE_DEV_S3_PORT:-38433}
compose=(docker compose -p porch-pulse -f "$pulse_repo/deploy/compose.dev.yaml")
admin="http://127.0.0.1:$PULSE_DEV_ADMIN_PORT"

work=$(mktemp -d)
chmod 700 "$work"
cleanup() {
  [[ -n "${porch_pid:-}" ]] && kill "$porch_pid" 2>/dev/null || true
  if [[ "${KEEP:-}" != 1 ]]; then "${compose[@]}" down -v >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

echo "== pulse dev stack (porch-pulse) from $pulse_repo"
make -C "$pulse_repo" deploy/.dev/master.key deploy/.dev/age.key >/dev/null
"${compose[@]}" down -v >/dev/null 2>&1 || true
"${compose[@]}" up -d --wait pulsed >/dev/null
py pulse-setup "$admin" "${compose[*]} exec -T pulsed pulsed" "$work"

echo "== porch (development) relaying to tls://localhost:$PULSE_DEV_NATS_PORT"
(cd "$root" && CGO_ENABLED=0 go build -o "$work/porch" ./cmd/porch)
PUB=$(free_port); MGMT=$(free_port)
cat > "$work/porch.yaml" <<YAML
mode: development
data_dir: $work/data
public_url: http://localhost:$PUB
http:
  listen: 127.0.0.1:$PUB
management:
  listen: 127.0.0.1:$MGMT
log:
  format: text
  level: info
events:
  pulse:
    enabled: true
    url: tls://localhost:$PULSE_DEV_NATS_PORT
    creds_file: $work/porch.creds
    ca_file: $work/pulse-ca.pem
    source: porch
YAML
# Porch refuses unknown PORCH_* variables, so run it without any.
unset_porch=()
while IFS= read -r v; do unset_porch+=(-u "$v"); done < <(compgen -e | grep '^PORCH_' || true)
run_porch() { env ${unset_porch[@]+"${unset_porch[@]}"} "$work/porch" "$@"; }
start_porch() {
  run_porch serve -config "$work/porch.yaml" >>"$work/porch.log" 2>&1 &
  porch_pid=$!
  for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$MGMT/readyz" >/dev/null && return; sleep 0.2; done
  echo "porch did not become ready:"; cat "$work/porch.log"; exit 1
}
setup=$(run_porch admin setup-token -config "$work/porch.yaml" 2>&1 | grep -o 'porch_setup_[A-Za-z0-9_-]*')
start_porch
py porch-setup "http://localhost:$PUB" "$setup" "$work"

echo "== 1. events arrive in pulsed"
py check "$admin" "$work"
grep -q "event relay connected to pulse" "$work/porch.log" || { echo "relay never connected:"; cat "$work/porch.log"; exit 1; }
before=$(py count "$admin" "$work")

echo "== 2. pulse down: Porch keeps working, events wait in the outbox"
"${compose[@]}" stop nats >/dev/null
curl -sf "http://127.0.0.1:$MGMT/readyz" >/dev/null && echo "  porch still ready with NATS stopped"
py porch-change "http://localhost:$PUB" "$work" offline
"${compose[@]}" start nats >/dev/null
py wait-for "$admin" "$work" offline

echo "== 3. restarting Porch publishes nothing twice"
sleep 5
mid=$(py count "$admin" "$work")
kill "$porch_pid"; wait "$porch_pid" 2>/dev/null || true; porch_pid=""
start_porch
sleep 10
after=$(py count "$admin" "$work")
py check "$admin" "$work" >/dev/null
[[ "$mid" -gt "$before" && "$after" -eq "$mid" ]] || { echo "event counts: $before, $mid before restart, $after after"; exit 1; }
echo "  $before events after step 1, $mid after step 2, still $after after the restart (none repeated)"
echo "OK: Porch events verified in a running pulsed"
