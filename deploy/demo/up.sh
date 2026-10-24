#!/usr/bin/env bash
# Starts the Porch demo stack (deploy/demo/compose.yaml). DEMO ONLY: includes a fake Google that signs in anyone.
#
# Usage: deploy/demo/up.sh [--manual] [--no-build]
#   (default)   build images, create the KEK, issue a setup token, start everything, complete first-time setup through
#               the API (owner, fake Google provider, tenant "smith", demo app, whoami forward-auth app) and start the
#               demo app.
#   --manual    stop after starting Porch and print the setup token; finish setup yourself in the browser
#               (https://auth.localhost:<port>/setup). The demo app is not started (it needs registered credentials).
#   --no-build  reuse existing images.
# Re-running is safe: the KEK, data and setup state are kept until deploy/demo/down.sh.
#
# Needs: docker (compose v2.24+), python3, curl. Settings: deploy/demo/.env (see .env.example).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
[[ -f .env ]] && { set -a; . ./.env; set +a; }
export DEMO_HTTPS_PORT=${DEMO_HTTPS_PORT:-28443}
export DEMO_SUBNET=${DEMO_SUBNET:-172.30.213.0/24}
export DEMO_GOOGLE_CLIENT_SECRET=${DEMO_GOOGLE_CLIENT_SECRET:-porch-demo-upstream-secret}

manual=0 build=1
for a in "$@"; do
  case "$a" in
    --manual) manual=1 ;;
    --no-build) build=0 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

compose=(docker compose -f "$here/compose.yaml")
state="$here/.state"
port=$DEMO_HTTPS_PORT
log() { printf '\033[1m==> %s\033[0m\n' "$*" >&2; }
die() { printf 'up.sh: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
command -v curl >/dev/null || die "curl is required"
mkdir -p "$state/ca"
chmod 700 "$state"

# The port must be free unless our own caddy already holds it.
if ! "${compose[@]}" ps --status running --services 2>/dev/null | grep -qx caddy; then
  python3 - "$port" <<'PY' || die "127.0.0.1:$port is in use; set DEMO_HTTPS_PORT in deploy/demo/.env"
import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.close()
PY
fi

if [[ $build == 1 ]]; then
  log "building images (porch:local, porch-demo-fakegoogle:local, porch-demo-app:local)"
  DEMO_BUILD_VERSION=$(git -C "$here" describe --tags --always --dirty 2>/dev/null || echo dev)
  DEMO_BUILD_COMMIT=$(git -C "$here" rev-parse HEAD 2>/dev/null || true)
  export DEMO_BUILD_VERSION DEMO_BUILD_COMMIT
  "${compose[@]}" --profile demo-app build porch fakegoogle demo-app
fi

log "starting caddy and exporting its internal root CA"
"${compose[@]}" up -d caddy
for _ in $(seq 1 60); do
  if "${compose[@]}" exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > "$state/ca/root.crt.tmp" 2>/dev/null \
     && [[ -s "$state/ca/root.crt.tmp" ]]; then
    mv "$state/ca/root.crt.tmp" "$state/ca/root.crt"
    break
  fi
  sleep 1
done
rm -f "$state/ca/root.crt.tmp"
[[ -s "$state/ca/root.crt" ]] || die "caddy did not create its internal CA (docker compose logs caddy)"
chmod 644 "$state/ca/root.crt"

log "creating the KEK (porch keys init; kept if it already exists)"
if ! out=$("${compose[@]}" run --rm --no-deps porch-init keys init --out /var/lib/porch-kek/porch.kek 2>&1); then
  grep -q 'file exists' <<<"$out" || die "keys init failed: $out"
  echo "KEK already exists" >&2
else
  echo "$out" >&2
fi

token=""
if [[ ! -f "$state/bootstrap.json" && ! -f "$state/manual-setup" ]]; then
  log "issuing a setup token (porch admin setup-token; Porch must not be running)"
  "${compose[@]}" stop porch >/dev/null 2>&1 || true
  if out=$("${compose[@]}" run --rm --no-deps porch-init admin setup-token 2>&1); then
    token=$(grep -o 'porch_setup_[A-Za-z0-9_-]*' <<<"$out" | head -1)
    ( umask 077; printf '%s\n' "$token" > "$state/setup-token.txt" )
  else
    echo "$out" >&2
    die "could not issue a setup token (already set up? run down.sh for a fresh stack)"
  fi
fi

log "starting porch, fakegoogle, whoami"
"${compose[@]}" up -d --wait --wait-timeout 120 caddy porch fakegoogle whoami

log "checking discovery through Caddy"
disc=$(curl -sS --fail --cacert "$state/ca/root.crt" --resolve "auth.localhost:$port:127.0.0.1" \
  "https://auth.localhost:$port/.well-known/openid-configuration") || die "discovery failed"
issuer=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' <<<"$disc")
[[ "$issuer" == "https://auth.localhost:$port" ]] || die "unexpected issuer $issuer"
echo "issuer: $issuer" >&2

if [[ $manual == 1 ]]; then
  touch "$state/manual-setup"
elif [[ -n "$token" ]]; then
  log "bootstrapping through the management API (owner, fake Google, tenant, demo app, forward-auth app)"
  python3 "$here/bootstrap.py" --port "$port" --token "$token" --state "$state" \
    --google-client-secret "$DEMO_GOOGLE_CLIENT_SECRET" >/dev/null
fi

if [[ -f "$state/demo-app.env" ]]; then
  log "starting the demo app"
  "${compose[@]}" --profile demo-app up -d --wait --wait-timeout 120 demo-app
fi

"${compose[@]}" --profile demo-app ps --format 'table {{.Service}}\t{{.Status}}'
cat <<EOF

Porch demo is up (DEMO ONLY: the fake Google signs in anyone who clicks a name).

  Porch (issuer)    https://auth.localhost:$port
  Fake Google       https://google.localhost:$port      users: Ada Smith, Bob Smith (smith.example), Carol (not enrolled)
  Demo OIDC app     https://demo.localhost:$port
  whoami (fwd-auth) https://whoami.localhost:$port
  Discovery         https://auth.localhost:$port/.well-known/openid-configuration

Browsers will warn about the certificate until you trust Caddy's local root CA:
  $state/ca/root.crt
  (macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$state/ca/root.crt";
   or curl --cacert "$state/ca/root.crt" ...). It is regenerated by down.sh.
EOF
if [[ -f "$state/setup-token.txt" ]]; then
  t=$(cat "$state/setup-token.txt")
  if [[ -f "$state/bootstrap.json" ]]; then
    echo "Setup token (already consumed by the automatic bootstrap): $t"
  else
    echo
    echo "Setup token (single use; paste it at https://auth.localhost:$port/setup):"
    echo
    echo "  $t"
  fi
fi
if [[ -f "$state/owner.txt" ]]; then
  echo
  cat "$state/owner.txt"
fi
if [[ -f "$state/bootstrap.json" ]]; then
  echo
  echo "Try: open https://demo.localhost:$port -> Sign in with Porch -> Continue with Google -> Ada Smith."
fi
echo
echo "Stop with: $here/down.sh   (removes containers, volumes, KEK and .state)"
