#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite (OP test plans) against a freshly started Porch, all in Docker.
# Exits non-zero when any test module FAILED or did not finish. See test/conformance/README.md.
#
# Usage: test/conformance/run.sh [plan ...]
#   default plans: oidcc-basic-certification-test-plan (discovery, static client) and oidcc-config-certification-test-plan
# Environment:
#   CONF_SKIP_BUILD=1   reuse test/conformance/.build/{porch,fakegoogle} (and the already built web UI)
#   CONF_KEEP=1         leave the stack running after the run (stop it with: docker compose -p porch-conformance down -v)
#   CONF_ONLY=a,b       run only these test modules
#   CONF_LOGIN_SHIM=0   disable the front proxy's login shim (to see HtmlUnit fail on the SPA)
#   CONF_SUITE_TAG      conformance-suite image tag (default latest)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
export CONF_SUITE_PORT=$(free_port) CONF_PORCH_PORT=$(free_port)
export CONF_BIN="$here/.build"
run_id=$(date +%Y%m%d-%H%M%S)
export CONF_WORK="$here/.work/$run_id"
mkdir -p "$CONF_WORK/tls" "$CONF_BIN"
chmod 700 "$here/.work" "$CONF_WORK"
compose=(docker compose -p porch-conformance -f "$here/docker-compose.yml")

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- porch log (tail)"; "${compose[@]}" logs --no-color --tail 40 porch-backend 2>/dev/null || true
  fi
  "${compose[@]}" logs --no-color > "$CONF_WORK/compose.log" 2>&1 || true
  if [[ "${CONF_KEEP:-}" == 1 ]]; then
    echo "stack left running: suite https://127.0.0.1:$CONF_SUITE_PORT/  porch https://127.0.0.1:$CONF_PORCH_PORT/ (Host: porch:8443)"
  else
    "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit $status
}
trap cleanup EXIT

# ---- build linux binaries for the Docker VM's architecture
if [[ "${CONF_SKIP_BUILD:-}" != 1 ]]; then
  (cd web && pnpm install --frozen-lockfile --silent && pnpm build >/dev/null)
fi
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) goarch=arm64 ;;
  x86_64|amd64) goarch=amd64 ;;
  *) echo "unsupported docker architecture" >&2; exit 2 ;;
esac
if [[ "${CONF_SKIP_BUILD:-}" != 1 || ! -x "$CONF_BIN/porch" ]]; then
  CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$CONF_BIN/porch" ./cmd/porch
  CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -o "$CONF_BIN/fakegoogle" ./test/fakegoogle
fi

# ---- Porch config, throwaway TLS certificate, front proxy config
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=porch" \
  -addext "subjectAltName=DNS:porch,DNS:porch-backend,DNS:localhost" \
  -keyout "$CONF_WORK/tls/key.pem" -out "$CONF_WORK/tls/cert.pem" 2>/dev/null
chmod 644 "$CONF_WORK/tls/key.pem"  # read by the nginx worker inside the container; throwaway key
cat > "$CONF_WORK/porch.yaml" <<YAML
mode: development
data_dir: /data/porch  # porch creates it 0700; the volume root itself is 0755
public_url: https://porch:8443
http:
  listen: 0.0.0.0:8443
  tls_cert_file: /work/tls/cert.pem
  tls_key_file: /work/tls/key.pem
management:
  listen: 0.0.0.0:9090
outbound:
  # the fake Google provider lives on the compose network (private addresses)
  allow_cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
log:
  format: text
  level: info
YAML
shim=1; [[ "${CONF_LOGIN_SHIM:-1}" == 0 ]] && shim=0
sed "s/__LOGIN_SHIM__/$shim/g" "$here/front.conf.tmpl" > "$CONF_WORK/front.conf"

# ---- start the stack
"${compose[@]}" up -d --wait --wait-timeout 180
for _ in $(seq 1 90); do
  curl -ksf "https://127.0.0.1:$CONF_SUITE_PORT/api/runner/available" >/dev/null && break
  sleep 2
done
curl -ksf "https://127.0.0.1:$CONF_SUITE_PORT/api/runner/available" >/dev/null || { echo "conformance suite did not start" >&2; exit 1; }
suite_version=$(curl -ksf "https://127.0.0.1:$CONF_SUITE_PORT/api/server" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("version","?"), d.get("revision", ""))' || echo "?")
token=$(grep -o 'porch_setup_[A-Za-z0-9_-]*' "$CONF_WORK/setup-token.out" | head -1)
[[ -n "$token" ]] || { echo "no setup token in $CONF_WORK/setup-token.out" >&2; exit 1; }

# ---- bootstrap Porch: owner, fake Google provider, tenant + domain rule, three OIDC clients
python3 "$here/bootstrap.py" --connect "127.0.0.1:$CONF_PORCH_PORT" --public-url https://porch:8443 --token "$token" \
  --idp-issuer http://fakegoogle:9000 --idp-client-id porch --idp-client-secret porch-conformance-upstream-secret \
  --redirect-uri https://localhost.emobix.co.uk:8443/test/a/porch/callback \
  --post-logout-uri https://localhost.emobix.co.uk:8443/test/a/porch/post_logout_redirect > "$CONF_WORK/clients.json"
python3 - "$here/config/porch-oidcc.json" "$CONF_WORK/clients.json" "$CONF_WORK/plan-config.json" <<'PY'
import json, sys
tmpl, clients, out = open(sys.argv[1]).read(), json.load(open(sys.argv[2])), sys.argv[3]
for k, v in {"CLIENT_ID": clients["client"]["client_id"], "CLIENT_SECRET": clients["client"]["client_secret"],
             "CLIENT2_ID": clients["client2"]["client_id"], "CLIENT2_SECRET": clients["client2"]["client_secret"],
             "POST_CLIENT_ID": clients["client_secret_post"]["client_id"],
             "POST_CLIENT_SECRET": clients["client_secret_post"]["client_secret"]}.items():
    tmpl = tmpl.replace("{" + k + "}", v)
open(out, "w").write(tmpl)
PY
echo "porch $(git describe --always --dirty 2>/dev/null || echo '?') | conformance suite $suite_version | work dir $CONF_WORK"

# ---- run the plans
plans=("$@")
if [[ ${#plans[@]} -eq 0 ]]; then
  plans=('oidcc-basic-certification-test-plan{"server_metadata":"discovery","client_registration":"static_client"}'
         'oidcc-config-certification-test-plan')
fi
status=0
python3 "$here/run_plans.py" --suite "https://127.0.0.1:$CONF_SUITE_PORT/" --config "$CONF_WORK/plan-config.json" \
  --out "$CONF_WORK/results.json" --only "${CONF_ONLY:-}" "${plans[@]}" || status=$?
python3 "$here/summarize.py" "$CONF_WORK/results.json" --suite-version "$suite_version" \
  --porch-version "$(git describe --always --dirty 2>/dev/null || echo '?')" > "$CONF_WORK/results.md" || true
echo "results: $CONF_WORK/results.md"
exit $status
