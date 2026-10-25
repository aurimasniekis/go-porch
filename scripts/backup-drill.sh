#!/usr/bin/env bash
# Restore drill against a real S3 implementation (MinIO in Docker, bucket with versioning + object lock):
#   1. porch serve with backups enabled; first owner; a tenant; POST /installation/backups
#   2. porch backup list / verify (signature, decryption, SQLite integrity)
#   3. porch restore into a clean data directory + KEK path; porch serve from it
#   4. old session rejected, signing keys replaced, data present (via a recovery link), audit chain intact
# Needs Docker, curl and python3. All credentials are generated per run.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
MINIO_IMAGE=${MINIO_IMAGE:-cgr.dev/chainguard/minio@sha256:32c504bea4574d8f29d719b37bc0dad920ecf3e22b81dc5cea0bb105af2ce10f}
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
work=$(mktemp -d); chmod 700 "$work"
S3=$(free_port); PUB=$(free_port); MGMT=$(free_port)
S3_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
export S3_ACCESS_KEY="drill$RANDOM" S3_SECRET_KEY
name="porch-drill-$$"
cleanup() {
  [[ -n "${pid:-}" ]] && kill "$pid" 2>/dev/null || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }

step "build"
CGO_ENABLED=0 go build -o bin/porch ./cmd/porch
go build -o bin/s3bucket ./test/s3bucket

step "MinIO ($MINIO_IMAGE) on 127.0.0.1:$S3"
docker run -d --name "$name" -p "127.0.0.1:$S3:9000" -e MINIO_ROOT_USER="$S3_ACCESS_KEY" -e MINIO_ROOT_PASSWORD="$S3_SECRET_KEY" \
  "$MINIO_IMAGE" server /data >/dev/null
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$S3/minio/health/ready" >/dev/null && break; sleep 0.5; done
bin/s3bucket -endpoint "127.0.0.1:$S3" -bucket porch-backups

bin/porch backup keygen -out "$work/backup.agekey" 2>"$work/keygen.txt"
recipient=$(grep -o 'age1[0-9a-z]*' "$work/keygen.txt")
printf '%s' "$S3_SECRET_KEY" >"$work/s3-secret"; chmod 600 "$work/s3-secret"
config() { # data_dir kek_file
  cat <<YAML
mode: development
data_dir: $1
kek:
  file: $2
public_url: http://localhost:$PUB
http:
  listen: 127.0.0.1:$PUB
management:
  listen: 127.0.0.1:$MGMT
outbound:
  allow_cidrs: [127.0.0.1/32]
log:
  level: warn
backup:
  enabled: true
  interval: 6h
  retention: 3
  recipients: [$recipient]
  s3:
    endpoint: 127.0.0.1:$S3
    bucket: porch-backups
    prefix: porch/
    access_key_id: $S3_ACCESS_KEY
    secret_access_key_file: $work/s3-secret
    insecure: true
    lookup: path
YAML
}
bin/porch keys init -out "$work/kek-a" >/dev/null
config "$work/data-a" "$work/kek-a" >"$work/a.yaml"
serve() { bin/porch serve -config "$1" >>"$work/porch.log" 2>&1 & pid=$!
  for _ in $(seq 1 60); do bin/porch healthcheck --url "http://127.0.0.1:$MGMT/readyz" >/dev/null 2>&1 && return; sleep 0.25; done
  tail -30 "$work/porch.log"; exit 1; }
stop() { kill "$pid"; wait "$pid" 2>/dev/null || true; pid=; }
api() { # method path [json] -> body (uses $cookie/$csrf)
  curl -sf -X "$1" "http://localhost:$PUB/api/v1$2" -H "Origin: http://localhost:$PUB" -H "Content-Type: application/json" \
    -H "Cookie: __Host-porch_session=$cookie" -H "X-Porch-CSRF: $csrf" ${3:+-d "$3"}; }
json() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

step "instance A: setup, data, backup"
token=$(bin/porch admin setup-token -config "$work/a.yaml" 2>/dev/null | grep -o 'porch_setup_[A-Za-z0-9_-]*')
serve "$work/a.yaml"
resp=$(curl -sf -D "$work/h" "http://localhost:$PUB/api/v1/setup" -H "Origin: http://localhost:$PUB" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$token\",\"display_name\":\"Olga Owner\",\"email\":\"olga@example.com\"}")
cookie=$(grep -io '__Host-porch_session=[^;]*' "$work/h" | cut -d= -f2); csrf=$(echo "$resp" | json "['csrf_token']")
api POST /tenants '{"slug":"smith","name":"Smith family"}' >/dev/null
api POST /tenants/smith/groups '{"slug":"kids","name":"Kids"}' >/dev/null
run=$(api POST /installation/backups); echo "$run"
[[ $(echo "$run" | json "['ok']") == True ]]
verify_key=$(api GET /installation/backups | json "['verify_key']")
kids_a=$(curl -sf "http://localhost:$PUB/jwks" | json "['keys'][0]['kid']")
stop

step "list and verify from object storage"
bin/porch backup list -config "$work/a.yaml"
bin/porch backup verify -config "$work/a.yaml" -identity "$work/backup.agekey" -verify-key "$verify_key"
if bin/porch backup verify -config "$work/a.yaml" -identity "$work/backup.agekey" \
    -verify-key "porch-backup-ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >/dev/null 2>&1; then
  echo "verification with a wrong key succeeded"; exit 1
fi

step "restore into a clean instance B"
config "$work/data-b" "$work/kek-b/porch.kek" >"$work/b.yaml"
bin/porch restore -config "$work/b.yaml" -identity "$work/backup.agekey" -verify-key "$verify_key"
[[ $(stat -f %Lp "$work/kek-b/porch.kek" 2>/dev/null || stat -c %a "$work/kek-b/porch.kek") == 400 ]]
serve "$work/b.yaml"
status=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PUB/api/v1/me" -H "Cookie: __Host-porch_session=$cookie")
[[ $status == 401 ]] || { echo "old session still valid ($status)"; exit 1; }
kids_b=$(curl -sf "http://localhost:$PUB/jwks" | json "['keys'][0]['kid']")
[[ $kids_a != "$kids_b" ]] || { echo "signing key not replaced"; exit 1; }
stop
link=$(bin/porch admin recover -config "$work/b.yaml" -user olga@example.com 2>/dev/null | grep -o 'token=[A-Za-z0-9_-]*' | cut -d= -f2)
bin/porch audit verify -config "$work/b.yaml"
serve "$work/b.yaml"
resp=$(curl -sf -D "$work/h2" "http://localhost:$PUB/api/v1/auth/recovery" -H "Origin: http://localhost:$PUB" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$link\"}")
cookie=$(grep -io '__Host-porch_session=[^;]*' "$work/h2" | cut -d= -f2); csrf=""
groups=$(curl -sf "http://localhost:$PUB/api/v1/tenants/smith/groups" -H "Cookie: __Host-porch_session=$cookie" | json "[0]['slug']")
[[ $groups == kids ]] || { echo "restored data missing"; exit 1; }
alerts=$(curl -sf "http://localhost:$PUB/api/v1/installation/alerts" -H "Cookie: __Host-porch_session=$cookie")
echo "$alerts" | grep -q installation_restored
stop
step "drill passed"
