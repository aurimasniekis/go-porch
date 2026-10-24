#!/usr/bin/env bash
# Validates the Prometheus alert rules (syntax + unit tests) and every PromQL query in the Grafana dashboard.
# Needs Docker (runs promtool from the official Prometheus image) and python3.
set -euo pipefail
cd "$(dirname "$0")"
img=prom/prometheus:v3.5.0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp porch-alerts.yaml porch-alerts.test.yaml "$tmp/"
python3 - "$tmp/dashboard-rules.yaml" <<'PY'
import json, sys
d = json.load(open("porch-dashboard.json"))
rules = []
for p in d["panels"]:
    for t in p.get("targets", []):
        e = t["expr"].replace("$job", "porch").replace("$instance", ".*").replace("${datasource}", "")
        rules.append({"record": f"porch_dashboard:panel{p['id']}_{t['refId'].lower()}", "expr": e})
with open(sys.argv[1], "w") as f:
    json.dump({"groups": [{"name": "dashboard-queries", "rules": rules}]}, f)
print(f"dashboard: {len(rules)} queries")
PY
run() { docker run --rm --entrypoint promtool -v "$tmp":/w -w /w "$img" "$@"; }
run check rules porch-alerts.yaml dashboard-rules.yaml
run test rules porch-alerts.test.yaml
