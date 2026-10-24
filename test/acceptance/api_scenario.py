#!/usr/bin/env python3
"""Acceptance scenario against a running `porch serve` (stdlib only).

Env: PORCH_URL (public origin), PORCH_MGMT (management origin), PORCH_SETUP_TOKEN (unused setup token).
Prints one line per acceptance check: "PASS <id> <text>" or "FAIL <id> <text>: <detail>"; exits 1 on any failure.
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ["PORCH_URL"]
MGMT = os.environ["PORCH_MGMT"]
failures = 0


def check(cid, text, ok, detail=""):
    global failures
    if ok:
        print(f"PASS {cid} {text}")
    else:
        failures += 1
        print(f"FAIL {cid} {text}: {detail}")


def call(method, path, body=None, token=None, cookie=None, csrf=None, expect=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + "/api/v1" + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if cookie:
        req.add_header("Cookie", "__Host-porch_session=" + cookie)
        req.add_header("Origin", BASE)
    if csrf:
        req.add_header("X-Porch-CSRF", csrf)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            status, headers = r.status, r.headers
    except urllib.error.HTTPError as e:
        raw, status, headers = e.read(), e.code, e.headers
    out = json.loads(raw) if raw else None
    if expect is not None and status != expect:
        raise SystemExit(f"{method} {path}: HTTP {status} (want {expect}): {raw[:300]!r}")
    return status, out, headers


# Owner via the CLI-issued setup token, then an installation automation token for everything else (Terraform-style).
st, me, hdr = call("POST", "/setup", {"token": os.environ["PORCH_SETUP_TOKEN"], "display_name": "Olga Owner",
                                      "email": "olga@example.com"}, expect=201)
cookie = [c.split("=", 1)[1].split(";")[0] for c in hdr.get_all("Set-Cookie") if c.startswith("__Host-porch_session=")][0]
csrf = me["csrf_token"]
_, tok, _ = call("POST", "/installation/automation-tokens", {"name": "acceptance", "role": "admin", "expires_in_days": 1},
                 cookie=cookie, csrf=csrf, expect=201)
T = tok["token"]
check("A01", "installation automation token issued once (porch_at_)", T.startswith("porch_at_"))

families = ["smith", "jones", "doe"]
users = {}
for fam in families:
    call("POST", "/tenants", {"slug": fam, "name": fam.title() + " family"}, token=T, expect=201)
    for who in ("parent", "kid"):
        _, u, _ = call("POST", "/users", {"display_name": f"{who.title()} {fam.title()}", "primary_email": f"{who}@{fam}.example"}, token=T, expect=201)
        call("POST", f"/tenants/{fam}/members", {"user_id": u["id"]}, token=T, expect=201)
        users[(fam, who)] = u["id"]
_, ts, _ = call("GET", "/tenants", token=T, expect=200)
check("A02", "three tenants with members", {t["slug"] for t in ts["items"]} >= set(families))

# A shared service: Jellyfin owned by smith, shared with jones only.
_, app, _ = call("POST", "/tenants/smith/applications", {"slug": "jellyfin", "name": "Jellyfin", "kind": "forward_auth",
                                                         "hosts": ["jellyfin.smith.example"]}, token=T, expect=201)
call("POST", f"/tenants/smith/applications/{app['id']}/shares", {"tenant": "jones"}, token=T, expect=204)


def decide(tenant, user, action, rtype, rid, ctx=None):
    body = {"user_id": user, "action": action, "resource": {"type": rtype, "id": rid}}
    if ctx:
        body["context"] = ctx
    return call("POST", f"/tenants/{tenant}/authz/check", body, token=T, expect=200)[1]


d1 = decide("smith", users[("jones", "kid")], "app:access", "app", app["id"])
d2 = decide("smith", users[("doe", "kid")], "app:access", "app", app["id"])
check("A03", "cross-tenant access only through an explicit share (jones yes, doe no)",
      d1["allowed"] and d1["trace"]["tenant_gate"]["via"] == "share:jones" and not d2["allowed"] and d2["reason"] == "tenant_gate",
      json.dumps([d1["reason"], d2["reason"]]))

# Roles, groups, a condition policy and the explain trace.
_, kids, _ = call("POST", "/tenants/smith/groups", {"slug": "kids", "name": "Kids"}, token=T, expect=201)
call("PUT", f"/tenants/smith/groups/kids/members/{users[('smith', 'kid')]}", token=T, expect=204)
_, pol, _ = call("POST", "/tenants/smith/policies", {"slug": "daytime", "name": "Daytime", "effect": "condition",
                                                      "expression": "context.hour >= 7 && context.hour < 21"}, token=T, expect=201)
_, res, _ = call("POST", "/tenants/smith/resources", {"type": "folder", "slug": "photos", "name": "Photos"}, token=T, expect=201)
_, role, _ = call("POST", "/tenants/smith/roles", {"slug": "viewer", "name": "Viewer", "permissions": ["folder:read"]}, token=T, expect=201)
_, asg, _ = call("POST", "/tenants/smith/assignments", {"subject_type": "group", "subject_id": kids["id"], "role_id": role["id"],
                                                         "scope_type": "resource", "scope_resource_type": "folder",
                                                         "scope_resource_id": res["id"], "condition_policy_id": pol["id"]},
                 token=T, expect=201)
kid = users[("smith", "kid")]
noon = decide("smith", kid, "folder:read", "folder", res["id"], {"hour": 12, "network": "external"})
night = decide("smith", kid, "folder:read", "folder", res["id"], {"hour": 23, "network": "external"})
check("A04", "explain trace: group grant with condition (allowed at noon, denied at night)",
      noon["allowed"] and not night["allowed"] and noon["trace"]["simulated"] and "kids" in noon["trace"]["groups"]
      and any(c.get("condition") for c in night["trace"]["candidates"]), json.dumps([noon["reason"], night["reason"]]))
call("DELETE", f"/tenants/smith/assignments/{asg['id']}", token=T, expect=204)
after = decide("smith", kid, "folder:read", "folder", res["id"], {"hour": 12, "network": "external"})
check("A05", "role removal takes effect immediately", not after["allowed"], after["reason"])

# Tenant automation tokens are limited to their tenant and permissions (delegation itself is covered by the e2e suite:
# a member with a family-admin role cannot assign Administrator).
_, ptok, _ = call("POST", "/tenants/doe/automation-tokens", {"name": "doe-groups", "permissions": ["group:manage"],
                                                              "expires_in_days": 1}, cookie=cookie, csrf=csrf, expect=201)
s1, _, _ = call("POST", "/tenants/doe/groups", {"slug": "parents", "name": "Parents"}, token=ptok["token"])
s2, _, _ = call("GET", "/tenants/doe/roles", token=ptok["token"])
s3, _, _ = call("GET", "/tenants/smith/groups", token=ptok["token"])
check("A06", "tenant automation token: allowed in its tenant/permission, refused elsewhere", (s1, s2, s3) == (201, 404, 404), str((s1, s2, s3)))

# Service account with client credentials.
_, sa, _ = call("POST", "/tenants/smith/service-accounts", {"slug": "media-sync", "name": "Media sync",
                                                            "audiences": ["https://jellyfin.smith.example"]}, token=T, expect=201)
import base64
import urllib.parse
req = urllib.request.Request(BASE + "/oauth2/token", data=urllib.parse.urlencode(
    {"grant_type": "client_credentials", "resource": "https://jellyfin.smith.example"}).encode(), method="POST")
req.add_header("Authorization", "Basic " + base64.b64encode(f"{sa['id']}:{sa['client_secret']}".encode()).decode())
req.add_header("Content-Type", "application/x-www-form-urlencoded")
with urllib.request.urlopen(req) as r:
    tr = json.loads(r.read())
check("A07", "service account obtains an audience-bound access token", tr.get("token_type", "").lower() == "bearer" and tr.get("access_token"))

# Idempotency: a retried create returns the stored response.
def idem(body, key):
    req = urllib.request.Request(BASE + "/api/v1/tenants/jones/groups", data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization", "Bearer " + T)
    req.add_header("Content-Type", "application/json")
    req.add_header("Idempotency-Key", key)
    with urllib.request.urlopen(req) as r:
        return r.status, r.headers.get("Idempotent-Replayed"), json.loads(r.read())
a = idem({"slug": "teens", "name": "Teens"}, "acc-1")
b = idem({"slug": "teens", "name": "Teens"}, "acc-1")
check("A08", "Idempotency-Key replays the stored response", a[0] == 201 and b[1] == "true" and a[2]["id"] == b[2]["id"])

# Events recorded in the outbox, health and metrics.
_, health, _ = call("GET", "/installation/health", token=T, expect=200)
check("A09", "domain events recorded in the outbox (relay to pulse configured separately)", health["outbox_pending"] > 0,
      str(health["outbox_pending"]))
check("A10", "system health reports ready storage and keyring", health["ready"] and health["storage"]["state"] == "ok" and health["keyring"])
with urllib.request.urlopen(MGMT + "/metrics") as r:
    metrics = r.read().decode()
want = ["porch_http_requests_total", "porch_authz_decisions_total", "porch_oidc_tokens_issued_total", "porch_store_tx_duration_seconds",
        "porch_ready 1", "porch_build_info"]
missing = [m for m in want if m not in metrics]
check("A11", "Prometheus /metrics on the management listener", not missing, ",".join(missing))
try:
    with urllib.request.urlopen(BASE + "/metrics") as r:  # the SPA answers unknown paths with index.html
        public_metrics = "porch_http_requests_total" in r.read().decode(errors="replace")
except urllib.error.HTTPError:
    public_metrics = False
check("A12", "metrics are not exposed on the public listener", not public_metrics)

_, audit, _ = call("GET", "/audit?action=automation_token.&limit=10", token=T, expect=200)
_, chain, _ = call("GET", "/installation/audit/verify", token=T, expect=200)
check("A13", "audit log records token issuance and the hash chain verifies", len(audit["items"]) >= 2 and chain["ok"],
      json.dumps(chain))
sys.exit(1 if failures else 0)
