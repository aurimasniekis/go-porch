#!/usr/bin/env python3
"""Bootstraps the Porch demo stack through the management API (stdlib only). Called by deploy/demo/up.sh.

Pattern adapted from test/conformance/bootstrap.py. Steps:
  1. POST /setup with the setup token -> owner "Demo Owner" and a short setup session (cookie + CSRF token).
  2. Enroll a backup login for the owner (handle "owner", random password, three demo answers) so the owner can sign in
     again later (Login -> backup login). Demo-only convenience; a real owner picks their own answers in the UI.
  3. Register the fake Google provider, tenant "smith" and a Workspace-domain JIT rule for smith.example.
  4. Register the demo OIDC app (confidential client) and a forward_auth app protecting whoami.localhost.

Porch is reached on 127.0.0.1:<port> (Caddy) with SNI/Host auth.localhost, and the certificate is verified against
Caddy's internal root (.state/ca/root.crt), so this does not depend on how the host resolves *.localhost.
Writes .state/demo-app.env, .state/owner.txt (0600) and .state/bootstrap.json; prints a summary on stdout.
"""

import argparse
import http.client
import json
import os
import secrets
import socket
import ssl
import sys

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--token", required=True)
ap.add_argument("--state", required=True, help="deploy/demo/.state")
ap.add_argument("--google-client-secret", required=True)
args = ap.parse_args()

port = args.port
origin = f"https://auth.localhost:{port}"
ctx = ssl.create_default_context(cafile=os.path.join(args.state, "ca", "root.crt"))
cookies: dict[str, str] = {}
csrf = ""


class Conn(http.client.HTTPSConnection):
    """HTTPS to 127.0.0.1 with SNI and certificate checks for the public host name."""

    def __init__(self, name: str):
        super().__init__(name, port, context=ctx, timeout=30)
        self._name = name

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", port), self.timeout)
        self.sock = ctx.wrap_socket(sock, server_hostname=self._name)


def call(method: str, path: str, body=None, ok_missing=False):
    global csrf
    conn = Conn("auth.localhost")
    headers = {"Host": f"auth.localhost:{port}", "Origin": origin, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if csrf:
        headers["X-Porch-CSRF"] = csrf
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    conn.request(method, "/api/v1" + path, body=None if body is None else json.dumps(body), headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    for name, value in resp.getheaders():
        if name.lower() == "set-cookie":
            k, _, rest = value.partition("=")
            cookies[k.strip()] = rest.split(";", 1)[0]
    if resp.status >= 300:
        msg = f"{method} {path} -> HTTP {resp.status}: {raw.decode(errors='replace')[:600]}"
        if ok_missing:
            print(f"bootstrap: WARNING: {msg}", file=sys.stderr)
            return None
        sys.exit(f"bootstrap: {msg}")
    return json.loads(raw) if raw else None


def write_private(name: str, content: str):
    path = os.path.join(args.state, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)


summary = {"issuer": origin}

me = call("POST", "/setup", {"token": args.token, "display_name": "Demo Owner", "email": "owner@demo.localhost"})
csrf = me["csrf_token"]
summary["owner_user_id"] = me.get("user_id")

# Backup login for the owner (the setup session is fresh, so step-up passes).
password = "Demo-" + secrets.token_urlsafe(18)
pairs = [
    {"title": "Demo question 1", "answer": "porch demo river"},
    {"title": "Demo question 2", "answer": "porch demo lantern"},
    {"title": "Demo question 3", "answer": "porch demo orchard"},
]
if call("PUT", "/me/backup-credential", {"password": password, "pairs": pairs, "confirm": [p["answer"] for p in pairs]},
        ok_missing=True) is not None:
    call("PUT", "/me/backup-handle", {"handle": "owner"}, ok_missing=True)
    write_private("owner.txt", "Porch demo owner backup login (DEMO ONLY)\n"
                  f"  1. Open {origin}/login and use the backup login form (not \"Continue with Google\").\n"
                  "  2. Backup handle or email:  owner      (the handle; the email no longer works once a handle is set)\n"
                  f"     Password:                 {password}\n"
                  "  3. Porch then shows three questions. Type the answer next to each title:\n"
                  + "".join(f"       {p['title']}  ->  {p['answer']}\n" for p in pairs)
                  + "  A wrong password or answer locks the backup login for 6 hours (Google sign-in still works). To unlock:\n"
                  "    cd deploy/demo && docker compose stop porch && \\\n"
                  "    docker compose run --rm porch-init admin unlock-backup -user owner@demo.localhost && docker compose start porch\n")
    summary["owner_backup_login"] = True
else:
    summary["owner_backup_login"] = False

prov = call("POST", "/identity-providers", {
    "slug": "google", "kind": "google", "name": "Google (fake, demo)",
    "issuer": f"https://google.localhost:{port}", "client_id": "porch", "client_secret": args.google_client_secret})
call("POST", "/tenants", {"slug": "smith", "name": "Smith family"})
call("POST", "/tenants/smith/domain-rules", {"domain": "smith.example", "provider_id": prov["id"],
                                             "evidence_kind": "workspace_hd", "mode": "jit"})

demo = f"https://demo.localhost:{port}"
app = call("POST", "/tenants/smith/applications", {
    "slug": "demo-app", "name": "Demo app", "kind": "oidc", "launch_url": demo + "/",
    "client": {"client_type": "confidential", "redirect_uris": [demo + "/callback"],
               "post_logout_redirect_uris": [demo + "/"], "grant_types": ["authorization_code", "refresh_token"],
               "audiences": ["https://api.smith.example"]},
    "disclosure": {"email": True, "groups": True, "roles": True, "entitlements": False},
})
write_private("demo-app.env", f"DEMO_CLIENT_ID={app['client']['client_id']}\nDEMO_CLIENT_SECRET={app['client_secret']}\n")
summary["demo_app_client_id"] = app["client"]["client_id"]

# Forward-auth (being implemented in M4): register whoami.localhost; a failure is reported but not fatal.
fwd = call("POST", "/tenants/smith/applications", {
    "slug": "whoami", "name": "whoami (forward-auth)", "kind": "forward_auth",
    "launch_url": f"https://whoami.localhost:{port}/", "hosts": ["whoami.localhost"],
}, ok_missing=True)
summary["forward_auth_app"] = bool(fwd)

with open(os.path.join(args.state, "bootstrap.json"), "w") as f:
    json.dump(summary, f, indent=2)
json.dump(summary, sys.stdout)
print()
