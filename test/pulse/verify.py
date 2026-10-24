#!/usr/bin/env python3
"""Drives test/pulse/verify.sh: prepares a throwaway pulsed for Porch's event relay, then checks what arrived.

  verify.py pulse-setup  ADMIN_URL PULSED_CMD WORKDIR   bootstrap an administrator (password + TOTP), save the NATS CA
                                                         and issue a publish-only client for evt.porch.> (.creds)
  verify.py porch-setup  PORCH_URL SETUP_TOKEN WORKDIR   create the Porch owner, then a tenant and a member so the
                                                         outbox gets tenancy/identity events; saves expected IDs
  verify.py check        ADMIN_URL WORKDIR [--min N]     wait until pulsed shows the events and verify subject, type,
                                                         source and event ID; prints one line per event
  verify.py porch-change PORCH_URL WORKDIR SLUG          create one more tenant with the saved owner session
  verify.py wait-for     ADMIN_URL WORKDIR SLUG          wait until that tenant's tenant.created event is in pulsed
  verify.py count        ADMIN_URL WORKDIR               number of evt.porch.> events in pulsed

TEST ONLY. Stdlib only. Everything it creates is throwaway; never point it at a real pulsed or Porch.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class Client:
    """A JSON client that keeps cookies itself (Secure cookies over http://localhost, which urllib's jar would not
    send) and sends Origin, which both pulsed and Porch check on mutations. cookie_file persists the cookies."""

    def __init__(self, base, csrf_header, cookie_file=None):
        self.base = base.rstrip("/")
        self.csrf_header = csrf_header
        self.csrf = ""
        self.cookie_file = cookie_file
        self.cookies = json.load(open(cookie_file)) if cookie_file and os.path.exists(cookie_file) else {}

    def call(self, method, path, body=None, ok=(200, 201, 204)):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Origin", self.base)
        req.add_header("Content-Type", "application/json")
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        if self.csrf:
            req.add_header(self.csrf_header, self.csrf)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, raw, headers = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e:
            status, raw, headers = e.code, e.read(), e.headers
        for sc in headers.get_all("Set-Cookie") or []:
            name, _, rest = sc.partition("=")
            value = rest.split(";", 1)[0]
            if value and "max-age=0" not in sc.lower() and "max-age=-1" not in sc.lower():
                self.cookies[name.strip()] = value
            else:
                self.cookies.pop(name.strip(), None)
        if self.cookie_file:
            with open(self.cookie_file, "w", opener=lambda p, f: os.open(p, f, 0o600)) as f:
                json.dump(self.cookies, f)
        out = json.loads(raw) if raw else {}
        if status not in ok:
            raise SystemExit(f"{method} {path}: {status} {raw[:400]!r}")
        return out


def totp(secret, at=None):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((at or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def next_step():
    time.sleep(30 - time.time() % 30 + 0.5)


def pulse_admin(admin_url, work):
    """Signs in with the administrator saved by pulse-setup (password, then TOTP)."""
    saved = json.load(open(os.path.join(work, "pulse-admin.json")))
    c = Client(admin_url, "X-Pulse-CSRF")
    me = c.call("POST", "/api/admin/v1/auth/login", {"email": saved["email"], "password": saved["password"]})["me"]
    c.csrf = me["csrf_token"]
    if c.call("GET", "/api/admin/v1/auth/me").get("mfa_pending"):
        try:
            me = c.call("POST", "/api/admin/v1/auth/mfa", {"code": totp(saved["totp"])})
        except SystemExit:
            next_step()  # this step's code was used already
            me = c.call("POST", "/api/admin/v1/auth/mfa", {"code": totp(saved["totp"])})
        c.csrf = me.get("csrf_token", c.csrf)
    return c


def pulse_setup(admin_url, pulsed_cmd, work):
    out = subprocess.run(pulsed_cmd.split() + ["admin", "bootstrap"], capture_output=True, text=True, check=True).stdout
    token = next(w for line in out.splitlines() if "token:" in line for w in [line.split("token:")[1].strip()])
    email, password = "porch-relay-check@example.com", base64.urlsafe_b64encode(os.urandom(18)).decode()
    c = Client(admin_url, "X-Pulse-CSRF")
    c.call("POST", "/api/admin/v1/auth/setup", {"token": token, "email": email, "display_name": "Relay check", "password": password})
    me = c.call("POST", "/api/admin/v1/auth/login", {"email": email, "password": password})["me"]
    c.csrf = me["csrf_token"]
    secret = c.call("POST", "/api/admin/v1/account/totp/begin")["secret"]
    c.call("POST", "/api/admin/v1/account/totp/confirm", {"code": totp(secret)})
    with open(os.path.join(work, "pulse-admin.json"), "w", opener=lambda p, f: os.open(p, f, 0o600)) as f:
        json.dump({"email": email, "password": password, "totp": secret}, f)
    next_step()  # the confirm code may not be reused for the second factor
    c = pulse_admin(admin_url, work)
    info = c.call("GET", "/api/admin/v1/system/info")
    open(os.path.join(work, "pulse-ca.pem"), "w").write(info["connect"]["ca_cert"])
    issued = c.call("POST", "/api/admin/v1/clients", {"name": "porch", "description": "Porch event relay (throwaway check)",
                                                      "grants": [{"action": "publish", "subject": "evt.porch.>"}]})
    with open(os.path.join(work, "porch.creds"), "w", opener=lambda p, f: os.open(p, f, 0o600)) as f:
        f.write(issued["creds"])
    print(f"pulsed: administrator {email}, client {issued['client'].get('name')} (publish evt.porch.>)")


def porch_client(porch_url, work):
    """The owner's setup session, kept in WORKDIR between commands (it lasts an hour)."""
    c = Client(porch_url, "X-Porch-CSRF", os.path.join(work, "porch-cookies.json"))
    c.csrf = c.call("GET", "/api/v1/me")["csrf_token"]
    return c


def porch_setup(porch_url, setup_token, work):
    c = Client(porch_url, "X-Porch-CSRF", os.path.join(work, "porch-cookies.json"))
    me = c.call("POST", "/api/v1/setup", {"token": setup_token, "display_name": "Relay owner"})
    c.csrf = me["csrf_token"]
    tenant = c.call("POST", "/api/v1/tenants", {"slug": "relay", "name": "Relay family"})
    user = c.call("POST", "/api/v1/users", {"display_name": "Rita Relay", "primary_email": "rita@relay.example"})
    c.call("POST", "/api/v1/tenants/relay/members", {"user_id": user["id"]})
    json.dump({"tenant_id": tenant["id"], "user_id": user["id"]}, open(os.path.join(work, "porch-objects.json"), "w"))
    print(f"porch: tenant relay ({tenant['id']}), user {user['id']} added as member")


def porch_change(porch_url, work, slug):
    """One more tenant; succeeds whether or not pulse is reachable."""
    t = porch_client(porch_url, work).call("POST", "/api/v1/tenants", {"slug": slug, "name": f"Tenant {slug}"})
    print(f"porch: tenant {slug} ({t['id']}) created")
    print(t["id"], file=open(os.path.join(work, f"tenant-{slug}.id"), "w"))


def wait_for(admin_url, work, tenant_id):
    deadline = time.time() + 120
    while time.time() < deadline:
        for e in porch_events(admin_url, work):
            if e["subject"] == "evt.porch.tenancy.tenant.created" and tenant_id in event_data(e):
                print(f"  seq {e['seq']:>3}  {e['subject']} for {tenant_id} arrived (id={e['id']})")
                return
        time.sleep(3)
    raise SystemExit(f"tenant.created for {tenant_id} never reached pulsed")


def event_data(e):
    d = e.get("data")
    if e.get("encoding") == "base64" and isinstance(d, str):
        return base64.b64decode(d).decode(errors="replace")
    return d if isinstance(d, str) else json.dumps(d)


def porch_events(admin_url, work):
    c = pulse_admin(admin_url, work)
    q = urllib.parse.urlencode({"subject": "evt.porch.>", "limit": 100})
    return c.call("GET", f"/api/admin/v1/events?{q}").get("events") or []


def check(admin_url, work, minimum):
    objs = json.load(open(os.path.join(work, "porch-objects.json")))
    want = {"evt.porch.tenancy.tenant.created", "evt.porch.identity.user.created", "evt.porch.tenancy.membership.created"}
    deadline, evs = time.time() + 90, []
    while time.time() < deadline:
        evs = porch_events(admin_url, work)
        if want <= {e["subject"] for e in evs} and len(evs) >= minimum:
            break
        time.sleep(3)
    subjects = {e["subject"] for e in evs}
    if not want <= subjects:
        raise SystemExit(f"missing in pulsed: {sorted(want - subjects)} (got {sorted(subjects)})")
    ids = [e["id"] for e in evs]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"duplicate event IDs in pulsed: {ids}")
    for e in evs:
        typ, src = e.get("type") or "", e.get("source") or ""
        area, entity, action = e["subject"].removeprefix("evt.porch.").split(".")
        expect_type = f"porch.{area}.{entity}_{action}.v1"
        if typ != expect_type or src != "porch" or not e.get("id"):
            raise SystemExit(f"unexpected envelope: {json.dumps(e)[:400]}")
        print(f"  seq {e['seq']:>3}  {e['subject']:<45} type={typ} source={src} id={e['id']}")
    data = " ".join(event_data(e) for e in evs)
    for k in ("tenant_id", "user_id"):
        if objs[k] not in data:
            raise SystemExit(f"{k} {objs[k]} not found in any event payload")
    print(f"pulsed has {len(evs)} Porch events with unique IDs; payloads name the created tenant and user")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "pulse-setup":
        pulse_setup(*args)
    elif cmd == "porch-setup":
        porch_setup(*args)
    elif cmd == "check":
        minimum = int(args[args.index("--min") + 1]) if "--min" in args else 0
        check(args[0], args[1], minimum)
    elif cmd == "porch-change":
        porch_change(*args)
    elif cmd == "wait-for":
        wait_for(args[0], args[1], open(os.path.join(args[1], f"tenant-{args[2]}.id")).read().strip())
    elif cmd == "count":
        print(len(porch_events(*args)))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
