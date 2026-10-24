#!/usr/bin/env python3
"""Runs OpenID conformance suite test plans through the suite's REST API (stdlib only) and summarises the results.

A small, dependency-free stand-in for the suite's scripts/run-test-plan.py: creates each plan, runs its modules one
by one (the config uses an alias, so they cannot run in parallel), waits for each to finish, then collects the
result and every FAILURE/WARNING log entry. Writes a JSON result file and prints a summary; exits 1 when any module
FAILED or did not finish.

usage: run_plans.py --suite https://127.0.0.1:PORT/ --config CONFIG.json --out results.json \
           PLAN[VARIANT_JSON] [PLAN[VARIANT_JSON] ...]
"""

import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--suite", required=True)
ap.add_argument("--config", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--module-timeout", type=int, default=300)
ap.add_argument("--only", default="", help="comma-separated module names to run (default: all)")
ap.add_argument("--pace", type=float, default=4.0,
                help="seconds to wait before each module: Porch rate-limits sign-in starts per source IP (burst 10, "
                     "30/min) and every suite request comes from the one suite container")
ap.add_argument("plans", nargs="+", help='plan name, optionally followed by a JSON variant: name{"k":"v"}')
args = ap.parse_args()
base = args.suite.rstrip("/") + "/"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # the suite's nginx uses a self-signed certificate


def api(method, path, params=None, body=None, timeout=60):
    url = base + "api/" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = None if body is None else body.encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json",
                                                                         "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def wait_state(mid, states, timeout):
    deadline = time.time() + timeout
    want = ",".join(states + ["INTERRUPTED"])
    while time.time() < deadline:
        ms = int(min(30, deadline - time.time()) * 1000)
        if ms <= 0:
            break
        st, body = api("GET", f"runner/{mid}/wait-state", {"states": want, "timeoutMs": ms}, timeout=ms / 1000 + 15)
        if st == 200 and isinstance(body, dict) and body.get("state"):
            return body["state"]
        if st == 404:  # finished tests leave the in-memory runner map
            st, info = api("GET", f"info/{mid}")
            if st == 200 and info.get("status") in states + ["INTERRUPTED"]:
                return info["status"]
    st, info = api("GET", f"info/{mid}")
    return info.get("status") if st == 200 else None


def problems(mid):
    st, log = api("GET", f"log/{mid}")
    out = []
    if st != 200:
        return out
    for e in log:
        if e.get("result") in ("FAILURE", "WARNING"):
            out.append({"result": e["result"], "src": e.get("src"), "msg": e.get("msg"),
                        "requirements": e.get("requirements")})
    return out


def run_plan(name, variant, config):
    params = {"planName": name}
    if variant:
        params["variant"] = json.dumps(variant)
    st, plan = api("POST", "plan", params, config)
    if st != 201:
        sys.exit(f"create plan {name}: HTTP {st} {plan}")
    print(f"\n== {name} {json.dumps(variant) if variant else ''}  plan {plan['id']}")
    print(f"   {base}plan-detail.html?plan={plan['id']}")
    results = []
    only = {m for m in args.only.split(",") if m}
    for mod in plan["modules"]:
        tm = mod["testModule"]
        if only and tm not in only:
            continue
        mv = mod.get("variant")
        time.sleep(args.pace)
        p = {"test": tm, "plan": plan["id"]}
        if mv:
            p["variant"] = json.dumps(mv)
        st, created = api("POST", "runner", p)
        if st != 201:
            results.append({"module": tm, "variant": mv, "status": "NOT_CREATED", "result": None,
                            "problems": [{"result": "FAILURE", "src": "run_plans.py", "msg": f"HTTP {st}: {created}"}]})
            print(f"   {tm:<70} NOT CREATED ({st})")
            continue
        mid = created["id"]
        t0 = time.time()
        state = wait_state(mid, ["CONFIGURED", "WAITING", "FINISHED"], 60)
        if state == "CONFIGURED":
            if tm == "oidcc-server-rotate-keys":
                api("POST", f"runner/{mid}")
            state = wait_state(mid, ["WAITING", "FINISHED"], 60)
        if state == "WAITING":
            state = wait_state(mid, ["FINISHED"], args.module_timeout)
        st, info = api("GET", f"info/{mid}")
        status = info.get("status") if st == 200 else state
        result = info.get("result") if st == 200 else None
        if status not in ("FINISHED", "INTERRUPTED"):
            api("DELETE", f"runner/{mid}")  # stuck (usually waiting for a screenshot upload): stop it
        r = {"module": tm, "variant": mv, "id": mid, "status": status, "result": result,
             "seconds": round(time.time() - t0, 1), "problems": problems(mid)}
        results.append(r)
        print(f"   {tm:<70} {status:<11} {result}  ({r['seconds']}s)", flush=True)
    return {"plan": name, "variant": variant, "plan_id": plan["id"], "modules": results}


config = open(args.config).read()
st, _ = api("GET", "runner/available")
if st != 200:
    sys.exit(f"suite API not available: HTTP {st}")
out = []
for spec in args.plans:
    name, _, v = spec.partition("{")
    out.append(run_plan(name, json.loads("{" + v) if v else None, config))
with open(args.out, "w") as f:
    json.dump(out, f, indent=2)

bad = 0
print("\n== Summary")
for p in out:
    counts = {}
    for m in p["modules"]:
        key = m["result"] or m["status"]
        counts[key] = counts.get(key, 0) + 1
        if m["result"] in (None, "FAILED") or m["status"] != "FINISHED":
            bad += 1
    print(f"   {p['plan']}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
sys.exit(1 if bad else 0)
