#!/usr/bin/env python3
"""Renders run_plans.py's JSON results as Markdown: per-plan counts, then every module with its result and the
suite's FAILURE/WARNING messages. Contains no secrets (client credentials are never part of the results)."""

import argparse
import datetime
import json

ap = argparse.ArgumentParser()
ap.add_argument("results")
ap.add_argument("--suite-version", default="?")
ap.add_argument("--porch-version", default="?")
ap.add_argument("--date", default=datetime.date.today().isoformat())
args = ap.parse_args()
plans = json.load(open(args.results))

ORDER = ["PASSED", "WARNING", "REVIEW", "SKIPPED", "FAILED", "UNFINISHED"]


def outcome(m):
    if m["status"] != "FINISHED" or not m["result"]:
        return "FAILED" if m["result"] == "FAILED" else "UNFINISHED"
    return m["result"]


print(f"# Conformance results {args.date}\n")
print(f"- Porch: `{args.porch_version}` (development mode, native TLS, behind the test front proxy)")
print(f"- Conformance suite: `{args.suite_version}` (registry.gitlab.com/openid/conformance-suite)")
print("- Driver: `test/conformance/run.sh` → `run_plans.py`\n")
print("| Plan | Variant | " + " | ".join(ORDER) + " |")
print("|---|---|" + "---|" * len(ORDER))
for p in plans:
    counts = {k: 0 for k in ORDER}
    for m in p["modules"]:
        counts[outcome(m)] += 1
    v = ", ".join(f"{k}={val}" for k, val in (p["variant"] or {}).items()) or "(fixed)"
    print(f"| {p['plan']} | {v} | " + " | ".join(str(counts[k]) for k in ORDER) + " |")
for p in plans:
    print(f"\n## {p['plan']}\n")
    print("| Module | Variant | Status | Result |")
    print("|---|---|---|---|")
    for m in p["modules"]:
        v = ", ".join(f"{k}={val}" for k, val in (m.get("variant") or {}).items())
        print(f"| `{m['module']}` | {v} | {m['status']} | {m['result'] or '-'} |")
    details = [m for m in p["modules"] if m["problems"]]
    if details:
        print("\n### Failures and warnings reported by the suite\n")
        for m in details:
            print(f"- `{m['module']}` ({m['result'] or m['status']})")
            seen = set()
            for x in m["problems"]:
                key = (x["result"], x["src"], x["msg"])
                if key in seen:
                    continue
                seen.add(key)
                msg = (x["msg"] or "").replace("\n", " ")
                print(f"  - {x['result']} `{x['src']}`: {msg}")
