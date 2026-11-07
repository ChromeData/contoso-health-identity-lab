#!/usr/bin/env python3
"""plan-fingerprint.py - one sha256 for everything a Terraform plan would change.

    terraform show -json tfplan > "$RUNNER_TEMP/plan.json"
    python3 -I .github/scripts/plan-fingerprint.py "$RUNNER_TEMP/plan.json"

Why: since the repo is public, the human gate is GitHub's Environment
"production" (required reviewer, "Prevent self-review"). GitHub asks for that
approval before a job starts, so the approval sits in its own job, between a
"plan for review" job and the apply job. The saved plan file cannot travel
between jobs: it holds every variable value in clear text, and an artifact on
a public repo is downloadable by any signed-in GitHub user. So the apply job
plans again and applies only when its plan has the SAME fingerprint as the
plan the owner reviewed.

The fingerprint covers, per changed resource (sorted by address): address,
actions, before, after, after_unknown, the sensitivity masks and
replace_paths; plus output_changes. So a different value, not only a
different resource list, changes it. Resources with action "no-op" or "read"
are left out (they change nothing). prior_state, timestamps and Terraform
version are left out, so two plans of the same code against the same state
give the same fingerprint.

Prints only the hex digest (a hash; no value can be read back from it).
"""

import hashlib
import json
import sys


def fingerprint(plan: dict) -> str:
    rows = []
    for rc in plan.get("resource_changes") or []:
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if actions in (["no-op"], ["read"]):
            continue
        rows.append({
            "address": rc.get("address"),
            "actions": actions,
            "before": ch.get("before"),
            "after": ch.get("after"),
            "after_unknown": ch.get("after_unknown"),
            "before_sensitive": ch.get("before_sensitive"),
            "after_sensitive": ch.get("after_sensitive"),
            "replace_paths": ch.get("replace_paths"),
        })
    rows.sort(key=lambda r: r["address"] or "")
    outputs = {k: v for k, v in sorted((plan.get("output_changes") or {}).items())
               if (v or {}).get("actions") not in (["no-op"],)}
    blob = json.dumps({"resources": rows, "outputs": outputs}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: plan-fingerprint.py <plan.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1]) as f:
        print(fingerprint(json.load(f)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
