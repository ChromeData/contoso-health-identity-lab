#!/usr/bin/env bash
# =============================================================================
# plan-changeset.sh - the "change set" of a Terraform plan: one line per
# resource the plan would change, "<actions> <address>", sorted.
#
#   terraform show -json tfplan > "$RUNNER_TEMP/plan.json"
#   .github/scripts/plan-changeset.sh "$RUNNER_TEMP/plan.json" > changeset.txt
#
# Why: the PR plan comment (terraform-plan.yml) and the apply run
# (terraform-apply.yml) both print this list and its sha256. The apply gate
# refuses to apply when the saved plan's list differs from the one the PR
# reviewer saw (karen-review A2: drift from portal edits, other merges or
# repository variables changed outside a PR must not be applied unseen).
#
# Prints ADDRESSES and ACTIONS only, never an attribute value. The plan JSON
# holds every variable in clear text: callers keep it in RUNNER_TEMP and
# delete it. No-op and read-only (data source) entries are left out, so an
# empty output means "No changes". Exit non-zero (nothing on stdout) when the
# file is not a plan: callers treat that as a failure, never as "no changes".
# =============================================================================
set -euo pipefail
plan_json="${1:?usage: plan-changeset.sh <plan.json>}"
jq -e 'has("resource_changes") or has("format_version")' "$plan_json" >/dev/null
jq -r '[ (.resource_changes // [])[]
         | select(.change.actions != ["no-op"] and .change.actions != ["read"])
         | "\(.change.actions | join("+")) \(.address)" ]
       | sort | .[]' "$plan_json"
