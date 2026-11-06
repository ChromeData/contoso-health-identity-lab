#!/usr/bin/env bash
# canary.sh - prove the RBAC linter still DETECTS, in every input shape it meets.
#
# WHY: unit tests feed the linter inputs the author chose. Twice in the earlier
# lab the linter said "No risky RBAC found" on a cluster full of planted
# escalation because the input came in a shape no test used: first the
# `kubectl -o json` "List" wrapper, then (found while porting, 2026-11-06) the
# raw API's typed "ClusterRoleList", whose items carry no kind. So this runs
# the linter on its own positive control (fixtures/risky-rbac.yaml) in all
# three shapes, and on the negative control (fixtures/clean-rbac.yaml), and
# fails if any answer is wrong.
#
# Exit codes it relies on (rbac_lint.py): 1 = findings, 0 = clean, 2 = could
# not run. Only exit 1 counts as a detection. The earlier canary also
# treated exit 1 as a detection, but that linter exited 1 on a missing file
# (sys.exit("error: ...")), so a canary pointed at the wrong path passed.
# The last check below pins that: a missing file must exit 2.
#
# Needs python3 + PyYAML only. Run: bash lab/k8s/rbac-lint/canary.sh

set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lint=(python3 -I "$here/rbac_lint.py")
risky="$here/fixtures/risky-rbac.yaml"
clean="$here/fixtures/clean-rbac.yaml"

fail=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Every planted role must be caught for its own risk, not just "some
# findings": lab-wildcard alone trips every risk id, so an exit code (or the
# set of risk ids) would still pass if every other planted role were missed.
# "[risk] Kind/name" as rbac_lint.py prints it; the namespaced Role is
# absent from the ClusterRoleList shape, which holds ClusterRoles only.
CLUSTER_PAIRS=(
  "escalate|ClusterRole/lab-escalate"
  "bind|ClusterRole/lab-bind"
  "secrets-read|ClusterRole/lab-secret-reader"
  "wildcard-all|ClusterRole/lab-wildcard"
  "impersonate|ClusterRole/lab-wildcard"
  "token-create|ClusterRole/lab-wildcard"
)
ROLE_PAIRS=("pods-create|Role/app/lab-pod-creator")

expect() {  # expect <label> <wanted exit code> <file> [risk|Kind/name ...]
  local label="$1" want="$2" target="$3" out rc pair missing=()
  shift 3
  out="$("${lint[@]}" "$target" 2>&1)"
  rc=$?
  for pair in "$@"; do
    grep -qE "^  \[${pair%%|*} +\] ${pair#*|}:" <<<"$out" || missing+=("$pair")
  done
  if [[ $rc -eq $want && ${#missing[@]} -eq 0 ]]; then
    echo "  OK    $label: exit $rc ($(echo "$out" | grep -E 'risky RBAC rule|No risky|^error' | head -1))${*:+, all $# planted pairs found}"
  else
    echo "  FAIL  $label: exit $rc, wanted $want${missing[*]:+; missing: ${missing[*]}}"
    echo "$out" | sed 's/^/        /'
    fail=1
  fi
}

# Shapes 2 and 3 are built from the fixture so they can never drift from it.
python3 -I - "$risky" "$work/list.json" "$work/typed.json" <<'PY' || { echo "  FAIL  could not build the wrapped inputs"; exit 1; }
import json, sys
import yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
# kubectl get ... -o json: kind List, every item keeps its kind.
json.dump({"kind": "List", "apiVersion": "v1", "items": docs}, open(sys.argv[2], "w"))
# The API itself (kubectl get --raw /apis/rbac.authorization.k8s.io/v1/clusterroles):
# kind ClusterRoleList, items WITHOUT kind or apiVersion (seen on k3s v1.31.4).
roles = [{k: v for k, v in d.items() if k not in ("kind", "apiVersion")}
         for d in docs if d.get("kind") == "ClusterRole"]
json.dump({"kind": "ClusterRoleList", "apiVersion": "rbac.authorization.k8s.io/v1",
           "items": roles}, open(sys.argv[3], "w"))
print(f"  built: List of {len(docs)} objects, ClusterRoleList of {len(roles)} kind-less items")
PY

echo "==> positive control: must find the planted escalation (exit 1)"
expect "risky-rbac.yaml as written"            1 "$risky"           "${CLUSTER_PAIRS[@]}" "${ROLE_PAIRS[@]}"
expect "kubectl -o json List wrapper"          1 "$work/list.json"  "${CLUSTER_PAIRS[@]}" "${ROLE_PAIRS[@]}"
expect "raw API ClusterRoleList (no item kind)" 1 "$work/typed.json" "${CLUSTER_PAIRS[@]}"
echo "==> negative control: the lab's own human roles must be clean (exit 0)"
expect "clean-rbac.yaml"                       0 "$clean"
echo "==> a missing input must be 'could not run' (exit 2), never a detection"
expect "missing file"                          2 "$work/does-not-exist.yaml"

echo
if [[ $fail -eq 0 ]]; then
  echo "CANARY PASSED: detects in all three shapes, quiet on the clean roles, fails closed."
else
  echo "CANARY FAILED"
  exit 1
fi
