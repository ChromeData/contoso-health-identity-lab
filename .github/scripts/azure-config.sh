#!/usr/bin/env bash
# =============================================================================
# azure-config.sh  -  is this repository wired to a real Azure / Entra tenant?
# -----------------------------------------------------------------------------
# Three jobs need the GitHub OIDC -> Entra federation: terraform plan
# (terraform-plan.yml), terraform apply (terraform-apply.yml) and the AI review
# (ai-review.yml). They all ask this script first, so that:
#   - a repository with NO Azure variables (this public copy: no tenant is
#     wired, so nothing here has run against one) shows those jobs as SKIPPED,
#     with a notice saying why, instead of a red X from azure/login; and
#   - a repository that IS wired keeps failing closed: once any variable of a
#     lane is set, the lane runs, and its first step refuses to go on unless
#     every variable it needs is set (never a login with partial settings).
#
# Usage
#   azure-config.sh gate <lane> <VAR>...
#       Writes run=true or run=false to $GITHUB_OUTPUT (stdout outside
#       Actions). run=false ONLY when every listed variable is empty and no
#       override below applies; then it also prints a ::notice:: and a line in
#       the job summary. A skipped job reports "Success", so it still
#       satisfies a required check (GitHub Docs, "Using conditions to control
#       job execution"); that is exactly why the overrides fail closed.
#   azure-config.sh require <lane> <VAR>...
#       Exit 1 with one ::error:: naming every missing variable, unless all of
#       them are set. The gated job runs this before azure/login.
#
# Overrides that force run=true in `gate` (fail closed):
#   AZURE_GATE_FORCE_RUN   any non-empty reason, e.g. "fork PR". GitHub's docs
#                          do not say whether a fork's (or Dependabot's)
#                          pull_request run receives this repository's
#                          variables, so an empty value there proves nothing.
#   AZURE_GATE_MARKER_REF  a commit, normally the PR's BASE (a PR cannot edit
#                          its base). If that commit contains
#                          .github/azure-lane.enabled, the lane runs whatever
#                          the variables look like. Commit that file in the
#                          PR that wires the tenant: Dependabot runs then
#                          plan (or fail) even if they cannot see variables.
#                          A commit that is not available locally also forces
#                          run=true.
#
# Values arrive as environment variables named exactly like the repository
# variables (the workflow maps ${{ vars.X }} to env X). They are identifiers,
# not secrets, but this script still prints NAMES only, never a value.
# Runs on GitHub's bash and on macOS bash 3.2.
# =============================================================================
set -euo pipefail

MARKER_PATH=".github/azure-lane.enabled"

usage() {
  echo "usage: ${0##*/} gate|require <lane> <VAR>..." >&2
  exit 2
}

[ "$#" -ge 3 ] || usage
mode=$1
lane=$2
shift 2
case $mode in gate|require) ;; *) usage ;; esac
case $lane in ''|*[!A-Za-z0-9_.-]*) echo "::error::azure-config: bad lane name" >&2; exit 2 ;; esac

out() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then printf '%s\n' "$1" >> "$GITHUB_OUTPUT"; else printf '%s\n' "$1"; fi
}
summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"; fi
}

set_names=""
unset_names=""
for name in "$@"; do
  case $name in
    ''|[0-9]*|*[!A-Za-z0-9_]*) echo "::error::azure-config: bad variable name '$name'" >&2; exit 2 ;;
  esac
  # ${!name} is the value of the variable whose NAME is in $name.
  if [ -n "${!name:-}" ]; then set_names="$set_names $name"; else unset_names="$unset_names $name"; fi
done
set_names=${set_names# }
unset_names=${unset_names# }

if [ "$mode" = require ]; then
  if [ -n "$unset_names" ]; then
    echo "::error title=${lane}: Azure configuration incomplete::Missing repository variable(s): ${unset_names}. Set all of them (lab/pipelines/README.md, section D) or none; this job never signs in with a partial configuration."
    exit 1
  fi
  echo "azure-config[$lane]: all $# required variables are set"
  exit 0
fi

# ---- gate -------------------------------------------------------------------
reason=""
if [ -n "${AZURE_GATE_FORCE_RUN:-}" ]; then
  reason="forced: ${AZURE_GATE_FORCE_RUN}"
elif [ -n "${AZURE_GATE_MARKER_REF:-}" ]; then
  if ! git cat-file -e "${AZURE_GATE_MARKER_REF}^{commit}" 2>/dev/null; then
    echo "::warning::azure-config[$lane]: base commit ${AZURE_GATE_MARKER_REF} is not available here; failing closed (run=true)"
    reason="base commit not available (fail closed)"
  elif git cat-file -e "${AZURE_GATE_MARKER_REF}:${MARKER_PATH}" 2>/dev/null; then
    reason="${MARKER_PATH} is committed on the base branch"
  fi
fi
if [ -z "$reason" ] && [ -n "$set_names" ]; then
  reason="configured (set: ${set_names})"
fi

if [ -n "$reason" ]; then
  echo "azure-config[$lane]: run=true (${reason})"
  out "run=true"
  exit 0
fi

msg="No Azure tenant is wired to this repository: none of ${unset_names} is set, so the ${lane} job is skipped instead of failing at azure/login. The credential-free checks (lab-tests, Checkov, TruffleHog, the kind pipeline) are separate jobs and are not affected. Setting these repository variables (lab/pipelines/README.md, section D) turns the job on, and it then fails closed if any of them is missing."
echo "::notice title=${lane} skipped: no Azure tenant wired::${msg}"
summary "### ${lane}: skipped (no Azure tenant wired)" "" "${msg}"
out "run=false"
