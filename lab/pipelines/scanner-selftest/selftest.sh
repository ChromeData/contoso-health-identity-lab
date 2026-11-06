#!/usr/bin/env bash
# =============================================================================
# selftest.sh - positive control for the merge gate's two scanners.
# -----------------------------------------------------------------------------
# WHY: a security scanner that never fails proves nothing. It may be reading
# nothing (wrong folder, a parser that skips the file, a config that
# suppresses the rule) and still print a confident green. ADR 0026: a green
# result is evidence only once the same check has been SEEN TO FAIL.
#
# WHAT: the gate in terraform-plan.yml runs Checkov (IaC misconfigurations)
# and TruffleHog (secrets). This script runs the same two scanners, in the
# same versions, on two fixtures:
#   fixtures/bad   deliberately unsafe: RDP and SSH open to the internet,
#                  plus a private key GENERATED here at run time into a
#                  temporary copy. BOTH scanners must report at least one
#                  finding, or this script fails.
#   fixtures/good  the clean twin. BOTH must report zero findings, or this
#                  script fails (a gate that blocks clean code gets switched
#                  off, which is the same hole from the other side).
#
# IT COUNTS, IT DOES NOT TRUST EXIT CODES: a scanner exits non-zero both when
# it finds something and when it crashes. So each count is parsed from the
# scanner's own JSON output, and a scanner that could not run, or ran over
# nothing, is reported as ERROR, never as a detection:
#   Checkov   : ERROR unless its JSON parses, resource_count >= 1 and
#               parsing_errors == 0 (Checkov can "descend into nothing" and
#               report 0 checks with a clean exit).
#   TruffleHog: ERROR unless it exits 0 and its "finished scanning" log line
#               says chunks >= 1 (a missing folder also exits 0 with
#               chunks 0).
#
# WHAT THIS DOES NOT PROVE (said plainly, also in ADR 0026):
#   - The gate's TruffleHog runs with --results=verified: it fails a PR only
#     on a credential that is LIVE (it logs in with it). A planted key can
#     never be live, so no positive control can make that mode fire. Here
#     TruffleHog runs with --no-verification (and no network): it proves the
#     detector matches a private key in this version, not that the gate
#     would block one. The verified-only setting is a deliberate trade-off
#     (no false positives on example keys), and its blind spot is real: an
#     unverifiable or revoked secret merges.
#   - The gate scans the PR's git diff; this scans a folder. Same detector,
#     different source.
#   - Checkov's framework is terraform, as in the gate; its secrets
#     framework is not run there, so it is not tested here either.
#
# NO SECRET IS COMMITTED: the key is a fresh 2048-bit RSA key from openssl,
# written only into a mktemp copy, never printed (scanner output goes to
# files, and only counts are echoed), deleted on exit.
#
# USAGE
#   lab/pipelines/scanner-selftest/selftest.sh          # pinned images (docker)
#   lab/pipelines/scanner-selftest/selftest.sh --local  # checkov / trufflehog on PATH
#   SELFTEST_CHECKOV_BIN / SELFTEST_TRUFFLEHOG_BIN override the --local
#   binaries (the offline test uses stubs).
# Exit 0 = both scanners caught bad and cleared good; 1 = not; 2 = refused.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# The gate's versions. Checkov: the image checkov-action v12.3109.0
# hard-codes (terraform-plan.yml comment: ghcr.io/bridgecrewio/checkov:3.3.3),
# pinned here by the digest the tag resolved to on 2026-11-06 (OCI index).
# TruffleHog: exactly the image terraform-plan.yml pins.
CHECKOV_IMAGE="${CHECKOV_IMAGE:-ghcr.io/bridgecrewio/checkov:3.3.3@sha256:2b82187f1392260528d82d0d10ed7c631129a6f274313de2c9729238462ff40d}"
TRUFFLEHOG_IMAGE="${TRUFFLEHOG_IMAGE:-ghcr.io/trufflesecurity/trufflehog:3.97.9@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db}"

MODE="docker"
case "${1:-}" in
  "") ;;
  --local) MODE="local" ;;
  -h|--help) sed -n '2,52p' "$0"; exit 0 ;;
  *) echo "unknown argument: $1 (use --local or nothing)" >&2; exit 2 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "REFUSED: $1 is not installed" >&2; exit 2; }; }
need python3
need openssl
if [[ "$MODE" == "docker" ]]; then
  need docker
else
  CHECKOV_BIN="${SELFTEST_CHECKOV_BIN:-checkov}"
  TRUFFLEHOG_BIN="${SELFTEST_TRUFFLEHOG_BIN:-trufflehog}"
  need "$CHECKOV_BIN"
  need "$TRUFFLEHOG_BIN"
fi

# Honours TMPDIR (Docker Desktop / colima share only some host folders, so a
# local docker run may need TMPDIR under $HOME). mktemp -d creates it 0700.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/scanner-selftest.XXXXXX")" || { echo "REFUSED: mktemp failed" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

# Fresh copies, so the generated key never lands in the repo folder.
cp -R "$HERE/fixtures/bad" "$WORK/bad"
cp -R "$HERE/fixtures/good" "$WORK/good"
if ! openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/bad/planted-key.pem" 2>"$WORK/openssl.err"; then
  echo "REFUSED: could not generate the planted key (openssl)" >&2
  exit 2
fi
# The container user must be able to read the copies (ro bind mount).
chmod -R a+rX "$WORK/bad" "$WORK/good"

# --- counters: print a number of findings, or ERROR -------------------------

run_checkov() { # run_checkov DIR OUTFILE ERRFILE -> scanner exit code
  local dir="$1" out="$2" err="$3"
  if [[ "$MODE" == "docker" ]]; then
    # --network none: Checkov needs nothing from the network for a local
    # terraform scan, and this guarantees it sends nothing anywhere.
    docker run --rm --network none -v "$dir:/scan:ro" "$CHECKOV_IMAGE" \
      -d /scan --framework terraform --quiet -o json >"$out" 2>"$err"
  else
    "$CHECKOV_BIN" -d "$dir" --framework terraform --quiet -o json >"$out" 2>"$err"
  fi
}

count_checkov() { # count_checkov DIR
  local dir="$1" name out err rc
  name="$(basename "$1")"; out="$WORK/checkov.$name.json"; err="$WORK/checkov.$name.err"
  run_checkov "$dir" "$out" "$err"; rc=$?
  # Checkov: 0 = no failed checks, 1 = failed checks; anything else = broken.
  if (( rc > 1 )); then echo "ERROR"; return; fi
  python3 -I - "$out" <<'PY' || echo "ERROR"
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
reports = d if isinstance(d, list) else [d]
total_resources = failed = 0
for r in reports:
    s = r.get("summary") or {}
    if s.get("parsing_errors", 0):
        sys.exit(1)                     # a file it could not read is not a scan
    total_resources += int(s.get("resource_count", 0))
    failed += len((r.get("results") or {}).get("failed_checks") or [])
if total_resources < 1:
    sys.exit(1)                         # descended into nothing
print(failed)
PY
}

run_trufflehog() { # run_trufflehog DIR OUTFILE ERRFILE -> scanner exit code
  local dir="$1" out="$2" err="$3"
  if [[ "$MODE" == "docker" ]]; then
    # --no-verification and --network none: no login attempt with anything
    # it finds, by flag and by sandbox.
    docker run --rm --network none -v "$dir:/scan:ro" "$TRUFFLEHOG_IMAGE" \
      filesystem /scan --no-verification --json --no-update >"$out" 2>"$err"
  else
    "$TRUFFLEHOG_BIN" filesystem "$dir" --no-verification --json --no-update >"$out" 2>"$err"
  fi
}

count_trufflehog() { # count_trufflehog DIR
  local dir="$1" name out err rc
  name="$(basename "$1")"; out="$WORK/trufflehog.$name.jsonl"; err="$WORK/trufflehog.$name.log"
  run_trufflehog "$dir" "$out" "$err"; rc=$?
  # No --fail here, so a finished scan exits 0 with or without findings.
  if (( rc != 0 )); then echo "ERROR"; return; fi
  python3 -I - "$out" "$err" <<'PY' || echo "ERROR"
import json, sys
chunks = None
for line in open(sys.argv[2], errors="replace"):
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("msg") == "finished scanning":
        chunks = int(rec.get("chunks", 0))
if not chunks:
    sys.exit(1)                         # no summary, or it scanned 0 chunks
findings = 0
for line in open(sys.argv[1], errors="replace"):
    try:
        rec = json.loads(line)
    except ValueError:
        continue
    if rec.get("DetectorName"):
        findings += 1
print(findings)
PY
}

# --- verdicts ----------------------------------------------------------------

fail=0
judge() { # judge LABEL COUNT WANT(found|none)
  local label="$1" n="$2" want="$3"
  if [[ "$n" == "ERROR" ]]; then
    echo "  $label: ERROR - the scanner could not run or scanned nothing. Not a result."
    fail=1
  elif [[ "$want" == "found" && "$n" -eq 0 ]]; then
    echo "  $label: 0 findings - the gate would NOT catch the unsafe fixture"
    fail=1
  elif [[ "$want" == "none" && "$n" -ne 0 ]]; then
    echo "  $label: $n finding(s) - the gate would block the clean fixture"
    fail=1
  else
    echo "  $label: $n finding(s) - as required"
  fi
}

echo "scanner self-test (mode: $MODE)"
echo "fixtures/bad  (each scanner must find something)"
judge "checkov   " "$(count_checkov "$WORK/bad")" found
judge "trufflehog" "$(count_trufflehog "$WORK/bad")" found
echo "fixtures/good (each scanner must find nothing)"
judge "checkov   " "$(count_checkov "$WORK/good")" none
judge "trufflehog" "$(count_trufflehog "$WORK/good")" none

if (( fail == 0 )); then
  echo "RESULT PASS: both scanners caught the unsafe fixture and cleared the clean one."
  exit 0
fi
echo "RESULT FAIL: see above."
exit 1
