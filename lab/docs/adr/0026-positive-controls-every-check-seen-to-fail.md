# ADR 0026: A check counts only after it has been seen to fail (positive controls)

- **Status:** BUILT. RAN · harness (2026-11-06, capture log L09): the scanner self-test passed locally with the gate's pinned Checkov 3.3.3 and TruffleHog 3.97.9 images; its stub test passed 11/11; with the Checkov image swapped for one without Checkov, it failed as it should. The CI job had not run when this was written; it first runs on this ADR's own pull request.
- **Date:** 2026-11-06
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-06, or when a scanner, its version or its flags change
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Source:** moved from `POSITIVE-CONTROLS.md` in the owner's older PAM-Cloud-Labs repo and rewritten for this lab.

## Context

A test or scanner that is broken still tends to report success. In the
owner's earlier labs this happened at least seven times, and none of them
showed an error:

- a gitleaks version bump changed what it detected, and the gate still passed;
- Checkov walked into a nested template, ran 0 checks and exited clean;
- an RBAC linter said "No risky RBAC found" on a cluster with four
  cluster-admin-equivalent roles;
- PSRule could not find the Bicep binary and processed 0 rules, twice;
- a pytest skip guard sat in a helper module, where pytest never reads it.

Two more were in the checks written to catch those: a canary that "passed"
against a missing file, and a gate self-test that scored a crashed scanner as
a detection. Both trusted an exit code, and a crash also exits non-zero.

## Decision

Every check in this lab has two properties:

1. **It counts. It does not just exit.** Parse the tool's own output and
   assert on the number of findings, rows or rules. "Could not run" and "ran
   over nothing" are their own failure (ERROR / NOT RUN), never a pass and
   never a detection.
2. **It has been seen to fail.** Break what it watches, watch it go red,
   restore it. Where possible that break runs in CI on every change, so a
   check that rots is caught on the next PR.

## Where the lab does this

| Check | Counts | Seen to fail |
|---|---|---|
| Merge-gate scanners: `lab/pipelines/scanner-selftest/selftest.sh`, CI job `scanner positive control` (`lab-tests.yml`) | Checkov failed checks and TruffleHog findings from their JSON. ERROR unless Checkov saw at least 1 resource with no parsing errors, and TruffleHog scanned at least 1 chunk | Every PR: RDP and SSH open to the internet (`fixtures/bad`) must be flagged, and a private key generated at run time must be found. The clean twin must pass. `tests/selftest.test.sh` breaks each scanner with a stub (finds nothing, crashes, scans nothing, flags clean code) and asserts the self-test fails |
| KQL detections: `lab/monitoring/kusto-harness/` | Rows per case. A rule with no case run is NOT RUN, not FAIL | Every rule needs a positive and a negative case, and an `xfail` case that passes fails the run. `run-on-workspace.py` reports watchlist cases as SKIPPED, never as passed |
| Every new test (team rule) | | It must fail against the code before the change |

## What this does not fix

- **The gate's TruffleHog fails a PR only on a verified secret**
  (`--results=verified`): one it has logged in with. A planted key can never
  be live, so no positive control can make that mode fire. The self-test
  therefore runs TruffleHog with `--no-verification` and no network, which
  proves the detector matches a key in the gate's version, not that the gate
  blocks one. The setting is chosen to avoid false positives on example keys.
  Its blind spot: an unverifiable or already-revoked secret still merges.
- **The gate scans the PR diff; the self-test scans a folder.** Same
  detector and version, different source.
- **Offline checks cannot see enforcement.** Whether Entra, Sentinel or AWS
  enforce a control is shown only by tenant evidence
  (`lab/docs/evidence-capture-plan.md`, statuses RAN · tenant).

## Consequences

- A new scanner, or a new flag on one, ships with its fixture and its count
  in `selftest.sh` in the same PR.
- `fixtures/bad` is never "fixed". It sits outside `lab/terraform`, so the
  gate's Checkov job never scans it, and no Terraform root uses it.
- The self-test pulls two pinned images on every PR (not yet timed in CI).
  The cost is accepted.
