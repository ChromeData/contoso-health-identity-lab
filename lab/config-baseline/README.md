# Configuration baseline and drift exceptions

The committed picture of the tenant configuration this repository owns, and
the time-boxed exceptions to differences from it. Read nightly by
`.github/workflows/config-drift.yml` through
[`Compare-IdentityConfig.ps1`](../scripts/powershell/Compare-IdentityConfig.ps1).

**Status: BUILT.** No tenant exists, so `identity-config.json` is a
placeholder (`{"status": "no-baseline"}`) and the compare reports "no
baseline yet". The loop it closes is described in
[`../scripts/powershell/README.md`](../scripts/powershell/README.md#configuration-drift-export-compare-nightly-reconcile)
and [`../pipelines/README.md`](../pipelines/README.md).

## `identity-config.json`: the baseline

What the tenant looked like the last time someone reviewed it: the output of
`Export-IdentityConfig.ps1 -Public` (Conditional Access policies, named
locations, authentication strengths, the authentication methods policy, PIM
role-management policies for directory roles and PIM for Groups, consent and
app-management policies, cross-tenant access defaults, break-glass exclusion
facts), normalised so the same tenant state always gives the same bytes, with
every object id and IP range hashed and no name, UPN or mailbox in it.

**Until the tenant run** the file is the placeholder. Running without a
baseline is itself a deviation from the drift-detection standard this folder
implements, so it is tracked as exception **E11** in the exception register
([`../docs/standards/exception-process.md`](../docs/standards/exception-process.md)):
owner IAM Engineering, closed by the first commit below. Until then the
nightly job still runs the two checks that need no baseline, the declared
intent in `lab.tfvars` and the break-glass invariants, and records any
section it could not read.

**Committing the first baseline (tenant time; evidence capture E59, which closes exception E11):**

1. `Export-IdentityConfig.ps1 -Public -Label baseline` after the post-apply
   steps have run and `01-Verify-Baseline.ps1` passes. The file lands in
   `lab/evidence/config-snapshots/<UTC>.json` with a `SHA256SUMS` line.
2. Read it. Every policy, rule and target in it is being declared correct.
   Microsoft-managed Conditional Access policies will be in it: keep them
   (they are then watched for change) or remove them from the baseline and
   register an exception for the `.../added` finding.
3. Copy it here as `identity-config.json`, in the same PR as the
   `lab/evidence/config-snapshots/` record, with the review in the PR
   description. The PR is the approval.
4. Every later change to the tenant configuration goes through a PR that
   changes the code AND this file (export again after the apply). A nightly
   finding is either a change that skipped the PR, or a baseline nobody
   updated: both are worth a look.

The export must be `-Public` here: this folder is in a public repository.
`Compare-IdentityConfig.ps1` refuses a public snapshot against a non-public
baseline and the reverse.

## `drift-exceptions.json`: the exception register for drift

One entry per accepted difference, following the exception process (rating,
approver, expiry). Fields:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | The register entry, `E<n>`, as in `exception-process.md` section 3 |
| `finding` | yes | The finding key the compare prints, e.g. `conditionalAccessPolicies/CA010 - Block device code flow for all users/conditions/users/excludeGroups`. `*` wildcards are allowed (`conditionalAccessPolicies/Microsoft-managed*/added`) |
| `owner` | yes | A RACI role or named owner ([`raci.md`](../docs/standards/raci.md)) |
| `approver` | per the rating | CISO for High, IAM lead + app owner for Medium, IAM lead for Low |
| `approved` | yes | `YYYY-MM-DD` |
| `expires` | yes | `YYYY-MM-DD`, at most 90 days after `approved` for a High finding, 180 for Medium or Low. Valid through the whole day; the day after, the finding is open again |
| `reason` | yes in practice | Business reason |
| `compensatingControls` | yes in practice | What covers the gap meanwhile |

```json
{
  "id": "E60",
  "finding": "conditionalAccessPolicies/CA010 - Block device code flow for all users/conditions/users/excludeGroups",
  "owner": "IAM Eng",
  "approver": "CISO",
  "approved": "2026-11-03",
  "expires": "2027-01-20",
  "reason": "CA010-Exclusion-AzCliDeviceCode group added for the operator until Invoke-BaselineAssessment.ps1 moves to browser sign-in",
  "compensatingControls": "device-code-signin.kql alerts on every device-code sign-in; group membership reviewed quarterly"
}
```

An entry without `id`, `finding`, `owner`, `approved` or `expires`, or whose
term exceeds the standard, is **ignored** with a warning and listed under
"exceptions ignored" in the summary: a malformed exception never hides
drift. An exception is a reason to fix the baseline or the code within its
term, not a permanent allow-list; renewal is one more entry with fresh
approval, as the process allows once.
