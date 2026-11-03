# IGA programme pack: birthright, separation of duties, review KPIs

Code for [ADR 0012](../docs/adr/0012-access-review-no-response-and-clinical-lockout.md)
(risk-tiered certification and clinical lockout). Contoso Health is fictional.

**Status: BUILT.** The four scripts below pass their Pester suites with
every Graph call mocked (part of the 917 lab tests that passed on
2026-10-20), and the entitlement module's 26 mocked `terraform test` runs
check the packages against `access-catalog.json`. **RAN · tenant: nothing.**
The scripts' `.NOTES` list what was confirmed on Microsoft Learn and what is
still `verify:`. The local proof of the same certification design is the
midPoint campaign (RAN · harness, 91/91):
[`../pam/midpoint/README.md`](../pam/midpoint/README.md).

## Files

| File | What it holds |
|---|---|
| `access-catalog.json` | Every package, group and directory role the rules may name, with tier (T1/T2/T3), assignment model and status. `terraform` = defined in `lab/terraform` (tests check it); `planned` = designed, not built. |
| `birthright-rules.json` | Department + job title (target: HR job code) to birthright package, one job profile per HR-feed persona. 72-hour mover grace. Privileged access is never birthright; no `memberOf`. |
| `sod-rules.json` | Nine clinical, finance and identity SoD rules (SOD-01 to SOD-09): sides, risk, regulatory driver, mitigating control if an exception is granted. |
| `admin-accounts.json` | The admin-account register: one cloud-only `adm-` account per person who does admin work, its owner's HR employee id and what it should be eligible for (reviewed intent; nothing is granted from this file). `post-apply/New-AdminAccounts.ps1` creates the accounts from it. |
| `nhi-secrets-register.json` | The long-lived secrets Graph cannot see (Key Vault, GitHub Actions, local files): names and store locations only (never a value), an owner role, an expiry and a rotation. `06-NHI-Inventory.ps1 -SecretsRegisterPath` merges it into the NHI inventory and reports SECRET-NO-OWNER, SECRET-EXPIRED, SECRET-NO-EXPIRY and SECRET-NO-ROTATION. Dates for the local secrets that exist come from file and volume metadata on the build machine (`dateSource` says how); a fresh PAM stack makes them stale. |
| `fixtures/` | **Synthetic** inputs for the offline runs and the Pester tests. Not tenant data. |

## Scripts (in `lab/scripts/powershell`)

| Script | Control | Writes |
|---|---|---|
| `post-apply/Set-AutoAssignmentPolicies.ps1` | T3 birthright: one automatic assignment policy per package | Entra policies (`-WhatIf`, prompts per change) |
| `post-apply/Set-IncompatibleAccessPackages.ps1` | Preventive SoD: incompatible packages and groups. Never gates a birthright package | Entra links (`-WhatIf`, `-Prune`) |
| `09-SoD-Report.ps1` | Detective SoD on existing access, including PIM-eligible roles and groups, and the **reviewer of record** (SOD-08: an identity admin who manages someone holding T2 access). Exit code = open violations (0-254); 255 = no valid report (a source unreadable, input invalid or refused, or the run failed) | `lab/evidence/sod/<UTC>/` (pseudonymised CSV + JSON + `manifest.sha256`) |
| `10-Review-KPIs.ps1` | Completion, revocation, rubber-stamp rate (reviewers with >= 10 items; thresholds in `access-catalog.json` `reviewTiers.rubberStamp`, also read by `lab/pam/midpoint/run-campaign.sh`), approve-against-recommendation, clinical lockouts (any review tier that removes a birthright package from someone in scope), per tier and per reviewer | `lab/evidence/kpis/reviews-<UTC>.json` + `.sha256` |

Identity detail (names, UPNs, object ids) only ever goes to the gitignored
`lab/evidence/out/`. A fixture run is refused in the public evidence tree.

## Run it offline

```powershell
cd lab/scripts/powershell
./post-apply/Set-AutoAssignmentPolicies.ps1 -RenderOnly       # the membership rules
./post-apply/Set-IncompatibleAccessPackages.ps1 -RenderOnly   # the links, and the detective-only rules
./09-SoD-Report.ps1 -InputPath ../../iga/fixtures/sod-tenant.json -WhatIf          # exit 7 (synthetic)
./10-Review-KPIs.ps1 -InputPath ../../iga/fixtures/review-decisions.json -WhatIf   # exit 2 (synthetic lockouts)
pwsh tests/Invoke-LabTests.ps1
```

## Tenant-time order

`lab/scripts/powershell/post-apply/Invoke-PostApply.ps1` runs steps 2 and 3
for you (its steps 5 and 6, in that order, when `enable_governance` is on).

1. `terraform apply` with `enable_governance` (packages and the request
   policies for T2 packages; birthright packages get no Terraform policy).
2. `Set-AutoAssignmentPolicies.ps1 -WhatIf`, then for real. Needs the
   **Identity Governance Administrator** role: catalog owners and access
   package managers cannot create automatic policies. **In the pipeline this
   step is automatic:** `terraform-apply.yml` runs it after every successful
   apply, app-only as the APPLY identity (`-UseAzureCliToken`, whose
   `EntitlementManagement.ReadWrite.All` needs no directory role), and puts
   one plain line per change in the Apply summary ("Automatic access rule
   set: **IT - Cloud Engineering Apps** goes to everyone in Information
   Technology with the job title Cloud Engineer.", or "No automatic access
   rules needed changing."). A refusal or failure turns the run red; the
   Terraform part stays applied and a re-run is safe.
3. `Set-IncompatibleAccessPackages.ps1 -WhatIf -Prune`, then `-Prune`. This
   removes the old Nurse -> Pharmacy link, which would otherwise gate the
   birthright package.
4. `09-SoD-Report.ps1`. Every open violation gets removed or an exception
   (`../docs/standards/exception-process.md`). Open violations:
   `<measured: count>`.
5. After the first review cycle, run `10-Review-KPIs.ps1` and record the
   numbers in ADR 0012 (completion `<measured: %>`, revocation
   `<measured: %>`, clinical lockouts `<measured: count>`).

## Still open

- **Tenant-time: the two hire-date mappings.** The birthright rule requires
  `user.employeeHireDate -le system.now` (no PHI access before day one).
  `Invoke-InboundProvisioning.ps1` sends `startDate` as `hireDate`; the
  provisioning mapping (`FormatDateTime` → `msDS-cloudExtensionAttribute1`)
  and the Cloud Sync mapping (→ `employeeHireDate`) are set in the tenant
  (verify: on the first job setup). verify: a user with no
  `employeeHireDate` does not match (expected: fail closed).
  `Set-AutoAssignmentPolicies.ps1` refuses to run while nobody in scope has
  a hire date.
- **Tenant-time: the `sod_holdings` upload.** Uploading the snapshot as the
  Sentinel watchlist `sod_holdings`, and copying it to the Splunk lookup
  `contoso_sod_holdings.csv`, are manual steps. Until then the detection
  sees 14 days of grants, and older pairs are caught by the next
  `09-SoD-Report.ps1` run.

Done since the first version of this pack: `Invoke-InboundProvisioning.ps1`
sends `startDate` as the SCIM `hireDate` (custom extension; a non-leaver
row without one is refused); `09-SoD-Report.ps1 -HoldingsSnapshotPath
<gitignored path>` writes the `sod_holdings` snapshot (refused inside the
public evidence tree); the `adm-` account register (`admin-accounts.json`)
and the NHI secrets register; per-package review tiers in
`modules/entitlement` (birthright packages have no request policy and are
never reviewed by a person); `Invoke-PostApply.ps1` runs auto-assignment then
`Set-IncompatibleAccessPackages.ps1` (`Set-AccessPackageSoD.ps1` is a
forwarding shim); `03-Mover.ps1` waits for the HR attribute and only
follows through; `Set-PimGroupEligibility.ps1` has no default persona.
