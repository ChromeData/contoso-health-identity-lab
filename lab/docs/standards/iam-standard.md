# IAM Standard: Workforce Identity

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Accountable: CISO (see [raci.md](raci.md)) |
| Related | [privileged-access-standard.md](privileged-access-standard.md), [nhi-standard.md](nhi-standard.md), [conditional-access-design-principles.md](conditional-access-design-principles.md), [exception-process.md](exception-process.md) |

"Must" is mandatory. Anything that can't meet a "must" goes through the
[exception process](exception-process.md). The last section of this document
lists where the lab doesn't yet meet the standard.

## 1. Identity types

| Type | Source of truth | Lifecycle owner | Lab implementation |
|---|---|---|---|
| Workforce (employee, contractor) | HR system of record | HR, through the provisioning service | `lab/scripts/mock-hr/hr_feed.csv` → API-driven inbound provisioning → AD → Cloud Sync |
| Privileged admin account | IAM Engineering | IAM Engineering | See the privileged-access standard |
| Emergency access (break-glass) | IAM Engineering | CISO (custody) | `lab/terraform/modules/groups` (`bg-admin-01/02`) |
| Guest / external (B2B) | Sponsor + app owner | Sponsor | A separate external catalog for affiliated physicians: connected-organization requestors, sponsor approval, 90-day expiry, monthly sponsor review (`modules/entitlement/b2b.tf`, behind `enable_b2b_governance`; code only). The clinical catalog stays internal-only. `05-Reports.ps1` reports guest sprawl |
| Non-human (apps, managed identities, service accounts) | Owning team | Named human owner | See [nhi-standard.md](nhi-standard.md) |

Rules:
- A workforce identity **must** be created only from an HR record. IT must not
  create workforce accounts by hand. In the lab, Terraform owns break-glass
  accounts and groups, and HR owns every workforce user (`lab/scripts/README.md`,
  "Who owns what").
- Each person has **one** workforce identity. Any privileged access goes on a
  separate admin account (privileged-access standard §1).
- Authoritative attributes (department, title, manager, enabled state) are
  mastered in HR and flow downstream. Synced attributes are never edited in
  Entra. Entra rejects those writes anyway, so `03-Mover.ps1` and
  `04-Leaver.ps1` wait for the synced value instead.

## 2. Naming

| Object | Convention | Lab example |
|---|---|---|
| Workforce UPN | `first.last@<verified domain>`, with a numeric suffix on collision | `dana.okafor@<domain>` |
| Admin account | `adm-first.last@<tenant>.onmicrosoft.com`, cloud-only | BUILT, not run: `lab/iga/admin-accounts.json` + `post-apply/New-AdminAccounts.ps1` (`Invoke-PostApply` step 1b) create `adm-` accounts for the IT personas (Ava Lin, Raj Patel, Mei Tanaka; Joan Ferris is the IT Director) and `adm-presenter`, the read-only demo presenter with no HR owner (sponsored by the lab owner), in the standing, role-assignable `Admin-Accounts` group (no role) |
| Break-glass | `bg-admin-NN@<tenant>.onmicrosoft.com` | `bg-admin-01`, `bg-admin-02` |
| AD Tier-0 admin | `tier0-admin-NN` | `lab/scripts/dc/02-Configure-Domain.ps1` |
| AD service account | `svc-<function>` | `svc-backup`, `svc-vault-rotator` |
| Birthright group (dynamic) | `All-<Department>` | `All-Nurses`, `All-ICU` |
| App access group | `App-<Application>[-<Role>]` | `App-ServiceNow-Users`, `App-AWS-IdentityCenter-Users` |
| Role-assignable group | `Privileged-<Function>` / `Break-Glass-Admins` | `Privileged-IAM-Admins` |
| Access package | `<Population> - <Scope> Apps` | `Nurse - Clinical Apps` |
| Conditional Access policy | `CA0NN - <action> for <persona>` | See the CA design principles §4 |

Detections rely on these names. For example, `lab/kql/break-glass-signin.kql`
matches on `bg-admin-NN`, so a rename **must** also update the detections.

## 3. Joiner, mover and leaver service levels

These are **targets**. The lab hasn't measured any of them yet because no
tenant run has taken place. Record the measured values in the "Measured" column
after a run, using the timestamps from `04-Leaver.ps1 -ReportPath` and the
provisioning logs.

| Event | Target | Mechanism (lab) | Measured |
|---|---|---|---|
| Joiner: account exists with birthright groups | Before start date (T-1 business day) | HR record → inbound provisioning; dynamic `All-<Dept>` groups. The birthright package follows from HR attributes on day one (automatic assignment, `Set-AutoAssignmentPolicies.ps1`) | *fill after running* |
| Joiner: first credential | On start date, by a one-time Temporary Access Pass (TAP) sent to the manager, never a password | Joiner Lifecycle Workflow, TAP 480 min, one-time use (`New-LifecycleWorkflows.ps1`) | *fill after running* |
| Joiner: role access | Package request auto-raised on day 1. Approver decision within **2 business days**; unanswered requests expire after 14 days | `02-Joiner.ps1`; `approval_timeout_days = 14` (`modules/entitlement`) | *fill after running* |
| Mover: old role access removed | Within **24 h** of the HR effective date for requested access. Birthright clinical packages go after a **72-hour** grace, so a mover isn't cut off mid-shift ([ADR 0012](../adr/0012-access-review-no-response-and-clinical-lockout.md)) | `03-Mover.ps1` removes the old requested package and requests the new one; the automatic assignment policy moves the birthright package; dynamic groups recompute | *fill after running* |
| Leaver, planned: account disabled | Within **60 min** of the HR termination time | HR `status=leaver` → AD disable → Cloud Sync | *fill after running* |
| Leaver, involuntary or urgent | Sessions revoked and the AD account disabled **within 15 min** of the HR or Security request. The Entra disable follows on the next sync cycle | `04-Leaver.ps1` revokes sessions even while the disable is still pending, then removes packages, groups, apps and SCIM accounts; or the on-demand leaver workflow | *fill after running* |
| Leaver: SaaS accounts deprovisioned | Within **4 h**. Clinical systems holding PHI are deprovisioned on demand (immediately) | SCIM cycle (about 40 min per the script) or `-ProvisionOnDemandApps` | *fill after running* |
| Leaver: owned NHIs re-homed | Before the account is disabled | `04-Leaver.ps1` step 7: reports the leaver's NHIs by default; opt-in, it hands low-privilege ones to the manager and flags privileged ones for review. It runs after the disable, not before (gap G4) | *fill after running* |

## 4. Access requests and recertification

- Role-based access **must** be delivered through an access package. A
  requested package has an expiry; the default is 180 days
  (`assignment_duration_days`). A birthright clinical package is assigned
  automatically from HR attributes and has no expiry; leaving scope removes
  it after the grace period (ADR 0012). Direct app or group assignment is an
  exception.
- Every request **must** carry a justification, and the approver is the
  manager or a named approver group (`modules/entitlement/main.tf`).
- Toxic combinations are declared as separation-of-duties (SoD) rules. The
  lab declares nine, SOD-01 to SOD-09 (`lab/iga/sod-rules.json`): preventive
  incompatibilities where access is requested
  (`post-apply/Set-IncompatibleAccessPackages.ps1`, never on a birthright
  package), and a detective report over existing access, PIM eligibility
  included (`09-SoD-Report.ps1`).
- Recertification is risk-tiered
  ([ADR 0012](../adr/0012-access-review-no-response-and-clinical-lockout.md)):
  - **Privileged access:** quarterly. An unanswered review **removes** it.
  - **Requestable packages:** every 180 days. Unanswered means **removed**.
  - **Birthright clinical access:** certified by HR attributes, and **never
    removed** because a reviewer stayed silent.

  `modules/entitlement` implements this: each package carries its tier, T3
  packages get no review and no expiry, and each review tier has its own
  flag (`enable_access_reviews_privileged`, `_requestable`, `_inactive`).
  All of it is off by default and has never run.
- Stale accounts: an enabled account with no interactive sign-in for **90
  days** is disabled after manager confirmation (`05-Reports.ps1 -StaleDays 90`).

## 5. Authentication

- All users **must** use MFA (CA001). Admin roles **must** use phishing-resistant
  MFA (CA002, custom authentication strength).
- Legacy authentication is blocked (CA003).
- New hires onboard with a TAP, never a temporary password.
- Registering a new method needs a one-time TAP or an existing
  phishing-resistant method (CA009, behind a staging flag).
- Target state: phishing-resistant authentication for all users. The lab has
  it as code only: CA008 (report-only, behind a staging flag) and
  `post-apply/Set-AuthenticationMethodsPolicy.ps1` (passkey profiles,
  one-time TAP; never run against a tenant). ADR 0016 records the design.

## 6. Where the lab is short of this standard

| # | Gap | Evidence | Path to close |
|---|---|---|---|
| G1 | Closed in code, tenant run pending: the cloud-only `adm-` accounts are BUILT but have never been created, so no PIM eligibility sits on one yet | `lab/iga/admin-accounts.json`, `post-apply/New-AdminAccounts.ps1`; `post-apply/Set-PimGroupEligibility.ps1` has no default person and warns on a non-`adm-` account | Run `Invoke-PostApply` step 1b, then put PIM eligibility on the `adm-` accounts |
| G2 | No SLA in §3 has been measured | `lab/evidence/` holds harness run records only (PAM, midPoint, Kubernetes); no JML record | Run the JML flow and record the timestamps |
| G3 | The guest (B2B) lifecycle is code only | `modules/entitlement/b2b.tf`, `post-apply/New-B2BConnectedOrganization.ps1`; `enable_b2b_governance = false` | Apply it, then run one sponsor review |
| G4 | The leaver hands off owned NHIs after the disable, not before, and only reports them by default | `04-Leaver.ps1` step 7 (`-NhiHandoff FlagOnly` default) | See [nhi-standard.md](nhi-standard.md) §3 |
| G5 | Access reviews are off by default | `lab.tfvars`: `enable_access_reviews_privileged`, `_requestable` and `_inactive` all `false` | Turn them on after HR users with managers exist |
| G6 | The authentication-methods policy has never been applied | `post-apply/Set-AuthenticationMethodsPolicy.ps1` (offline preview only) | Run it at tenant time, then measure registration |

verify: the Cloud Sync user cycle. `04-Leaver.ps1` assumes about 10–20 minutes,
which sits inside the 60-minute target but outside the 15-minute urgent
target, so that path relies on session revocation. Also check whether Cloud
Sync's provision-on-demand can push the disable sooner.
