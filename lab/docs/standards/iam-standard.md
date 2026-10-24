# IAM Standard: Workforce Identity

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Accountable: CISO ([raci.md](raci.md)) |
| Related | [privileged-access-standard.md](privileged-access-standard.md), [nhi-standard.md](nhi-standard.md), [conditional-access-design-principles.md](conditional-access-design-principles.md), [exception-process.md](exception-process.md) |

"Must" is mandatory. Anything that can't meet a "must" goes through the
[exception process](exception-process.md). §6 lists where the lab falls
short.

## 1. Identity types

| Type | Source of truth | Lifecycle owner | Lab implementation |
|---|---|---|---|
| Workforce (employee, contractor) | HR system of record | HR, through the provisioning service | `hr_feed.csv` → API-driven inbound provisioning → AD → Cloud Sync |
| Privileged admin account | IAM Engineering | IAM Engineering | Privileged-access standard |
| Emergency access (break-glass) | IAM Engineering | CISO (custody) | `modules/groups` (`bg-admin-01/02`) |
| Guest / external (B2B) | Sponsor + app owner | Sponsor | A separate catalog for affiliated physicians: sponsor approval, 90-day expiry, monthly sponsor review (`modules/entitlement/b2b.tf`, behind `enable_b2b_governance`) |
| Non-human | Owning team | Named human owner | [nhi-standard.md](nhi-standard.md) |

- A workforce identity **must** be created only from an HR record; IT never
  creates workforce accounts by hand.
- Each person has **one** workforce identity; privileged access goes on a
  separate admin account.
- Authoritative attributes (department, title, manager, enabled state) are
  mastered in HR and never edited in Entra. Entra rejects those writes for
  synced users anyway, so `03-Mover.ps1` and `04-Leaver.ps1` wait for the
  synced value.

## 2. Naming

| Object | Convention | Lab example |
|---|---|---|
| Workforce UPN | `first.last@<verified domain>`, numeric suffix on collision | `dana.okafor@<domain>` |
| Admin account | `adm-first.last@<tenant>.onmicrosoft.com`, cloud-only | BUILT, not run: `lab/iga/admin-accounts.json` + `post-apply/New-AdminAccounts.ps1`, into the standing, role-assignable `Admin-Accounts` group (no role) |
| Break-glass | `bg-admin-NN@<tenant>.onmicrosoft.com` | `bg-admin-01`, `bg-admin-02` |
| AD Tier-0 admin / service account | `tier0-admin-NN` / `svc-<function>` | `svc-backup`, `svc-vault-rotator` |
| Birthright group (dynamic) | `All-<Department>` | `All-Nurses`, `All-ICU` |
| App access group | `App-<Application>[-<Role>]` | `App-AWS-IdentityCenter-Users` |
| Role-assignable group | `Privileged-<Function>` / `Break-Glass-Admins` | `Privileged-IAM-Admins` |
| Access package | `<Population> - <Scope> Apps` | `Nurse - Clinical Apps` |
| CA policy | `CA0NN - <action> for <persona>` | CA design principles §4 |

Detections rely on these names (`break-glass-signin.kql` matches
`bg-admin-NN`), so a rename **must** also update the detections.

## 3. Joiner, mover and leaver service levels

Targets only: no tenant run has measured them. Record measured values from
`04-Leaver.ps1 -ReportPath` and the provisioning logs after a run.

| Event | Target | Mechanism (lab) | Measured |
|---|---|---|---|
| Joiner: account with birthright access | Before start date (T-1 business day); birthright package on day one | HR record → inbound provisioning; dynamic `All-<Dept>` groups; automatic assignment (`Set-AutoAssignmentPolicies.ps1`) | *fill after running* |
| Joiner: first credential | On start date: a one-time TAP to the manager, never a password | Joiner Lifecycle Workflow, TAP 480 min, one-time | *fill after running* |
| Joiner: role access | Approver decision within **2 business days**; unanswered requests expire after 14 days | `02-Joiner.ps1`; `approval_timeout_days = 14` | *fill after running* |
| Mover: old access removed | Requested access within **24 h** of the HR effective date; birthright after a **72-hour** grace ([ADR 0012](../adr/0012-access-review-no-response-and-clinical-lockout.md)) | `03-Mover.ps1`; the automatic assignment policy | *fill after running* |
| Leaver, planned | Account disabled within **60 min** of the HR termination time | HR `status=leaver` → AD disable → Cloud Sync | *fill after running* |
| Leaver, urgent | Sessions revoked and AD account disabled **within 15 min** of the HR or Security request | `04-Leaver.ps1` revokes sessions even while the disable is pending | *fill after running* |
| Leaver: SaaS accounts | Within **4 h**; PHI systems on demand | SCIM cycle or `-ProvisionOnDemandApps` | *fill after running* |
| Leaver: owned NHIs re-homed | Before the account is disabled | `04-Leaver.ps1` step 7 (runs after the disable today: G4) | *fill after running* |

## 4. Access requests and recertification

- Role-based access **must** come through an access package. A requested
  package expires (default 180 days); a birthright clinical package is
  assigned automatically from HR attributes and has no expiry (ADR 0012).
  Direct app or group assignment is an exception.
- Every request **must** carry a justification; the approver is the manager
  or a named approver group.
- Toxic combinations are SoD rules: nine in `lab/iga/sod-rules.json`,
  preventive where access is requested (never on a birthright package) and
  detective over existing access, PIM eligibility included.
- Recertification is risk-tiered (ADR 0012): privileged access quarterly,
  removed if unanswered; requestable packages every 180 days, removed if
  unanswered; birthright clinical access certified by HR attributes and
  **never removed** because a reviewer stayed silent. Each tier has its own
  flag; all are off by default and none has run.
- An enabled account with no interactive sign-in for **90 days** is
  disabled after manager confirmation (`05-Reports.ps1 -StaleDays 90`).

## 5. Authentication

- All users **must** use MFA (CA001); admin roles **must** use
  phishing-resistant MFA (CA002). Legacy authentication is blocked (CA003).
- New hires onboard with a TAP, never a temporary password.
- Registering a new method needs a one-time TAP or an existing
  phishing-resistant method (CA009).
- Target: phishing-resistant authentication for all users (CA008, ADR 0016,
  [passwordless-rollout-plan.md](../passwordless-rollout-plan.md)).

## 6. Where the lab is short of this standard

| # | Gap | Path to close |
|---|---|---|
| G1 | The `adm-` accounts are BUILT but never created, so no PIM eligibility sits on one yet | Run `Invoke-PostApply` step 1b, then put eligibility on the `adm-` accounts |
| G2 | No §3 service level has been measured; `lab/evidence/` holds harness records only | Run the JML flow and record the timestamps |
| G3 | The guest lifecycle is code only (`enable_b2b_governance = false`) | Apply it and run one sponsor review |
| G4 | The leaver hands off owned NHIs after the disable, and only reports them by default | [nhi-standard.md](nhi-standard.md) §3 |
| G5 | The per-tier review flags are all `false` in `lab.tfvars` | Turn them on once HR users with managers exist |
| G6 | The authentication methods policy has never been applied | Run it at tenant time, then measure registration |
