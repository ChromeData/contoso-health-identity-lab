# IAM / PAM Exception Process

| | |
|---|---|
| Scope | Any deviation from the IAM, privileged-access, NHI or CA standards in this folder, or from an external baseline the lab measures itself against (CISA SCuBA, through `Invoke-BaselineAssessment.ps1`). Contoso Health (fictional, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering (register). Accountable: CISO |

## 1. When an exception is needed

When a "must" in a standard can't be met: a CA exclusion other than
break-glass, a standing privileged role, a client secret on an app, an NHI
with Tier-0 permissions, a rotation interval longer than the standard, an
unrecorded Tier-0 session, or a direct (non-package) access assignment.

## 2. Steps

1. **Request.** A ticket with the standard and rule ID (for example NHI N2),
   scope (object IDs), business reason, proposed compensating controls and
   requested end date.
2. **Assess.** IAM Engineering rates it: **High** (Tier 0, or a policy
   affecting all users), **Medium** (Tier 1, or a clinical persona), **Low**
   (anything else). The SOC confirms detection coverage for the gap.
3. **Approve.** High: CISO. Medium: IAM lead and the app owner. Low: IAM
   lead. Clinical Operations is consulted for a clinical persona.
4. **Implement** through code wherever possible: a PR that references the
   exception ID. A CA exclusion uses a `CA0NN-Exclusion-<reason>` group.
5. **Register** it below; it shows up in the evidence pack.
6. **Review and expire.** At most **90 days** for High, **180 days** for
   Medium or Low; renewable once with fresh approval, then a remediation
   plan or a formal CISO risk acceptance. On expiry the control comes back
   into force.

## 3. Register template

| ID | Standard / rule | Object(s) | Risk | Compensating controls | Owner | Approver | Approved | Expires | Status |
|---|---|---|---|---|---|---|---|---|---|
| E*n* | | | H/M/L | | | | *date* | *date* | Proposed / Approved / Expired / Closed |

## 4. Proposed entries the lab already needs

None is approved: a lab has no approver, so "Approved" and "Expires" stay
blank until someone signs. Each names a [raci.md](raci.md) owner and the
lab's quarterly review date, 2027-01-20 (E9 ends with the trial). The
compensating controls are detailed where each row points.

| ID | Standard / rule | Object(s) | Risk | Compensating controls (detail) | Owner | Next review | Status |
|---|---|---|---|---|---|---|---|
| E1 | NHI N6, PAM Tier 0 | `gh-oidc-entra-apply`: `RoleManagement.ReadWrite.Directory`, plus `AppRoleAssignment.ReadWrite.All` while `enable_app_management_roles` is on | H | Subject scoped to `environment:prod`, `prod` reviewer, main-only, state lock ([ADR 0005](../adr/0005-risk-acceptance-apply-identity-tier0.md), R01) | IAM Eng | 2027-01-20 | Proposed |
| E3 | NHI N1, N2 | `midpoint-reader` client secret | M | Read-only Graph permissions; secret held only in midPoint; listed in `nhi-secrets-register.json` | IAM Eng | 2027-01-20 | Proposed |
| E4 | PAM §4 (broker sign-in with SSO and MFA) | Per-operator Guacamole users with local passwords until Entra OIDC is on | M | Connect-only access for one operator, revoked at check-in; per-check-out Vault token names the operator and ticket (R06) | IAM Eng | 2027-01-20 | Proposed |
| E5 | PAM §2 (approver ≠ requester) | Solo-repo self-approval of the `prod` deployment | H | Required checks (plan, Checkov, TruffleHog); "Prevent self-review" once a second maintainer exists (ADR 0005) | IAM Eng | 2027-01-20 | Proposed |
| E6 | PAM §3 (HA, split custody) | Single DC, single Vault unseal key | M | HA and DR rehearsed on a laptop cluster; production design in [ADR 0019](../adr/0019-pam-vault-high-availability-and-dr.md) (R09) | IAM Eng | 2027-01-20 | Proposed |
| E7 | PAM §2 (zero standing privilege) | Containment playbook identity: standing Authentication Administrator, only if deployed with `-GrantDisableRole` | H | Off by default; every action needs a Teams answer from a listed approver who isn't the subject; admins and break-glass out of reach; scoped to an AU if ever granted ([ADR 0017](../adr/0017-approval-gated-identity-containment.md), R16) | SOC | 2027-01-20 | Proposed |
| E8 | CISA SCuBA MS.AAD.2.1 (block high-risk users) | CA006 remediates High user risk instead of blocking | H | CA007 blocks High sign-in risk; Medium to the SOC; a confirmed compromise gets a block ([ADR 0015](../adr/0015-risk-based-conditional-access-thresholds.md)) | IAM Eng | 2027-01-20 | Proposed |
| E9 | CA principles §2 (14-day report-only minimum) | Graduations inside the 30-day trial, after 5–11 days of report-only data | H | One policy per PR, every persona's results checked, break-glass re-verified, 72-hour watch, one-line revert ([graduate-a-ca-policy.md](../runbooks/graduate-a-ca-policy.md)). Trial tenant only | IAM Eng | End of the trial | Proposed |

E2 and E10 were withdrawn on 2026-10-21: the `adm-` accounts are now code
(IAM standard G1 tracks the tenant run), and the Tier-1 approval rule now
matches the code (ADR 0002).

## 5. Metrics

Collected once the process runs: open exceptions by risk, exceptions past
expiry (target 0), median age of open exceptions, and the share closed by
remediation rather than renewal. *Fill after running.*
