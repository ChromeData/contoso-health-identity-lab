# IAM / PAM Exception Process

| | |
|---|---|
| Scope | Any deviation from the IAM, privileged-access, NHI or CA standards in this folder, or from an external baseline the lab measures itself against (CISA SCuBA, through `Invoke-BaselineAssessment.ps1`). Contoso Health (fictional, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering (register). Accountable: CISO |

## 1. When an exception is needed

You need an exception when a "must" in a standard can't be met. Common cases:
- a CA exclusion other than break-glass;
- a standing privileged role;
- a client secret on an app;
- an NHI or app with Tier-0 permissions;
- a rotation interval longer than the standard;
- an unrecorded Tier-0 session;
- a direct (non-package) access assignment.

## 2. Steps

1. **Request.** The requester files a ticket with:
   - the standard and rule ID (for example, NHI N2);
   - scope (object IDs);
   - business reason;
   - proposed compensating controls;
   - requested end date.
2. **Assess.** IAM Engineering rates the risk:
   - **High**: Tier 0, or a policy affecting all users;
   - **Medium**: Tier 1, or a clinical persona;
   - **Low**: anything else.
   The SOC confirms detection coverage for the gap.
3. **Approve.** Approval depends on the rating:
   - High: CISO;
   - Medium: IAM lead and the app owner;
   - Low: IAM lead.
   For a clinical persona, Clinical Operations is consulted.
4. **Implement.** The change goes through code wherever possible: a PR that
   references the exception ID. A CA exclusion uses a
   `CA0NN-Exclusion-<reason>` group.
5. **Register.** The exception is added to the register below and shows up in
   the evidence pack.
6. **Review and expire.** The exception expires at most **90 days** after
   approval for High, and **180 days** for Medium or Low. It can be renewed once
   with fresh approval. After that it needs a remediation plan or a formal risk
   acceptance by the CISO. When it expires, the underlying control comes back
   into force.

## 3. Register template

| ID | Standard / rule | Object(s) | Risk | Compensating controls | Owner | Approver | Approved | Expires | Status |
|---|---|---|---|---|---|---|---|---|---|
| E*n* | | | H/M/L | | | | *date* | *date* | Proposed / Approved / Expired / Closed |

## 4. Proposed entries the lab already needs

None of these is approved: there is no approver in a lab, and the "Approved"
and "Expires" columns stay blank until someone signs them off. Each one comes
from the committed code. Each still names an owner (a [raci.md](raci.md)
role) and a next review date, so none is ownerless. The date is the lab's
quarterly review, 2027-01-20, as in ADR 0005 and ADR 0013. E9 ends with the
trial instead.

| ID | Standard / rule | Object(s) | Risk | Compensating controls (as built) | Owner | Next review | Status |
|---|---|---|---|---|---|---|---|
| E1 | NHI N6, PAM Tier 0 | `gh-oidc-entra-apply (write)`: `RoleManagement.ReadWrite.Directory` and other Graph writes (`modules/pipeline-identity/variables.tf`), plus `AppRoleAssignment.ReadWrite.All` while `envs/bootstrap` `enable_app_management_roles` is on | H | Federated credential scoped to `environment:prod`; `prod` reviewer; deployment branches limited to `main`; read-only state-account lock (`lab/terraform/README.md`). Residual risk is documented there. The lab's own time-boxed acceptance is [ADR 0005](../adr/0005-risk-acceptance-apply-identity-tier0.md) (review 2027-01-20); a scenario CISO approval is still needed | IAM Eng (identity platform owner) | 2027-01-20 (ADR 0005) | Proposed |
| E2 | PAM §1–2 (cloud-only admin account, eligibility ≤ 365 days) | `Privileged-IAM-Admins` eligibility on a workforce account (no `adm-` accounts exist); its expiry is now `P365D` in code, inside the 365-day rule | M | PIM activation needs MFA, justification and approval; capped at 4 h; activation alert (`kql/pim-activation.kql`); members added outside PIM alert (`kql/pim-group-member-added-outside-pim.kql`) | IAM Eng | 2027-01-20 | Proposed |
| E3 | NHI N1, N2 | `midpoint-reader` client secret (`lab/pam/README.md`) | M | Read-only Graph application permissions; secret held only in midPoint | IAM Eng | 2027-01-20 | Proposed |
| E4 | PAM §4 (per-person broker sign-in with SSO and MFA) | Per-operator Guacamole users with local passwords, until Entra OIDC sign-in is on (tenant time) | M | Connection-level READ for one named operator, revoked at check-in; a per-check-out Vault token names the operator and the ticket in the audit log; check-out needs an approved change assigned to that operator | IAM Eng | 2027-01-20 | Proposed |
| E5 | PAM §2 (approver ≠ requester) | Solo-repo self-approval of the `prod` deployment (`lab/pipelines/README.md` §5F) | H | Required status checks (plan, Checkov, TruffleHog); turn on "Prevent self-review" once a second maintainer exists | IAM Eng | 2027-01-20 | Proposed |
| E6 | PAM §3 (HA / split custody) | Single DC, single Vault unseal key (`lab/docs/STAND-INS.md`) | M | Lab-only stand-in; HA with auto-unseal and the DR drill are rehearsed on a laptop cluster (`lab/pam/vault-ha.sh`, `dr-drill.sh`); production design is at least two DCs per site, and the vault design in [ADR 0019](../adr/0019-pam-vault-high-availability-and-dr.md): auto-unseal from a Key Vault HSM key, recovery keys split 3-of-5 | IAM Eng | 2027-01-20 | Proposed |
| E7 | PAM §2 (zero standing privilege) | Containment playbook identity (`pb-identity-contain`, ADR 0017): standing Authentication Administrator, only if deployed with `-GrantDisableRole`. Tenant-wide by default, or one administrative unit (`-DirectoryRoleScope`) | H | Off by default: without it the disable step returns 403 and sessions are still revoked. Every action needs a Teams answer from an `ITDR-Containment-Approvers` member who isn't the subject; admins and break-glass are out of reach; `role-assigned-outside-pim.kql` alerts on the assignment. If granted, scope it to an AU of cloud-only, non-admin accounts: the workforce is synced from AD (ADR 0006), and for synced accounts the playbook only flags. Whoever can edit the Logic App controls this role: on `rg-identity-lab` that is the APPLY identity (E1), the bootstrapping Owner until it is converted to eligible, and `PIM-Azure-RG-Contributors` after activation (`modules/pim/azure.tf`, which already treats that resource group as Tier 0) | SOC | 2027-01-20 | Proposed |
| E8 | CISA SCuBA MS.AAD.2.1 (block high-risk users) | CA006: High user risk gets MFA plus a secure password change instead of a block ([ADR 0015](../adr/0015-risk-based-conditional-access-thresholds.md)). `Invoke-BaselineAssessment.ps1` reports the expected FAIL | H | High sign-in risk is blocked (CA007); Medium risk goes to the SOC (`identity-risk.kql`); containment revokes sessions. Limit: self-remediation is only safe once CA009 is enforced and the account's methods are clean. Until then an attacker holding a method they registered passes CA006 ([compromised-identity.md](../runbooks/compromised-identity.md) §2) | IAM Eng | 2027-01-20 | Proposed |
| E9 | CA design principles §2 (14-day report-only minimum) | Graduations inside the 30-day E5 trial: `evidence-capture-plan.md` graduates after about five days of report-only data | H | One policy per PR; report-only results checked for every persona in scope before the flip; break-glass exclusion re-verified (`01-Verify-Baseline.ps1`); 72-hour post-enforcement watch and a one-line revert PR ([graduate-a-ca-policy.md](../runbooks/graduate-a-ca-policy.md)). Trial tenant only: any later rollout uses the 14 days | IAM Eng | End of the trial (Day 30) | Proposed |
| E10 | PAM §2 (approval for Tier-1 roles that read content in bulk) | `PIM-Tier1-Exchange-Admins` and `PIM-Tier1-SharePoint-Admins`: no `require_approval` in `pim_tier_groups` (`modules/pim/variables.tf`) | M | MFA, justification, 8-hour cap; every activation alerts (`pim-activation.kql`); CA002's admin strength once enforced. Remediation is one line per group (`require_approval = true`), which closes this row | IAM Eng | 2027-01-20 | Proposed |
| E11 | Drift detection (ADR 0021: every nightly compare runs against a committed tenant baseline) | `lab/config-baseline/identity-config.json` is the `no-baseline` placeholder until the first tenant export | M | The nightly job still runs the two checks that need no baseline (declared intent in `lab.tfvars`, break-glass invariants) and records every section it could not read; real-time rules (`ca-policy-changed.kql`, `role-assigned-outside-pim.kql`) are unaffected. Closed by committing the first reviewed export (evidence capture E59, Day 1 of the tenant run) | IAM Eng | First tenant run (E59) | Proposed |

## 5. Metrics

Collect these after the process runs. The lab has no figures yet.

| Metric | Value |
|---|---|
| Open exceptions by risk | *fill after running* |
| Exceptions past expiry | *fill after running*. The target is 0 |
| Median age of open exceptions | *fill after running* |
| Exceptions closed by remediation (not renewal) | *fill after running* |
