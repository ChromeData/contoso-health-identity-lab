# Privileged Access Standard

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): Entra ID, Azure, on-prem AD, PAM tooling, CI/CD |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Accountable: CISO |
| Principle | No standing admins. No secrets in the delivery pipeline; every remaining secret is inventoried with an owner, expiry and rotation (`lab/iga/nhi-secrets-register.json`, [nhi-standard.md](nhi-standard.md) §4). Every identity change goes through a PR |

The lab runs Vault, Guacamole and Conjur in place of CyberArk's Digital
Vault and CPM, PSM and Secrets Manager ([`STAND-INS.md`](../STAND-INS.md)).
This standard is written for the capability, not for one product.

## 1. Tiers and account types

The tiers follow Microsoft's Enterprise Access Model.

| Tier | What it controls | Examples (lab) |
|---|---|---|
| **Tier 0**: identity control plane | Anything that can grant itself or others any access | Global Admin, Privileged Role Admin, CA Admin, Security Admin, Application Admin; AD Domain Admins; `svc-vault-rotator` (resets Domain Admin passwords through AdminSDHolder); the pipeline **APPLY** identity. The full Entra role-to-tier map is `pim_tier_groups` in `modules/pim/variables.tf` ([ADR 0002](../adr/0002-pim-for-groups-vs-direct-role-eligibility.md)) |
| **Tier 1**: management plane | Servers, apps and user objects, not the control plane | User Administrator (`Privileged-IAM-Admins`), Intune, Exchange, SharePoint, Teams, License, Groups, IGA and help-desk roles. Intune moves to Tier 0 once privileged workstations are Intune-managed |
| **Tier 2**: user access | Workstations, help desk | Service desk work. PIM has two activation profiles, so `PIM-Tier1-Helpdesk` uses the Tier-1 rules |

**Privileged roles outside the map are not assigned.** Needing one means
adding it to the map in a PR, with a tier. An active assignment of any role
outside PIM alerts High (`role-assigned-outside-pim.kql`).

| Account type | Rule |
|---|---|
| Admin account | Separate, **cloud-only** (`adm-` prefix), no mailbox, no browsing. Never the synced workforce account |
| Break-glass | §6 |
| AD Tier-0 admin | Vaulted and checked out exclusively. Nobody knows its password |
| Service, reconcile and pipeline identities | [nhi-standard.md](nhi-standard.md). Tier-0 rights need a risk acceptance |

## 2. Just-in-time: rules and PIM settings

- **Zero standing privilege.** The only standing privileged assignments are
  the two break-glass accounts (through `Break-Glass-Admins`) and the roles
  held by PIM-governed groups with no standing members. `05-Reports.ps1`
  reports any other standing assignment; `role-assigned-outside-pim.kql` and
  `pim-group-member-added-outside-pim.kql` alert when one is created; and
  `Find-ShadowAdmins.ps1` reports who could give themselves a role in one
  step. The containment playbook's opt-in directory role would be a
  standing assignment, so it needs exception E7.
- Elevation runs through **PIM for Groups**: a role-assignable group holds
  the role, PIM controls membership. The design and its reasoning are
  [ADR 0002](../adr/0002-pim-for-groups-vs-direct-role-eligibility.md).

| PIM setting | Standard | Lab value (`modules/pim`) |
|---|---|---|
| Max activation | Tier 0: **4 h**; **2 h** for Global Administrator and Privileged Authentication Administrator. Tier 1: **8 h**, one shift | `PT4H`, `PT2H`, `PT8H`; `Privileged-IAM-Admins` `PT4H` |
| MFA on activation | Required, phishing-resistant | `require_mfa_on_activation`, plus CA002. Tier 0 moves to auth context `c1` (CA021) once CA021 is enforced |
| Justification | Required; a ticket reference for Tier 0 | `require_justification`; `tier0_require_ticket_info` |
| Approval | Tier 0: required. Tier 1: required for roles that reach Tier-0 assets or every non-admin account (User Administrator, Intune, the IGA group). Approver is a **group**, never the requester | Required on `Privileged-IAM-Admins`, every Tier-0 group, Global Administrator, Intune and `PIM-Tier1-IGA-Admins`. Approvers: role-assignable `PIM-Approvers-Tier0` and `-Tier1` |
| Active assignment max | 15 days, exceptions only | `P15D` |
| Eligible assignment expiry | **≤ 365 days**, renewed through a privileged access review | Tier 0 `P180D` (Global Administrator too); Tier 1 and `Privileged-IAM-Admins` `P365D`. The one permanent eligibility is a group's (Contributor on the lab resource group, `azure.tf`), whose members are reviewed quarterly |
| Notification | Every activation alerts the SOC | `pim-activation.kql`; `pim-activation-without-auth-context.kql` (Tier 0 without the step-up; preview); PIM's own emails to `pim_alert_mailbox` |

Exchange and SharePoint Administrator activate without approval: each can
reach mailbox or site content (PHI), so every activation alerts and is
matched to a ticket (ADR 0002, Consequences).

## 3. Vaulting and rotation

| Credential | Vaulted | Rotation | Lab |
|---|---|---|---|
| AD Tier-0 admin (interactive) | Yes, exclusive check-out | **On every check-in**; check-out TTL 1 h, max 4 h | Vault library `tier0-admin-01/02` (`lab/pam/lib.sh`). Check-out needs an approved change assigned to the operator and, for Tier 0, two approvers who aren't the requester (RAN · harness) |
| AD service account | Yes | At most every **30 days**, after a dependency check | `svc/*` static roles (`pam-policy.json` tier `svc`: 720 h). Onboarding and `rotate.sh` refuse while a consumer in `accounts-dependencies.json` is unresolved |
| Vault bind/reconcile account | Yes; only the vault knows it | At onboarding (`--rotate-root`), then at least every **90 days** | `vault-onboard-ad.sh --rotate-root`; no scheduled re-rotation |
| Break-glass password | Offline, sealed | After every use, at least annually | Human step 6 (`lab/terraform/README.md`) |
| Workload secrets | Yes, issued by policy to a workload identity | Per owner, ≤ 90 days | Conjur `apps/nightly-report` |

- A plaintext privileged credential **must not** appear on a command line,
  in Terraform state or in a repo. The lab pipes the bind password over
  stdin from Key Vault.
- The vault audit log must be on and reach the SIEM. In the lab it is on;
  `ingest-vault-audit.sh` ships it to `VaultCheckout_CL` (tested offline,
  never run against a workspace).

## 4. Session management and recording

| Scope | Requirement | Lab |
|---|---|---|
| Interactive Tier-0 sessions (DCs, CA/PKI, vault admin) | **Brokered and recorded;** the operator never sees the password | Guacamole RDP with the credential injected at check-out (`psm-session.sh`) |
| Tier-1 server sessions | Brokered; recording risk-based | Not in the lab |
| SSH to Linux infrastructure | Brokered and recorded, short-lived certificates | 10-minute Vault SSH CA certificates, recorded (`psm-ssh.sh`; RAN · harness, one Docker target) |
| Cloud admin portals | Compliant device (CA005), phishing-resistant MFA, PIM | CA005 report-only, pilot group; CA020 and CA022 behind staging flags |

- Each person signs in to the broker **as themselves**, with SSO and MFA.
- Recordings are kept on write-once storage for the records schedule's
  period (scenario placeholder: 1 year); the SOC reviews them on alert.

## 5. Approval of privileged changes

Tier-0 configuration (CA, PIM, role-assignable groups, access packages)
changes **only** through a PR, a plan and the protected `prod` environment
with a required reviewer. A portal change is drift; the next apply puts the
reviewed code back.

## 6. Break-glass

- Two cloud-only accounts on `*.onmicrosoft.com`, each with standing Global
  Admin; validation enforces the domain and the two-account minimum.
- Excluded from **every** CA policy, only through `Break-Glass-Admins`;
  `01-Verify-Baseline.ps1` proves it.
- Two FIDO2 keys per account in separate safes; the password is sealed
  backup material only, never in Key Vault.
- **Any** sign-in alerts the SOC, threshold 1. Suppression is a change
  ticket logged in advance, never a muted rule.
- **Drill every 90 days** ([break-glass-drill.md](../runbooks/break-glass-drill.md)).
  After any real use: rotate the password, review the audit log, file a
  post-incident review.

## 7. Where the lab is short of this standard

Gaps already tracked in the [risk register](../risk-register.md) or the
[exception register](exception-process.md) (break-glass drill R02, broker
sign-in E4/R06, single DC and unseal key E6/R09, APPLY E1/R01, containment
role E7/R16, `adm-` accounts not yet created IAM G1) are not repeated here.

| # | Gap | Evidence |
|---|---|---|
| P3 | In a solo lab the approver groups hold one person. Keeping approvers apart from the people they approve is a convention: `Set-PimGroupEligibility.ps1` warns on overlap but doesn't refuse | `modules/pim/approvers.tf`; `Set-PimGroupEligibility.ps1` |
| P5 | Recordings sit on a laptop Docker volume, with no WORM storage and no retention | `guac-recordings` (`lab/pam/docker-compose.yml`) |
| P6 | Discovery, onboarding and the dependency gate have run only against the Samba DC; the Windows dependency scan only in its Pester tests | `lab/pam/discover.sh`, `onboard.sh`, `rotate.sh`, `dependency-scan/` |
| P9 | `tier0-logon-without-checkout.kql` has never run in a workspace: it needs DC01 security events and the vault feed | `lab/kql/tier0-logon-without-checkout.kql`, `ingest-vault-audit.sh` |
| P12 | Whether the CA directory-role condition covers a role held through a PIM-for-Groups group isn't confirmed, so CA002 and CA020 also target the admin groups directly (`admin_scope_group_object_ids`) | `modules/conditional-access` |
