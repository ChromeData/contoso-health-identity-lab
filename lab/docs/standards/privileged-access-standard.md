# Privileged Access Standard

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): Entra ID, Azure, on-prem AD, PAM tooling, CI/CD |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Accountable: CISO |
| Principle | No standing admins. No secrets in the delivery pipeline; every remaining secret is inventoried with an owner, expiry and rotation. Every identity change goes through a PR. The lab's own long-lived secrets (e.g. the Splunk HEC token and the Okta client secret) are listed in `lab/iga/nhi-secrets-register.json` (names and store locations only) and checked by `06-NHI-Inventory.ps1 -SecretsRegisterPath` ([nhi-standard.md](nhi-standard.md) §4) |

The lab's privileged-access products are Microsoft-native
([ADR 0036](../adr/0036-microsoft-native-pam.md)): Azure Key Vault for secrets,
Azure Bastion session recording for admin sessions, Windows LAPS for local
admin passwords, Intune Endpoint Privilege Management for local admin rights,
and PIM for just-in-time roles. A local Vault and Guacamole harness also
exists (`lab/docs/STAND-INS.md`). This standard is written for the capability, not for
any one product.

## 1. Tiers and account types

The tiers follow Microsoft's Enterprise Access Model.

| Tier | What it controls | Examples (lab) |
|---|---|---|
| **Tier 0**: identity control plane | Anything that can grant itself or others any access | Global Admin, Privileged Role Admin, CA Admin, Security Admin, Application Admin; AD Domain Admins; `svc-vault-rotator` (it resets Domain Admin passwords through AdminSDHolder, per `lab/scripts/dc/02-Configure-Domain.ps1`); the pipeline **APPLY** identity (holds `RoleManagement.ReadWrite.Directory`). The full Entra role-to-tier map is `pim_tier_groups` in `modules/pim/variables.tf` |
| **Tier 1**: management plane | Servers, apps and user objects, but not the control plane | User Administrator (held by `Privileged-IAM-Admins`), Intune admin (`PIM-Tier1-Intune-Admins`), app owners' admin roles. Intune Administrator moves to Tier 0 once privileged workstations are Intune-managed (CA005's production design), because it can push scripts to them |
| **Tier 2**: user access | Workstations, helpdesk | Service desk roles. PIM has only two activation profiles in `modules/pim`, so `PIM-Tier1-Helpdesk` uses the Tier-1 rules |

**Privileged roles outside the map are not assigned.** Roles Microsoft
labels privileged that aren't in `pim_tier_groups` (for example Password,
Domain Name and External Identity Provider Administrator) are held by
nobody. One exception, read-only: `PIM-Demo-Readers`
(`modules/pim/demo-readers.tf`) holds Global Reader and Security Reader for
the demo presenter, eligible-only, outside the tier map and outside CA002 /
CA020. Needing one means adding it to
the map in a PR, with a tier. An active assignment of any role outside PIM
alerts (`role-assigned-outside-pim.kql`, High), and CA002 already targets
these roles. A new PIM *eligibility* on an unmapped role has no rule yet.

| Account type | Rule |
|---|---|
| Admin account | Separate, **cloud-only** (`adm-` prefix), with no mailbox and no internet browsing. Never the synced workforce account |
| Break-glass | See §6 |
| AD Tier-0 admin | Held in the vault and checked out exclusively. Nobody knows its password |
| Service, reconcile and pipeline identities | Governed by [nhi-standard.md](nhi-standard.md). Tier-0 rights need a risk acceptance |

## 2. Just-in-time (JIT): rules and PIM settings

- **Zero standing privilege.** The only standing privileged role assignments are
  the two break-glass accounts (through `Break-Glass-Admins`) and the role
  bindings held by PIM-governed groups that have no standing members
  (`Privileged-IAM-Admins` → User Administrator, the tier groups in
  `modules/pim/tiers.tf`, and `PIM-Demo-Readers` → Global Reader + Security
  Reader in `modules/pim/demo-readers.tf`). `05-Reports.ps1` reports every other standing
  assignment as a finding; `role-assigned-outside-pim.kql` and
  `pim-group-member-added-outside-pim.kql` alert when one is created; and
  `Find-ShadowAdmins.ps1` reports who could give themselves a role in one
  step (owners of role-assignable groups or Tier-0 apps, for example). The
  containment playbook's opt-in directory role is a standing assignment,
  so it needs an exception (E7).
- Elevation runs through **PIM for Groups**. The role-assignable group holds the
  role, and PIM controls group membership (`lab/terraform/modules/pim`; ADR
  0002, partly superseded by ADR 0020).

| PIM setting | Standard | Lab value (`modules/pim`, `envs/dev`) |
|---|---|---|
| Max activation | Tier 0: **4 h**, and **2 h** for the two roles that can take over any account in one step (Global Administrator, Privileged Authentication Administrator). Tier 1: **8 h**, one shift | `PT4H` (`Privileged-IAM-Admins`, Tier-0 tier groups); `PT2H` (Global Administrator, Privileged Authentication Administrator); `PT8H` (Tier-1 tier groups) |
| MFA on activation | Required, phishing-resistant | `require_mfa_on_activation = true`, plus CA002 auth strength. Tier 0 can require auth context c1 instead (`tier0_activation_auth_context_id`), which CA021 meets only with the admin strength and a fresh sign-in |
| Justification | Required, with a ticket reference for Tier 0 | `require_justification = true`; Tier 0 also requires ticket information (`tier0_require_ticket_info`) |
| Approval | Tier 0: required. Tier 1: required for User Administrator and for roles that can read secrets or other people's content in bulk (Intune, Exchange, SharePoint); not required for the other Tier-1 roles. Approver is a **group**, never the requester | Required on `Privileged-IAM-Admins`, every Tier-0 group, Global Administrator, the Intune group and the IGA group (`PIM-Tier1-IGA-Admins`). **Not yet on the Exchange and SharePoint groups** (exception E10). **Not on `PIM-Demo-Readers`** either, although Global Reader and Security Reader can read BitLocker recovery keys: a read-only presenter activates alone, on camera; compensated by MFA + reason, 8 h, a mail on every activation and the quarterly review (`demo-readers.tf` header). Approvers are role-assignable groups, `PIM-Approvers-Tier0` and `-Tier1` (`approvers.tf`) |
| Active assignment max | 15 days, for exceptions only | `P15D` |
| Eligible assignment expiry | **≤ 365 days**, renewed through a privileged access review | Tier 0 `P180D` (Global Administrator too), Tier 1 and `Privileged-IAM-Admins` `P365D`. The one permanent eligibility is a group's, not a person's: the group eligible for Contributor on the lab resource group (`azure.tf`), whose members are reviewed quarterly. The privileged access review is rendered (`modules/entitlement/reviews.tf`), off by default |
| Notification | Every activation is alerted to the SOC | `lab/kql/pim-activation.kql`; `pim-activation-without-auth-context.kql` (a Tier-0 activation without the step-up; preview, behind `enable_itdr_detections_v2`). PIM's own admin notifications go to `pim_alert_mailbox` when it is set |

**Why these caps and this approval split.** A cap shorter than the work
makes people re-activate in the middle of a change, and each Tier-0
re-activation is another approval request. A steady stream of requests is
how approval becomes a rubber stamp. So Tier 0 gets 4 h, and only the two
roles that can take over any account directly get 2 h. Tier 1 gets 8 h
because the service desk works in shifts. The service desk activates
Helpdesk and Authentication Administrator every shift, so an approval queue
there would run around the clock. Its controls are the administrative-unit
scope (`enable_helpdesk_au_scoping`, off by default) and the
identity-verification runbook instead. Groups, Teams and
License Administrator change configuration and membership, not content or
secrets. Every Tier-1 activation still needs MFA and a justification, and
raises the activation alert. Exchange and SharePoint Administrator are
different: each can grant itself access to any mailbox or site (verify),
and in a hospital that means PHI. So they need approval, like Intune.

## 3. Vaulting and rotation

| Credential | Vaulted | Rotation | Lab |
|---|---|---|---|
| AD Tier-0 admin (interactive) | Yes, with exclusive check-out | **On every check-in**. Check-out TTL 1 h, max 4 h | Vault library `tier0-admin-01/02`: `ttl=1h max_ttl=4h` (`lab/pam/lib.sh`). Check-out needs an approved change assigned to the operator (`pam-policy.json` `require_ticket`) and, for Tier 0, two distinct approvers who are not the requester (dual control, `approvals_required`; RAN · harness) |
| AD service account | Yes | At most every **30 days**, after a dependency check | `svc-backup` static role (`rotation_period=24h`, `lib.sh`) and the `svc/*` roles `onboard.sh` creates (`pam-policy.json` tier `svc`: 720 h). Onboarding and `rotate.sh` refuse while a consumer in `accounts-dependencies.json` is unresolved or the account has no record. Vault's own scheduled rotation doesn't ask, which is why the gate sits at onboarding |
| Vault bind/reconcile account | Yes. Only the vault knows it | At onboarding (`--rotate-root`), then at least every **90 days** | `vault-onboard-ad.sh --rotate-root`. No scheduled re-rotation |
| Break-glass password | Offline, sealed | After every use, and at least annually | Human step 6 in `lab/terraform/README.md` |
| Workload secrets | Yes, issued by policy to a workload identity | Per secret owner, ≤ 90 days | Vault role `nightly-report` on kind (`lab/terraform/k8s/identity`); target: Azure Key Vault through Entra Workload ID (ADR 0036) |

- A plaintext privileged credential **must not** appear on a command line, in
  Terraform state or in a repo. The lab pipes the bind password over stdin
  from Key Vault (`vault-onboard-ad.sh`).
- The vault audit log must be on and must reach the SIEM. In the lab it is on
  (`pam-up.sh` enables it). `lab/scripts/monitoring/ingest-vault-audit.sh`
  ships check-outs and check-ins to the `VaultCheckout_CL` table, and with
  `--signals all` also credential reads, failed rotations, root-token use,
  failed logins and denials for `vault-privileged-access-anomaly.kql`. It is
  tested offline with a stubbed API and has never run against a workspace.

## 4. Session management and recording

| Scope | Requirement | Lab |
|---|---|---|
| Interactive Tier-0 sessions (DCs, CA/PKI, vault admin) | **Brokered and recorded.** The operator never sees the password | Guacamole RDP to DC01 with the credential injected at check-out (`lab/pam/psm-session.sh`) |
| Tier-1 server sessions | Brokered. Recording is risk-based | Not in the lab |
| SSH to Linux infrastructure | Brokered and recorded, with short-lived certificates | Guacamole SSH with a 10-minute Vault SSH CA certificate the operator never holds, recorded (`lab/pam/psm-ssh.sh`). Ran in the local harness against one Docker target |
| Cloud admin portals | Compliant device (CA005), phishing-resistant MFA, PIM | CA005 is report-only and limited to the pilot group. CA020 (sign-in every 4 h) and CA022 (admin strength for the PAM broker and admin portals) are code behind staging flags |

- Each person signs in to the session broker **as themselves**, with SSO and MFA.
- Recordings are kept on write-once storage. The retention period is set by the
  records schedule (lab-scenario placeholder: 1 year), and the SOC reviews them
  on alert.

## 5. Approval of privileged changes

Tier-0 configuration (CA, PIM, role-assignable groups, access packages) changes
**only** through a PR, then a plan, then the protected `prod` environment with a
required reviewer (`lab/pipelines/README.md` §1, §5E). A portal change counts
as drift, and the next apply puts the reviewed code back.

## 6. Break-glass

- Two accounts, cloud-only, on `*.onmicrosoft.com`, each with standing Global
  Admin. The Terraform variable validation enforces the domain and the
  two-account minimum (`modules/groups/variables.tf`).
- They are excluded from **every** CA policy, and only through the
  `Break-Glass-Admins` group. `01-Verify-Baseline.ps1` proves the exclusion.
- They sign in with two FIDO2 keys per account, kept in separate safes. The
  password is backup material in sealed physical copies only, never in
  `kv-idlab` (human step 6).
- **Any** sign-in alerts the SOC immediately, threshold 1
  (`lab/kql/break-glass-signin.kql`). Suppression is by a change ticket logged in
  advance, never by muting the rule.
- **Drill every 90 days.** Each drill signs in with each key, confirms that the
  alert fired, re-seals the safes and records the result in a dated log.
- After any real use: rotate the password, review the audit log and file a
  post-incident review.

## 7. Where the lab is short of this standard

| # | Gap | Evidence |
|---|---|---|
| P1 | No break-glass drill has been run. The procedure is written and `Invoke-BreakGlassDrill.ps1` automates its checks, but neither has run, and the drill log is an empty template | `lab/docs/runbooks/break-glass-drill.md`; `lab/scripts/powershell/Invoke-BreakGlassDrill.ps1`; `lab/evidence/drills/README.md` |
| P2 | Eligibility now expires (code only). Separate `adm-` accounts are BUILT (`New-AdminAccounts.ps1`, `lab/iga/admin-accounts.json`), not run; eligibility goes on them (IAM standard G1) | `modules/pim/main.tf`, `tiers.tf`; `Set-PimGroupEligibility.ps1` |
| P3 | Approver groups exist as code, but in a solo lab they can hold only one person, the operator. Keeping approvers apart from the people they approve is a convention, not a control: `Set-PimGroupEligibility.ps1` warns on an overlap but doesn't refuse it | `modules/pim/approvers.tf` (warns on fewer than two approvers); `Set-PimGroupEligibility.ps1` |
| P4 | Each operator has their own Guacamole user, but signs in with a local password until Entra OIDC sign-in is on (tenant time), and `guacadmin`/`guac-db` can read the stored password until check-in | `lab/pam/README.md` (per-person sign-in), `psm-session.sh` header |
| P5 | Recordings sit on a laptop Docker volume, with no WORM storage and no retention | `guac-recordings` volume (`lab/pam/docker-compose.yml`) |
| P6 | Discovery, bulk onboarding and the dependency gate have run only against the Samba DC; the Windows dependency scan has run only in its Pester tests | `lab/pam/discover.sh`, `onboard.sh`, `rotate.sh`, `dependency-scan/` |
| P7 | Single DC, and the working vault has a single unseal key. HA (3-node Raft, auto-unseal) and the timed DR drill exist only as a laptop rehearsal (ADR 0019) | `lab/pam/vault-ha.sh`, `dr-drill.sh`; `lab/docs/STAND-INS.md` |
| P8 | The APPLY identity holds Tier-0 Graph rights. This is accepted risk, not compliance | [ADR 0005](../adr/0005-risk-acceptance-apply-identity-tier0.md); [exception-process.md](exception-process.md), register item E1 |
| P9 | `tier0-logon-without-checkout.kql` ties a Tier-0 logon on DC01 to a vault check-out, but it has never run: it needs DC01 security events and the vault feed in the workspace | `lab/kql/tier0-logon-without-checkout.kql`, `lab/scripts/monitoring/ingest-vault-audit.sh` |
| P10 | Exchange and SharePoint Administrator activate without approval in code | `modules/pim/variables.tf` (`pim_tier_groups`: no `require_approval` on either); [exception-process.md](exception-process.md) E10 |
| P11 | The containment playbook's identity can hold a standing Authentication Administrator assignment (opt-in) | `lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1` (`-GrantDisableRole`); [exception-process.md](exception-process.md) E7 |

verify: whether the CA "directory roles" condition (CA002) applies to a role
held through a role-assignable group activated with PIM for Groups. Until
that is confirmed, CA002 and CA020 are built to target the admin groups
directly as well (`admin_scope_group_object_ids` in
`modules/conditional-access`: `Privileged-IAM-Admins`, the tier groups and
the help-desk group).
