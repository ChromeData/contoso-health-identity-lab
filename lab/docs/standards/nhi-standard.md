# Non-Human Identity (NHI) Standard

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): app registrations, service principals, managed identities, federated workload identities, Kubernetes service accounts, AD service accounts, vault workload hosts, AI agents |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Each NHI has a named human owner (see §1) |

## 1. Rules

| # | Rule |
|---|---|
| N1 | **An owner is required.** Every NHI has at least **two** human owners, or one owner plus a team group. An NHI without an owner is disabled after 30 days |
| N2 | **No password credentials.** App registrations must not hold client secrets. Use federated credentials first, then managed identities, then certificates |
| N3 | **Federation is preferred.** CI/CD and external workloads use workload identity federation. The subject is exact and environment-scoped, never a wildcard or a branch name alone |
| N4 | **Managed identity for Azure-hosted workloads**, with RBAC scoped to the resource and conditions (ABAC) where they're supported |
| N5 | **Maximum certificate lifetime is 180 days.** On apps created after the app-management policy's cut-off date, Entra refuses a longer one (`Set-AppGovernancePolicy.ps1`, ADR 0018). On older apps the platform doesn't stop it, so `06-NHI-Inventory.ps1` reports it (`CRED-LONG-LIVED`). SAML token-signing certificates are outside this rule; only their expiry is tracked. Certificates are kept in Key Vault, never on disk or in a repo |
| N6 | **Least privilege.** Graph *application* permissions are listed and justified. `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` and `Directory.ReadWrite.All` make an NHI **Tier 0** and need a risk acceptance ([exception-process.md](exception-process.md)) |
| N7 | **Short-lived tokens.** Workload tokens are audience-bound and last 1 h or less. No long-lived token is stored as a secret |
| N8 | **Quarterly review.** Owners attest each NHI's purpose, permissions and credentials. Credentials unused for 90 days are removed. NHIs with no sign-in for 90 days are disabled |
| N9 | **Leaver hand-off.** Ownership is reassigned before an owner's account is disabled (§3) |
| N10 | **AI agents get their own identity**, with a human sponsor, scoped permissions and no shared secrets. A workflow that calls a model under someone else's identity isn't an agent identity |
| N11 | **AD service accounts** are vaulted and rotated (privileged-access standard §3). Where the application supports it, use a gMSA instead. They are denied interactive logon |

## 2. How the lab maps

| NHI (lab) | Type | Credential | Rules met | Rules not met |
|---|---|---|---|---|
| `gh-oidc-entra-plan (read-only)` | App + SP | Federated, subjects `…:pull_request` and `…:ref:refs/heads/main` (config-drift) | N2, N3, N6 (read-only) | **N1**: no `owners` in `modules/pipeline-identity/main.tf` |
| `HR-SYNC (gh-oidc hr-feed upload)` (opt-in, `enable_hr_sync`) | App + SP | Federated, subject `…:ref:refs/heads/hr-feed` | N2, N3; N6: `SynchronizationData-User.Upload.OwnedBy` (only the HR provisioning app it owns) + `AuditLog.Read.All`, no Azure RBAC | **N1**; it can create and disable workforce accounts through the provisioning job, so the `hr-feed` branch ruleset (only the HR owner pushes) is its real gate |
| `gh-oidc-entra-apply (write)` | App + SP, **Tier 0** | Federated, subject `…:environment:prod` | N2, N3; gated by the `prod` reviewer and a main-only deployment branch | **N1**; N6 needs a risk acceptance: lab acceptance in [ADR 0005](../adr/0005-risk-acceptance-apply-identity-tier0.md), register E1. The opt-in `enable_app_management_roles` adds `AppRoleAssignment.ReadWrite.All`, a second Tier-0 permission |
| `midpoint-reader` (manual, `lab/pam/README.md`) | App + SP | **Client secret** | Read-only Graph scopes | **N2**, N1; not in Terraform. `Set-AppGovernancePolicy.ps1` would cap any new secret on it at 90 days (never run) |
| Containment playbook identity (`pb-identity-contain`, ADR 0017) | System-assigned managed identity | None (managed) | N4; N6: four Graph app roles, each justified in `Deploy-ContainmentPlaybook.ps1` | The opt-in `-GrantDisableRole` adds a **standing** Authentication Administrator assignment outside PIM: exception E7. Whoever can edit the Logic App in `rg-identity-lab` controls that role |
| Key Vault UAMI (`modules/keyvault`) | User-assigned managed identity | None (managed) | N4: Secrets User, ABAC-limited to named secrets (`tests/uami_abac.tftest.hcl`) | n/a |
| DC01 VM identity (`modules/dc-vm`) | System-assigned managed identity | None (managed) | N4: Secrets Officer, ABAC-limited to three secrets | ABAC on Key Vault is preview (verify) |
| `clinical-apps:nightly-report` (`lab/terraform/k8s/identity`) | Kubernetes SA → Vault role | Projected SA token, audience `vault`; Vault token 15 min | N3, N7: no Kubernetes Secret, admission policy pins images | n/a. The Entra Workload ID mapping (`lab/terraform/k8s/aks-mapping`) is **never applied** |
| Conjur `apps/nightly-report` (`lab/pam/conjur/policy.yml`) | Conjur workload host | API key | Policy-as-code allow and deny | N7: the API key is a lab shortcut (the policy comment says so) |
| `svc-backup`, `svc-vault-rotator` (`lab/scripts/dc/02-Configure-Domain.ps1`) | AD service accounts | Vault-rotated | N11 (vaulted, rotated) | gMSA not evaluated |
| AI review workflow (`ai-review.yml`) | Uses the **PLAN** identity | Federated | n/a | **N10**: this is an advisory reviewer under a shared identity, not an agent identity, and must not be described as one |
| "Contoso Access Review Assistant" (`post-apply/New-AgentIdentity.ps1`; its runtime managed identity comes from `enable_agent_identity`) | Entra Agent ID blueprint + agent identity | Federated credential from a managed identity; no secret | N1 (owners), N2, N10 (its own identity, a human sponsor) | Identity only: no permission granted and no runtime. Never run against a tenant |

## 3. Leaver hand-off

1. HR raises a leaver event, or a role change for an NHI owner.
2. IAM lists the objects the user owns (`ownedObjects`) and any NHI where they
   are the **sole** owner.
3. The owner's manager names a new owner before the disable date. If nobody is
   named, the NHI is disabled when the owner leaves and goes on the exception
   register.
4. Credentials the leaver could have seen (secrets, certificates) are rotated.

`04-Leaver.ps1` step 7 implements part of this; it has never run against a
tenant. By default it reports what the leaver owns (app registrations,
service principals, agent identities) and changes nothing. With
`-NhiHandoff ReassignToManager` it adds the manager as owner before removing
the leaver, but only for low-privilege NHIs. One with a Tier-0 permission or
a directory role is flagged for review, never handed to a manager, and one
holding a secret or certificate is flagged for rotation. Two gaps remain: it
runs after the disable, not before, and step 3's "manager names a new owner"
is not a workflow.

## 4. Review cadence and inventory

| Activity | Cadence | Output |
|---|---|---|
| NHI inventory: owner, credential type and expiry, last sign-in, high-privilege roles | Monthly, automated | Inventory CSV in the evidence pack |
| Owner attestation | Quarterly | Signed-off review |
| Tier-0 NHI permission review | Quarterly, by IAM and the CISO | Renewed risk acceptance or a reduction |

The design is in [ADR 0018](../adr/0018-nhi-ownership-and-agent-identity-sponsorship.md). `06-NHI-Inventory.ps1` produces the monthly inventory: owners, credential
type and expiry, last sign-in and Tier-0 permissions, with findings mapped to
the rules above. It has been tested only against a built-in mock tenant
(`-Offline`, labelled `offline-mock` so it can never pass for evidence).
`Find-ShadowAdmins.ps1` adds the owners of Tier-0 apps. Owner attestation
and the Tier-0 permission review have no tooling.

The secrets that live outside Entra (the lab's own long-lived secrets, such
as stack passwords, API keys and tokens) are listed in a register,
`lab/iga/nhi-secrets-register.json`: names, owners, store locations and
dates only, never a value. `06-NHI-Inventory.ps1 -SecretsRegisterPath`
reads it and reports SECRET-NO-OWNER, SECRET-EXPIRED, SECRET-NO-EXPIRY and
SECRET-NO-ROTATION. Like the rest of the inventory, this is tested offline
only.

## 5. Gaps summary

1. No owners on the pipeline apps (`modules/pipeline-identity`). The SSO
   apps in `modules/apps` set owners.
2. The app management policy (`Set-AppGovernancePolicy.ps1`: no new
   secrets on new apps, capped certificate and secret lifetimes) and the
   consent policy (`Set-ConsentPolicy.ps1`) have never been applied.
3. The inventory has never run against a tenant, and there is no
   attestation tooling.
4. The leaver hand-off is partial (§3).
5. `midpoint-reader` uses a client secret.
6. The agent identity is identity only and has never been created. The AI
   reviewer must not be called one.

verify:
- the licensing for tenant-wide app management policies (the default
  `appManagementPolicy` and its `passwordAddition` / key-lifetime
  restrictions). Some Microsoft pages tie them to Workload ID Premium.
- that Conditional Access for workload identities (service principals)
  needs Workload ID Premium. The lab applies no CA to the pipeline
  identities.
- Key Vault data-plane ABAC preview status (also flagged in
  `lab/terraform/README.md`).
