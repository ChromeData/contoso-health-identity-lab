# Non-Human Identity (NHI) Standard

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario): app registrations, service principals, managed identities, federated workload identities, Kubernetes service accounts, AD service accounts, vault workload hosts, AI agents |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering. Each NHI has a named human owner (N1). Design: [ADR 0018](../adr/0018-nhi-ownership-and-agent-identity-sponsorship.md) |

## 1. Rules

| # | Rule |
|---|---|
| N1 | **An owner is required:** at least **two** human owners, or one plus a team group. An NHI without an owner is disabled after 30 days |
| N2 | **No password credentials.** No client secrets on app registrations: federated credentials first, then managed identities, then certificates |
| N3 | **Federation is preferred** for CI/CD and external workloads, with an exact, environment-scoped subject, never a wildcard or a branch name alone |
| N4 | **Managed identity for Azure-hosted workloads,** RBAC scoped to the resource, with ABAC conditions where supported |
| N5 | **Certificates last 180 days at most.** Entra refuses longer on apps created after the app management policy's cut-off (`Set-AppGovernancePolicy.ps1`); on older apps the inventory reports it (`CRED-LONG-LIVED`). Certificates live in Key Vault, never on disk or in a repo |
| N6 | **Least privilege.** Graph application permissions are listed and justified. `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` and `Directory.ReadWrite.All` make an NHI **Tier 0** and need a risk acceptance |
| N7 | **Short-lived tokens:** audience-bound, 1 h or less; no long-lived token stored as a secret |
| N8 | **Quarterly review.** Owners attest purpose, permissions and credentials; credentials unused for 90 days are removed; NHIs with no sign-in for 90 days are disabled |
| N9 | **Leaver hand-off:** ownership is reassigned before an owner's account is disabled (§3) |
| N10 | **AI agents get their own identity,** with a human sponsor, scoped permissions and no shared secrets. A workflow that calls a model under someone else's identity isn't an agent identity |
| N11 | **AD service accounts** are vaulted and rotated (privileged-access standard §3), gMSA where the application supports it, and denied interactive logon |

## 2. How the lab maps

| NHI (lab) | Type | Credential | Rules met | Rules not met |
|---|---|---|---|---|
| `gh-oidc-entra-plan (read-only)` | App + SP | Federated, `…:pull_request` | N2, N3, N6 | **N1**: no `owners` in `modules/pipeline-identity` |
| `gh-oidc-entra-apply (write)` | App + SP, **Tier 0** | Federated, `…:environment:prod` | N2, N3; `prod` reviewer and main-only deployments | **N1**; N6 needs a risk acceptance: [ADR 0005](../adr/0005-risk-acceptance-apply-identity-tier0.md), register E1 |
| `midpoint-reader` | App + SP | **Client secret** | Read-only Graph scopes | **N2**, N1; not in Terraform (exception E3) |
| Containment playbook identity (ADR 0017) | System-assigned managed identity | None | N4; N6, each Graph app role justified in `Deploy-ContainmentPlaybook.ps1` | The opt-in `-GrantDisableRole` adds a standing Authentication Administrator assignment (exception E7) |
| Key Vault UAMI, DC01 VM identity | Managed identities | None | N4, ABAC-limited to named secrets | Key Vault data-plane ABAC is preview (verify) |
| `clinical-apps:nightly-report` (Kubernetes) | SA → Vault role | Projected SA token, audience `vault`; Vault token 15 min | N3, N7; no Kubernetes Secret | The Entra Workload ID mapping is **never applied** |
| Conjur `apps/nightly-report` | Conjur host | API key | Policy-as-code allow and deny | N7: the API key is a lab shortcut |
| `svc-backup`, `svc-vault-rotator` | AD service accounts | Vault-rotated | N11 | gMSA not evaluated |
| The lab's own secrets outside Entra (stack passwords, API keys, tokens) | Register entries | Stored in their own stores | Listed by name, owner, store and dates in `lab/iga/nhi-secrets-register.json` (12 entries) | Checked offline only (`06-NHI-Inventory.ps1 -SecretsRegisterPath`) |
| AI review workflow (`ai-review.yml`) | Uses the **PLAN** identity | Federated | n/a | **N10**: an advisory reviewer under a shared identity, never described as an agent |
| "Contoso Access Review Assistant" (`New-AgentIdentity.ps1`) | Entra Agent ID blueprint + agent identity | Federated from a managed identity | N1, N2, N10 | Identity only: no permission, no runtime, never run |

## 3. Leaver hand-off

1. HR raises a leaver event, or a role change for an NHI owner.
2. IAM lists what the user owns (`ownedObjects`) and any NHI where they are
   the **sole** owner.
3. The owner's manager names a new owner before the disable date. If nobody
   is named, the NHI is disabled when the owner leaves and goes on the
   exception register.
4. Credentials the leaver could have seen are rotated.

`04-Leaver.ps1` step 7 implements part of this (never run against a
tenant): by default it reports what the leaver owns and changes nothing;
with `-NhiHandoff ReassignToManager` it hands low-privilege NHIs to the
manager. Tier-0 or role-holding NHIs are flagged for review, never handed
over; secret-holding ones are flagged for rotation. Gaps: it runs after the
disable, not before, and step 3 is not a workflow.

## 4. Review cadence and inventory

| Activity | Cadence | Output |
|---|---|---|
| NHI inventory: owner, credential type and expiry, last sign-in, high-privilege roles, registered secrets | Monthly, automated | Inventory CSV in the evidence pack |
| Owner attestation | Quarterly | Signed-off review |
| Tier-0 NHI permission review | Quarterly, IAM and the CISO | Renewed risk acceptance or a reduction |

`06-NHI-Inventory.ps1` produces the monthly inventory with findings mapped
to the rules above. With `-SecretsRegisterPath` it also reads the secrets
register and reports SECRET-NO-OWNER, SECRET-EXPIRED, SECRET-NO-EXPIRY and
SECRET-NO-ROTATION. Tested only against a built-in mock tenant (labelled
`offline-mock`, so it can never pass for evidence). Owner attestation and
the Tier-0 permission review have no tooling.

verify: whether tenant-wide app management policies need Workload ID
Premium; CA for workload identities does, and the lab applies none to the
pipeline identities.
