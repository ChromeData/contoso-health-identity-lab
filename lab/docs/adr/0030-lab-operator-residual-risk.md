# ADR 0030: Lab operator residual risk - read-only by default, writes only in an owner-opened session

- **Status:** BUILT (2026-11-06). Not applied. The owner applies `lab/terraform/envs/operator` himself. Until he does, the operator still holds the grants listed in ADR 0024.
- **Date:** 2026-11-06
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-06, or earlier on any revisit trigger below
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.
- **Amends:** [ADR 0024](0024-lab-operator-workload-identity.md). It retires the ADR 0024 amendment "who applies `envs/operator`" (2026-11-05).
- **Source:** hostile review 2026-11-06, finding B1 and parts of B2 and E1.

## Context

The lab says "no standing admin". A review found that the claim was not
true for one identity: the **lab operator** (ADR 0024).

- It is a service principal. Its only credential is a certificate. The
  private key is in the login Keychain of the owner's Mac.
- It held these Graph application permissions all the time:
  Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
  RoleManagement.ReadWrite.Directory, UserAuthenticationMethod.ReadWrite.All,
  User.ReadWrite.All, GroupMember.ReadWrite.All and ten other writes.
- It held **Owner** on the lab subscription.
- No Conditional Access policy applies to it.
- It applied changes to its own permissions (ADR 0024 amendment, 2026-11-05).

Each permission was added with the note "no new reach: the operator was
already Tier 0". That reasoning is wrong. Being Tier 0 already is a reason
to remove rights, not a reason to add more. **This ADR retires that
reasoning.** A new grant must now say which job needs it and for how long.

So in practice, the lab moved standing Global-Administrator-level power from
a person (with MFA and CA020) to an unattended identity (with no CA and a
key in a file). This ADR reduces that power and states what remains.

## Decision

### 1. Standing rights are read-only

Between sessions, the operator holds only what its routine jobs need. Those
jobs are reads: the KPI one-pager, the NHI inventory, the SoD report, the
drift check, the evidence read-back and the demo's read-only checks.

| Where | Standing (every day) |
|---|---|
| Graph | 12 read permissions (Directory.Read.All, AuditLog.Read.All, Policy.Read.All, the PIM, review, workflow and Intune reads, SecurityEvents.Read.All) |
| Azure | Reader, Storage Blob Data Contributor (Terraform state lease; the evidence container's immutability policy still refuses deletes), Key Vault Secrets User |
| Entra role | Security Reader |

A variable validation refuses a write permission in the standing Graph list.
A second validation refuses Owner, User Access Administrator and Role Based
Access Control Administrator in the standing Azure list.

**Effect on the evidence store (finding E1).** Without Owner, the operator
has no `Microsoft.Authorization/*/write` or `*/delete`. So it cannot remove
the evidence store's `CanNotDelete` lock, and it cannot create a role
assignment.

### 2. Writes exist only in a write session

The owner opens a **write session** with a human apply of `envs/operator`:

```hcl
operator_write_session = {
  opened_utc  = "2026-11-07T14:00:00Z"
  expires_utc = "2026-11-07T18:00:00Z"
  reason      = "recording day: demo resets and TAPs"
}
```

He closes it with a second apply, with the variable unset.

- **Window:** at most 8 hours. The variable validation refuses a longer one.
  A plan after `expires_utc` fails, so a stale session cannot be re-applied.
- **Graph:** the 16 write permissions in `operator_session_graph_roles` are
  granted. Graph application permissions have no PIM and no expiry. So the
  owner's closing apply removes them.
- **Azure:** a custom role, **Contoso Lab Operator Session**, and Key Vault
  Secrets Officer. They are **time-bound active** PIM assignments. Azure ends
  them at `expires_utc` by itself, even if nobody closes the session.
- **The custom role** is Contributor minus: the storage account, container
  and immutability-policy deletes and writes; the Log Analytics workspace
  delete, purge and table delete; the workspace and table writes, which can
  lower retention; and diagnostic-setting writes and deletes. So even in a
  session, the operator cannot erase the evidence store or the sign-in logs,
  or make them expire early.

**Why time-bound active, not eligible.** Microsoft Learn (Azure RBAC,
"Eligible and time-bound role assignments"): "you can't create eligible role
assignments for applications, service principals, or managed identities
because they can't perform the activation steps." Entra directory roles and
Graph app roles have no eligibility for service principals either. Time-bound
active is the closest option Microsoft offers a service principal.

### 3. Only the owner applies `envs/operator`

The 2026-11-05 amendment to ADR 0024 let the operator apply its own
permissions after a PR merge. That amendment is **retired**. An identity
must not approve or apply changes to its own permissions. The owner applies
this root, signed in as himself. Without Owner, the operator cannot apply it
outside a session anyway: the root writes Azure role assignments.
`envs/bootstrap` role-assignment changes go back to the owner for the same
reason.

### 4. Conditional Access for the operator: DESIGNED, blocked by licence

`workload-ca.tf` holds CA090: block the operator from every location except
the owner's network. It is off (`enable_operator_workload_ca = false`).

**Blocker:** Microsoft Learn: "Workload Identities Premium licenses are
required to create or modify Conditional Access policies scoped to service
principals." The tenant has no such licence (subscribedSkus, read as the
operator on 2026-11-07: INTUNE_A, SPE_E5, ID Governance step-up for P2). The
lab buys nothing. Microsoft offers a Workload ID Premium trial. Starting it
is the owner's decision. When licensed, CA090 starts report-only (ADR 0003).
It is a new policy and changes no existing policy.

## The honest count of standing Tier-0 principals

Say this number, not "zero".

| Principal | Kind | Why it is Tier 0 | After this ADR |
|---|---|---|---|
| The build account (the owner's admin account) | Human | Standing Global Administrator | Still standing until `Convert-BuildAccountToEligible.ps1` runs (owner task; agents must not change the owner account) |
| APPLY (`gh-oidc-apply`) | Workload, GitHub OIDC, no stored secret | Writes CA, PIM and roles (ADR 0005) | Unchanged. Runs only after the owner approves a gated apply |
| The lab operator | Workload, certificate in Keychain | Graph writes + Azure Owner | **Not standing Tier 0 any more.** Tier 0 only inside a session the owner opens, for at most 8 hours |
| bg-admin-01, bg-admin-02 | Human (break-glass) | Global Administrator by design | Unchanged (ADR 0003) |

So: **1 standing human admin outside break-glass, 1 standing Tier-0 workload
identity (APPLY), and 1 Tier-0 workload identity that is Tier 0 only during
a session.**

## What remains (residual risk, accepted for the lab)

1. **Inside a session, the operator is still Tier 0.**
   AppRoleAssignment.ReadWrite.All can grant any Graph permission, including
   to itself, and the grant would outlive the session. The owner's closing
   apply removes the reviewed grants, but not a grant the operator made
   outside Terraform. Mitigation: a detection for any change to the
   operator's own app role assignments (the detection work, not this PR),
   and the NHI inventory, which compares live grants with this root.
2. **Graph writes do not expire by themselves.** If the owner forgets to
   close a session, the Graph writes stay. Azure's part ends on time. The
   plan check stops a stale session from being re-applied, but it does not
   remove anything. Mitigation: close the session in the same sitting.
3. **The key is a file-based key in a login Keychain.** Whoever holds the
   unlocked Mac holds the operator's standing reads, and its writes during a
   session. Mitigation (owner task): move the key to the Secure Enclave or a
   YubiKey PIV slot.
4. **UserAuthenticationMethod.ReadWrite.All in a session can add a
   credential to a break-glass account.** Break-glass accounts are excluded
   from every CA policy (ADR 0003). So during a session the operator is, in
   effect, a CA-exempt Global Administrator. Mitigation: no TAP or passkey
   work in a session unless it is the reason for the session; a detection
   for any auth method added to a Break-Glass-Admins member (detection
   work, not this PR).
5. **No location limit.** Until CA090 is licensed, the certificate works from
   any network.
6. **Storage Blob Data Contributor stays standing** at subscription scope
   (the state account's ReadOnly lock blocks narrower assignments). In the
   evidence container the immutability policy refuses deletes and overwrites
   inside the retention period. The policy is Unlocked in the lab, by rule.
   Production locks it.
7. **AWS is unchanged.** The operator's AWS role is AdministratorAccess
   minus every IAM write (ADR 0024, ADR 0025). AWS sessions already issued
   stay valid up to an hour after the kill switch.

## Production

- Split the operator by blast radius: a read-only reporter, and a separate
  write identity with no credential at rest.
- Hardware-backed key.
- CA for workload identities, pinned to the automation network.
- Evidence in a separate subscription where the identity team has no
  Owner, with the immutability policy locked.

## Revisit triggers

- Workload ID Premium is licensed: turn on CA090, report-only first.
- A second maintainer, or the Mac stops being single-user: hardware key.
- Any new permission for the operator: it goes in the session list unless
  a routine read job needs it. It names the job and the window.
- A session is found open after its window: shorten the maximum window.

## Evidence

- Offline: `terraform test` in `lab/terraform/envs/operator`, 12 runs. They
  pin: no standing Graph write, no standing Owner, the session window
  (at most 8 hours, a stale one fails the plan), the session role's
  NotActions, and CA090 off and report-only.
- Live: none yet. The owner's first apply after this merge is the first run.
  Capture it as a new capture-log row: the operator's app role assignments
  before and after, and the Azure role assignments.

## Follow-up (2026-11-08): a sandbox for throwaway test objects, and a time-boxed Intune write

Three proofs create and delete their own Azure objects in one run: the
Kubernetes Key Vault pipeline (`lab/k8s/ci`), the Key Vault state-leak proof
(`lab/secrets/state-leak`) and the Bastion recording capture (`lab/bastion`).
Each needs a storage account or a vault plus role assignments on it. Under
this ADR the operator cannot do either, even in a session: the session role
keeps `storageAccounts/write` in NotActions (the evidence store) and has no
`Microsoft.Authorization` write.

The answer is a scoped path, not Owner (`envs/operator/sandbox.tf`):

- One standing resource group, `rg-lab-sandbox`, that holds only throwaway
  objects.
- During a session only, the operator gets **Contributor** and **Role Based
  Access Control Administrator** at that resource group's scope, as
  time-bound active PIM assignments that end with the session.
- **Limit, said plainly:** `azurerm_pim_active_role_assignment` takes no ABAC
  condition, so the RBAC Administrator grant is not narrowed to data roles.
  Inside the sandbox, during a session, the operator could assign any role.
  Nothing it assigns there reaches outside that resource group.

`DeviceManagementConfiguration.ReadWrite.All` joins the session Graph roles,
time-boxed to the E5 trial (ends 2026-11-26), for the Intune EPM and LAPS
policies (ADR 0036). A `check` warns on every plan after that date until a PR
removes it.
