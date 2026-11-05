# ADR 0024: The lab operator — a certificate workload identity for unattended admin work, trusted by AWS through Entra

- **Status:** RAN · tenant (2026-11-04): applied by the admin; the operator signed in to Entra with its certificate and to AWS account 182002546409 as contoso-lab-operator; CreateAccessKey and UpdateAssumeRolePolicy were refused by the guardrail Denies.
- **Date:** 2026-11-04
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-04, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Some lab work runs outside the pipeline and needs admin rights: the human
bootstrap applies (`envs/bootstrap`, `lab/terraform/aws`), provisioning on
demand, demo resets and evidence checks. Until now all of it borrowed the
admin's own account. That account is behind MFA and CA020's 4-hour sign-in
frequency, so every session needs a person at a phone, and in AWS the only
working path was the root user plus an emailed code.

Weakening CA020 or MFA for the admin would undo a control the lab exists to
show. The work needs its own identity.

## Options considered

1. **Keep borrowing the admin account.** No new identity, but no unattended
   work, and every action is logged as the human.
2. **A second user account with a stored password and TOTP seed.** It looks
   like a person in the logs, falls under user CA policies it then has to be
   excluded from, and the stored seed defeats MFA's point.
3. **A workload identity with a certificate (chosen).** Entra's model for
   non-human callers: no password, no MFA prompt, its own sign-in log
   category. For AWS, either an IAM user with access keys (static keys, which
   the lab forbids), IAM Roles Anywhere (a second PKI to run), or web-identity
   federation to Entra (chosen): AWS trusts tokens Entra issues to this one
   service principal.

## Decision

`lab/terraform/envs/operator` (human-applied) creates the **lab operator**:
an app registration and service principal whose only credential is a
179-day certificate made on the admin's Mac (`lab/scripts/operator`). The
private key's lasting copy is a login Keychain item; a session copy (mode
600) exists only between sign-in and sign-out.

- **Microsoft Graph:** Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
  Directory.Read.All, Synchronization.ReadWrite.All, AuditLog.Read.All,
  EntitlementManagement.ReadWrite.All, Policy.Read.All; added 2026-11-05 after
  the map readiness check hit 403s: AccessReview, LifecycleWorkflows, PIM
  eligibility and policy reads, Intune device and configuration reads (all
  read-only), and User.DeleteRestore.All for demo-hire resets; then, to finish
  the lab's last tenant steps without borrowing the admin account,
  AdministrativeUnit.ReadWrite.All, RoleManagement.ReadWrite.Directory,
  LifecycleWorkflows.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All,
  User.ReadWrite.All and GroupMember.ReadWrite.All (no new reach: the
  operator was already Tier 0 through AppRoleAssignment.ReadWrite.All)
- **Azure, lab subscription:** Owner, Storage Blob Data Contributor,
  Key Vault Secrets Officer (Secrets User until 2026-11-05)
- **Entra role:** Security Reader (refreshing the tenant diagnostic setting)

`lab/terraform/aws/entra-operator.tf` registers the tenant's v2 issuer as an
IAM OIDC provider and creates `contoso-lab-operator`, which accepts only
tokens whose audience is the operator's client id and whose subject is its
service principal object id. The role has AdministratorAccess in the lab
account minus an account-wide Deny on **every IAM write** (and PassRole, IAM
Roles Anywhere and account closure). A Deny scoped to the operator's own
role is not enough: AdministratorAccess could create a second admin role,
assume it and shed the Denies, keeping access after the kill switch. IAM
changes in the lab account stay human-applied.

Two changes stay with the human admin by design: the AWS IAM objects above,
and the tenant diagnostic setting in `envs/bootstrap` (the operator holds
Security Reader, so it can plan that setting but not write it).

## Compensating controls

- Certificate only: no secret, no federated credential, 179-day validity
  inside the tenant's 180-day cap; `lab-signin.sh` warns 14 days ahead.
- The private key never goes on a command line or into the repo; it is
  passed to `security` on stdin.
- A separate az CLI profile (`~/.contoso-operator/azure`) keeps the
  operator's session apart from the admin's.
- `lab-signin.sh` refuses to continue unless Azure says the caller is the
  operator in the lab tenant and AWS says the account is 182002546409.
- One kill switch for both clouds: `kill-switch.sh` disables the service
  principal. Entra stops issuing tokens, so AWS stops issuing sessions.
- Every Azure sign-in is a service-principal sign-in in Entra's log; every
  AWS session is an `AssumeRoleWithWebIdentity` event in CloudTrail whose
  session name starts `lab-operator-`.

## Consequences and residual risk

The operator is **Tier 0**, like APPLY (ADR 0005), and for the same reason:
AppRoleAssignment.ReadWrite.All can grant any Graph permission, and Owner can
grant any Azure role. Whoever holds the Mac's unlocked login Keychain holds
the operator. `envs/operator` being human-applied is a change-control rule,
not a privilege boundary: the operator could rewrite its own grants through
the API.

Conditional Access for workload identities (Workload ID Premium) is not
licensed in the lab, so no location condition limits where the certificate
works. AWS sessions already issued stay valid up to an hour after the kill
switch.

## Revisit trigger

- A second maintainer, or the Mac stops being single-user: move the key to a
  hardware-backed store (Secure Enclave or a YubiKey PIV slot).
- Workload ID Premium is licensed: add a CA policy that pins the operator to
  the admin's network.
- Production: split the operator by blast radius, the same as APPLY (ADR 0005,
  option 3).

## Evidence

- Offline: `tofu test` in `lab/terraform/envs/operator` and `lab/terraform/aws`
  (`tests/operator.tftest.hcl`, `tests/entra_operator.tftest.hcl`).
- First run (2026-11-04): `lab-signin.sh` printed the operator in the lab
  tenant and the AWS role contoso-lab-operator in account 182002546409; the
  guardrail check returned "explicit deny" for CreateAccessKey and
  UpdateAssumeRolePolicy. (The first guardrail set protected only the role
  itself; review moved it to the account-wide IAM-write Deny above.) Still to capture: the Entra service-principal
  sign-in record and the CloudTrail `AssumeRoleWithWebIdentity` record.

## Amendment 2026-11-05: who applies `envs/operator`

The owner asked for the lab's remaining work to run without them. From this
date, after the first human apply, changes to `envs/operator` are applied by
the operator itself once their pull request is reviewed and merged. This
removes the last human-only change step for the operator, which was already a
change-control boundary rather than a privilege boundary (Consequences above):
the review and merge are now the control, as for every other change. Every
such apply is a service-principal sign-in plus "Add app role assignment"
audit events by the operator, which `app-consent-granted.kql` logs.

## Amendment 2026-11-05: PIM-group eligibility (ADR 0025)

`PrivilegedEligibilitySchedule.Read.AzureADGroup` becomes
`PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`, so the operator can
make the lab-operations admin account ELIGIBLE for `PIM-AWS-Lab-Admins`
(ADR 0025), the step `Set-PimGroupEligibility.ps1` does for people. It is
not given `PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup`: making a
member ACTIVE stays an activation by the member, with MFA and a reason. No
new reach: the operator was already Tier 0 (Consequences above).
