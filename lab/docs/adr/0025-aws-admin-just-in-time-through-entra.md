# ADR 0025: AWS administration is just-in-time through Entra PIM, not the root user

- **Status:** RAN · tenant (2026-11-05). The Entra side was applied by CI (#132); `adm-labops` was created, enrolled and made eligible; the operator applied `LabAdministrator` once (targeted, before v2); then `adm-labops` activated `PIM-AWS-Lab-Admins` in the PIM portal (10:44Z, 2 h, MFA + reason), SCIM put it in the AWS group, `aws sso login` gave a LabAdministrator session in 182002546409, and with that session guardrails v2 were applied (10:57:02Z, CloudTrail `PutRolePolicy` by `AWSReservedSSO_LabAdministrator_.../adm-labops@...`) and `idlab-admin` was removed. The operator now gets "explicit deny" on Identity Center, identity store, IAM and account-creating writes. Capture log E95-E99.
- **Date:** 2026-11-05
- **Risk owner:** Identity platform owner (in the lab, the repository maintainer)
- **Next review:** 2027-02-05, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

The lab's AWS account (182002546409) is the AWS Organizations management
account and holds the IAM Identity Center instance. Until now there were
three ways to administer it, and none was acceptable:

1. **The root user.** It was the only way to change IAM: the lab operator
   (ADR 0024) is denied every IAM write, so applying the operator's own
   guardrail change, or any IAM change at all, meant the owner's root
   password plus an emailed code. Root cannot be scoped, time-boxed or
   switched off from Entra, and CloudTrail records "root", not a person.
   Read on 2026-11-05: root has no access keys, and **no MFA device**
   (`AccountMFAEnabled = 0`); its last sign-in was 2026-11-05T02:09Z.
2. **The operator, around its own Deny.** Its IAM Deny did not cover IAM
   Identity Center or the identity store. With `sso:*` and `identitystore:*`
   still allowed, the operator could create a permission set with
   AdministratorAccess, create a local Identity Center user (or a SCIM
   token) and assign the set: a second admin path that never touches IAM
   and survives the Entra kill switch.
3. **A leftover local admin.** `idlab-admin`, a local Identity Center user
   (not an IAM user: the account has none) made by root on 2026-10-28,
   held a console-made `AdministratorAccess` permission set. It could not
   sign in since the identity source moved to Entra, but it was a standing
   admin assignment nobody owned.

The rest of the lab already answers "how does anyone get admin power?" the
same way every time: an eligible membership, activated through PIM for a
stated reason, for a short time, in a log (ADR 0002, ADR 0020). AWS was the
exception.

## Options considered

1. **Keep root for IAM changes.** Rejected for the reasons above. Root
   stays, as AWS's own break-glass, not as an admin path.
2. **Give the operator IAM rights.** Rejected. An unattended Tier-0 workload
   with standing AWS admin could mint access (an IAM user with keys, a role
   with a foreign trust) that outlives the Entra kill switch.
3. **A standing admin: an IAM user, a local Identity Center user, or a
   permanent Identity Center assignment to an Entra admin account.**
   Rejected: standing access, and for the first two a credential Entra
   cannot see or disable.
4. **PIM for Groups feeding an Identity Center permission set (chosen).**
   This is the pattern Microsoft documents for PIM with app provisioning
   (Learn, *PIM for Groups*, "Privileged Identity Management and app
   provisioning"): an always-active all-users group with a low role and an
   eligible privileged group with the privileged role, both assigned to the
   application. Activating membership triggers SCIM for that membership
   within 2-10 minutes.

## Decision

**The only AWS admin path is a PIM activation in Entra.**

```
adm-labops (or any admin account made eligible)
  -> PIM for Groups: activate PIM-AWS-Lab-Admins          modules/pim aws.tf
       2 h maximum, MFA, written justification,
       every activation mailed to the security mailbox
  -> the group is the AWS app's second principal          modules/apps
       (eligible = not assigned: no SAML sign-in to AWS at rest)
  -> SCIM copies the ACTIVE membership (2-10 min)
  -> Identity Store group PIM-AWS-Lab-Admins
  -> permission set LabAdministrator                      lab/terraform/aws lab-admin.tf
       AWS managed AdministratorAccess, 1-hour sessions, account 182002546409
```

| Control | Rule | Where |
|---|---|---|
| Root | Not used to administer. No access keys. Its email is an alias only the owner reads. Root is AWS's break-glass, like the Entra break-glass accounts | Read with `aws iam get-account-summary`; owner step below for MFA |
| Operator | AdministratorAccess minus: every IAM write and PassRole; every IAM Identity Center, identity store and Identity Center directory write (no permission set, assignment, local user, group, SCIM token or identity-source change); Organizations writes that add accounts, delegate administration or change policies; `sts:AssumeRoot`; Roles Anywhere; closing or detaching the account | `entra-operator.tf` guardrails v2 (Deny, account-wide) |
| PIM group | `PIM-AWS-Lab-Admins`, role-assignable (only Privileged Role Administrators, Global Administrators and owners change it, and nobody else can reset its members' credentials), eligible-only, eligibility expires after 180 days, direct active membership expires and needs justification + MFA, reviewed quarterly | `modules/pim/aws.tf`, `reviews.tf` |
| AWS app | Two principals, each its own resource: the staff group (ViewOnlyAccess) and the PIM group. No list of extras | `modules/apps/main.tf` |
| Permission set | `LabAdministrator`, AWS managed AdministratorAccess, PT1H, assigned only to the SCIM-created `PIM-AWS-Lab-Admins` group, optionally pinned to the Entra object id | `lab/terraform/aws/lab-admin.tf` |
| Leftovers | `idlab-admin`, its assignment and the console-made `AdministratorAccess` set are removed, with the PIM path, as its first use | One-time step, capture log |

**The first admin account: `adm-labops`.** A cloud-only user,
`adm-labops@contosohealthlab.onmicrosoft.com`, display name "Lab
Operations (automation)", employee type "Automation account". It is not a
row in `lab/iga/admin-accounts.json`: that register is one admin account per
PERSON, owned by their HR record, signing in with a passkey and inside
`Admin-Accounts` (the admin passkey target, and CA002's scope once CA002 is
enforced). This account is driven by the helpers who finish the lab on the
owner's behalf, so it signs in with a password and an authenticator-app
code, both generated on the admin Mac and held only in its login Keychain
(the staff sign-in toolkit, `lab/scripts/demo/signin`). Following ADR 0018's
owner/sponsor split, its **sponsor** is the owner (the person who answers
for it); it has no Entra role, no licence and no mailbox, and its only
access is eligibility for `PIM-AWS-Lab-Admins`. It exists so that no helper
ever uses the owner's own account, and so that every AWS admin action
appears in CloudTrail under a named Entra identity
(`AWSReservedSSO_LabAdministrator_.../adm-labops@...`), not "root".

**Why no approval.** PIM never lets a requester approve their own request,
and the lab has one human admin. Approval would make the AWS admin path
depend on a second person who does not exist. Instead every activation and
every eligibility change is mailed to the security mailbox, activations are
capped at two hours, AWS sessions at one, and the activation reason is in
the PIM audit log. `aws_admin_require_approval = true` routes approval to
`PIM-Approvers-Tier0` the day a second admin exists.

## Compensating controls

- The group is role-assignable: a Helpdesk, Authentication or User
  Administrator cannot reset `adm-labops`'s credentials and activate on its
  behalf (Learn's warning about activation without approval).
- Eligible is not assigned: at rest `adm-labops` is not in the AWS app's
  scope, so Entra refuses the SAML sign-in and AWS has no active member in
  the group.
- 2-hour activation, 1-hour AWS session, 180-day eligibility, quarterly
  review with silence = deny.
- Every AWS admin action carries the Entra user's name in CloudTrail; every
  activation is a PIM audit record with its justification.
- The Entra kill switch still works: disabling `adm-labops` (or removing its
  eligibility) ends new AWS admin sessions.

## Consequences and residual risk

- **Root has no MFA yet.** Registering a hardware security key on root is an
  owner step (it needs the root password, the emailed code and the physical
  key). Until then root is protected by its password and the emailed
  sign-in code only. Not done by this change.
- **One Keychain, two credentials.** `adm-labops`'s password and TOTP seed
  sit in the same login Keychain as the operator's certificate key (ADR
  0024): whoever holds the unlocked Mac holds both. TOTP is not
  phishing-resistant, which is why the account is kept out of CA002's scope
  (it would lock it out). Revisit trigger below.
- **An AWS-provisioned admin account needs a name.** AWS's SCIM endpoint
  refuses a user without `name` ("name: The attribute name is required",
  provisioning log 2026-11-05T10:45:44Z): the PIM-triggered provisioning of
  `adm-labops` failed until it was given a given name and surname. An
  `adm-first.last` account from `New-AdminAccounts.ps1` has neither, so it
  needs both before it is made eligible here.
- **AWS admin can outlive the activation.** Learn documents the fast SCIM
  path for activation; removal waits for the next 40-minute cycle, and an
  AWS session already issued lasts its hour. Worst case about 1 h 40 min
  past the activation's end. Measured 2026-11-05 (E99): ended at 11:01:07Z,
  out of the AWS group and the AWS user disabled by 11:14:21Z; new
  LabAdministrator credentials were refused from then on, while the
  credentials already issued kept working until they were thrown away.
- **Entra Tier 0 is AWS admin.** Anyone who can make a user eligible and
  activate (Privileged Role Administrators, Global Administrators, the
  operator through its Graph roles) can reach AWS admin. That path is
  visible (PIM audit, activation mail, provisioning log, CloudTrail with the
  user's name) and dies with the Entra account, unlike the paths this ADR
  closes. Inside AWS an activated admin can still create AWS-local access
  (an IAM user with keys); an alert on `iam:CreateUser` / `CreateAccessKey`
  is not written.
- **Management account, group assignment.** AWS recommends user
  assignments and a delegated administrator account. The lab has one
  account; the group's membership is Tier-0-controlled in Entra, which is
  the risk AWS's recommendation is about.
- **IAM and Identity Center changes now need an activation.** The operator
  can no longer apply the IAM or Identity Center resources in
  `lab/terraform/aws`; those applies run with the `idlab-labadmin` profile
  (a LabAdministrator session). The patient-portal bucket stays operator-applied.

## Session Manager: the same rule for servers (added 2026-11-07)

**Status:** RAN · tenant 2026-11-07 (capture-log E125-E127), then switched
off to save cost. Code: `lab/terraform/aws/session-manager.tf`.

**Decision.** Server access in AWS follows the same rule as AWS admin: no
standing access, a PIM activation first. The lab's AWS server has no inbound
port, no SSH key and no public IP. The only way in is a Session Manager
shell, logged command by command to CloudWatch Logs, and only the
`LabServerSession` permission set can open one: shell document only, servers
tagged `session-access = lab-server-session` only, own sessions only.
`LabServerSession` is assigned only to the SCIM copy of `PIM-AWS-Lab-Admins`.

**Why Session Manager and not a bastion or SSH.** No port to scan, no key to
leak or rotate, a per-command log, and the identity on every session is the
Entra person (`.../AWSReservedSSO_LabServerSession_.../adm-labops@...`). It
is AWS's own tool for AWS servers (program brief 2026-11-06); Azure servers
use Azure Bastion.

**Consequences (seen live).**
- The split by person is not done: the same PIM group holds
  LabAdministrator and LabServerSession. A server-only group is the next
  step.
- The same residual as above, twice: issued 1-hour credentials outlive the
  activation, and an open shell is not re-checked when the activation ends
  (one stayed open more than 20 minutes after SCIM disabled the AWS user).
  The preferences cap every shell at 60 minutes; `terminate-session` ends one
  at once. Not built: an automatic "end open sessions when the activation
  ends" action.
- `ssm-user` can `sudo` on Amazon Linux. Every command is still logged.
- The lab operator opened a shell with no activation in the live run
  (standing AdministratorAccess). Guardrails v4 (`NoServerShell`,
  `NoSessionLogTampering` in `entra-operator.tf`) close that in code; they
  are BUILT, not applied, and go live with the next LabAdministrator apply.
- Sources (checked 2026-11-06): AWS Systems Manager User Guide, "Additional
  sample IAM policies for Session Manager" (ssm:resourceTag, own sessions
  via aws:ssmmessages:session-id), "Session document schema", "Logging
  session data", VPC endpoints for Systems Manager.

## Revisit trigger

- A second human admin: turn on `aws_admin_require_approval`, and give that
  person their own `adm-first.last` account with eligibility.
- A phishing-resistant method that works headless for `adm-labops`
  (certificate-based authentication, or a passkey held in a hardware or
  OS key store): register it, remove TOTP, and add `PIM-AWS-Lab-Admins` to
  CA002.
- A member account appears: move LabAdministrator to the member account and
  run Identity Center from a delegated administrator account.

## Evidence

- Offline: `terraform test` in `modules/pim` (`aws_admin_*` runs),
  `modules/apps` (`aws_admins_*`), `envs/dev` (`mock_plan`), and
  `lab/terraform/aws` (`lab_admin.tftest.hcl`, `entra_operator.tftest.hcl`).
- Live: capture-log rows for the account, the activation, the AWS sign-in,
  the guardrails v2 apply, the `idlab-admin` removal and the operator's
  explicit deny on an Identity Center write.

## Sources (checked 2026-11-05)

- https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups
  (role-assignable protections incl. eligible members; activation triggers
  SCIM in 2-10 minutes; two groups per app, the privileged one eligible)
- https://docs.aws.amazon.com/singlesignon/latest/userguide/useraccess.html
  (assigning access in the management account; users, not groups, recommended)
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycenter.html
  (the `sso:` actions the operator guardrail denies)
