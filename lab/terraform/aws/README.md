# aws — IAM Identity Center permission sets as code (separately applied)

**No stand-in.** This root targets the real **AWS IAM Identity Center** (listed
under "Real products" in [`lab/docs/STAND-INS.md`](../../docs/STAND-INS.md)).

Entra ID decides **who** gets into AWS; this root decides **what** they get.
The Entra half of SAML and SCIM is now code too:
[`modules/apps`](../modules/apps/README.md), behind the `enable_sso_apps` and
`enable_scim_provisioning` flags, not yet applied. It builds the gallery app,
the signing certificate, the claims and the single group assignment, plus the
provisioning job and its Key Vault-sourced credential. The AWS half has no
API: switching the identity source and enabling automatic provisioning stay
console steps (step 2 of [Order of operations](#order-of-operations) below).
This root codifies the step after that, the permission set and its
assignment, which used to be pure console clicks:

| Object | Terraform | Value |
|---|---|---|
| IAM Identity Center instance | `data.aws_ssoadmin_instances.this` | looked up in `var.aws_region`; fails the plan loudly if none |
| Entra group, as SCIM created it | `data.aws_identitystore_group.aws_users` | `App-AWS-IdentityCenter-Users`, looked up by `DisplayName` (**read only**) |
| Permission set | `aws_ssoadmin_permission_set.view_only` | `ViewOnlyAccess`, session `PT4H` |
| Policy on the permission set | `aws_ssoadmin_managed_policy_attachment.view_only` | `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` (AWS managed, job-function; the partition comes from `data.aws_partition`) |
| Account assignment | `aws_ssoadmin_account_assignment.view_only_users` | group → permission set → `var.target_account_id` (default: the profile's own account) |

Provider: **hashicorp/aws `~> 6.0`** (6.69.1 current on 2026-10-19).

---

## The identity chain this closes

```
HR feed ─► AD ─► Cloud Sync ─► Entra user (Dana)
  ─► access package "Nurse – Clinical Apps"          modules/entitlement
  ─► Entra group App-AWS-IdentityCenter-Users        modules/groups
  ─► SCIM (Entra provisioning, ~40-min cycle / on demand)
  ─► Identity Store group, same DisplayName          READ by this root
  ─► account assignment + ViewOnlyAccess             OWNED by this root
  ─► IAM role AWSReservedSSO_ViewOnlyAccess_<suffix> in the target account
```

**Ownership boundary.** This root never creates an `aws_identitystore_group`
and never touches group membership. An AWS-local group would sit outside the
Entra lifecycle, and the leaver flow (`04-Leaver.ps1` → SCIM deprovision)
could never take anyone out of it. Entra and SCIM own the group and who is in
it. Terraform owns only what that group is allowed to do.

---

## Why a separate root (and not `envs/dev`)

1. **Different cloud, different credentials.** The Entra pipeline's identities
   are Azure apps with GitHub OIDC federation. They have no AWS trust. Giving
   them one would stretch the APPLY identity, which is already effectively
   Tier 0 in Entra, into AWS as well.
2. **It depends on a human step that Terraform can't see.** The group exists
   only after SCIM provisioning has run. In `envs/dev`, every plan would fail
   until it had, or the root would need a flag tied to something outside
   Terraform.
3. **Isolated state and blast radius.** An AWS outage or credential problem
   can't block an Entra change, and the reverse is also true.
4. **Human-applied, like `envs/bootstrap`.** It's small, it rarely changes,
   and it runs locally from a short-lived SSO session.

CI still *checks* it. `terraform-plan.yml` runs `fmt -check -recursive` and
Checkov over all of `lab/terraform/**`, so this directory is format-checked and
scanned on every PR. It is never planned or applied by CI.

---

## Prerequisites

- **An organization instance of IAM Identity Center.** That's an instance
  enabled in the AWS Organizations management account. Assigning permission
  sets to AWS accounts needs an organization instance; an *account instance*
  supports application assignments only. A standalone account can enable an
  organization instance (see the AWS docs, "Organization and account instances
  of IAM Identity Center").
- **The instance's region.** Identity Center is regional. Find it under
  *Identity Center → Settings → Details → Region* and put it in `aws_region`.
- **An AWS CLI profile that issues short-lived credentials.** Use
  `aws configure sso --profile idlab-admin`, then `aws sso login --profile
  idlab-admin`. The role needs Identity Center admin rights in the instance's
  account: the AWS managed policy `AWSSSOMasterAccountAdministrator`
  (`sso:*`, `identitystore:*`, plus the Organizations reads) **and
  `IAMFullAccess`**, or `AdministratorAccess` in a throwaway lab org. The
  second policy is needed because the default target is the management
  account (see below), and AWS documents assigning access to the management
  account as a privileged action that needs both policies. (The guide states
  this for the console. verify: that the API path enforces the same.)
  `IAMFullAccess` also covers the `aws iam list-roles` check in the verify
  list. **No access keys.** No
  `access_key` or `secret_key` belongs in code, tfvars or env files, and
  TruffleHog fails any PR that commits one.
  *Bootstrap note:* your very first admin session can't come from something
  this root creates. Make it once in the console, for example an
  `AdministratorAccess` permission set assigned to your own `admin@` user
  (SCIM-provisioned once that user is assigned to the Entra app). This is
  the same pattern as `envs/bootstrap` on the Azure side.
- Terraform `>= 1.6` or OpenTofu `>= 1.6`.

### The target is the management account (a deliberate lab trade-off)

`target_account_id` defaults to the account the profile signs into. With an
organization instance, that's the Organizations **management account**, the
only account in this lab. AWS's delegated-administration best practices say
to assign **users, not groups**, to permission sets in the management
account. Their reason: whoever controls the group's membership controls
management-account access. Here that means Entra admins and the
access-package approvers.

The lab does it anyway, on purpose:

- There is one account.
- The policy is view-only.
- The group-driven joiner/leaver chain is the thing being demonstrated.

Even so, ViewOnlyAccess in the management account can list the organization's
accounts, OUs and policies (`organizations:List*`).

**In production:**

- Set `target_account_id` to a **member** account.
- Keep the management account on direct user assignments.
- Run this root from the Identity Center **delegated administrator** account.
  It can manage member-account assignments, and AWS documents that it can't
  alter permission sets provisioned in the management account. That keeps
  this automation out of the management account.

---

## Order of operations

1. **Entra (Terraform, pipeline).** `envs/dev` with `enable_premium = true`
   has created `App-AWS-IdentityCenter-Users` (modules/groups).
2. **SAML first, then SCIM.** With `enable_sso_apps` on, follow the staged
   order in [`modules/apps/README.md`](../modules/apps/README.md#staged-order-tenant-time).
   There, the Entra steps below (2.2 and 2.4) are Terraform plus two
   post-apply commands, and the token goes AWS → Key Vault → one seeding
   apply. The fully manual path below remains the fallback, and it is what
   the module codifies:
   1. **AWS:** *IAM Identity Center → Settings → Identity source → Actions →
      Change identity source → External identity provider*. Keep that page
      open. It holds the service-provider metadata Entra needs.
   2. **Entra:** *Enterprise applications → New application* → gallery app
      *AWS IAM Identity Center* → *Single sign-on → SAML* → *Upload metadata
      file* (the AWS one) → Save. (verify: the AWS console may offer the file
      only after the change. If so, copy the *Identifier* and *Reply URL*
      from the same AWS page instead.) Download the app's **Federation
      Metadata XML**, upload it on the AWS page under *IdP SAML metadata*,
      type `ACCEPT`, then *Change identity source*.
   3. **AWS:** *Settings → Automatic provisioning → Enable*. Copy the **SCIM
      endpoint** and **access token**. AWS shows them only once.
   4. **Entra app:** *Provisioning → Provisioning Mode: Automatic*. Paste the
      endpoint (*Tenant URL*) and the token (*Secret Token*) yourself →
      *Test Connection* → Save. The token never goes into the repo or
      Terraform. Under *Users and groups*, assign
      `App-AWS-IdentityCenter-Users`, then *Overview → Start provisioning*.
3. **Wait for SCIM to create the group.** Use *Provision on demand* in Entra
   for the group (or Dana), or wait for the ~40-minute cycle. Then confirm:
   ```bash
   aws identitystore get-group-id --profile idlab-admin --region <region> \
     --identity-store-id <d-xxxxxxxxxx> \
     --alternate-identifier '{"UniqueAttribute":{"AttributePath":"displayName","AttributeValue":"App-AWS-IdentityCenter-Users"}}'
   ```
   (`aws sso-admin list-instances` prints the identity store id. Use JSON
   here, not CLI shorthand: `AttributeValue` is a document type.)
4. **Optional: lineage pin.** Run
   `aws identitystore describe-group --identity-store-id <id> --group-id <GroupId>`.
   If `ExternalIds` shows the Entra group's object id, set
   `entra_group_object_id` (from
   `terraform -chdir=../envs/dev output -json app_access_group_object_ids | jq -r .aws`).
   From then on, the plan refuses to grant access to any group that isn't
   that exact Entra group.
5. **Apply this root:**
   ```bash
   cd lab/terraform/aws
   cp terraform.tfvars.example terraform.tfvars    # edit: profile, region, allowed_account_ids
   aws sso login --profile idlab-admin
   terraform init
   terraform plan  -out aws.tfplan                  # expect: 3 to add
   terraform apply aws.tfplan
   ```
6. **Verify** (list below), then **stop creating the permission set and
   assignment in the console**. They are now code.

**Already created the permission set by hand?** Then a `ViewOnlyAccess`
permission set exists, and creating a second one with the same name will fail
(verify: the exact error the API returns for a duplicate name). Either delete the
hand-made one in the console, or adopt it. To adopt it, put this in a
temporary `import.tf`, then plan, apply and delete the file:

```hcl
import {
  to = aws_ssoadmin_permission_set.view_only
  id = "<permission-set-arn>,<instance-arn>"
}
import {
  to = aws_ssoadmin_managed_policy_attachment.view_only
  id = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess,<permission-set-arn>,<instance-arn>"
}
import {
  to = aws_ssoadmin_account_assignment.view_only_users
  id = "<group-id>,GROUP,<account-id>,AWS_ACCOUNT,<permission-set-arn>,<instance-arn>"
}
```

**Teardown.** `terraform destroy` detaches the policy, removes the assignment
(Dana loses AWS access) and deletes the permission set. It does **not** touch
the group, its members, or the SAML/SCIM configuration.

---

## Verify list

Run each check with `--profile idlab-admin --region <region>`. Values come
from `terraform output`.

- [ ] `terraform plan` after apply shows **No changes** (no drift between code and console).
- [ ] `aws sso-admin describe-permission-set --instance-arn $(terraform output -raw identity_center_instance_arn) --permission-set-arn $(terraform output -raw permission_set_arn)` → `Name: ViewOnlyAccess`, `SessionDuration: PT4H`.
- [ ] `aws sso-admin list-managed-policies-in-permission-set --instance-arn … --permission-set-arn …` → exactly `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`.
- [ ] `aws sso-admin list-account-assignments --instance-arn … --account-id $(terraform output -raw target_account_id) --permission-set-arn …` → one row, `PrincipalType: GROUP`, `PrincipalId` = `terraform output -raw aws_users_group_id`.
- [ ] `terraform output aws_users_group_external_ids` is non-empty (the group came from SCIM, not the console). If it's empty, the `group_is_scim_provisioned` check prints a warning on every plan.
- [ ] `aws iam list-roles --query "Roles[?starts_with(RoleName,'AWSReservedSSO_ViewOnlyAccess_')].RoleName"` in the target account → one role. This needs `iam:ListRoles`, which `IAMFullAccess` / `AdministratorAccess` have. Dana's own ViewOnlyAccess session (`iam:List*`) can run it too.
- [ ] As **Dana** (private window): myapps.microsoft.com → AWS tile → access portal → the account → **ViewOnlyAccess** → console opens. Listing resources works. Creating anything (an S3 bucket, say) → **AccessDenied**.
- [ ] Session ends about 4 h after sign-in (`PT4H`).
- [ ] CloudTrail (Identity Center region) shows `CreatePermissionSet`, `CreateAccountAssignment` and `AttachManagedPolicyToPermissionSet` by **your SSO session**. The `userAgent` contains `terraform-provider-aws`, which shows the change came from this reviewed code and not from a console click. A console click would also be attributed to a person; reviewability is what code adds.
- [ ] **Leaver:** after `04-Leaver.ps1` and the next SCIM cycle (or provision on demand), Dana is out of the group in Identity Center and the account no longer appears in Dana's portal. Terraform shows **No changes**. The grant belongs to the group, not to Dana.

---

## Validate / fmt status (offline only)

Run on 2026-10-19 with **HashiCorp Terraform v1.16.5** and **OpenTofu
v1.13.1**, provider **hashicorp/aws 6.69.1**. Nothing here contacted AWS.

| Check | Result |
|---|---|
| `terraform init -backend=false` | ok (aws 6.69.1 from the committed lock file, which it left unchanged) |
| `terraform validate` | **Success** |
| `terraform fmt -check` | clean |
| `tofu init -backend=false` (in a scratch copy, see the lock-file note) | ok (aws 6.69.1 resolved) |
| `tofu validate` | **Success** |
| `tofu fmt -check` | clean |

What the committed code itself guarantees (read each in the file named):
- **Inputs** (`variables.tf` `validation` blocks): `session_duration` is
  whole hours `PT1H`–`PT12H` (so `PT13H` and `PT90M` are rejected); every
  `allowed_account_ids` entry and a non-empty `target_account_id` are 12-digit
  account ids; `aws_region` is an AWS region code (`eastus2` is rejected);
  `entra_group_object_id` is empty or a GUID; `aws_profile` has no
  whitespace; `group_display_name` is not empty.
- **Wrong region** (`main.tf`, postcondition on `data.aws_ssoadmin_instances.this`):
  an empty instance list fails the plan with an explicit message.
- **Lineage pin** (`main.tf`, postcondition on `data.aws_identitystore_group.aws_users`):
  with `entra_group_object_id` set, the group must carry it as an external id
  (compared case-insensitively), or the plan fails.
- **Hand-made group** (`main.tf`, `check "group_is_scim_provisioned"`): a group
  with no external ids raises a warning (never blocks on its own).
- **Grant** (`main.tf`): `ViewOnlyAccess`, `PT4H` by default, the AWS managed
  job-function policy ARN built from `data.aws_partition` (verify: the
  non-commercial partitions were not exercised), a `GROUP` principal and an
  `AWS_ACCOUNT` target that defaults to the caller's account unless
  `target_account_id` is set.

- **GitHub OIDC** (`github-oidc.tf`, `variables.tf`): nothing exists unless
  `enable_github_oidc = true`. The subject suffixes are `pull_request` or an
  exact `ref:refs/heads|tags/<name>`, so wildcards and `environment:` (the
  write path) are rejected. The trust is `StringEquals` on the immutable
  subject plus the `sts.amazonaws.com` audience. Every `Allow` is a read, and
  the write verbs plus `iam:PassRole` are explicitly denied. Missing GitHub ids
  fail the plan. An existing provider ARN is reused, not duplicated.

**Committed mocked test** (re-run 2026-10-20, HashiCorp Terraform 1.16.5,
aws 6.69.1, no AWS call): `terraform init -backend=false && terraform test`
runs `tests/github_oidc.tftest.hcl` and reports **7 passed, 0 failed**. Three
of the runs are mocked *applies*, so the provider's own ARN validation is
exercised. A mutation check confirmed the assertions bite: adding
`sso:CreateAccountAssignment` to the Allow list, or switching the trust to
`StringLike`, makes the suite fail. The permission-set grant in `main.tf` is
covered only incidentally, through the same mocked applies. Checkov 3.3.20 on
this directory reports 0 failed.

**Not verified (needs a live AWS account):**
- The real apply.
- The duplicate-name error text.
- Whether `CreateAccountAssignment` to the management account through the API
  needs `IAMFullAccess`, as the console path is documented to need.
- Whether Entra's AWS connector stamps the group's `objectId` as its SCIM
  `externalId`. Both the warning check and the optional pin depend on this,
  so confirm it with `describe-group` before relying on either.
- The end-to-end Dana sign-in.

Lock file: **committed** (`.terraform.lock.hcl`), the same policy as the other
two roots in `lab/terraform`. It holds the `registry.terraform.io/hashicorp/aws`
6.69.1 hashes, generated by HashiCorp Terraform 1.16.5 with
`terraform providers lock -platform=linux_amd64 -platform=darwin_arm64
-platform=darwin_amd64`. Never commit a lock file that `tofu init` has
touched: it rewrites the entry to `registry.opentofu.org/hashicorp/aws`. That's
why the `tofu init` row above ran in a scratch copy.

---

## GitHub OIDC → AWS: the read-only role (built, staged off) and the write role (described, not built)

### Built: `github-oidc.tf` (`enable_github_oidc`, default `false`)

| Object | Terraform | Value |
|---|---|---|
| OIDC identity provider | `aws_iam_openid_connect_provider.github` | `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`, no thumbprint. *verify:* AWS validates this issuer against its own CA store. Skipped when `existing_github_oidc_provider_arn` is set, because an account allows one per URL. |
| Read-only role | `aws_iam_role.github_readonly` | Trust is `StringEquals` on `sub = repo:<owner>@<owner_id>/<repo>@<repo_id>:pull_request` (the Entra PLAN identity's exact subject) and `aud = sts.amazonaws.com`. Sessions last 1 hour. |
| Its permissions | `aws_iam_role_policy.github_readonly` | Allow: `sso:Describe*`, `sso:Get*`, `sso:List*` (the prefixes of AWS's own `AWSSSOReadOnly`); `identitystore:GetGroupId` and `identitystore:DescribeGroup`; and reads of its own OIDC provider and role. Deny: every Identity Center, Identity Store and IAM write verb, plus `iam:PassRole`. |

**Why build only the read half.** The lab now has two CI paths into AWS:

- **Pull-request drift checks.** These need a remote backend first (step 4
  below). Until then, this root's state is local.
- **A scheduled "who can reach AWS" evidence export.** Add
  `"ref:refs/heads/main"` to `github_oidc_subject_suffixes`.

Both are reads. A compromised workflow can see the Identity Center
configuration and cannot change it. That holds even if someone later attaches
a broad policy to the role, because the explicit Deny wins. The write role
stays unbuilt for the reasons below.

**Using it from a workflow** (wiring, not in this directory):
```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@<full-commit-SHA>   # pin like every other action
    with:
      role-to-assume: ${{ vars.AWS_READONLY_ROLE_ARN }}            # terraform output -raw github_readonly_role_arn
      aws-region: ${{ vars.AWS_IDENTITY_CENTER_REGION }}
  - run: aws sso-admin list-account-assignments --instance-arn … --account-id … --permission-set-arn …
```

**Negative test to capture at tenant time.** Run the same workflow from a
branch push (subject `…:ref:refs/heads/<branch>`). It must fail with
`AccessDenied` / *Not authorized to perform sts:AssumeRoleWithWebIdentity*.
That is the AWS twin of the Entra AADSTS70021 negative path.

### Described, not built: the full CI design

In a real org this root would run from CI without any stored AWS key, using
the same pattern the Azure side already uses:

1. **Trust.** A human-applied bootstrap creates an IAM OIDC identity provider
   for `https://token.actions.githubusercontent.com` with audience
   `sts.amazonaws.com`. The pipeline never creates its own trust.
2. **Two roles, mirroring the Entra PLAN/APPLY split.**
   - **plan role.** Trust condition
     `token.actions.githubusercontent.com:sub = repo:<owner>@<owner_id>/<repo>@<repo_id>:pull_request`.
     AWS permissions are read-only: `sso:Describe*`, `sso:List*`,
     `identitystore:GetGroupId` and `identitystore:DescribeGroup`. On the
     state bucket it needs `s3:ListBucket` on the bucket and `s3:GetObject`
     on the state key. It also needs
     `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject` on the `<key>.tflock`
     lock object, because S3-native locking takes a lock during plan too
     (or run plan with `-lock=false`).
   - **apply role.** Trust condition
     `token.actions.githubusercontent.com:sub = repo:<owner>@<owner_id>/<repo>@<repo_id>:environment:aws-prod`,
     a GitHub environment with a required reviewer. It needs the plan role's
     reads. It adds only the `sso:` create, attach, tag and provision actions
     this root uses, scoped to the instance and permission-set ARNs, plus
     `s3:PutObject` on the state key. (verify: the exact action list against
     the Service Authorization Reference for IAM Identity Center.)
   - Both roles also pin `token.actions.githubusercontent.com:aud = sts.amazonaws.com`.
3. **Workflow.** Set `permissions: id-token: write` and use
   `aws-actions/configure-aws-credentials`, pinned to a full commit SHA like
   every other action here, with `role-to-assume`. Store no
   `AWS_ACCESS_KEY_ID` or secret anywhere.
4. **State.** An S3 backend with versioning, SSE-KMS, public access
   blocked, and S3-native locking (`use_lockfile = true`; verify: needs
   Terraform ≥ 1.11 / OpenTofu ≥ 1.10). It would replace this root's local
   state.
5. **Delegated administration.** Register a member account as Identity
   Center delegated administrator so CI never holds credentials in the
   management account. AWS documents that the delegated administrator can't
   alter permission sets provisioned in the management account. That's
   intended: CI then targets member accounts only (see "The target is the
   management account" above).

**Why the write role and the S3 backend aren't built here.** The lab has one
account, this root changes about once, and a CI identity that can *write*
into a second cloud is more attack surface than the lab needs. Only the
read-only half above earns its place. Saying that out loud is part of the
design.

**Natural next step (PIM for AWS).** Create a second, PIM-governed Entra group
assigned to the same app, and give it a stronger permission set in this root.
Activating the group membership in Entra PIM then becomes just-in-time AWS
admin. Microsoft documents this pattern in the AWS IAM Identity Center
provisioning tutorial. That tutorial also gives the timing:

- An activation reaches AWS in about 2–10 minutes.
- Deactivation waits for the regular provisioning cycle, which runs about
  every 40 minutes.

So keep the permission set's `session_duration` short. A session that is
already open in AWS outlives its PIM activation.

---

## Sources (checked 2026-10-19; GitHub OIDC additions 2026-10-20)

- Provider docs v6.69.1: `d/ssoadmin_instances`, `d/identitystore_group`
  (`alternate_identifier.unique_attribute`, `DisplayName` as used in the
  provider's own acceptance test), `r/ssoadmin_permission_set`,
  `r/ssoadmin_managed_policy_attachment` (the `depends_on` ordering note),
  `r/ssoadmin_account_assignment`.
- AWS Managed Policy Reference: `ViewOnlyAccess`
  (`arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`, job function),
  `AWSSSOMasterAccountAdministrator`.
- IAM Identity Center User Guide: organization vs account instances; session
  duration 1–12 h (default 1 h); *Delegated administration* (best practices:
  user-only assignments in the management account; the delegated admin can't
  alter management-account permission sets); *Delegate who can assign single
  sign-on access … in the management account*
  (AWSSSOMasterAccountAdministrator plus IAMFullAccess); *Configure SAML and
  SCIM with Microsoft Entra ID and IAM Identity Center* (the console labels in
  Order of operations, step 2).
- Terraform S3 backend docs: `use_lockfile` needs `s3:GetObject`,
  `s3:PutObject` and `s3:DeleteObject` on the `.tflock` object.
- Identity Store API: `GetGroupId` (`displayName` unique attribute).
  IAM Identity Center SCIM: `CreateGroup` accepts `externalId`.
- Microsoft Learn: *Configure AWS IAM Identity Center for automatic user
  provisioning*, covering group mapping targets (`displayName`, `externalId`,
  `members`), the 40-minute cycle, and PIM for Groups JIT.
- GitHub Docs: *Configuring OpenID Connect in Amazon Web Services*.
- Added 2026-10-20 for `github-oidc.tf`: the provider 6.69.1 schema for
  `aws_iam_openid_connect_provider` (`thumbprint_list` optional and computed),
  `aws_iam_role` and `aws_iam_role_policy`; the AWS Managed Policy Reference
  for `AWSSSOReadOnly` v12 (its `sso:Describe*` / `Get*` / `List*` prefixes,
  plus the conditional `kms:Decrypt` it carries for customer-managed-key
  instances).
