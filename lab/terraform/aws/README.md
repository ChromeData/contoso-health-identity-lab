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

Plus one small stand-in for the patient portal the cloud engineers run: a
private S3 bucket with two objects (see
[Patient portal stand-in](#patient-portal-stand-in-patient-portaltf)).

And the account's own audit trail, built but not yet applied: a CloudTrail
trail, its locked-down bucket and an IAM Access Analyzer (see
[Audit trail](#audit-trail-audit-trailtf-built-not-applied)).

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

## AWS admin without root (`lab-admin.tf`, `entra-operator.tf` v2; ADR 0025)

**Status: RAN · tenant (2026-11-05, capture log E95-E99).** The steps
below ran in this order; the guardrails v2 apply and the removal of the
leftover `idlab-admin` were made with `adm-labops`'s LabAdministrator
session, not root.

**Nobody administers this account as root, and the operator can't make
itself an admin path.** AWS administration is borrowed for at most two hours
through the same Entra admin-power rules as every other admin role
([ADR 0025](../../docs/adr/0025-aws-admin-just-in-time-through-entra.md)):

```
adm-labops ──PIM for Groups: activate PIM-AWS-Lab-Admins (2 h, MFA, reason, mailed)──►
  member of PIM-AWS-Lab-Admins (Entra; second principal on the AWS app)   modules/pim, modules/apps
  ──SCIM, 2-10 min after activation──► Identity Store group PIM-AWS-Lab-Admins
  ──LabAdministrator (AdministratorAccess, PT1H)──► account 182002546409   lab-admin.tf
```

| Object | Terraform | Value |
|---|---|---|
| Admin group, as SCIM created it | `data.aws_identitystore_group.lab_admins` | `PIM-AWS-Lab-Admins` (read only; empty at rest) |
| Permission set | `aws_ssoadmin_permission_set.lab_admin` | `LabAdministrator`, `PT1H` (`PT2H` max: never longer than the activation) |
| Policy | `aws_ssoadmin_managed_policy_attachment.lab_admin` | AWS managed `AdministratorAccess` |
| Assignment | `aws_ssoadmin_account_assignment.lab_admins` | the admin group only; a postcondition refuses the staff group |

**Operator guardrails v2.** `contoso-lab-operator` keeps AdministratorAccess
minus, account-wide: every IAM write (v2 adds the Accept/Associate/Disable/
Reject/Send verbs); every `sso:`, `identitystore:` and `sso-directory:`
write (permission sets, assignments, provisioning, local users and groups,
SCIM bearer tokens, the identity source); the Organizations writes that add
accounts, invite, delegate administration or change policies;
`sts:AssumeRoot`; the account's primary email and alternate contacts; Roles
Anywhere; closing or detaching the account. Reads stay open.

**Who applies what, after guardrails v2:**

| Resources | Profile |
|---|---|
| IAM (`entra-operator.tf`, `github-oidc.tf`) and Identity Center (`main.tf`, `lab-admin.tf`) | `idlab-labadmin`: a LabAdministrator session, after a PIM activation (`-var aws_profile=idlab-labadmin`) |
| Patient portal bucket (`patient-portal.tf`) | `idlab-operator` (unchanged) |

The `idlab-labadmin` profile is an IAM Identity Center profile, so its
credentials are short-lived and fetched by the CLI from its SSO cache (no key
is ever written down):

```ini
[sso-session idlab]
sso_start_url = https://d-90666212c7.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile idlab-labadmin]
sso_session = idlab
sso_account_id = 182002546409
sso_role_name = LabAdministrator
region = us-east-1
```

`aws sso login --profile idlab-labadmin` works only while the PIM activation
lasts (outside it, Entra refuses the SAML sign-in and the AWS group is
empty); always check `aws sts get-caller-identity --profile idlab-labadmin`
shows account 182002546409 before an apply.

**First apply (order matters).** The very first LabAdministrator apply must
run BEFORE guardrails v2, because nothing else can write Identity Center
without root:

1. envs/dev `enable_pim_aws_admin` applied; SCIM has created the (empty)
   `PIM-AWS-Lab-Admins` group in the Identity Store.
2. As the operator (v1 guardrails still allow Identity Center writes):
   `terraform apply -var enable_lab_admin_jit=true -target=aws_ssoadmin_permission_set.lab_admin -target=aws_ssoadmin_account_assignment.lab_admins -target=aws_ssoadmin_managed_policy_attachment.lab_admin`
   (targeted: the console-made ViewOnlyAccess set and the bucket are not
   touched).
3. Make the admin account eligible (operator, `eligibilityScheduleRequests`
   `adminAssign`, `afterDuration P180D`), then, as that account: Entra admin
   center > Privileged Identity Management > My roles > Groups >
   `PIM-AWS-Lab-Admins` > Activate (reason; 2 hours), wait for SCIM (2-10
   minutes; the account needs a given name and surname or AWS refuses it),
   `aws sso login --profile idlab-labadmin`.
4. With that session: `terraform apply -var aws_profile=idlab-labadmin -target=aws_iam_role_policy.entra_operator_guardrails`
   (guardrails v2), then remove the leftover local admin (`idlab-admin`: its
   account assignment, the user, the console-made `AdministratorAccess`
   permission set).
5. Check as the operator: an Identity Center write now fails with
   "explicit deny" (`aws iam simulate-principal-policy` for the role, and
   one real `sso-admin create-permission-set` attempt).

**Root.** Root has no access keys and is not used to administer. Its MFA is
an owner step (a hardware security key); until it is registered, root is
protected by its password and the emailed sign-in code only.

## Session Manager: a server with no way in but a logged shell (`session-manager.tf`; ADR 0025)

**Status: RAN · tenant** (2026-11-07, capture-log E125-E127), then turned
off again (`enable_session_manager = false`: server and endpoints destroyed).

**What it is.** One small Linux server (`lab-ssm-node-01`, t4g.micro, the
smallest free-tier-eligible type) that has **no inbound port, no SSH key and
no public IP**. Its subnet has no route to the internet. The only way in is
an AWS Systems Manager **Session Manager** shell: the server's agent dials
out to four private VPC endpoints, and a user's shell rides on that channel.
Every command and its output is written to CloudWatch Logs
(`/contoso-lab/session-manager`).

**Who gets in.** Only someone who holds the Identity Center permission set
**LabServerSession**, and that permission set is assigned only to the SCIM
copy of the Entra PIM-for-Groups group `PIM-AWS-Lab-Admins`. So: no PIM
activation, no AWS group membership, no LabServerSession, no shell.

| LabServerSession may | It may not |
|---|---|
| Start a shell (`SSM-SessionManagerRunShell`) on a server tagged `session-access = lab-server-session` | Start a shell on an untagged server (seen live: AccessDenied) |
| End or resume its own sessions | End someone else's session (seen live: AccessDenied) |
| List servers and sessions | Port forwarding / SSH tunnels (`AWS-StartPortForwardingSession`: AccessDenied live), `ssm:SendCommand` (AccessDenied live), any EC2 write (`StopInstances`: UnauthorizedOperation live) |

**Plain limits (true today, say them):**
- LabServerSession shares its PIM group with LabAdministrator. An activated
  member can pick either one at the access portal. A dedicated
  `PIM-AWS-Server-Operators` group (an envs/dev change: modules/pim +
  modules/apps) is a later step and is **not built**.
- Inside the shell the user is `ssm-user`, which Amazon Linux lets run
  `sudo` (seen live). The shell is fully logged, but it is root-capable.
- Ending the PIM activation stops **new** AWS credentials once SCIM has run
  (it disables the AWS user). Credentials already issued keep working until
  their 1-hour expiry, and a shell that is already open stays open (seen
  live, below). The preferences document caps every shell at 60 minutes. An
  admin can cut an open shell at once with `aws ssm terminate-session`.
- **The operator bypassed PIM in the live run.** The lab operator role
  (`contoso-lab-operator`, standing AdministratorAccess minus IAM writes)
  opened a shell on the server at 01:15:51Z with no activation (CloudTrail,
  E126). The fix is in code, **BUILT, not applied**: guardrails v4 in
  `entra-operator.tf` (`NoServerShell`: StartSession, ResumeSession,
  SendCommand, EC2 Instance Connect, Fleet Manager GUI; `NoSessionLogTampering`:
  the preferences document and the session log group). Apply it with the
  next activation (`-target=aws_iam_role_policy.entra_operator_guardrails`
  in step 2 below). That one policy also carries guardrails v3
  (`NoAuditTampering`, from audit-trail.tf), which is not live yet either
  (read 2026-11-07: live Sids are v2 only). Until then, "only through PIM"
  is true for people, not for the operator. The operator also keeps EC2
  admin over the server itself (stop it, change it), which these Denies do
  not remove.
- `cloudWatchEncryptionEnabled` is false: true would refuse every session
  unless the log group had a customer KMS key ($1/month). CloudWatch Logs
  still encrypts the data at rest with its own keys. The log group keeps 30
  days; it is not WORM.

**Apply (needs an activation).** IAM and Identity Center writes are denied to
the operator, so this runs with `idlab-labadmin`:

```bash
# 1. adm-labops: PIM > My roles > Groups > PIM-AWS-Lab-Admins > Activate (reason)
#    (or lab/scripts/demo/signin/identity.mjs activatePim). Wait for SCIM.
aws sso login --profile idlab-labadmin
aws sts get-caller-identity --profile idlab-labadmin   # must show 182002546409
# 2. targeted apply of session-manager.tf only (19 resources), against the
#    root's own state; OpenTofu wrote that state, so use tofu
tofu plan  -var aws_profile=idlab-labadmin -var enable_session_manager=true \
  -var session_group_entra_object_id=<PIM-AWS-Lab-Admins object id> \
  -target=aws_vpc.ssm -target=aws_subnet.ssm -target=aws_security_group.ssm_node \
  -target=aws_security_group.ssm_endpoints -target=aws_vpc_endpoint.ssm \
  -target=aws_cloudwatch_log_group.ssm_sessions -target=aws_ssm_document.session_preferences \
  -target=aws_iam_role.ssm_node -target=aws_iam_role_policy_attachment.ssm_node_core \
  -target=aws_iam_role_policy.ssm_node_logs -target=aws_iam_instance_profile.ssm_node \
  -target=aws_instance.ssm_node -target=aws_ec2_instance_state.ssm_node \
  -target=aws_ssoadmin_permission_set.server_session \
  -target=aws_ssoadmin_permission_set_inline_policy.server_session \
  -target=aws_ssoadmin_account_assignment.server_session \
  -target=aws_iam_role_policy.entra_operator_guardrails -out ssm.tfplan   # + guardrails v3/v4 for the operator
tofu apply ssm.tfplan   # 19 added (+ the operator guardrails policy updated in place)
# 3. a session (needs session-manager-plugin)
aws ssm start-session --profile <LabServerSession profile> --target $(tofu output -raw session_node_instance_id)
# 4. after the capture: the same targets with -destroy (or the flag false)
```

The CLI profile for the session (`~/.aws/config`): same `sso_session` as
`idlab-labadmin`, `sso_role_name = LabServerSession`.

**Timings seen live (2026-11-07 UTC):**

| Step | Time | Took |
|---|---|---|
| PIM activation (adm-labops, 2 h, MFA + reason) | 00:52:33 | 33 s (headless sign-in + blade) |
| In the AWS group (SCIM provision on demand by the operator, so not waiting up to 40 min) | 00:53:33 | 1 min |
| `aws sso login` (device code, approved as adm-labops) | 01:03:28 | under 1 min once run |
| Targeted apply, 19 resources | 01:07:56-01:09:36 | 1 min 40 s (endpoints ~1 min) |
| Agent online (no internet, endpoints only) | 01:13:00 | ~3.5 min after launch |
| First shell as LabServerSession (`whoami` ssm-user, `hostname` ip-10-42-0-23, `uptime`, no internet) | 01:13:32-01:13:56 | 24 s |
| Transcript in CloudWatch, read as the operator | 01:14:10 | seconds (streaming) |
| Denials: port forwarding, SendCommand, untagged server, EC2 stop | 01:14:50-01:15:24 | - |
| Own session ended / someone else's refused | 01:16:10 / 01:15:58 | - |
| PIM deactivated early | 01:18:00 | Entra group empty by 01:18:22 |
| SCIM's scheduled cycle removed the AWS member and DISABLED the AWS user | 01:26:14 | ~8 min after deactivation (no on-demand push) |
| New credentials request: refused ("SSO session ... invalid") | 01:27:09 | - |
| Already-issued 1-hour credentials still opened a new shell | 01:26:56 | residual, until ~02:13 |
| A shell opened at 01:17 before deactivation was still printing | 01:39 (and later) | residual: open sessions are not re-checked |

## Patient portal stand-in (`patient-portal.tf`)

Something real behind the AWS door. The hospital's patient portal is run by
the cloud engineers, who get AWS through the **IT - Cloud Engineering Apps**
package (`modules/entitlement`). This bucket stands in for the portal: no
patient data, no web hosting, no compute, effectively $0.

| Object | Terraform | Value |
|---|---|---|
| Bucket | `aws_s3_bucket.patient_portal` | `contoso-health-patient-portal-<account id>` (or `-<patient_portal_bucket_suffix>`); tags `App=PatientPortal`, `Owner=CloudEngineering`, `Environment=lab` |
| Lock-down | `aws_s3_bucket_public_access_block`, `_ownership_controls`, `_versioning`, `_server_side_encryption_configuration`, `_lifecycle_configuration`, `_policy` | all four public-access blocks on, ACLs off, versioned, SSE-KMS with the AWS managed `aws/s3` key and a Bucket Key, noncurrent versions expire after 30 days, TLS only |
| Objects | `aws_s3_object.patient_portal` | `index.html` ("Contoso Health patient portal (lab)") and `status.json` |

**What a cloud engineer sees.** ViewOnlyAccess (AWS managed policy, v48)
allows `s3:ListAllMyBuckets` and `s3:ListBucket`, so the bucket and both
object names show in the S3 console. It has no `s3:GetObject`, so opening or
downloading an object is **AccessDenied**. That is by design: reading or
changing the portal belongs to a stronger permission set (see *Natural next
step* below). The bucket policy adds one read for ViewOnlyAccess sessions,
`s3:GetBucketLocation`, which the managed policy lacks and the console uses
to open a bucket (verify: whether the console still needs it).

**Apply it.** The lab's `ViewOnlyAccess` permission set and its assignment
were made in the console (E24), not by this root, so a full plan would try to
create them a second time. Either adopt them first (the `import` blocks above,
then a full plan), or create only the portal. It needs an admin session in the
lab account; the `idlab-admin` profile stopped working when the identity
source moved to Entra (`lab/docs/your-turn/07-apps-sso.md`, heads-up).

```bash
cd lab/terraform/aws
terraform init
terraform plan -out portal.tfplan \
  -target=aws_s3_object.patient_portal \
  -target=aws_s3_bucket_policy.patient_portal \
  -target=aws_s3_bucket_lifecycle_configuration.patient_portal   # expect: 9 to add
terraform apply portal.tfplan
terraform output patient_portal_console_url
```

**Verify.** As a cloud engineer (private window): myapps.microsoft.com → AWS
tile → the account → **ViewOnlyAccess** → open `patient_portal_console_url`.
The bucket shows `index.html` and `status.json`; **Open** on either is
AccessDenied. **Teardown:** `terraform destroy -target=aws_s3_bucket.patient_portal`
removes the bucket, its objects and old versions (`force_destroy`, lab only).

## Audit trail (`audit-trail.tf`, built, not applied)

**Status: BUILT.** Mocked tests pass and a targeted plan ran as the operator
against the real account on 2026-11-06 (no apply): 9 to add, 1 to change
(the operator guardrails), 0 to destroy. Capture log E105.

**Why.** The lab quotes CloudTrail records as evidence (ADR 0024, ADR 0025),
but nothing here created a trail. On 2026-11-06 account 182002546409 had no
trail and no Access Analyzer (`describe-trails --include-shadow-trails` and
`list-analyzers`: both empty). Those records came from CloudTrail **Event
history**: on by default and free, but 90 days, one region at a time, and
no file anyone can keep. A trail writes every event to S3, in every region,
with a signed digest each hour that shows whether a log file was changed or
deleted afterwards.

| Object | Terraform | Value |
|---|---|---|
| Trail | `aws_cloudtrail.audit` | `contoso-lab-audit-trail`: all regions, global services (IAM, STS, Identity Center), log file validation on, management events (reads and writes) only |
| Bucket | `aws_s3_bucket.audit` + public-access block, ownership controls, versioning, encryption, lifecycle | `contoso-health-audit-trail-<account id>`: private, ACLs off, versioned, SSE-S3, kept 365 days (`audit_log_retention_days`, 90-3650), not `force_destroy` |
| Bucket policy | `aws_s3_bucket_policy.audit` | CloudTrail may check the ACL and write under `AWSLogs/<account>/`, **only for this trail** (`aws:SourceArn`); anything not over TLS is denied |
| Access Analyzer | `aws_accessanalyzer_analyzer.external_access` | `contoso-lab-external-access`, type `ACCOUNT`, in `aws_region` only: lists that region's resources shared outside the account. A bucket or key shared from another region would not show; this root builds everything in `aws_region` (us-east-1), and a second region needs its own analyzer |

**The operator can't erase it (guardrails v3).** Before this change the
operator, with AdministratorAccess, could stop or delete the trail
(`simulate-principal-policy` on 2026-11-06: `cloudtrail:StopLogging` and
`cloudtrail:DeleteTrail` "allowed"). Two new Deny statements on
`contoso-lab-operator`:

- `NoAuditTampering`, account-wide: stop, delete or reconfigure any trail;
  delete the analyzer, or hide its findings (archive rules, `UpdateFindings`).
- `NoAuditBucketTampering`, on the audit bucket only: delete the bucket or
  any log file or version, write into it, or change its policy, lifecycle,
  versioning, encryption, public-access block, ownership, object lock or
  Requester Pays (CloudTrail can't deliver to a Requester Pays bucket).
  It's scoped to one bucket because the operator still runs the patient
  portal. A role-scoped Deny is usually dodged by making a new principal,
  and the operator can't make one (`NoIamChanges`).

Reads stay open: the operator still runs `lookup-events` and reads log files
for evidence. CloudTrail writes as the `cloudtrail.amazonaws.com` service,
which a Deny on the operator's role doesn't touch.

**Cost** (AWS pricing pages, read 2026-11-06): the first copy of management
events delivered to S3 is free, and this is the account's only trail. No
data events, Insights or CloudWatch Logs copy, so CloudTrail bills nothing
else. S3 for a quiet lab account: a few MB a month, cents. External access
analysis: "no additional charge" (the paid unused-access and internal-access
analyzers aren't built).

**Not ported** from the old AWS-Multi-Account-Baseline repo: GuardDuty,
Security Hub and its CIS/FSBP standards (monthly charges, and nobody reads
their findings yet), AWS Config, and the LocalStack switch.

**Apply it** (one LabAdministrator session, after a PIM activation of
`PIM-AWS-Lab-Admins`; see [AWS admin without root](#aws-admin-without-root-lab-admintf-entra-operatortf-v2-adr-0025)).
Not the operator: creating the analyzer also creates the service-linked role
`AWSServiceRoleForAccessAnalyzer` (absent on 2026-11-06), and the operator
gets `explicitDeny` on `iam:CreateServiceLinkedRole`. The guardrails change
is an IAM write, so it needs the same session. The local state of this root
was written by OpenTofu (its provider address is `registry.opentofu.org`),
so the 2026-11-06 plan ran with `tofu`; use the same tool for the apply.

```bash
aws sts get-caller-identity --profile idlab-labadmin   # must say 182002546409
tofu plan -var aws_profile=idlab-labadmin -var enable_audit_baseline=true -out audit.tfplan \
  -target=aws_cloudtrail.audit -target=aws_accessanalyzer_analyzer.external_access \
  -target=aws_s3_bucket_lifecycle_configuration.audit -target=aws_s3_bucket_ownership_controls.audit \
  -target=aws_s3_bucket_server_side_encryption_configuration.audit \
  -target=aws_iam_role_policy.entra_operator_guardrails   # expect: 9 to add, 1 to change
tofu apply audit.tfplan
```

Then set `enable_audit_baseline = true` in `terraform.tfvars`, so a later
full plan doesn't try to remove them.

**Verify after the apply** (not run yet):

- `aws cloudtrail get-trail-status --name contoso-lab-audit-trail`:
  `IsLogging: true`, and after about 15 minutes a `LatestDeliveryTime`.
- `aws cloudtrail validate-logs --trail-arn <audit_trail_arn> --start-time <apply time>`
  reports the digest and log files as valid (digests start an hour in).
- As the operator: `aws iam simulate-principal-policy` for
  `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail` and `s3:DeleteObject`
  on the bucket shows `explicitDeny`; `cloudtrail:LookupEvents` stays
  `allowed`.
- `aws accessanalyzer list-findings-v2 --analyzer-arn <access_analyzer_arn>`
  answers (an empty list is a valid answer).

**Teardown.** The bucket isn't `force_destroy`, on purpose: empty it
(every version) by hand first, then `tofu destroy -target=aws_cloudtrail.audit ...`.

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
`tests/patient_portal.tftest.hcl` (added 2026-11-02, same versions) pins the
portal bucket: private, versioned, SSE-KMS, tagged, exactly `index.html` and
`status.json`, a TLS-only policy whose one Allow is `s3:GetBucketLocation`.
Both files together: **12 passed, 0 failed**.
`tests/audit_trail.tftest.hcl` (added 2026-11-06, Terraform 1.16.5, aws
6.69.1) pins the audit trail: off by default; all regions, global services,
log file validation, management events only; the bucket private,
versioned, SSE-S3, kept a year and not `force_destroy`; CloudTrail may write
only for this trail (and the hand-built trail ARN equals the real one); the
analyzer is the free `ACCOUNT` type; retention under 90 days is refused.
`tests/entra_operator.tftest.hcl` gained `guardrails_v3_protect_the_audit_trail`,
which fails against the v2 guardrails. All six files on 2026-11-06:
**30 passed, 0 failed**. Mutation checks: the old guardrails fail the v3
run, and a trail ARN with the old repo's trail name fails two audit runs.
Checkov 3.3.20 on this directory: 0 failed.

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

- Added 2026-11-06 for `audit-trail.tf`: CloudTrail User Guide, *Amazon S3
  bucket policy for CloudTrail* (the two statements and the `aws:SourceArn`
  recommendation) and *Encrypting CloudTrail log files ... with AWS KMS keys*
  (SSE-S3 when SSE-KMS isn't enabled); the CloudTrail and IAM Access
  Analyzer pricing pages; action names checked against the AWS policy
  generator's service map (awspolicygen.s3.amazonaws.com/js/policies.js).

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
