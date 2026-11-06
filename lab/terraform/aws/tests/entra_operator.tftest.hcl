# Offline, mocked tests for the lab operator role (entra-operator.tf).
# No AWS call is made:  tofu init -backend=false && tofu test
#
# What these pin: nothing is created unless enable_entra_operator; the trust
# names the Entra v2 issuer of THIS tenant and only the operator's exact client
# id (aud) and service-principal object id (sub), with StringEquals; the
# guardrail Denies block every IAM write account-wide; bad ids are refused before anything is made.
# Guardrails v2 (ADR 0025): also every IAM Identity Center / identity store /
# Identity Center directory write (the admin path around the IAM Deny), the
# Organizations writes that add accounts or delegate administration,
# sts:AssumeRoot and the account's recovery contacts - while reads stay open.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_ssoadmin_instances" {
    defaults = {
      arns               = ["arn:aws:sso:::instance/ssoins-1111111111111111"]
      identity_store_ids = ["d-1234567890"]
    }
  }
  mock_data "aws_identitystore_group" {
    defaults = {
      group_id     = "90676d1b-1111-2222-3333-444455556666"
      external_ids = [{ id = "55555555-5555-5555-5555-555555555555", issuer = "" }]
    }
  }
  # Mocked APPLY runs also create main.tf's grant; the provider validates ARNs.
  mock_resource "aws_ssoadmin_permission_set" {
    defaults = { arn = "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222" }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      id  = "contoso-lab-operator"
      arn = "arn:aws:iam::123456789012:role/contoso-lab-operator"
    }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0" }
  }
}

variables {
  entra_tenant_id          = "11111111-1111-1111-1111-111111111111"
  entra_operator_client_id = "22222222-2222-2222-2222-222222222222"
  entra_operator_object_id = "33333333-3333-3333-3333-333333333333"
}

run "off_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_openid_connect_provider.entra) == 0 && length(aws_iam_role.entra_operator) == 0 && length(aws_iam_role_policy.entra_operator_guardrails) == 0
    error_message = "no Entra trust may exist unless enable_entra_operator = true"
  }
}

run "trust_is_the_operator_only" {
  command = apply

  variables {
    enable_entra_operator = true
  }

  assert {
    condition     = aws_iam_openid_connect_provider.entra[0].url == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    error_message = "the provider must be this tenant's v2 issuer"
  }
  assert {
    condition     = aws_iam_openid_connect_provider.entra[0].client_id_list == toset(["22222222-2222-2222-2222-222222222222"])
    error_message = "the provider's only audience must be the operator's client id"
  }
  assert {
    condition     = jsondecode(aws_iam_role.entra_operator[0].assume_role_policy).Statement[0].Condition.StringEquals["login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0:sub"] == "33333333-3333-3333-3333-333333333333"
    error_message = "the role must trust only the operator service principal's object id"
  }
  assert {
    condition     = jsondecode(aws_iam_role.entra_operator[0].assume_role_policy).Statement[0].Condition.StringEquals["login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0:aud"] == "22222222-2222-2222-2222-222222222222"
    error_message = "the audience must be pinned to the operator's client id"
  }
  assert {
    condition     = !strcontains(aws_iam_role.entra_operator[0].assume_role_policy, "StringLike") && !strcontains(aws_iam_role.entra_operator[0].assume_role_policy, "*")
    error_message = "no StringLike and no wildcard anywhere in the trust policy"
  }
  assert {
    condition     = aws_iam_role.entra_operator[0].max_session_duration == 3600
    error_message = "sessions must stay at one hour"
  }
}

run "guardrails_deny_every_iam_write" {
  command = apply

  variables {
    enable_entra_operator = true
  }

  assert {
    condition = length(setsubtract(
      ["iam:Create*", "iam:Put*", "iam:Attach*", "iam:Update*", "iam:Delete*", "iam:PassRole", "rolesanywhere:Create*", "account:CloseAccount"],
      flatten([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Effect == "Deny"])
    )) == 0
    error_message = "the guardrails must deny every IAM write (no second role, user, key or trust edit), PassRole, Roles Anywhere and account closure"
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Effect == "Deny" && (s.Resource == "*" || s.Sid == "NoAuditBucketTampering")])
    error_message = "the guardrail policy may only Deny, account-wide (a Deny scoped to the operator's own role is bypassed by creating another role); the one exception is the audit-bucket statement"
  }
  assert {
    condition     = jsondecode(aws_iam_role.entra_operator[0].assume_role_policy).Statement[0].Principal.Federated == aws_iam_openid_connect_provider.entra[0].arn
    error_message = "the trust must reference the provider resource (ordering on a fresh apply)"
  }
}

run "bad_ids_are_refused" {
  command = plan

  variables {
    enable_entra_operator    = true
    entra_operator_object_id = "not-a-guid"
  }

  expect_failures = [aws_iam_role.entra_operator]
}

run "guardrails_v2_close_the_identity_center_path" {
  command = apply

  variables {
    enable_entra_operator = true
  }

  # Every IAM write VERB the AWS policy generator lists (2026-11-05); a verb
  # missing here is an IAM write the operator could still make.
  assert {
    condition = length(setsubtract(
      [for v in ["Accept", "Add", "Associate", "Attach", "Change", "Create", "Deactivate", "Delete", "Detach", "Disable", "Enable", "Put", "Reject", "Remove", "Reset", "Resync", "Send", "Set", "Tag", "Untag", "Update", "Upload"] : "iam:${v}*"],
      one([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Sid == "NoIamChanges"])
    )) == 0
    error_message = "NoIamChanges must deny every IAM write verb (v2 adds Accept, Associate, Disable, Reject, Send)"
  }
  assert {
    condition = length(setsubtract(
      [
        "sso:Create*", "sso:Put*", "sso:Attach*", "sso:Detach*", "sso:Delete*", "sso:Update*", "sso:Provision*",
        "sso:Associate*", "sso:Disassociate*", "sso:Import*", "sso:Start*",
        "identitystore:Create*", "identitystore:Update*", "identitystore:Delete*",
        "sso-directory:Create*", "sso-directory:Update*", "sso-directory:Delete*", "sso-directory:Add*", "sso-directory:Enable*",
      ],
      one([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Sid == "NoIdentityCenterChanges"])
    )) == 0
    error_message = "no permission set, assignment, provisioning, local user or group, SCIM bearer token (sso-directory:CreateBearerToken) or identity-source change by the operator"
  }
  assert {
    condition = alltrue([
      for a in one([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Sid == "NoIdentityCenterChanges"]) :
      !can(regex(":(Describe|Get|List|Search|IsMemberIn)", a)) && !strcontains(a, ":*")
    ])
    error_message = "Identity Center READS must stay allowed (the operator reports on them) and no blanket <service>:* deny"
  }
  assert {
    condition = length(setsubtract(
      ["organizations:Create*", "organizations:Invite*", "organizations:Register*", "organizations:Enable*", "organizations:Attach*", "organizations:Detach*", "organizations:Put*", "sts:AssumeRoot", "account:StartPrimaryEmailUpdate", "account:PutAlternateContact"],
      one([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Sid == "NoNewAccountsOrDelegation"])
    )) == 0
    error_message = "no new member account (OrganizationAccountAccessRole), invitation, delegated administrator, SCP change, root session or recovery-contact change"
  }
  assert {
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Effect == "Deny" && (s.Resource == "*" || s.Sid == "NoAuditBucketTampering") && !contains(s.Action, "*")])
    error_message = "every guardrail statement is an account-wide Deny (the audit-bucket one aside, v3), and none denies everything"
  }
}

# Guardrails v3 (audit-trail.tf): the watched identity can't switch off or
# erase what watches it. Fails against v2, which had no such statement.
run "guardrails_v3_protect_the_audit_trail" {
  command = apply

  variables {
    enable_entra_operator = true
  }

  assert {
    condition = length(setsubtract(
      ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors", "access-analyzer:DeleteAnalyzer", "access-analyzer:CreateArchiveRule", "access-analyzer:UpdateFindings"],
      flatten([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Action if s.Effect == "Deny" && s.Resource == "*"])
    )) == 0
    error_message = "the operator must be denied, account-wide, stopping/deleting/reconfiguring any trail and deleting the analyzer or hiding its findings"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement :
      length(setsubtract(["s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObject", "s3:PutBucketRequestPayment"], s.Action)) == 0
      && toset(s.Resource) == toset(["arn:aws:s3:::contoso-health-audit-trail-123456789012", "arn:aws:s3:::contoso-health-audit-trail-123456789012/*"])
      if s.Sid == "NoAuditBucketTampering"
    ]) && length([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s if s.Sid == "NoAuditBucketTampering"]) == 1
    error_message = "the operator must be denied deleting, overwriting or loosening the audit bucket and its objects, or making it Requester Pays (CloudTrail cannot deliver to one) - and only that bucket (it still runs the patient portal)"
  }
  assert {
    condition = !anytrue([
      for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement :
      contains(flatten([s.Action]), "cloudtrail:CreateTrail") || contains(flatten([s.Action]), "cloudtrail:LookupEvents") || contains(flatten([s.Action]), "s3:GetObject")
    ])
    error_message = "reads stay open: the operator still reads the trail (LookupEvents, log files) for evidence"
  }
}
