# Offline, mocked tests for the lab operator role (entra-operator.tf).
# No AWS call is made:  tofu init -backend=false && tofu test
#
# What these pin: nothing is created unless enable_entra_operator; the trust
# names the Entra v2 issuer of THIS tenant and only the operator's exact client
# id (aud) and service-principal object id (sub), with StringEquals; the
# guardrail Denies block every IAM write account-wide; bad ids are refused before anything is made.

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
    condition     = alltrue([for s in jsondecode(aws_iam_role_policy.entra_operator_guardrails[0].policy).Statement : s.Effect == "Deny" && s.Resource == "*"])
    error_message = "the guardrail policy may only Deny, account-wide (a Deny scoped to the operator's own role is bypassed by creating another role)"
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
