# Offline, mocked tests for the GitHub OIDC read-only role (github-oidc.tf).
# No AWS call is made:  terraform init -backend=false && terraform test
#
# What these pin: nothing is created unless enable_github_oidc; the trust is
# this repo's exact immutable subject + the STS audience, matched with
# StringEquals; every ALLOW in the role policy is a read; writes are denied;
# wildcards and environment subjects are refused; an existing provider is
# reused instead of duplicated.
#
# The mocked data sources also satisfy main.tf's existing guards (an Identity
# Center instance exists, the group carries an external id).

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
      id  = "gh-oidc-aws-identitycenter-readonly"
      arn = "arn:aws:iam::123456789012:role/gh-oidc-aws-identitycenter-readonly"
    }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
  }
}

variables {
  github_owner    = "contoso-health"
  github_owner_id = "1234567"
  github_repo     = "contoso-health-identity-lab"
  github_repo_id  = "7654321"
}

run "off_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0 && length(aws_iam_role.github_readonly) == 0 && length(aws_iam_role_policy.github_readonly) == 0
    error_message = "no GitHub trust may exist unless enable_github_oidc = true"
  }
}

run "trust_is_this_repos_exact_subject" {
  command = apply # mocked: resolves the provider ARN into the trust policy

  variables {
    enable_github_oidc = true
  }

  assert {
    condition     = jsondecode(aws_iam_role.github_readonly[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == ["repo:contoso-health@1234567/contoso-health-identity-lab@7654321:pull_request"]
    error_message = "the role must trust only this repo's immutable pull_request subject"
  }
  assert {
    condition     = jsondecode(aws_iam_role.github_readonly[0].assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "the audience must be pinned to sts.amazonaws.com"
  }
  assert {
    condition     = !strcontains(aws_iam_role.github_readonly[0].assume_role_policy, "StringLike") && !strcontains(aws_iam_role.github_readonly[0].assume_role_policy, "*")
    error_message = "no StringLike and no wildcard anywhere in the trust policy"
  }
  assert {
    condition     = jsondecode(aws_iam_role.github_readonly[0].assume_role_policy).Statement[0].Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    error_message = "the trust must name the GitHub OIDC provider created here"
  }
  assert {
    condition     = aws_iam_role.github_readonly[0].max_session_duration == 3600
    error_message = "sessions must stay at the 1-hour IAM minimum"
  }
}

run "every_allow_is_a_read_and_writes_are_denied" {
  command = apply

  variables {
    enable_github_oidc = true
  }

  assert {
    condition = alltrue(flatten([
      for s in jsondecode(aws_iam_role_policy.github_readonly[0].policy).Statement : [
        for a in flatten([s.Action]) :
        can(regex("^(sso:(Describe|Get|List)\\*|identitystore:(GetGroupId|DescribeGroup)|iam:(Get|List)[A-Za-z]+)$", a))
      ] if s.Effect == "Allow"
    ]))
    error_message = "every Allow action must be a read (sso Describe/Get/List, identitystore lookups, iam Get/List)"
  }
  assert {
    condition = anytrue([
      for s in jsondecode(aws_iam_role_policy.github_readonly[0].policy).Statement :
      s.Effect == "Deny" && contains(flatten([s.Action]), "sso:Create*") && contains(flatten([s.Action]), "iam:PassRole")
    ])
    error_message = "writes (and PassRole) must be explicitly denied"
  }
}

run "wildcard_subject_is_rejected" {
  command = plan

  variables {
    enable_github_oidc           = true
    github_oidc_subject_suffixes = ["ref:refs/heads/*"]
  }

  expect_failures = [var.github_oidc_subject_suffixes]
}

run "environment_subject_is_rejected" {
  command = plan

  variables {
    enable_github_oidc           = true
    github_oidc_subject_suffixes = ["environment:aws-prod"]
  }

  expect_failures = [var.github_oidc_subject_suffixes]
}

run "missing_repo_ids_fail_the_plan" {
  command = plan

  variables {
    enable_github_oidc = true
    github_repo_id     = ""
  }

  expect_failures = [aws_iam_role.github_readonly]
}

run "existing_provider_is_reused" {
  command = apply

  variables {
    enable_github_oidc                = true
    existing_github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  }

  assert {
    condition     = length(aws_iam_openid_connect_provider.github) == 0
    error_message = "an existing GitHub OIDC provider must be reused, not duplicated"
  }
  assert {
    condition     = output.github_oidc_provider_arn == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    error_message = "the output must name the reused provider"
  }
}
