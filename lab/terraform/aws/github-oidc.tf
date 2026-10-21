# =============================================================================
# aws :: github-oidc.tf
# -----------------------------------------------------------------------------
# WHAT: a GitHub Actions OIDC identity provider in this AWS account, and ONE
# read-only IAM role that a workflow of THIS repository can assume - with no
# AWS access key anywhere. It is the AWS twin of the Entra PLAN identity
# (lab/terraform/modules/pipeline-identity): same immutable subject, same
# "read in CI, write only by a human" split.
#
# STAGED + HUMAN-APPLIED: enable_github_oidc defaults to false, and like the
# rest of this root it is applied from a laptop with a short-lived SSO
# session, never by CI. CI cannot create, widen or re-trust its own role: the
# trust and the permissions live here, behind a human apply.
#
# WHAT THE ROLE MAY DO: read IAM Identity Center configuration (permission
# sets, assignments, the SCIM-created group) and read its own IAM objects -
# enough for a pull-request plan / drift check of this root once it moves to
# remote state, or for a scheduled "who can reach AWS" evidence export. It can
# change nothing: no write is allowed, and the common write verbs are
# explicitly DENIED, so attaching a broad policy to it later still cannot turn
# it into a deploy role. A WRITE (apply) role is deliberately not built:
# README "Production option" describes it and why the lab does not need it.
#
# NOTHING HERE HAS RUN AGAINST AWS. Validated offline only (fmt, validate,
# mocked `terraform test` in tests/).
# =============================================================================

locals {
  github_oidc_host = "token.actions.githubusercontent.com"

  # GitHub's immutable subject form, identical to the Entra pipeline's
  # (modules/pipeline-identity): repo:OWNER@OWNER_ID/REPO@REPO_ID:<context>.
  # The numeric ids are never reused, so a deleted-and-recreated owner or repo
  # with the same name can never mint a token this role accepts.
  # verify: GitHub documents the :ref: example of this form; confirm the
  # :pull_request subject with GitHub's OIDC subject preview before first use
  # (the same open item as on the Entra side).
  github_repo_path = "${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
  github_oidc_subjects = [
    for suffix in var.github_oidc_subject_suffixes : "repo:${local.github_repo_path}:${suffix}"
  ]

  # One GitHub OIDC provider per account: reuse an existing one if given.
  create_github_oidc_provider = var.enable_github_oidc && var.existing_github_oidc_provider_arn == ""
  github_oidc_provider_arn = (
    var.existing_github_oidc_provider_arn != ""
    ? var.existing_github_oidc_provider_arn
    : one(aws_iam_openid_connect_provider.github[*].arn)
  )

  github_readonly_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.github_readonly_role_name}"

  # Trust policy as jsonencode() rather than data.aws_iam_policy_document:
  # identical JSON, but deterministic offline, so the mocked tests can assert
  # the exact subject and audience (a mocked data source returns random JSON).
  github_readonly_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "GitHubActionsThisRepoExactSubject"
        Effect    = "Allow"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Principal = { Federated = local.github_oidc_provider_arn }
        Condition = {
          # StringEquals, never StringLike: no wildcard can widen the trust to
          # other branches, environments or repositories.
          StringEquals = {
            "${local.github_oidc_host}:aud" = "sts.amazonaws.com"
            "${local.github_oidc_host}:sub" = local.github_oidc_subjects
          }
        }
      },
    ]
  })

  github_readonly_permissions = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # The same read prefixes AWS's own AWSSSOReadOnly managed policy uses,
        # without its Organizations / Directory Service / KMS extras.
        # List/Describe on Identity Center mostly do not support resource-level
        # scoping, hence "*". verify: kms:Decrypt (kms:ViaService sso.*) is
        # also needed if the instance uses a customer-managed KMS key.
        Sid      = "ReadIdentityCenterConfiguration"
        Effect   = "Allow"
        Action   = ["sso:Describe*", "sso:Get*", "sso:List*"]
        Resource = "*"
      },
      {
        # Exactly what data.aws_identitystore_group in main.tf calls.
        Sid      = "LookUpTheScimProvisionedGroup"
        Effect   = "Allow"
        Action   = ["identitystore:GetGroupId", "identitystore:DescribeGroup"]
        Resource = "*"
      },
      {
        # Refreshing this root's own IAM objects during a plan.
        Sid      = "ReadOwnOidcTrust"
        Effect   = "Allow"
        Action   = ["iam:GetOpenIDConnectProvider"]
        Resource = local.github_oidc_provider_arn
      },
      {
        Sid      = "ReadOwnRole"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies"]
        Resource = local.github_readonly_role_arn
      },
      {
        # Read-only by construction: even if someone later attaches a broad
        # managed policy to this role, these verbs stay denied (an explicit
        # Deny always wins in IAM policy evaluation).
        Sid    = "NeverWrite"
        Effect = "Deny"
        Action = [
          "sso:Create*", "sso:Delete*", "sso:Put*", "sso:Attach*", "sso:Detach*",
          "sso:Update*", "sso:Provision*", "sso:Tag*", "sso:Untag*",
          "identitystore:Create*", "identitystore:Delete*", "identitystore:Update*",
          "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*", "iam:Detach*",
          "iam:Update*", "iam:Add*", "iam:Remove*", "iam:Tag*", "iam:Untag*",
          "iam:PassRole",
        ]
        Resource = "*"
      },
    ]
  })
}

# The account-level trust in GitHub's OIDC issuer. No thumbprint_list: AWS
# validates token.actions.githubusercontent.com against its own trusted root
# CAs and no longer uses configured thumbprints for this issuer (the provider
# makes the argument optional and AWS fills it in). verify: on first apply.
resource "aws_iam_openid_connect_provider" "github" {
  count = local.create_github_oidc_provider ? 1 : 0

  url            = "https://${local.github_oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "github_readonly" {
  count = var.enable_github_oidc ? 1 : 0

  name                 = var.github_readonly_role_name
  description          = "GitHub Actions (OIDC, this repo only, ${join(" / ", var.github_oidc_subject_suffixes)}): READ-ONLY IAM Identity Center. No access keys. Managed by Terraform - lab/terraform/aws (human-applied)."
  assume_role_policy   = local.github_readonly_trust_policy
  max_session_duration = 3600 # the IAM minimum; a CI job needs minutes

  lifecycle {
    precondition {
      condition = (
        can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", var.github_owner))
        && can(regex("^[0-9]+$", var.github_owner_id))
        && can(regex("^[A-Za-z0-9._-]{1,100}$", var.github_repo))
        && can(regex("^[0-9]+$", var.github_repo_id))
      )
      error_message = "enable_github_oidc = true needs github_owner, github_owner_id, github_repo and github_repo_id (ids: gh api repos/OWNER/REPO --jq '.owner.id, .id')."
    }
  }
}

resource "aws_iam_role_policy" "github_readonly" {
  count = var.enable_github_oidc ? 1 : 0

  name   = "identity-center-read-only"
  role   = aws_iam_role.github_readonly[0].id
  policy = local.github_readonly_permissions
}
