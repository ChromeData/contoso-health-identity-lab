# =============================================================================
# aws :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY by a human admin, never by CI (same rule as envs/bootstrap on
# the Azure side).
#
# AUTHENTICATION: a named profile from the operator's AWS CLI config - ideally
# one created with `aws configure sso` and refreshed with `aws sso login`, so
# every credential is short-lived and every API call is attributed to a named
# person in CloudTrail. There are NO access_key / secret_key arguments here and
# there must never be: no static AWS keys in code, tfvars, state or the
# environment of this repo. (TruffleHog in CI fails a PR that commits one.)
#
# REGION: IAM Identity Center is a regional service. var.aws_region MUST be the
# region where your Identity Center instance lives, or the instance lookup in
# main.tf finds nothing and fails the plan with an explicit message.
#
# `tofu/terraform validate` and the mocked `tofu test` do not contact AWS, so an
# unconfigured profile is fine for offline checks. plan/apply need a live
# `aws sso login --profile <aws_profile>` session.
# =============================================================================

provider "aws" {
  region = var.aws_region

  # Empty string = fall back to the standard chain (AWS_PROFILE, then the
  # default profile). Keep it set: an explicit profile is a reviewable fact.
  profile = var.aws_profile != "" ? var.aws_profile : null

  # Guard rail: refuse to plan/apply if the profile resolves to an account
  # that is not on this list (wrong-profile protection). Empty list = no guard.
  allowed_account_ids = length(var.allowed_account_ids) > 0 ? var.allowed_account_ids : null

  # Applied to every taggable resource (here: the permission set). Account
  # assignments and policy attachments are not taggable AWS objects.
  default_tags {
    tags = var.tags
  }
}
