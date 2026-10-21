# =============================================================================
# aws :: outputs.tf
# -----------------------------------------------------------------------------
# Everything here is an identifier, not a credential. The values feed the
# README verify list (aws sso-admin / aws identitystore commands) and the
# evidence pack: they prove WHICH Entra-sourced group holds WHICH permission
# set in WHICH account, as code rather than as a console screenshot.
# =============================================================================

output "identity_center_instance_arn" {
  description = "ARN of the IAM Identity Center instance (--instance-arn for aws sso-admin commands)."
  value       = local.instance_arn
}

output "identity_store_id" {
  description = "Identity Store id (d-xxxxxxxxxx) holding the SCIM-provisioned users and groups."
  value       = local.identity_store_id
}

output "aws_users_group_id" {
  description = "Identity Store id of App-AWS-IdentityCenter-Users as created by SCIM (the assignment principal)."
  value       = data.aws_identitystore_group.aws_users.group_id
}

output "aws_users_group_external_ids" {
  description = "External ids SCIM stamped on the group (expected: the Entra group object id). Empty suggests a hand-made group."
  value       = [for e in data.aws_identitystore_group.aws_users.external_ids : e.id]
}

output "permission_set_arn" {
  description = "ARN of the ViewOnlyAccess permission set."
  value       = aws_ssoadmin_permission_set.view_only.arn
}

output "permission_set_session_duration" {
  description = "Session length of the permission set (ISO-8601)."
  value       = aws_ssoadmin_permission_set.view_only.session_duration
}

output "target_account_id" {
  description = "AWS account the group was granted ViewOnlyAccess in."
  value       = local.target_account_id
}

output "account_assignment_id" {
  description = "Composite id of the assignment: principal_id,principal_type,target_id,target_type,permission_set_arn,instance_arn."
  value       = aws_ssoadmin_account_assignment.view_only_users.id
}

# ---- GitHub Actions OIDC (null unless enable_github_oidc) -------------------

output "github_oidc_provider_arn" {
  description = "IAM OIDC provider trusted for token.actions.githubusercontent.com (created here or reused)."
  value       = var.enable_github_oidc ? local.github_oidc_provider_arn : null
}

output "github_readonly_role_arn" {
  description = "role-to-assume for aws-actions/configure-aws-credentials in a read-only workflow of this repo."
  value       = one(aws_iam_role.github_readonly[*].arn)
}

output "github_readonly_role_subjects" {
  description = "Exact OIDC subjects the read-only role trusts (StringEquals)."
  value       = var.enable_github_oidc ? local.github_oidc_subjects : []
}
