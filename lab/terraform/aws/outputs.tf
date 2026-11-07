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

# ---- Patient portal stand-in (patient-portal.tf) ----------------------------

output "patient_portal_bucket_name" {
  description = "The patient-portal stand-in bucket (owned by Cloud Engineering)."
  value       = aws_s3_bucket.patient_portal.bucket
}

output "patient_portal_console_url" {
  description = "Where a cloud engineer opens the bucket after signing in through the AWS access portal (ViewOnlyAccess lists the objects; reading one is AccessDenied)."
  value       = "https://${var.aws_region}.console.aws.amazon.com/s3/buckets/${aws_s3_bucket.patient_portal.bucket}?region=${var.aws_region}"
}

output "patient_portal_object_keys" {
  description = "The objects Terraform keeps in the bucket."
  value       = sort(keys(aws_s3_object.patient_portal))
}

output "entra_operator_role_arn" {
  description = "Role the lab operator assumes with its Entra token (lab/scripts/operator)."
  value       = one(aws_iam_role.entra_operator[*].arn)
}

# ---- AWS admin without root (null unless enable_lab_admin_jit) ----------------

output "lab_admin_permission_set_arn" {
  description = "ARN of the LabAdministrator permission set (ADR 0025)."
  value       = one(aws_ssoadmin_permission_set.lab_admin[*].arn)
}

output "lab_admin_group_id" {
  description = "Identity Store id of PIM-AWS-Lab-Admins as SCIM created it (the only principal holding LabAdministrator)."
  value       = one(data.aws_identitystore_group.lab_admins[*].group_id)
}

output "lab_admin_group_external_ids" {
  description = "External ids SCIM stamped on the PIM admin group (expected: the Entra object id of PIM-AWS-Lab-Admins)."
  value       = var.enable_lab_admin_jit ? [for e in data.aws_identitystore_group.lab_admins[0].external_ids : e.id] : []
}

output "lab_admin_account_assignment_id" {
  description = "Composite id of the LabAdministrator assignment (principal, type, account, permission set, instance)."
  value       = one(aws_ssoadmin_account_assignment.lab_admins[*].id)
}

# ---- Audit trail (audit-trail.tf) ---------------------------------------------

output "audit_trail_arn" {
  description = "ARN of the CloudTrail trail (null unless enable_audit_baseline). Check it with: aws cloudtrail get-trail-status --name <arn>."
  value       = one(aws_cloudtrail.audit[*].arn)
}

output "audit_bucket_name" {
  description = "S3 bucket holding the trail's log and digest files (null unless enable_audit_baseline)."
  value       = one(aws_s3_bucket.audit[*].bucket)
}

output "access_analyzer_arn" {
  description = "ARN of the external-access IAM Access Analyzer (null unless enable_audit_baseline). Findings: aws accessanalyzer list-findings-v2 --analyzer-arn <arn>."
  value       = one(aws_accessanalyzer_analyzer.external_access[*].arn)
}

# ---- Session Manager (null unless enable_session_manager) ---------------------

output "session_node_instance_id" {
  description = "Instance id of the Session Manager server (aws ssm start-session --target <this>)."
  value       = one(aws_instance.ssm_node[*].id)
}

output "session_log_group_name" {
  description = "CloudWatch Logs group that holds every session transcript."
  value       = one(aws_cloudwatch_log_group.ssm_sessions[*].name)
}

output "server_session_permission_set_arn" {
  description = "ARN of the LabServerSession permission set."
  value       = one(aws_ssoadmin_permission_set.server_session[*].arn)
}
