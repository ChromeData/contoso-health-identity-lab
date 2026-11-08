# =============================================================================
# aws :: entra-operator.tf
# -----------------------------------------------------------------------------
# WHAT: AWS trusts the lab's Entra tenant as an OIDC identity provider, and ONE
# IAM role, contoso-lab-operator, accepts tokens whose subject is the LAB
# OPERATOR service principal (lab/terraform/envs/operator) - nobody else in
# the tenant. The operator signs in to Entra with its certificate, asks Entra
# for a token to itself, and trades it with STS for a one-hour AWS session:
# no AWS access key exists anywhere, and disabling the service principal in
# Entra ends AWS access too.
#
# WHY NOT IAM IDENTITY CENTER: Identity Center sign-in is interactive (a
# person, a browser, Entra MFA). The operator is unattended, so it uses the
# same web-identity federation as the GitHub role in github-oidc.tf.
#
# WHAT THE ROLE MAY DO: AdministratorAccess in this one account - the lab
# account the provider's allowed_account_ids pins - EXCEPT anything that
# changes WHO can administer AWS, or erases the record of what it did. An
# explicit Deny keeps that true even for an admin. Guardrails v2 (ADR 0025)
# and v3 (audit-trail.tf) - every statement but the audit-bucket one is
# account-wide, because a Deny scoped to the operator's own role is bypassed by making
# another principal:
#   * NoIamChanges: every IAM write verb, PassRole included: no users or
#     access keys, no second role it could assume or hand to a service, no
#     edit to its own trust or to the Entra provider. Without this,
#     AdministratorAccess could create a new admin role, assume it and shed
#     these Denies - access that would outlive the Entra kill switch.
#   * NoIdentityCenterChanges (new in v2): every IAM Identity Center
#     (sso:), identity store (identitystore:) and Identity Center directory
#     (sso-directory:) write. v1 left these open, which was a second admin
#     path that never touches IAM: create a permission set with
#     AdministratorAccess, a local Identity Center user (or a SCIM bearer
#     token, or a new identity source) and assign it. Reads stay allowed
#     (Describe/Get/List/Search), so the operator can still report on them.
#   * NoNewAccountsOrDelegation (new in v2): the Organizations writes that
#     would put admin somewhere these Denies do not reach - a new member
#     account (it comes with OrganizationAccountAccessRole), an invitation,
#     a delegated administrator, a service-access or policy change - plus
#     sts:AssumeRoot (centralized root access) and the account's primary
#     email / alternate contacts (the root-recovery and security-alert
#     paths).
#   * NoOtherWayIn: IAM Roles Anywhere trust anchors, profiles, CRLs and
#     attribute mappings (a certificate way in without Entra).
#   * CannotCloseOrDetachTheAccount.
#   * NoServerShell + NoSessionLogTampering (new in v4, session-manager.tf):
#     no Session Manager shell, SendCommand, EC2 Instance Connect or Fleet
#     Manager GUI connection for the operator - servers are reached only
#     through a PIM activation (LabServerSession) - and no edit or delete of
#     the session preferences document or the session log group.
#   * NoAuditTampering (new in v3, audit-trail.tf): the operator can't
#     stop, delete or reconfigure any CloudTrail trail, can't delete the
#     Access Analyzer or hide its findings (archive rules, UpdateFindings),
#     and can't delete, overwrite or loosen anything in the audit bucket,
#     or make it Requester Pays (CloudTrail can't deliver to one).
#     Before v3 it could (simulate-principal-policy 2026-11-06:
#     cloudtrail:StopLogging and DeleteTrail "allowed"), which means the
#     identity being watched could switch the camera off. The S3 part is
#     scoped to the audit bucket, the one exception to "account-wide": the
#     operator still runs the patient-portal bucket, and the reason for the
#     account-wide rule (a new principal sheds a role-scoped Deny) can't
#     apply, because NoIamChanges stops it making one. CloudTrail itself
#     writes as the cloudtrail.amazonaws.com service, which this role-level
#     Deny doesn't touch. Action names checked 2026-11-06 against the same
#     service map.
# Action names checked 2026-11-05 against the AWS policy generator's
# service map (awspolicygen.s3.amazonaws.com/js/policies.js) and the
# Service Authorization Reference.
#
# WHO CHANGES IAM AND IDENTITY CENTER NOW: a person who activated
# PIM-AWS-Lab-Admins in Entra (lab-admin.tf, ADR 0025) - never root, never
# this role.
#
# STAGED + HUMAN-APPLIED: enable_entra_operator defaults to false; turned on
# with a targeted apply from the admin's laptop, like the rest of this root.
# =============================================================================

locals {
  # v2 issuer (envs/operator sets requested_access_token_version = 2).
  entra_issuer_host = "login.microsoftonline.com/${var.entra_tenant_id}/v2.0"

  # From the resource, not a string: the role's trust then depends on the
  # provider, so a fresh apply creates the provider first.
  entra_operator_provider_arn = one(aws_iam_openid_connect_provider.entra[*].arn)

  entra_operator_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "LabOperatorServicePrincipalOnly"
        Effect    = "Allow"
        Action    = "sts:AssumeRoleWithWebIdentity"
        Principal = { Federated = local.entra_operator_provider_arn }
        Condition = {
          # aud: the operator asked for a token to itself (api://<client id>),
          #      so aud (and azp, which IAM prefers when present) = its client id.
          # sub: an app-only Entra token's subject is the service principal's
          #      object id - immutable, never reused.
          StringEquals = {
            "${local.entra_issuer_host}:aud" = var.entra_operator_client_id
            "${local.entra_issuer_host}:sub" = var.entra_operator_object_id
          }
        }
      },
    ]
  })

  entra_operator_guardrails = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Every IAM write. iam:Get*/List*/Generate*/Simulate* stay allowed.
        # v2 adds Accept/Associate/Disable/Reject/Send (delegation requests,
        # root-credential and outbound-federation switches).
        Sid    = "NoIamChanges"
        Effect = "Deny"
        Action = [
          "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*", "iam:Detach*",
          "iam:Update*", "iam:Add*", "iam:Remove*", "iam:Upload*", "iam:Tag*",
          "iam:Untag*", "iam:Set*", "iam:Enable*", "iam:Disable*", "iam:Deactivate*",
          "iam:Resync*", "iam:Change*", "iam:Reset*", "iam:Accept*", "iam:Associate*",
          "iam:Reject*", "iam:Send*", "iam:PassRole",
        ]
        Resource = "*"
      },
      {
        # Every write verb of the three Identity Center prefixes. Reads
        # (Describe*/Get*/List*/Search*/IsMemberIn*) stay allowed.
        Sid    = "NoIdentityCenterChanges"
        Effect = "Deny"
        Action = [
          "sso:Create*", "sso:Put*", "sso:Attach*", "sso:Detach*", "sso:Delete*",
          "sso:Update*", "sso:Provision*", "sso:Associate*", "sso:Disassociate*",
          "sso:Import*", "sso:Start*", "sso:Add*", "sso:Remove*", "sso:Tag*",
          "sso:Untag*",
          "identitystore:Create*", "identitystore:Update*", "identitystore:Delete*",
          "identitystore:Add*", "identitystore:Remove*", "identitystore:Reserve*",
          "sso-directory:Create*", "sso-directory:Update*", "sso-directory:Delete*",
          "sso-directory:Add*", "sso-directory:Remove*", "sso-directory:Enable*",
          "sso-directory:Disable*", "sso-directory:Import*", "sso-directory:Start*",
          "sso-directory:Complete*", "sso-directory:Verify*",
        ]
        Resource = "*"
      },
      {
        Sid    = "NoNewAccountsOrDelegation"
        Effect = "Deny"
        Action = [
          "organizations:Create*", "organizations:Invite*", "organizations:Accept*",
          "organizations:Register*", "organizations:Deregister*", "organizations:Enable*",
          "organizations:Disable*", "organizations:Attach*", "organizations:Detach*",
          "organizations:Update*", "organizations:Delete*", "organizations:Move*",
          "organizations:Put*", "organizations:Remove*",
          "sts:AssumeRoot",
          "account:StartPrimaryEmailUpdate", "account:AcceptPrimaryEmailUpdate",
          "account:PutAlternateContact", "account:DeleteAlternateContact",
          "account:PutContactInformation",
        ]
        Resource = "*"
      },
      {
        Sid    = "NoOtherWayIn"
        Effect = "Deny"
        Action = [
          "rolesanywhere:Create*", "rolesanywhere:Update*", "rolesanywhere:Enable*",
          "rolesanywhere:Put*", "rolesanywhere:Import*",
        ]
        Resource = "*"
      },
      {
        Sid    = "NoAuditTampering"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
          "access-analyzer:DeleteAnalyzer", "access-analyzer:CreateArchiveRule",
          "access-analyzer:UpdateArchiveRule", "access-analyzer:ApplyArchiveRule",
          "access-analyzer:UpdateFindings",
        ]
        Resource = "*"
      },
      {
        Sid    = "NoAuditBucketTampering"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning",
          "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketOwnershipControls", "s3:PutBucketAcl",
          # Requester Pays: CloudTrail can't deliver to such a bucket, so
          # switching it on would stop new logs without a CloudTrail call.
          "s3:PutBucketRequestPayment",
          "s3:PutBucketObjectLockConfiguration", "s3:PutObjectRetention",
          "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
        ]
        Resource = [local.audit_bucket_arn, "${local.audit_bucket_arn}/*"]
      },
      {
        # v4 (session-manager.tf): servers are reached ONLY through a PIM
        # activation (LabServerSession). Without this the operator's
        # AdministratorAccess opened a shell on the Session Manager server
        # with no activation (seen live 2026-11-07 01:15:51Z, E126) and could
        # SendCommand outside the logged shell. Account-wide: every channel
        # that runs code on, or logs in to, an instance. Action names checked
        # 2026-11-07 against the Service Authorization Reference (Systems
        # Manager, EC2 Instance Connect, Fleet Manager GUI Connect).
        Sid    = "NoServerShell"
        Effect = "Deny"
        Action = [
          "ssm:StartSession", "ssm:ResumeSession", "ssm:SendCommand",
          "ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
          "ec2-instance-connect:OpenTunnel", "ssm-guiconnect:StartConnection",
        ]
        Resource = "*"
      },
      {
        # v4: the operator can't switch the session log off or erase it:
        # not edit or delete the account-wide preferences document, not
        # delete or shorten the session log group. Scoped like the audit
        # bucket (the operator still runs other documents and log groups;
        # NoIamChanges stops it making a principal that sheds this Deny).
        Sid    = "NoSessionLogTampering"
        Effect = "Deny"
        Action = [
          "ssm:UpdateDocument", "ssm:DeleteDocument", "ssm:UpdateDocumentDefaultVersion",
          "logs:DeleteLogGroup", "logs:DeleteLogStream", "logs:PutRetentionPolicy",
          "logs:DeleteRetentionPolicy", "logs:DisassociateKmsKey",
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:document/SSM-SessionManagerRunShell",
          "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/contoso-lab/session-manager",
          "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/contoso-lab/session-manager:*",
        ]
      },
      {
        Sid      = "CannotCloseOrDetachTheAccount"
        Effect   = "Deny"
        Action   = ["account:CloseAccount", "organizations:LeaveOrganization", "organizations:DeleteOrganization"]
        Resource = "*"
      },
    ]
  })
}

# No thumbprint_list: login.microsoftonline.com chains to a public root CA
# that AWS already trusts, so IAM ignores configured thumbprints for it (the
# same reasoning as the GitHub provider). verify: on first apply.
resource "aws_iam_openid_connect_provider" "entra" {
  count = var.enable_entra_operator ? 1 : 0

  url            = "https://${local.entra_issuer_host}"
  client_id_list = [var.entra_operator_client_id]
}

resource "aws_iam_role" "entra_operator" {
  count = var.enable_entra_operator ? 1 : 0

  name                 = var.entra_operator_role_name
  description          = "Lab operator (Entra service principal ${var.entra_operator_object_id}, certificate on the admin's Mac). No access keys. Managed by Terraform - lab/terraform/aws (human-applied)."
  assume_role_policy   = local.entra_operator_trust_policy
  max_session_duration = 3600

  lifecycle {
    precondition {
      condition = (
        can(regex("^[0-9a-f-]{36}$", var.entra_tenant_id))
        && can(regex("^[0-9a-f-]{36}$", var.entra_operator_client_id))
        && can(regex("^[0-9a-f-]{36}$", var.entra_operator_object_id))
      )
      error_message = "enable_entra_operator = true needs entra_tenant_id, entra_operator_client_id and entra_operator_object_id (lab/terraform/envs/operator outputs)."
    }
  }
}

resource "aws_iam_role_policy_attachment" "entra_operator_admin" {
  count = var.enable_entra_operator ? 1 : 0

  role       = aws_iam_role.entra_operator[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy" "entra_operator_guardrails" {
  count = var.enable_entra_operator ? 1 : 0

  name   = "guardrails"
  role   = aws_iam_role.entra_operator[0].id
  policy = local.entra_operator_guardrails
}
