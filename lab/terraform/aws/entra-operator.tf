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
# account the provider's allowed_account_ids pins - minus guardrails that an
# explicit Deny keeps true even for an admin:
#   * no long-lived credentials: no IAM users, access keys or console
#     passwords (the lab rule: no static AWS keys anywhere)
#   * cannot edit its own trust, permissions or the Entra provider, so it
#     cannot widen who may assume it or outlive the kill switch
#   * cannot close the account or leave / delete the organization
#
# STAGED + HUMAN-APPLIED: enable_entra_operator defaults to false; turned on
# with a targeted apply from the admin's laptop, like the rest of this root.
# =============================================================================

locals {
  # v2 issuer (envs/operator sets requested_access_token_version = 2).
  entra_issuer_host = "login.microsoftonline.com/${var.entra_tenant_id}/v2.0"

  entra_operator_provider_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.entra_issuer_host}"
  entra_operator_role_arn     = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.entra_operator_role_name}"

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
        Sid    = "NoLongLivedCredentials"
        Effect = "Deny"
        Action = [
          "iam:CreateUser", "iam:CreateAccessKey", "iam:UpdateAccessKey",
          "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
          "iam:CreateServiceSpecificCredential", "iam:UploadSSHPublicKey",
        ]
        Resource = "*"
      },
      {
        Sid    = "CannotChangeItsOwnTrustOrRights"
        Effect = "Deny"
        Action = [
          "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePermissionsBoundary", "iam:UpdateRole", "iam:DeleteRole",
          "iam:TagRole", "iam:UntagRole",
        ]
        Resource = local.entra_operator_role_arn
      },
      {
        Sid    = "CannotChangeTheEntraTrust"
        Effect = "Deny"
        Action = [
          "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider",
          "iam:AddClientIDToOpenIDConnectProvider", "iam:RemoveClientIDFromOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint", "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider",
        ]
        Resource = local.entra_operator_provider_arn
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
