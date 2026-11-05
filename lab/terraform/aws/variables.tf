# =============================================================================
# aws :: variables.tf
# -----------------------------------------------------------------------------
# Nothing here is a secret. The account id is not a credential, but keep real
# values in terraform.tfvars (gitignored) rather than committing them - copy
# terraform.tfvars.example to start.
# =============================================================================

# ---- Provider / authentication ----------------------------------------------

variable "aws_profile" {
  type        = string
  description = <<-EOT
    AWS CLI profile used for plan/apply - create it with
    `aws configure sso --profile <name>` and refresh with `aws sso login`.
    The profile's role needs IAM Identity Center admin rights in the account
    that holds the instance: AWS managed AWSSSOMasterAccountAdministrator, PLUS
    IAMFullAccess while the target is the management account (the lab
    default - AWS treats assigning access to it as privileged), or simply
    AdministratorAccess in a throwaway lab org.
    Empty = the standard chain (AWS_PROFILE / default profile).
  EOT
  default     = "idlab-admin"

  validation {
    condition     = can(regex("^\\S*$", var.aws_profile))
    error_message = "aws_profile must not contain whitespace."
  }
}

variable "aws_region" {
  type        = string
  description = <<-EOT
    Region of your IAM Identity Center instance (Identity Center is regional:
    Settings -> Details -> Region in the console). A wrong region is caught at
    plan time by the instance lookup in main.tf.
  EOT
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be an AWS region code such as us-east-1 or eu-central-1."
  }
}

variable "allowed_account_ids" {
  type        = list(string)
  description = <<-EOT
    Account ids the provider is allowed to operate in (wrong-profile guard).
    Set it to the account that holds the Identity Center instance. Empty = no
    guard (not recommended outside offline validation).
  EOT
  default     = []

  validation {
    condition     = alltrue([for a in var.allowed_account_ids : can(regex("^[0-9]{12}$", a))])
    error_message = "Each allowed_account_ids entry must be a 12-digit AWS account id."
  }
}

# ---- What gets granted -------------------------------------------------------

variable "target_account_id" {
  type        = string
  description = <<-EOT
    AWS account the group is granted ViewOnlyAccess in. Empty (default) = the
    account the profile signs into (aws_caller_identity), i.e. the lab's
    single account - which, with an organization instance, is the
    Organizations MANAGEMENT account. AWS recommends user-only (not group)
    assignments there (see main.tf header); the lab accepts it for one
    view-only grant. In a multi-account org, set this to a MEMBER account id.
  EOT
  default     = ""

  validation {
    condition     = var.target_account_id == "" || can(regex("^[0-9]{12}$", var.target_account_id))
    error_message = "target_account_id must be empty or a 12-digit AWS account id."
  }
}

variable "group_display_name" {
  type        = string
  description = <<-EOT
    DisplayName of the group SCIM provisioned from Entra into the Identity
    Store. Contract name from modules/groups: App-AWS-IdentityCenter-Users.
    Terraform only READS this group - Entra and SCIM own it and its members.
  EOT
  default     = "App-AWS-IdentityCenter-Users"

  validation {
    condition     = length(trimspace(var.group_display_name)) > 0
    error_message = "group_display_name must not be empty."
  }
}

variable "entra_group_object_id" {
  type        = string
  description = <<-EOT
    OPTIONAL lineage pin. The Entra object id of App-AWS-IdentityCenter-Users
    (terraform -chdir=../envs/dev output -json app_access_group_object_ids
    | jq -r .aws). When set, plan FAILS unless the Identity Store group carries
    that id as an external id - proving the AWS principal is the Terraform-
    managed Entra group, not a same-named group created some other way.
    Empty (default) = no pin. verify: relies on the Entra AWS gallery app's
    default group mapping sending objectId as the SCIM externalId; check the
    group's ExternalIds with `aws identitystore describe-group` before setting.
  EOT
  default     = ""

  validation {
    condition     = var.entra_group_object_id == "" || can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", var.entra_group_object_id))
    error_message = "entra_group_object_id must be empty or an Entra object id (GUID)."
  }
}

variable "session_duration" {
  type        = string
  description = <<-EOT
    Permission-set session length, ISO-8601 whole hours. Identity Center allows
    1-12 hours (default 1 h); the lab contract is PT4H, matching the 4-hour PIM
    activation window on the Entra side.
  EOT
  default     = "PT4H"

  validation {
    condition     = can(regex("^PT([1-9]|1[0-2])H$", var.session_duration))
    error_message = "session_duration must be whole hours from PT1H to PT12H (IAM Identity Center limits)."
  }
}

# ---- Patient portal stand-in (patient-portal.tf) -----------------------------

variable "patient_portal_bucket_suffix" {
  type        = string
  description = <<-EOT
    Makes the patient-portal bucket name globally unique:
    contoso-health-patient-portal-<suffix>. Empty (default) = the account id
    the profile signs into. Set it only if that name is already taken.
  EOT
  default     = ""

  validation {
    # The prefix is 30 characters; S3 allows 63 in all.
    condition     = var.patient_portal_bucket_suffix == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$", var.patient_portal_bucket_suffix))
    error_message = "patient_portal_bucket_suffix must be empty or 1-32 lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

# ---- Tagging ----------------------------------------------------------------

variable "tags" {
  type        = map(string)
  description = "Tags applied (via provider default_tags) to every taggable AWS resource in this root."
  default = {
    project     = "contoso-health-identity-lab"
    environment = "dev"
    managed_by  = "terraform"
    source_idp  = "entra-id"
  }
}

# ---- GitHub Actions OIDC (github-oidc.tf) -------------------------------------
# Staged and off by default. None of these are secrets; the owner/repo ids are
# public numbers. Keep real values in terraform.tfvars (gitignored).

variable "enable_github_oidc" {
  type        = bool
  description = <<-EOT
    Create the GitHub Actions OIDC provider (unless existing_github_oidc_provider_arn
    is set) and the READ-ONLY role a workflow of this repo can assume. Applied
    by a human like the rest of this root; CI can only USE the role.
  EOT
  default     = false
}

variable "github_owner" {
  type        = string
  description = "GitHub org/user owning this repo (OWNER in repo:OWNER@OWNER_ID/REPO@REPO_ID). Same value as envs/bootstrap."
  default     = ""

  validation {
    condition     = var.github_owner == "" || can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$", var.github_owner))
    error_message = "github_owner must be empty or a GitHub user/org name."
  }
}

variable "github_owner_id" {
  type        = string
  description = "Numeric id of github_owner: gh api repos/OWNER/REPO --jq '.owner.id'."
  default     = ""

  validation {
    condition     = var.github_owner_id == "" || can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be empty or the numeric owner id."
  }
}

variable "github_repo" {
  type        = string
  description = "Repository name (REPO in repo:OWNER@OWNER_ID/REPO@REPO_ID)."
  default     = ""

  validation {
    condition     = var.github_repo == "" || can(regex("^[A-Za-z0-9._-]{1,100}$", var.github_repo))
    error_message = "github_repo must be empty or a GitHub repository name."
  }
}

variable "github_repo_id" {
  type        = string
  description = "Numeric id of github_repo: gh api repos/OWNER/REPO --jq '.id'."
  default     = ""

  validation {
    condition     = var.github_repo_id == "" || can(regex("^[0-9]+$", var.github_repo_id))
    error_message = "github_repo_id must be empty or the numeric repository id."
  }
}

variable "github_oidc_subject_suffixes" {
  type        = list(string)
  description = <<-EOT
    Workflow contexts allowed to assume the read-only role, appended to
    repo:OWNER@OWNER_ID/REPO@REPO_ID:. Default pull_request = the Entra PLAN
    identity's context. Add "ref:refs/heads/main" for a scheduled evidence
    job on main. Matched with StringEquals: wildcards are rejected here, and
    an environment: subject belongs to a WRITE role, which this is not.
  EOT
  default     = ["pull_request"]

  validation {
    condition = length(var.github_oidc_subject_suffixes) > 0 && alltrue([
      for s in var.github_oidc_subject_suffixes :
      can(regex("^(pull_request|ref:refs/(heads|tags)/[A-Za-z0-9._/-]+)$", s)) && !strcontains(s, "*")
    ])
    error_message = "github_oidc_subject_suffixes entries must be pull_request or ref:refs/heads|tags/<exact name> - no wildcards, no environment: (that is the write path)."
  }
}

variable "existing_github_oidc_provider_arn" {
  type        = string
  description = <<-EOT
    ARN of an IAM OIDC provider for token.actions.githubusercontent.com that
    already exists in this account (AWS allows one per issuer URL). Set it to
    reuse instead of create. Empty = this root creates it.
  EOT
  default     = ""

  validation {
    condition     = var.existing_github_oidc_provider_arn == "" || can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.existing_github_oidc_provider_arn))
    error_message = "existing_github_oidc_provider_arn must be empty or arn:aws:iam::<account>:oidc-provider/token.actions.githubusercontent.com."
  }
}

variable "github_readonly_role_name" {
  type        = string
  description = "Name of the read-only CI role (role-to-assume in aws-actions/configure-aws-credentials)."
  default     = "gh-oidc-aws-identitycenter-readonly"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.github_readonly_role_name))
    error_message = "github_readonly_role_name must be a valid IAM role name (1-64 chars of A-Za-z0-9+=,.@_-)."
  }
}

# ---- Lab operator (entra-operator.tf) ----------------------------------------

variable "enable_entra_operator" {
  type        = bool
  description = "Create the Entra OIDC provider and the contoso-lab-operator role (entra-operator.tf)."
  default     = false
}

variable "entra_tenant_id" {
  type        = string
  description = "The lab Entra tenant id (the token issuer)."
  default     = ""
}

variable "entra_operator_client_id" {
  type        = string
  description = "lab/terraform/envs/operator output operator_client_id: the token audience."
  default     = ""
}

variable "entra_operator_object_id" {
  type        = string
  description = "lab/terraform/envs/operator output operator_object_id: the token subject (service principal object id)."
  default     = ""
}

variable "entra_operator_role_name" {
  type        = string
  description = "Name of the operator role."
  default     = "contoso-lab-operator"

  validation {
    condition     = can(regex("^[A-Za-z0-9+=,.@_-]{1,64}$", var.entra_operator_role_name))
    error_message = "entra_operator_role_name must be a valid IAM role name."
  }
}
