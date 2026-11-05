# =============================================================================
# envs/operator :: variables.tf
# =============================================================================

variable "subscription_id" {
  description = "The lab subscription the operator may manage."
  type        = string
}

variable "tenant_id" {
  description = "The lab Entra tenant."
  type        = string
}

variable "operator_certificate_path" {
  description = <<-EOT
    Path to the operator's PUBLIC certificate (PEM), made by
    lab/scripts/operator/new-operator-cert.sh. The private key never leaves the
    Mac's login Keychain; only this public half is uploaded to Entra.
  EOT
  type        = string
  default     = "~/.contoso-operator/operator.crt"
}

variable "operator_display_name" {
  description = "Display name of the operator app registration."
  type        = string
  default     = "Contoso Lab Operator (local Mac, certificate)"
}

variable "operator_graph_roles" {
  description = <<-EOT
    Microsoft Graph APPLICATION permissions for the operator. The default is
    what the after-sign-in runbook needs without a human:
      Application.ReadWrite.All           envs/bootstrap (the CI apps and their
                                          federated credentials), app owners
      AppRoleAssignment.ReadWrite.All     envs/bootstrap Graph grants to the CI
                                          identities. TIER 0 (see main.tf).
      Directory.Read.All                  users, groups, roles
      Synchronization.ReadWrite.All       provision on demand (HR inbound, AWS
                                          SCIM), job restarts
      AuditLog.Read.All                   provisioning and sign-in logs
      EntitlementManagement.ReadWrite.All access packages and their policies
      Policy.Read.All                     Conditional Access, auth methods
  EOT
  type        = list(string)
  default = [
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.Read.All",
    "Synchronization.ReadWrite.All",
    "AuditLog.Read.All",
    "EntitlementManagement.ReadWrite.All",
    "Policy.Read.All",
  ]
}

variable "operator_azure_roles" {
  description = <<-EOT
    Azure built-in roles for the operator at SUBSCRIPTION scope.
      Owner                         envs/bootstrap creates role assignments
                                    for the CI identities (Contributor, the
                                    constrained RBAC Administrator), which
                                    needs unconstrained roleAssignments/write
      Storage Blob Data Contributor Terraform state (Entra auth, Shared Key is
                                    off) and evidence read-back. Subscription
                                    scope because the state account's ReadOnly
                                    lock blocks account- and container-scoped
                                    role assignments
      Key Vault Secrets User        read lab secrets (e.g. the AWS SCIM token)
  EOT
  type        = list(string)
  default     = ["Owner", "Storage Blob Data Contributor", "Key Vault Secrets User"]
}

variable "operator_directory_roles" {
  description = <<-EOT
    Entra directory roles for the operator. Security Reader: a bootstrap plan
    refreshes the tenant diagnostic setting (microsoft.aadiam), which ARM
    authorizes with Entra roles, not Azure RBAC.
  EOT
  type        = list(string)
  default     = ["Security Reader"]
}
