# =============================================================================
# envs/bootstrap :: pipeline-config.tf
# -----------------------------------------------------------------------------
# WHAT: a small Key Vault that holds the five privacy values the Terraform
# pipeline needs (the operator's IP ranges, the alert email, the human app
# owners' object ids, the SAML certificate notification emails and the PIM
# alert mailbox). The PLAN and APPLY identities read them at run time with
# their GitHub OIDC sign-in. Nothing is stored in GitHub any more.
#
# WHY: before this file the five values were GitHub repository secrets, and a
# copy of each was a Dependabot secret (10 stored values). None of them is a
# credential; they were secrets only so GitHub masks them in run logs. A value
# stored in GitHub cannot be read back, audited per read or rotated from one
# place. In this vault:
#   * every read is an Entra-authenticated call by a named workload identity
#     (PLAN or APPLY, GitHub OIDC federation, no stored credential), logged as
#     an AuditEvent in loga-idlab;
#   * the writer is a human or the lab operator (Key Vault Secrets Officer),
#     never CI;
#   * .github/scripts/pipeline-config.sh masks each value AND each element of
#     a JSON list before it reaches $GITHUB_ENV (a repo secret masked only the
#     whole string).
#
# WHY A SEPARATE VAULT, NOT kv-idlab (modules/keyvault): kv-idlab's firewall
# is deny-by-default with only the operator's IP and a private endpoint, so a
# GitHub-hosted runner cannot reach it. Opening it to the runners would also
# open the vault that holds the lab's real secrets (break-glass and VM admin
# passwords). This vault holds only the five non-credential values, so it can
# accept public network traffic and rely on Entra RBAC alone. GitHub-hosted
# runner IPs are not a fixed, small list, so an IP allow-list is not an option
# (GitHub docs, "About GitHub-hosted runners", IP addresses).
#
# WHY HERE (envs/bootstrap), NOT envs/dev: the vault feeds the identity that
# applies envs/dev. If envs/dev owned it, a merged PR could change the values
# its own apply runs with. It also needs two role assignments (Key Vault
# Secrets User) that bootstrap already owns for the same identities.
#
# WHY ITS OWN RESOURCE GROUP: rg-identity-lab-tfstate has a ReadOnly lock (no
# new resources), and rg-identity-lab is the RG envs/dev and its APPLY
# identity manage. Once APPLY's Contributor is narrowed to rg-identity-lab
# (the least-privilege PR, senior gap 8), APPLY has no control-plane right on
# this RG at all, so it cannot switch the vault to access policies and grant
# itself more. UNTIL THEN its subscription Contributor still reaches this RG
# (residual, the same as for kv-idlab today).
#
# Verified (Microsoft Learn, read 2026-11-07):
#   * Key Vault Secrets User = 4633458b-17de-408a-b874-0445c86b69e6, "Read
#     secret contents" (built-in roles, Security).
#   * AuditEvent is the Key Vault diagnostic log category (Key Vault logging).
#   * azurerm 4.x: rbac_authorization_enabled (enable_rbac_authorization is
#     deprecated), as modules/keyvault already uses.
# =============================================================================

locals {
  pipeline_config_enabled = var.enable_pipeline_config_vault

  # The five secret names the workflows read (.github/scripts/pipeline-config.sh
  # keeps the same list). Key Vault names allow letters, digits and dashes.
  pipeline_config_secret_names = [
    "tf-operator-ip-ranges",
    "tf-alert-email",
    "tf-app-owner-object-ids",
    "tf-saml-cert-notification-emails",
    "tf-pim-alert-mailbox",
  ]
}

resource "azurerm_resource_group" "pipeline_config" {
  count    = local.pipeline_config_enabled ? 1 : 0
  name     = var.pipeline_config_resource_group_name
  location = var.pipeline_config_location
  tags = {
    project    = "contoso-health-identity-lab"
    managed_by = "terraform-bootstrap"
    purpose    = "pipeline-config"
  }
}

resource "azurerm_key_vault" "pipeline_config" {
  count = local.pipeline_config_enabled ? 1 : 0
  #checkov:skip=CKV_AZURE_189:GitHub-hosted runners must reach it and their IPs are not a fixed list; access is Entra RBAC only and the vault holds no credential (header).
  #checkov:skip=CKV_AZURE_109:Same reason: a firewall default of Deny would refuse the hosted runners. RBAC + per-read audit is the control.
  #checkov:skip=CKV2_AZURE_32:A private endpoint is unreachable from GitHub-hosted runners (the reason this vault exists).
  name                = var.pipeline_config_vault_name
  location            = azurerm_resource_group.pipeline_config[0].location
  resource_group_name = azurerm_resource_group.pipeline_config[0].name
  tenant_id           = data.azurerm_subscription.current.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled    = true
  public_network_access_enabled = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7

  network_acls {
    default_action = "Allow"
    bypass         = "AzureServices"
  }

  tags = azurerm_resource_group.pipeline_config[0].tags

  lifecycle {
    precondition {
      condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.pipeline_config_vault_name))
      error_message = "enable_pipeline_config_vault needs pipeline_config_vault_name: 3-24 letters, digits and dashes, starting with a letter (globally unique), e.g. kv-idlab-cicd-20f1."
    }
  }
}

# Read-only data-plane access for the two pipeline identities, at vault scope
# (the vault holds only the five values). Pinned by role id, not name.
resource "azurerm_role_assignment" "pipeline_config_reader" {
  for_each = local.pipeline_config_enabled ? {
    plan  = local.plan_sp
    apply = local.apply_sp
  } : {}

  scope              = azurerm_key_vault.pipeline_config[0].id
  role_definition_id = "/subscriptions/${data.azurerm_subscription.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
  principal_id       = each.value
  principal_type     = "ServicePrincipal"
  description        = "${upper(each.key)} pipeline identity: read the pipeline's privacy values at run time (GitHub OIDC). No write."
}

# Every read lands in loga-idlab (who read which value, when).
resource "azurerm_monitor_diagnostic_setting" "pipeline_config" {
  count = local.pipeline_config_enabled && var.log_analytics_workspace_id != "" ? 1 : 0

  name                       = "diag-pipeline-config"
  target_resource_id         = azurerm_key_vault.pipeline_config[0].id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "AuditEvent"
  }
}
