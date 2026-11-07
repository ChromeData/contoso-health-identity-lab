# Offline checks of the Entra Workload ID trust and the Key Vault grant,
# against mocked providers (no tenant, no credentials). The federated
# credential must trust exactly the subject ../identity runs as, with the
# Entra token-exchange audience, from an HTTPS issuer Entra can reach; the
# workload gets Key Vault Secrets User on ONE secret, not the vault.
# Run offline: terraform init -backend=false && terraform test

mock_provider "azuread" {
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/22222222-2222-2222-2222-222222222222"
      client_id = "33333333-3333-3333-3333-333333333333"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = {
      object_id = "44444444-4444-4444-4444-444444444444"
    }
  }
}

mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000"
    }
  }
}

variables {
  # Placeholders, recognisably fake (one-digit-repeated GUIDs, the only kind
  # of made-up GUID the public-repo release gate accepts).
  run_id       = "0a1b2c3d"
  issuer_url   = "https://stk8skv0a1b2c3d.z20.web.core.windows.net"
  key_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-k8skv-test-0a1b2c3d/providers/Microsoft.KeyVault/vaults/kv-k8s-0a1b2c3d"
}

run "fic_trusts_exactly_nightly_report_for_token_exchange" {
  command = apply

  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.subject == "system:serviceaccount:clinical-apps:nightly-report"
    error_message = "the federated credential must trust exactly system:serviceaccount:clinical-apps:nightly-report"
  }
  assert {
    condition     = toset(azuread_application_federated_identity_credential.nightly_report.audiences) == toset(["api://AzureADTokenExchange"])
    error_message = "the federated credential must accept exactly one audience: api://AzureADTokenExchange"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.issuer == var.issuer_url
    error_message = "the issuer must be the cluster's issuer verbatim (Entra compares it to iss exactly)"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.application_id == azuread_application.nightly_report.id
    error_message = "the credential belongs to this run's app registration"
  }
  assert {
    condition     = output.client_id == "33333333-3333-3333-3333-333333333333"
    error_message = "output client_id must be the app's client id (what the SecretProviderClass names)"
  }
}

run "key_vault_grant_is_one_secret_read_only" {
  command = apply

  assert {
    condition     = azurerm_role_assignment.secret_reader.scope == "${var.key_vault_id}/secrets/clinical-db"
    error_message = "the role must be scoped to the one secret, not the vault"
  }
  assert {
    condition     = endswith(azurerm_role_assignment.secret_reader.role_definition_id, "/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6")
    error_message = "the role must be Key Vault Secrets User (4633458b-...), by id"
  }
  assert {
    condition     = azurerm_role_assignment.secret_reader.principal_id == azuread_service_principal.nightly_report.object_id && azurerm_role_assignment.secret_reader.principal_type == "ServicePrincipal"
    error_message = "the assignee must be this run's service principal"
  }
}

# The Entra subject must name the identity ../identity creates and the CSI
# SecretProviderClass serves. Checked statically against ../identity/main.tf.
run "subject_matches_the_identity_root" {
  command = plan

  assert {
    condition = (
      strcontains(file("${path.module}/../identity/main.tf"), "clinical_namespace = \"clinical-apps\"") &&
      strcontains(file("${path.module}/../identity/main.tf"), "approved_sa        = \"nightly-report\"")
    )
    error_message = "../identity must still create clinical-apps/nightly-report, the subject this credential trusts"
  }
}

run "kind_default_issuer_is_rejected" {
  command = plan

  variables {
    issuer_url = "https://kubernetes.default.svc.cluster.local"
  }

  expect_failures = [var.issuer_url]
}

run "trailing_slash_issuer_is_rejected" {
  command = plan

  variables {
    issuer_url = "https://stk8skv0a1b2c3d.z20.web.core.windows.net/"
  }

  expect_failures = [var.issuer_url]
}

run "http_issuer_is_rejected" {
  command = plan

  variables {
    issuer_url = "http://stk8skv0a1b2c3d.z20.web.core.windows.net"
  }

  expect_failures = [var.issuer_url]
}
