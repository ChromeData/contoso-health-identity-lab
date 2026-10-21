# Plan-only checks of the Entra Workload ID mapping, against a mocked azuread
# provider (no tenant, no credentials). The FIC must trust exactly the
# subject the lab's Vault role binds, with the Entra token-exchange audience,
# from an HTTPS issuer Entra can reach.
# Run offline: terraform init -backend=false && terraform test

mock_provider "azuread" {}

variables {
  # Placeholders, recognisably fake: one-digit-repeated GUIDs (the only kind
  # of made-up GUID the public-repo release gate accepts), in the documented
  # AKS issuer shape. Object id and client id differ, so a test can tell
  # which one ended up where.
  aks_oidc_issuer_url   = "https://eastus.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/11111111-1111-1111-1111-111111111111/"
  application_object_id = "22222222-2222-2222-2222-222222222222"
  application_client_id = "33333333-3333-3333-3333-333333333333"
}

run "fic_trusts_exactly_nightly_report_for_token_exchange" {
  command = plan

  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.subject == "system:serviceaccount:clinical-apps:nightly-report"
    error_message = "the FIC must trust exactly system:serviceaccount:clinical-apps:nightly-report"
  }
  assert {
    condition     = toset(azuread_application_federated_identity_credential.nightly_report.audiences) == toset(["api://AzureADTokenExchange"])
    error_message = "the FIC must accept exactly one audience: api://AzureADTokenExchange"
  }
  assert {
    condition     = startswith(azuread_application_federated_identity_credential.nightly_report.issuer, "https://")
    error_message = "the issuer must be HTTPS"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.issuer == var.aks_oidc_issuer_url
    error_message = "the issuer must be the AKS OIDC issuer URL verbatim (Entra compares it to iss exactly)"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.nightly_report.application_id == "/applications/${var.application_object_id}"
    error_message = "application_id must be the application's resource id /applications/<object id> (azuread 3.x)"
  }
  assert {
    condition     = output.kubernetes_side.service_account_annotations["azure.workload.identity/client-id"] == var.application_client_id && output.kubernetes_side.pod_labels["azure.workload.identity/use"] == "true"
    error_message = "the Kubernetes half must annotate the SA with the client id and label the pod for the webhook"
  }
}

# The Entra subject and the Vault role must name the same identity. Checked
# statically against ../identity/main.tf, the root that builds the Vault role.
run "subject_matches_the_vault_role_in_identity" {
  command = plan

  assert {
    condition = (
      length(regexall("clinical_namespace\\s*=\\s*\"clinical-apps\"", file("${path.module}/../identity/main.tf"))) == 1 &&
      length(regexall("approved_sa\\s*=\\s*\"nightly-report\"", file("${path.module}/../identity/main.tf"))) == 1
    )
    error_message = "../identity no longer binds clinical-apps/nightly-report; update this mapping with it"
  }
}

run "plain_http_issuer_is_rejected" {
  command = plan

  variables {
    aks_oidc_issuer_url = "http://eastus.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/11111111-1111-1111-1111-111111111111/"
  }

  expect_failures = [var.aks_oidc_issuer_url]
}

run "kind_issuer_is_rejected" {
  command = plan

  variables {
    aks_oidc_issuer_url = "https://kubernetes.default.svc.cluster.local"
  }

  expect_failures = [var.aks_oidc_issuer_url]
}

run "loopback_issuer_is_rejected" {
  command = plan

  variables {
    aks_oidc_issuer_url = "https://127.0.0.1:6443"
  }

  expect_failures = [var.aks_oidc_issuer_url]
}

run "private_ip_issuer_is_rejected" {
  command = plan

  variables {
    aks_oidc_issuer_url = "https://10.0.0.5/"
  }

  expect_failures = [var.aks_oidc_issuer_url]
}

# A resource id (/applications/<guid>) where the bare object id belongs: main.tf
# adds the prefix itself, so this would become /applications//applications/...
# (A CLIENT id in the same place cannot be caught: it is a GUID like the
# object id. README "Decisions".)
run "resource_id_where_object_id_belongs_is_rejected" {
  command = plan

  variables {
    application_object_id = "/applications/22222222-2222-2222-2222-222222222222"
  }

  expect_failures = [var.application_object_id]
}
