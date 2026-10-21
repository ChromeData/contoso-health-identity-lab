# Stage 1 (platform) guard rails, checked offline against mocked providers:
# PSA labels per namespace, the Vault Helm values that the rest of the segment
# depends on (dev mode, digest-pinned images, NodePort 30820, fail-closed injector
# webhook scoped to clinical-apps), and the input validation that keeps a weak
# root token or a non-kind context out.
# Run offline: terraform init -backend=false && terraform test

mock_provider "kubernetes" {}
mock_provider "helm" {}

variables {
  # Format-valid placeholder for the mocked plan; not a credential.
  vault_dev_root_token = "tftest-placeholder-token-0000000000000000"
}

run "namespaces_carry_the_pod_security_levels" {
  command = plan

  assert {
    condition     = kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/enforce"] == "restricted"
    error_message = "clinical-apps must ENFORCE the restricted Pod Security profile"
  }
  assert {
    condition = alltrue([
      for mode in ["warn", "audit"] :
      kubernetes_namespace_v1.clinical_apps.metadata[0].labels["pod-security.kubernetes.io/${mode}"] == "restricted"
    ])
    error_message = "clinical-apps must also warn and audit at restricted"
  }
  assert {
    condition     = kubernetes_namespace_v1.vault.metadata[0].labels["pod-security.kubernetes.io/enforce"] == "baseline"
    error_message = "the vault namespace must enforce baseline"
  }
}

run "vault_release_is_pinned_and_wired_for_the_lab" {
  command = plan

  assert {
    condition     = helm_release.vault.version == "0.34.1" && helm_release.vault.chart == "vault"
    error_message = "the Vault chart must be pinned to hashicorp/vault 0.34.1"
  }
  assert {
    condition     = yamldecode(helm_release.vault.values[0]).server.dev.enabled == true
    error_message = "Vault must run in dev mode (in-memory, ephemeral cluster)"
  }
  assert {
    condition = (
      startswith(yamldecode(helm_release.vault.values[0]).server.image.tag, "2.1.1@") &&
      yamldecode(helm_release.vault.values[0]).injector.agentImage.tag == yamldecode(helm_release.vault.values[0]).server.image.tag
    )
    error_message = "server and injected agent must both run hashicorp/vault:2.1.1 (same digest)"
  }
  # Every image the chart runs is pinned by digest. The chart renders
  # "<repository>:<tag>", so the digest rides in the tag. The agent pin is
  # load-bearing: ../identity's admission policy rejects any container in
  # clinical-apps (the injected agent included) without "@sha256:".
  assert {
    condition = alltrue([
      for tag in [
        yamldecode(helm_release.vault.values[0]).server.image.tag,
        yamldecode(helm_release.vault.values[0]).injector.agentImage.tag,
        yamldecode(helm_release.vault.values[0]).injector.image.tag,
      ] : can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+@sha256:[0-9a-f]{64}$", tag))
    ])
    error_message = "server, agent and injector images must be <version>@sha256:<64 hex> (digest-pinned)"
  }
  assert {
    condition     = output.vault_agent_image == "hashicorp/vault:${yamldecode(helm_release.vault.values[0]).injector.agentImage.tag}"
    error_message = "output vault_agent_image must be exactly the agent image the injector writes into pods"
  }
  assert {
    condition = (
      yamldecode(helm_release.vault.values[0]).server.service.type == "NodePort" &&
      yamldecode(helm_release.vault.values[0]).server.service.nodePort == 30820
    )
    error_message = "the Vault service must be NodePort 30820 (kind maps it to 127.0.0.1:18200)"
  }
  assert {
    condition     = !can(yamldecode(helm_release.vault.values[0]).server.dev.devRootToken)
    error_message = "the root token must never be in the plain values (it goes through set_wo only)"
  }
  assert {
    condition     = helm_release.vault.set_wo_revision >= 1
    error_message = "set_wo_revision must be >= 1 or the provider ignores set_wo"
  }
  assert {
    condition     = helm_release.vault.wait == true && helm_release.vault.timeout == 600
    error_message = "the release must wait (up to 600s) for Vault and the injector to be Ready"
  }
}

run "injector_webhook_fails_closed_and_only_where_opted_in" {
  command = plan

  assert {
    condition     = yamldecode(helm_release.vault.values[0]).injector.webhook.failurePolicy == "Fail"
    error_message = "the injector webhook must fail closed (no silently un-injected pods)"
  }
  # An empty selector would match EVERY namespace (kube-system included), so
  # "non-empty" is asserted separately: the alltrue() below is vacuously true
  # on an empty map.
  assert {
    condition     = length(yamldecode(helm_release.vault.values[0]).injector.webhook.namespaceSelector.matchLabels) > 0
    error_message = "the webhook namespaceSelector must not be empty (that would select every namespace)"
  }
  assert {
    condition = alltrue([
      for k, v in yamldecode(helm_release.vault.values[0]).injector.webhook.namespaceSelector.matchLabels :
      lookup(kubernetes_namespace_v1.clinical_apps.metadata[0].labels, k, null) == v
    ])
    error_message = "clinical-apps must carry every label the webhook namespaceSelector matches on"
  }
  assert {
    condition = alltrue([
      for k, v in yamldecode(helm_release.vault.values[0]).injector.webhook.namespaceSelector.matchLabels :
      lookup(kubernetes_namespace_v1.vault.metadata[0].labels, k, null) != v
    ])
    error_message = "the vault namespace must NOT be opted in to injection"
  }
}

run "weak_root_token_is_rejected" {
  command = plan

  variables {
    vault_dev_root_token = "root"
  }

  expect_failures = [var.vault_dev_root_token]
}

run "non_kind_context_is_rejected" {
  command = plan

  variables {
    kube_context = "aks-contoso-prod"
  }

  expect_failures = [var.kube_context]
}
