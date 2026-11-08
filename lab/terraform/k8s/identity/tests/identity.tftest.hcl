# Stage 2 (identity) guard rails, checked offline against mocked providers.
# These are the properties the whole "no static secret" story rests on, so a
# change that widens any of them fails `terraform test` before a cluster is
# ever built:
#   * the SecretProviderClass serves ONE Key Vault secret through Workload ID
#     (usePodIdentity false, clientID set), as a file, and never syncs it
#     into a Kubernetes Secret (no secretObjects)
#   * only nightly-report carries the workload's client id
#   * the human Roles never touch secrets, RBAC, SA tokens, exec or
#     SecretProviderClasses, the deployer cannot write pods or ReplicaSets,
#     and every grant is a namespaced RoleBinding (no ClusterRoleBinding)
#   * the ValidatingAdmissionPolicy that binds nightly-report to one reviewed
#     build and to the pipeline exists, denies, covers pods + Deployments in
#     clinical-apps only, and its image allowlist is digest-pinned and agrees
#     with lab/k8s/manifests
#   * a non-kind context, a tag-only image and a catch-all launcher group are
#     refused
# Run offline: terraform init -backend=false && terraform test

mock_provider "kubernetes" {}

variables {
  # Placeholders, recognisably fake (one-digit-repeated GUIDs).
  tenant_id          = "00000000-0000-0000-0000-000000000000"
  workload_client_id = "33333333-3333-3333-3333-333333333333"
  key_vault_name     = "kv-k8s-0a1b2c3d"
}

run "secret_provider_class_serves_one_secret_through_workload_id" {
  command = plan

  assert {
    condition = (
      kubernetes_manifest.secret_provider_class.manifest.apiVersion == "secrets-store.csi.x-k8s.io/v1" &&
      kubernetes_manifest.secret_provider_class.manifest.kind == "SecretProviderClass" &&
      kubernetes_manifest.secret_provider_class.manifest.metadata.name == "nightly-report-db" &&
      kubernetes_manifest.secret_provider_class.manifest.metadata.namespace == "clinical-apps"
    )
    error_message = "expected SecretProviderClass secrets-store.csi.x-k8s.io/v1 clinical-apps/nightly-report-db"
  }
  assert {
    condition = (
      kubernetes_manifest.secret_provider_class.manifest.spec.provider == "azure" &&
      kubernetes_manifest.secret_provider_class.manifest.spec.parameters.usePodIdentity == "false" &&
      kubernetes_manifest.secret_provider_class.manifest.spec.parameters.clientID == var.workload_client_id &&
      kubernetes_manifest.secret_provider_class.manifest.spec.parameters.tenantId == var.tenant_id &&
      kubernetes_manifest.secret_provider_class.manifest.spec.parameters.keyvaultName == var.key_vault_name
    )
    error_message = "the class must use the Azure provider with Workload ID (usePodIdentity false + clientID) for this tenant and vault"
  }
  assert {
    condition = (
      length(yamldecode(kubernetes_manifest.secret_provider_class.manifest.spec.parameters.objects).array) == 1 &&
      yamldecode(yamldecode(kubernetes_manifest.secret_provider_class.manifest.spec.parameters.objects).array[0]).objectName == "clinical-db" &&
      yamldecode(yamldecode(kubernetes_manifest.secret_provider_class.manifest.spec.parameters.objects).array[0]).objectType == "secret" &&
      yamldecode(yamldecode(kubernetes_manifest.secret_provider_class.manifest.spec.parameters.objects).array[0]).objectAlias == "db"
    )
    error_message = "the class must serve exactly one object: secret clinical-db, as the file db"
  }
  assert {
    condition     = !can(kubernetes_manifest.secret_provider_class.manifest.spec.secretObjects)
    error_message = "no secretObjects: a Key Vault value must never be synced into a Kubernetes Secret"
  }
  # Static: the Deployment mounts this class at the path the probes check.
  assert {
    condition = (
      strcontains(file("${path.module}/../../../k8s/manifests/nightly-report.yaml"), "secretProviderClass: nightly-report-db") &&
      strcontains(file("${path.module}/../../../k8s/manifests/nightly-report.yaml"), "/mnt/secrets-store/db")
    )
    error_message = "lab/k8s/manifests/nightly-report.yaml must mount nightly-report-db and read /mnt/secrets-store/db"
  }
}

run "workload_service_accounts_mount_no_api_token" {
  command = plan

  assert {
    condition     = toset(keys(kubernetes_service_account_v1.workload)) == toset(["nightly-report", "unapproved-job"])
    error_message = "expected exactly the approved SA and the negative-control SA"
  }
  assert {
    condition     = alltrue([for sa in kubernetes_service_account_v1.workload : sa.automount_service_account_token == false])
    error_message = "no workload SA may auto-mount an API-server token"
  }
  assert {
    condition     = alltrue([for sa in kubernetes_service_account_v1.workload : sa.metadata[0].namespace == "clinical-apps"])
    error_message = "workload SAs belong in clinical-apps"
  }
  assert {
    condition = (
      kubernetes_service_account_v1.workload["nightly-report"].metadata[0].annotations["azure.workload.identity/client-id"] == var.workload_client_id &&
      !contains(keys(kubernetes_service_account_v1.workload["unapproved-job"].metadata[0].annotations), "azure.workload.identity/client-id")
    )
    error_message = "only nightly-report carries the workload's client id"
  }
}

run "human_rbac_has_no_secrets_and_no_cluster_scope" {
  command = plan

  # The contract's line: app-deployer never sees Kubernetes Secrets.
  assert {
    condition = alltrue([
      for rule in kubernetes_role_v1.human["app-deployer"].rule : !contains(rule.resources, "secrets")
    ])
    error_message = "app-deployer rules must not contain \"secrets\""
  }

  # Wider net, both roles: nothing that is a secret, mints a token, edits RBAC,
  # gets a shell/stream/debug container into a running pod, reaches the node,
  # or names an identity to impersonate; and no wildcards. Writing pods is
  # pinned separately (run "app_deployer_cannot_write_pods").
  assert {
    condition = alltrue(flatten([
      for role in kubernetes_role_v1.human : [
        for rule in role.rule : length(setintersection(rule.resources, toset([
          "secrets", "serviceaccounts", "serviceaccounts/token",
          "roles", "rolebindings", "clusterroles", "clusterrolebindings",
          "pods/exec", "pods/attach", "pods/portforward", "pods/proxy",
          "pods/ephemeralcontainers", "nodes", "nodes/proxy",
          "users", "groups", "userextras/*", "secretproviderclasses", "*",
        ]))) == 0
      ]
    ]))
    error_message = "a human Role grants a forbidden resource (secrets, SA tokens, RBAC, exec/attach/port-forward/proxy/ephemeral containers, nodes, impersonation targets, SecretProviderClasses, or *)"
  }
  assert {
    condition = alltrue(flatten([
      for role in kubernetes_role_v1.human : [
        for rule in role.rule : !contains(rule.verbs, "*") && !contains(rule.api_groups, "*") && !contains(rule.api_groups, "rbac.authorization.k8s.io")
      ]
    ]))
    error_message = "human Roles must not use wildcard verbs/apiGroups or the RBAC API group"
  }
  # Verbs that change WHO you are or WHAT you may grant, on any resource.
  assert {
    condition = alltrue(flatten([
      for role in kubernetes_role_v1.human : [
        for rule in role.rule : length(setintersection(toset(rule.verbs), toset(["impersonate", "escalate", "bind"]))) == 0
      ]
    ]))
    error_message = "human Roles must not grant impersonate, escalate or bind"
  }
  assert {
    condition = alltrue(flatten([
      for rule in kubernetes_role_v1.human["auditor"].rule : [
        for v in rule.verbs : contains(["get", "list", "watch"], v)
      ]
    ]))
    error_message = "auditor must be read-only (get/list/watch)"
  }

  # Every grant is a RoleBinding -> Role in clinical-apps, to a Group.
  assert {
    condition = alltrue([
      for b in kubernetes_role_binding_v1.human :
      b.role_ref[0].kind == "Role" && b.metadata[0].namespace == "clinical-apps" && alltrue([for s in b.subject : s.kind == "Group"])
    ])
    error_message = "every human binding must be a namespaced RoleBinding to a Role, with Group subjects"
  }
  assert {
    condition = (
      kubernetes_role_binding_v1.human["app-deployer"].subject[0].name == "k8s-clinical-deployers" &&
      kubernetes_role_binding_v1.human["auditor"].subject[0].name == "k8s-clinical-auditors"
    )
    error_message = "role -> group mapping drifted from the contract"
  }

  # A test can only see resources that exist, so "no ClusterRoleBinding" is
  # checked statically: no .tf file in this root declares a cluster-scoped
  # RBAC resource (any provider version, with or without the _v1 suffix).
  assert {
    condition = alltrue([
      for f in fileset(path.module, "*.tf") :
      length(regexall("resource\\s+\"kubernetes_cluster_role", file("${path.module}/${f}"))) == 0
    ])
    error_message = "this root must not declare a ClusterRole or ClusterRoleBinding"
  }
  # ...nor smuggle one in through kubernetes_manifest.
  assert {
    condition = alltrue([
      for f in fileset(path.module, "*.tf") :
      length(regexall("kind\\s*=\\s*\"ClusterRole", file("${path.module}/${f}"))) == 0
    ])
    error_message = "this root must not declare a ClusterRole or ClusterRoleBinding via kubernetes_manifest"
  }
}

# A1: pods (and ReplicaSets) are read-only for the deployer. Writing pods is
# how a running pod's image gets swapped (the kubelet restarts the container
# in the SAME pod, rendered secret file and all) and how a bare pod is
# started as any service account. Deployments still work: the controllers
# make the ReplicaSets and pods.
run "app_deployer_cannot_write_pods" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for rule in kubernetes_role_v1.human["app-deployer"].rule : [
        for v in rule.verbs : contains(["get", "list", "watch"], v)
      ] if contains(rule.resources, "pods") && contains(rule.api_groups, "")
    ]))
    error_message = "app-deployer may only get/list/watch pods (no create/update/patch/delete/deletecollection)"
  }
  # Read access is still there (the deployer operates through logs and get),
  # so the assertion above cannot pass by simply dropping the pods rule.
  assert {
    condition = anytrue([
      for rule in kubernetes_role_v1.human["app-deployer"].rule :
      contains(rule.resources, "pods") && contains(rule.verbs, "get")
    ])
    error_message = "app-deployer must still be able to get pods"
  }
  assert {
    condition = alltrue(flatten([
      for rule in kubernetes_role_v1.human["app-deployer"].rule : [
        for v in rule.verbs : v == "get"
      ] if contains(rule.resources, "pods/log")
    ]))
    error_message = "app-deployer gets pods/log with verb get only"
  }
  # ReplicaSets too: deleting nightly-report's ReplicaSet makes the Deployment
  # controller (trusted by rule 4) recreate it, i.e. a restart the policy
  # refuses when it is asked for as `kubectl rollout restart`.
  assert {
    condition = alltrue(flatten([
      for rule in kubernetes_role_v1.human["app-deployer"].rule : [
        for v in rule.verbs : contains(["get", "list", "watch"], v)
      ] if contains(rule.resources, "replicasets")
    ]))
    error_message = "app-deployer may only get/list/watch replicasets (controllers write them)"
  }
  assert {
    condition = anytrue([
      for rule in kubernetes_role_v1.human["app-deployer"].rule :
      contains(rule.api_groups, "apps") && contains(rule.resources, "deployments") && contains(rule.verbs, "create") && contains(rule.verbs, "patch")
    ])
    error_message = "app-deployer must keep create/patch on Deployments (the supported way to ship)"
  }
}

# A2: the admission policy that binds nightly-report to one reviewed build and
# to the pipeline. These are plan-time checks of the object Terraform will
# send; the e2e test proves the API server actually denies.
run "admission_policy_binds_nightly_report_to_code_and_pipeline" {
  command = plan

  assert {
    condition = (
      kubernetes_manifest.workload_identity_policy.manifest.apiVersion == "admissionregistration.k8s.io/v1" &&
      kubernetes_manifest.workload_identity_policy.manifest.kind == "ValidatingAdmissionPolicy" &&
      kubernetes_manifest.workload_identity_policy.manifest.metadata.name == "clinical-apps-workload-identity"
    )
    error_message = "expected ValidatingAdmissionPolicy admissionregistration.k8s.io/v1 clinical-apps-workload-identity"
  }
  assert {
    condition     = kubernetes_manifest.workload_identity_policy.manifest.spec.failurePolicy == "Fail"
    error_message = "the policy must fail closed (failurePolicy Fail)"
  }
  assert {
    condition = (
      kubernetes_manifest.workload_identity_policy_binding.manifest.kind == "ValidatingAdmissionPolicyBinding" &&
      kubernetes_manifest.workload_identity_policy_binding.manifest.spec.policyName == kubernetes_manifest.workload_identity_policy.manifest.metadata.name &&
      kubernetes_manifest.workload_identity_policy_binding.manifest.spec.validationActions == ["Deny"]
    )
    error_message = "the binding must point at the policy with validationActions exactly [Deny]"
  }
  # Matches CREATE and UPDATE of core/v1 pods AND apps/v1 deployments.
  assert {
    condition = anytrue([
      for r in kubernetes_manifest.workload_identity_policy.manifest.spec.matchConstraints.resourceRules :
      contains(r.apiGroups, "") && contains(r.apiVersions, "v1") && contains(r.resources, "pods") &&
      contains(r.operations, "CREATE") && contains(r.operations, "UPDATE")
    ])
    error_message = "the policy must match CREATE and UPDATE of pods"
  }
  assert {
    condition = anytrue([
      for r in kubernetes_manifest.workload_identity_policy.manifest.spec.matchConstraints.resourceRules :
      contains(r.apiGroups, "apps") && contains(r.apiVersions, "v1") && contains(r.resources, "deployments") &&
      contains(r.operations, "CREATE") && contains(r.operations, "UPDATE")
    ])
    error_message = "the policy must match CREATE and UPDATE of apps/v1 deployments"
  }
  # Scoped to clinical-apps in the policy AND the binding (an empty selector
  # would match every namespace, kube-system included).
  assert {
    condition = (
      kubernetes_manifest.workload_identity_policy.manifest.spec.matchConstraints.namespaceSelector.matchLabels == { "kubernetes.io/metadata.name" = "clinical-apps" } &&
      kubernetes_manifest.workload_identity_policy_binding.manifest.spec.matchResources.namespaceSelector.matchLabels == { "kubernetes.io/metadata.name" = "clinical-apps" }
    )
    error_message = "policy and binding must both select exactly namespace clinical-apps"
  }
  # The four rules are there, each with a message a human can act on.
  assert {
    condition = length(kubernetes_manifest.workload_identity_policy.manifest.spec.validations) == 4 && alltrue([
      for v in kubernetes_manifest.workload_identity_policy.manifest.spec.validations : length(v.message) > 20
    ])
    error_message = "expected 4 validations (digest pin, nightly-report image allowlist, automount off, launcher), each with a message"
  }
  assert {
    condition = (
      strcontains(kubernetes_manifest.workload_identity_policy.manifest.spec.validations[0].expression, "@sha256:") &&
      strcontains(kubernetes_manifest.workload_identity_policy.manifest.spec.validations[1].expression, "variables.approvedDigests") &&
      strcontains(kubernetes_manifest.workload_identity_policy.manifest.spec.validations[2].expression, "automountServiceAccountToken == false") &&
      strcontains(kubernetes_manifest.workload_identity_policy.manifest.spec.validations[3].expression, "variables.trustedLauncher")
    )
    error_message = "validation order/content drifted: (1) digest pin, (2) approved digests for nightly-report, (3) automount false, (4) launcher"
  }
  # Rule 4 judges an UPDATE on both sides: a workload that IS nightly-report
  # cannot be edited by a non-launcher, not even by moving it to another
  # service account in the same patch (found by review on a kept cluster).
  assert {
    condition = (
      strcontains(kubernetes_manifest.workload_identity_policy.manifest.spec.validations[3].expression, "variables.wasNightlyReport") &&
      strcontains(one([for v in kubernetes_manifest.workload_identity_policy.manifest.spec.variables : v.expression if v.name == "wasNightlyReport"]), "oldObject != null") &&
      strcontains(one([for v in kubernetes_manifest.workload_identity_policy.manifest.spec.variables : v.expression if v.name == "oldPodSpec"]), "oldObject.spec")
    )
    error_message = "rule 4 must also check the object before the update (variables.wasNightlyReport from oldObject)"
  }
  # The nightly-report allowlist: non-empty, digests only, and exactly the app
  # build (nothing is injected any more).
  assert {
    condition = (
      length(local.nightly_report_approved_digests) > 0 &&
      alltrue([for d in local.nightly_report_approved_digests : can(regex("^sha256:[0-9a-f]{64}$", d))])
    )
    error_message = "the nightly-report image allowlist must be non-empty and contain only sha256 digests"
  }
  assert {
    condition     = toset(local.nightly_report_approved_digests) == toset([split("@", var.nightly_report_app_image)[1]])
    error_message = "the allowlist must be exactly the approved app digest"
  }
  assert {
    condition = alltrue([
      for d in local.nightly_report_approved_digests :
      strcontains(one([for v in kubernetes_manifest.workload_identity_policy.manifest.spec.variables : v.expression if v.name == "approvedDigests"]), d)
    ])
    error_message = "every approved digest must be in the policy's approvedDigests variable"
  }
  # Cross-root and cross-file agreement, checked offline so a version bump in
  # one place fails here instead of at deploy time in the pipeline.
  assert {
    condition     = strcontains(file("${path.module}/../../../k8s/manifests/nightly-report.yaml"), var.nightly_report_app_image)
    error_message = "var.nightly_report_app_image must be the image lab/k8s/manifests/nightly-report.yaml runs"
  }
  # The launcher list (rule 4) never includes the human deployers.
  assert {
    condition     = !contains(var.nightly_report_launcher_groups, "k8s-clinical-deployers") && strcontains(one([for v in kubernetes_manifest.workload_identity_policy.manifest.spec.variables : v.expression if v.name == "trustedLauncher"]), "kubeadm:cluster-admins")
    error_message = "rule 4 must allow the pipeline group and never the human deployer group"
  }
}

run "tag_only_app_image_is_rejected" {
  command = plan

  variables {
    nightly_report_app_image = "docker.io/library/busybox:1.37.0"
  }

  expect_failures = [var.nightly_report_app_image]
}

run "catch_all_launcher_group_is_rejected" {
  command = plan

  variables {
    nightly_report_launcher_groups = ["kubeadm:cluster-admins", "system:authenticated"]
  }

  expect_failures = [var.nightly_report_launcher_groups]
}

run "non_kind_context_is_rejected" {
  command = plan

  variables {
    kube_context = "aks-contoso-prod"
  }

  expect_failures = [var.kube_context]
}
