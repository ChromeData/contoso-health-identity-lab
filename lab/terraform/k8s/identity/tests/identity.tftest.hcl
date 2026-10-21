# Stage 2 (identity) guard rails, checked offline against mocked providers.
# These are the properties the whole "no static secret" story rests on, so a
# change that widens any of them fails `terraform test` before a cluster is
# ever built:
#   * the Vault role trusts ONE service account in ONE namespace, only for
#     tokens with audience "vault", and issues tokens of <= 15 minutes
#   * its policy is read-only on exactly clinical/data/db
#   * the human Roles never touch secrets, RBAC, SA tokens or exec, the
#     deployer cannot write pods or ReplicaSets, and every grant is a
#     namespaced RoleBinding
#     (no ClusterRoleBinding anywhere)
#   * the ValidatingAdmissionPolicy that binds nightly-report to one reviewed
#     build and to the pipeline exists, denies, covers pods + Deployments in
#     clinical-apps only, and its image allowlist is digest-pinned and agrees
#     with ../platform and lab/k8s/manifests
#   * a weak token, a non-kind context, plain HTTP off loopback, a tag-only
#     image and a catch-all launcher group are refused
# Run offline: terraform init -backend=false && terraform test

mock_provider "vault" {}
mock_provider "kubernetes" {}

variables {
  # Format-valid placeholder for the mocked plan; not a credential.
  vault_dev_root_token = "tftest-placeholder-token-0000000000000000"
}

run "vault_role_trusts_only_nightly_report_in_clinical_apps" {
  command = plan

  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.bound_service_account_names == toset(["nightly-report"])
    error_message = "the Vault role must bind exactly one service account: nightly-report"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.bound_service_account_namespaces == toset(["clinical-apps"])
    error_message = "the Vault role must bind exactly one namespace: clinical-apps"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.bound_service_account_namespace_selector == null
    error_message = "no namespace label selector may widen the role beyond clinical-apps"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.audience == "vault"
    error_message = "the role must require audience \"vault\" (default-audience API tokens must be refused)"
  }
  assert {
    condition = (
      vault_kubernetes_auth_backend_role.nightly_report.token_ttl <= 900 &&
      vault_kubernetes_auth_backend_role.nightly_report.token_max_ttl <= 900 &&
      vault_kubernetes_auth_backend_role.nightly_report.token_max_ttl > 0
    )
    error_message = "Vault tokens from this role must live at most 900s (and have a max TTL set at all)"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.token_policies == toset(["nightly-report-read"])
    error_message = "the role must attach only the nightly-report-read policy"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_role.nightly_report.alias_name_source == "serviceaccount_uid"
    error_message = "identity aliases must be keyed on the SA UID, not its (reusable) name"
  }
  assert {
    condition     = vault_auth_backend.kubernetes.type == "kubernetes" && vault_auth_backend.kubernetes.path == "kubernetes"
    error_message = "the Kubernetes auth method must be mounted at auth/kubernetes (the injector's authPath)"
  }
  assert {
    condition     = vault_kubernetes_auth_backend_config.in_cluster.kubernetes_host == "https://kubernetes.default.svc:443"
    error_message = "Vault must review tokens against the in-cluster API server"
  }
}

run "policy_is_read_only_on_exactly_one_path" {
  command = plan

  assert {
    condition     = vault_policy.nightly_report_read.name == "nightly-report-read"
    error_message = "policy name drifted from the contract"
  }
  assert {
    condition     = keys(jsondecode(vault_policy.nightly_report_read.policy).path) == ["clinical/data/db"]
    error_message = "the policy must name exactly one path: clinical/data/db"
  }
  assert {
    condition     = jsondecode(vault_policy.nightly_report_read.policy).path["clinical/data/db"].capabilities == ["read"]
    error_message = "the only capability on clinical/data/db must be read"
  }
  assert {
    condition     = keys(jsondecode(vault_policy.nightly_report_read.policy)) == ["path"]
    error_message = "the policy must contain path rules only"
  }
  assert {
    condition     = vault_mount.clinical.path == "clinical" && vault_mount.clinical.type == "kv" && vault_mount.clinical.options["version"] == "2"
    error_message = "the secret must live on a KV v2 mount at clinical/"
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
          "users", "groups", "userextras/*", "*",
        ]))) == 0
      ]
    ]))
    error_message = "a human Role grants a forbidden resource (secrets, SA tokens, RBAC, exec/attach/port-forward/proxy/ephemeral containers, nodes, impersonation targets, or *)"
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
  # build + the Vault Agent.
  assert {
    condition = (
      length(local.nightly_report_approved_digests) > 0 &&
      alltrue([for d in local.nightly_report_approved_digests : can(regex("^sha256:[0-9a-f]{64}$", d))])
    )
    error_message = "the nightly-report image allowlist must be non-empty and contain only sha256 digests"
  }
  assert {
    condition = toset(local.nightly_report_approved_digests) == toset([
      split("@", var.nightly_report_app_image)[1], split("@", var.vault_agent_image)[1],
    ])
    error_message = "the allowlist must be exactly the approved app digest and the Vault Agent digest"
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
    condition     = strcontains(file("${path.module}/../platform/main.tf"), split("@", var.vault_agent_image)[1])
    error_message = "var.vault_agent_image's digest must be the one ../platform pins for the injector's agentImage"
  }
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

run "plain_http_off_loopback_is_rejected" {
  command = plan

  variables {
    vault_addr = "http://vault.example.internal:8200"
  }

  expect_failures = [var.vault_addr]
}
