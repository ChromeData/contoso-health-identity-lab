# =============================================================================
# k8s/identity :: main.tf
# -----------------------------------------------------------------------------
# WHAT (stage 2 of 2; ../platform must be applied first):
#
#   Kubernetes (namespace clinical-apps)
#     * service accounts      nightly-report (approved; annotated with the
#                             Entra client id of ../keyvault-trust), and
#                             unapproved-job (negative control: no federated
#                             credential trusts it). Neither auto-mounts a token.
#     * SecretProviderClass   nightly-report-db: the Azure provider, Workload
#                             ID (clientID), ONE Key Vault secret, mounted as
#                             the file "db". No secretObjects: never synced
#                             into a Kubernetes Secret.
#     * Roles + RoleBindings  app-deployer -> group k8s-clinical-deployers
#                             auditor      -> group k8s-clinical-auditors
#                             Namespaced only: no ClusterRole(Binding) here.
#   Kubernetes (cluster-scoped object, scoped to clinical-apps by selector)
#     * ValidatingAdmissionPolicy + Binding  clinical-apps-workload-identity:
#                             digest-pinned images, no API token, and only
#                             the pipeline may run the approved build as
#                             nightly-report (see below)
#
# THE FLOW THIS ENABLES (the "no static secret" claim):
#   the kubelet mounts the pod's CSI volume -> the Secrets Store CSI Driver
#   requests a token for SA nightly-report, audience api://AzureADTokenExchange
#   -> the Azure provider sends it to Microsoft Entra ID as a client assertion
#   -> Entra checks it against the federated credential (issuer, subject,
#      audience) in ../keyvault-trust and returns a Key Vault access token
#   -> Key Vault checks Azure RBAC (Secrets User on that ONE secret)
#   -> the driver writes the value to /mnt/secrets-store/db (tmpfs, in the pod)
#   No Kubernetes Secret, env var or manifest value ever holds the password,
#   and the VALUE is not in this Terraform either: the pipeline sets it in Key
#   Vault (stage 4), so it never enters state.
#
# This replaces HashiCorp Vault's Kubernetes auth + Agent Injector (ADR 0027,
# "Microsoft-native PAM"). Key Vault, Entra Workload ID and the Azure
# provider are the real products; kind stands in for AKS (STAND-INS.md).
#
# IDENTITY BORROWING, AND HOW IT IS CLOSED (README "Who can act as
# nightly-report"). Kubernetes lets anyone who can create a pod in a namespace
# run it as ANY service account there, and a running pod's container image is
# mutable in place: so "can deploy" used to mean "can be nightly-report" and
# "can read /mnt/secrets-store/db" (swap the image or the command, read pods/log).
# Three layers now stand in the way, each tested:
#   1. RBAC (below): app-deployer has NO create/update/patch/delete on pods
#      or ReplicaSets, only on Deployments/ConfigMaps/Services, plus read on
#      pods, ReplicaSets and pods/log. Controllers make the rest.
#   2. ValidatingAdmissionPolicy clinical-apps-workload-identity (bottom of
#      this file), on Pods (+ ephemeral containers), Deployments and
#      ReplicaSets in clinical-apps, Deny:
#        (1) every image pinned by digest
#        (2) a workload running as nightly-report runs ONLY the approved app
#            digest (identity bound to code)
#        (3) automountServiceAccountToken: false in the pod spec
#        (4) only the launcher groups (the pipeline) and the kube-system
#            controllers may create a workload that runs as nightly-report,
#            or change one that does - judged on the object before AND
#            after an update, so moving it to another service account is a
#            change too (identity bound to who deploys it)
#      Rule (4) is what closes "same image, different command": the approved
#      image is a general-purpose busybox, so (2) alone would still let a
#      deployer patch the Deployment's args to print the file. (2) still matters: it binds what even
#      the pipeline may run as nightly-report to a reviewed digest.
#   3. Entra: the federated credential trusts exactly one SA in one
#      namespace, and Key Vault RBAC grants that SA one secret.
# What is NOT closed, said out loud: the deployer can still DELETE the
# nightly-report Deployment (availability, not identity: DELETE is not an
# operation the policy matches, see below) and then create a Deployment of
# that name under another service account, which no federated credential
# trusts. Every
# other write to that workload - image, command, annotations, replicas, a
# `rollout restart`, moving it off nightly-report - is refused by (4), and
# deployments/scale and ReplicaSet writes are not granted. A cluster admin
# can delete the policy; that is an audited admission change, not a quiet one.
# =============================================================================

locals {
  # ---- Shared names (must match lab/k8s/manifests and lab/k8s/test) ---------
  clinical_namespace = "clinical-apps" # created by ../platform with PSA labels
  approved_sa        = "nightly-report"

  # The SecretProviderClass the Deployment's CSI volume names, and the file
  # name the secret appears under (objectAlias) in /mnt/secrets-store.
  secret_provider_class = "nightly-report-db"
  mounted_file_name     = "db"

  service_accounts = {
    "nightly-report" = "Approved workload. The only service account an Entra federated credential (../keyvault-trust) trusts."
    "unapproved-job" = "Negative control. Same namespace, but no federated credential trusts it: Entra refuses its token."
  }

  # ---- Human RBAC (groups) ---------------------------------------------------
  # On kind these group names are asserted by impersonation
  # (kubectl --as=<user> --as-group=<group>). On AKS with Microsoft Entra
  # integration and Kubernetes RBAC, the subject name would be the Entra
  # group's OBJECT ID (a GUID), not a display name; with Azure RBAC for
  # Kubernetes the same intent becomes Azure role assignments on the
  # namespace scope. The rules themselves carry over unchanged.
  #
  # Neither role gets: secrets (the whole point - secrets live in Key Vault, and
  # nothing here should even be able to list Kubernetes Secrets), RBAC objects
  # (no self-escalation), serviceaccounts / serviceaccounts/token (no minting
  # tokens for nightly-report), pods/exec|attach|portforward|ephemeralcontainers
  # (no shell or debug container in a running pod), nodes, users/groups, and
  # the impersonate/escalate/bind verbs. tests/identity.tftest.hcl pins this.
  #
  # Pods AND ReplicaSets are READ-ONLY for the deployer: humans write
  # Deployments, controllers write what Deployments turn into.
  #  * Writing pods directly is how an image gets swapped inside a running
  #    pod (spec.containers[*].image is mutable, the kubelet restarts that
  #    container in the SAME pod with the same rendered secret file) and how
  #    a bare pod gets started as any service account.
  #  * Deleting a ReplicaSet makes the Deployment controller (a trusted
  #    kube-system launcher) recreate it and its pods: a restart of
  #    nightly-report that rule (4) of the policy below refuses when asked
  #    for as `kubectl rollout restart` (found by review; the first version
  #    of this pass kept write verbs on replicasets).
  # The ReplicaSet and pods of the deployer's own Deployments are written by
  # the controllers under their own identities, so a deployer loses nothing
  # it needs; `kubectl rollout status/history/undo` only read ReplicaSets.
  # The admission policy at the bottom of this file still matches
  # ReplicaSets, for any identity that does hold those verbs.
  deployer_verbs = ["get", "list", "watch", "create", "update", "patch", "delete"]
  reader_verbs   = ["get", "list", "watch"]

  human_roles = {
    "app-deployer" = {
      group   = "k8s-clinical-deployers"
      purpose = "Ship and operate workloads in clinical-apps through Deployments. Pods and ReplicaSets read-only. No secrets, no RBAC, no service-account tokens, no exec."
      rules = [
        { api_groups = ["apps"], resources = ["deployments"], verbs = local.deployer_verbs },
        { api_groups = ["apps"], resources = ["replicasets"], verbs = local.reader_verbs },
        { api_groups = [""], resources = ["configmaps", "services"], verbs = local.deployer_verbs },
        { api_groups = [""], resources = ["pods"], verbs = local.reader_verbs },
        { api_groups = [""], resources = ["pods/log"], verbs = ["get"] },
      ]
    }
    "auditor" = {
      group   = "k8s-clinical-auditors"
      purpose = "Read-only review of clinical-apps workloads and events. No secrets, no writes."
      rules = [
        { api_groups = [""], resources = ["pods", "services", "configmaps", "events"], verbs = local.reader_verbs },
        { api_groups = ["apps"], resources = ["deployments"], verbs = local.reader_verbs },
      ]
    }
  }

  common_labels = {
    "app.kubernetes.io/part-of"    = "contoso-health-identity-lab"
    "app.kubernetes.io/managed-by" = "terraform"
  }

  # ---- Admission policy: who may be nightly-report, running what ------------
  workload_policy_name = "clinical-apps-workload-identity"

  # Compared as digests, not whole strings: the same bytes may be referenced
  # as docker.io/library/busybox:1.37.0@sha256:X or busybox@sha256:X, and the
  # kubelet verifies content against the digest, so the digest IS the code.
  # One build only: with the CSI driver nothing is injected into the pod, so
  # the app image is the only container that runs as nightly-report.
  nightly_report_approved_digests = distinct([
    for ref in [var.nightly_report_app_image] : split("@", ref)[1]
  ])

  # RE2, used by CEL matches(): a reference ending in @sha256:<64 hex>.
  digest_pin_regex = "@sha256:[0-9a-f]{64}$"

  # CEL, one expression per string. Heredocs keep them readable; CEL treats
  # the newlines as whitespace. Values from Terraform are embedded with
  # jsonencode(), which yields valid CEL string/list literals.
  policy_variables = [
    # Pods (and the pods/ephemeralcontainers subresource, whose object is the
    # Pod) carry the spec directly; Deployments and ReplicaSets carry it in
    # their pod template. request.resource is always set, unlike object.kind.
    { name = "podSpec", expression = "request.resource.resource == 'pods' ? object.spec : object.spec.template.spec" },
    # Every container that will run: app containers, init containers and
    # ephemeral debug containers.
    {
      name = "images"
      expression = trimspace(<<-CEL
        (variables.podSpec.containers
          + (has(variables.podSpec.initContainers) ? variables.podSpec.initContainers : [])
          + (has(variables.podSpec.ephemeralContainers) ? variables.podSpec.ephemeralContainers : [])
        ).map(c, c.image)
      CEL
      )
    },
    # The identity the pod will run as. Unset means "default"; the deprecated
    # spec.serviceAccount alias is read too, in case a client sets only that.
    {
      name = "serviceAccount"
      expression = trimspace(<<-CEL
        has(variables.podSpec.serviceAccountName) && variables.podSpec.serviceAccountName != ''
          ? variables.podSpec.serviceAccountName
          : (has(variables.podSpec.serviceAccount) && variables.podSpec.serviceAccount != ''
              ? variables.podSpec.serviceAccount : 'default')
      CEL
      )
    },
    { name = "runsAsNightlyReport", expression = "variables.serviceAccount == ${jsonencode(local.approved_sa)}" },
    # The same question about the object as it is NOW, before this UPDATE.
    # Without it, rule (4) only sees where a workload is going: one patch
    # that moves the live nightly-report Deployment to another service
    # account would also be free to rewrite its image, command and
    # annotations (found by review on a kept cluster). oldObject is null on
    # CREATE; CEL evaluates variables lazily and `?:` only takes one branch,
    # so oldPodSpec is never read on a CREATE.
    { name = "oldPodSpec", expression = "request.resource.resource == 'pods' ? oldObject.spec : oldObject.spec.template.spec" },
    {
      name = "wasNightlyReport"
      expression = trimspace(<<-CEL
        oldObject != null && (
          has(variables.oldPodSpec.serviceAccountName) && variables.oldPodSpec.serviceAccountName != ''
            ? variables.oldPodSpec.serviceAccountName
            : (has(variables.oldPodSpec.serviceAccount) && variables.oldPodSpec.serviceAccount != ''
                ? variables.oldPodSpec.serviceAccount : 'default')
        ) == ${jsonencode(local.approved_sa)}
      CEL
      )
    },
    { name = "approvedDigests", expression = jsonencode(local.nightly_report_approved_digests) },
    # Who is asking. The kube-system controllers are what turn a Deployment
    # into a ReplicaSet and pods (kubeadm runs kube-controller-manager with
    # --use-service-account-credentials, so each controller has its own
    # system:serviceaccount:kube-system:* identity; system:kube-controller-
    # manager covers clusters that do not). Anyone able to act as those is
    # already cluster-admin-equivalent.
    {
      name = "trustedLauncher"
      expression = trimspace(<<-CEL
        request.userInfo.username.startsWith('system:serviceaccount:kube-system:')
          || request.userInfo.username == 'system:kube-controller-manager'
          || (has(request.userInfo.groups)
              && request.userInfo.groups.exists(g, g in ${jsonencode(var.nightly_report_launcher_groups)}))
      CEL
      )
    },
  ]

  # Order matters for the message a caller sees first, so the image rules
  # come before the launcher rule: an image swap by a deployer is reported as
  # an image problem. Each message starts with a fixed phrase the e2e test
  # (lab/k8s/test) can match; messageExpression appends the offending values.
  # If a messageExpression fails, the API server falls back to `message`.
  policy_validations = [
    {
      # (1) Supply chain: a tag can be re-pushed, a digest cannot.
      expression        = "variables.images.all(i, i.matches(${jsonencode(local.digest_pin_regex)}))"
      message           = "image not pinned by digest: every container image in clinical-apps must be <repo>[:tag]@sha256:<64 hex>"
      messageExpression = "'image not pinned by digest: ' + variables.images.filter(i, !i.matches(${jsonencode(local.digest_pin_regex)})).join(', ')"
      reason            = "Invalid"
    },
    {
      # (2) Identity bound to code: nightly-report runs one reviewed build,
      # whoever deploys it.
      expression        = "!variables.runsAsNightlyReport || variables.images.all(i, variables.approvedDigests.exists(d, i.endsWith('@' + d)))"
      message           = "service account nightly-report may run only the approved app image"
      messageExpression = "'service account nightly-report may run only the approved app image, not: ' + variables.images.filter(i, !variables.approvedDigests.exists(d, i.endsWith('@' + d))).join(', ')"
      reason            = "Forbidden"
    },
    {
      # (3) No API-server token in workload pods: the pod holds no token at
      # all (the CSI driver requests its own). Must be stated in the pod spec (the
      # ServiceAccount's own false is a default a pod spec can override).
      expression = "has(variables.podSpec.automountServiceAccountToken) && variables.podSpec.automountServiceAccountToken == false"
      message    = "automountServiceAccountToken must be false in the pod spec (workloads here get no Kubernetes API token)"
      reason     = "Invalid"
    },
    {
      # (4) Identity bound to who deploys: using nightly-report is a
      # release-pipeline decision, not a human deployer's. Closes "same
      # approved image, different command/annotations" which (2) cannot see.
      # Checked on BOTH sides of an UPDATE: a workload that runs as
      # nightly-report now cannot be edited by anyone else, including an
      # edit that moves it to another service account. (2) stays new-side
      # only on purpose: it is about what runs AS nightly-report, and the
      # pipeline moving a workload off it is a legitimate change.
      expression        = "!(variables.runsAsNightlyReport || variables.wasNightlyReport) || variables.trustedLauncher"
      message           = "only the release pipeline may create or change a workload that runs as service account nightly-report"
      messageExpression = "'only the release pipeline may create or change a workload that runs as service account nightly-report, not ' + request.userInfo.username"
      reason            = "Forbidden"
    },
  ]
}

# -----------------------------------------------------------------------------
# Kubernetes: workload service accounts
# -----------------------------------------------------------------------------

resource "kubernetes_service_account_v1" "workload" {
  for_each = local.service_accounts

  metadata {
    name      = each.key
    namespace = local.clinical_namespace
    labels    = local.common_labels
    annotations = merge(
      { "contoso.health/purpose" = each.value },
      # Entra Workload ID convention: the client id this SA signs in as. The
      # CSI path reads clientID from the SecretProviderClass, not from here;
      # the annotation records the pairing on the identity itself (and is
      # what the workload identity webhook would read on AKS).
      each.key == local.approved_sa ? { "azure.workload.identity/client-id" = var.workload_client_id } : {},
    )
  }

  # No API-server token is mounted. The pod holds NO token at all: the CSI
  # driver asks the kubelet for one (audience api://AzureADTokenExchange) at
  # mount time and hands it only to the Azure provider. (Kubernetes >= 1.24
  # also no longer creates long-lived token Secrets; nothing asks for one.)
  automount_service_account_token = false
}

# -----------------------------------------------------------------------------
# The ONE Key Vault secret, as a CSI volume source
# -----------------------------------------------------------------------------
# Fields from Microsoft Learn, "Access Azure Key Vault with the CSI Driver
# Identity Provider" (Workload ID tab): usePodIdentity "false" + clientID =
# Workload ID. objectAlias names the file. No secretObjects block, so the
# driver never creates a Kubernetes Secret from it. A SecretProviderClass
# holds identifiers only (vault name, tenant, client id), no value.
#
# WHO CAN USE IT: any pod in clinical-apps can NAME this class, but the
# driver always requests the token for the POD's own service account. Only
# nightly-report has a federated credential, so a pod running as anything
# else gets an Entra refusal and no file (the e2e test proves it).
resource "kubernetes_manifest" "secret_provider_class" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = local.secret_provider_class
      namespace = local.clinical_namespace
      labels    = local.common_labels
    }
    spec = {
      provider = "azure"
      parameters = {
        usePodIdentity = "false"
        clientID       = var.workload_client_id
        keyvaultName   = var.key_vault_name
        tenantId       = var.tenant_id
        # The provider takes `objects` as a YAML string with an array of
        # YAML strings (its documented format).
        objects = yamlencode({
          array = [yamlencode({
            objectName    = var.secret_name
            objectType    = "secret"
            objectAlias   = local.mounted_file_name
            objectVersion = ""
          })]
        })
      }
    }
  }

  field_manager {
    force_conflicts = true
  }
}

# -----------------------------------------------------------------------------
# Kubernetes: human RBAC as code (namespaced Roles bound to groups)
# -----------------------------------------------------------------------------

resource "kubernetes_role_v1" "human" {
  for_each = local.human_roles

  metadata {
    name      = each.key
    namespace = local.clinical_namespace
    labels    = local.common_labels
    annotations = {
      "contoso.health/purpose" = each.value.purpose
    }
  }

  dynamic "rule" {
    for_each = each.value.rules
    content {
      api_groups = rule.value.api_groups
      resources  = rule.value.resources
      verbs      = rule.value.verbs
    }
  }
}

resource "kubernetes_role_binding_v1" "human" {
  for_each = local.human_roles

  metadata {
    name      = "${each.key}--${each.value.group}"
    namespace = local.clinical_namespace
    labels    = local.common_labels
  }

  # A RoleBinding to a Role: the grant cannot reach beyond clinical-apps.
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.human[each.key].metadata[0].name
  }

  subject {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Group"
    name      = each.value.group
  }
}

# -----------------------------------------------------------------------------
# Admission: ValidatingAdmissionPolicy (CEL, in the API server; GA since 1.30)
# -----------------------------------------------------------------------------
# WHY A VAP, NOT A WEBHOOK: it runs inside the API server, so there is no
# extra pod to keep alive, no TLS to manage, and no way for it to be "down"
# and fail open. WHY TERRAFORM: it is identity policy, reviewed with the
# service account and the federated credential it protects. kubernetes_manifest (the provider has no typed
# binding resource) needs the API server at PLAN time; this root already
# requires a live cluster (stage 2 runs after ../platform), and the mocked
# tests do not.
#
# NOTHING IS INJECTED: the CSI driver adds no container to the pod, so the
# policy judges exactly the containers the Deployment declares.
#
# Pod Security Admission is a built-in validating plugin ordered before
# ValidatingAdmissionPolicy, so a privileged pod is still rejected with the
# PSA message (the existing negative test keeps its meaning).

resource "kubernetes_manifest" "workload_identity_policy" {
  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicy"
    metadata = {
      name   = local.workload_policy_name
      labels = local.common_labels
      annotations = {
        "contoso.health/purpose" = "Workloads in clinical-apps: digest-pinned images, no API token, and only the pipeline may run the approved build as nightly-report."
      }
    }
    spec = {
      # Fail closed: if an expression cannot be evaluated, the request is
      # refused rather than admitted unchecked.
      failurePolicy = "Fail"
      matchConstraints = {
        # Also scoped here, not only in the binding: a second, careless
        # binding can never stretch this policy onto kube-system.
        namespaceSelector = {
          matchLabels = { "kubernetes.io/metadata.name" = local.clinical_namespace }
        }
        resourceRules = [
          {
            apiGroups   = [""]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            # pods/ephemeralcontainers: `kubectl debug` adds containers to a
            # RUNNING pod through this subresource; without it, a debug
            # container could bring any image into a nightly-report pod.
            resources = ["pods", "pods/ephemeralcontainers"]
          },
          {
            apiGroups   = ["apps"]
            apiVersions = ["v1"]
            operations  = ["CREATE", "UPDATE"]
            # Checked at the template too, so a bad Deployment is refused when
            # it is applied (a clear error to the caller) instead of leaving a
            # ReplicaSet that silently fails to create pods. ReplicaSets so
            # that any identity holding write on them (app-deployer no longer
            # does) meets the same rules as a Deployment.
            resources = ["deployments", "replicasets"]
          },
        ]
        # Not DELETE, on purpose: a pod's final DELETE comes from the kubelet
        # (system:node:*) finishing a graceful shutdown, and the namespace
        # and garbage collectors delete too, so matching DELETE would need
        # its own exemptions in rule (4) for an availability-only gain. The
        # deployer's remaining DELETE (the Deployment) is documented above.
      }
      variables   = local.policy_variables
      validations = local.policy_validations
    }
  }

  # kubernetes_manifest uses server-side apply. If someone edits a field this
  # resource declares (say failurePolicy -> Ignore) with kubectl, that edit
  # takes field ownership: `terraform plan` still shows the drift, but a plain
  # apply then stops on a field-manager conflict. force_conflicts makes
  # Terraform the authority on every field it declares, so apply heals it.
  # (Checked on a scratch kind v1.36.4 cluster, 2026-10-20.)
  field_manager {
    force_conflicts = true
  }
}

resource "kubernetes_manifest" "workload_identity_policy_binding" {
  manifest = {
    apiVersion = "admissionregistration.k8s.io/v1"
    kind       = "ValidatingAdmissionPolicyBinding"
    metadata = {
      name   = local.workload_policy_name
      labels = local.common_labels
    }
    spec = {
      # Referencing the policy resource orders creation: policy, then binding.
      policyName = kubernetes_manifest.workload_identity_policy.manifest.metadata.name
      # Deny only: a violation is a rejected request, not a warning. (Audit
      # would add an annotation to the audit event; the rejection is already
      # in the audit log as the response status.)
      validationActions = ["Deny"]
      matchResources = {
        # kubernetes.io/metadata.name is set by the API server on every
        # namespace and cannot be changed, so this matches clinical-apps and
        # nothing else, whoever edits namespace labels.
        namespaceSelector = {
          matchLabels = { "kubernetes.io/metadata.name" = local.clinical_namespace }
        }
      }
    }
  }

  # Same reason as the policy. One limit even with force_conflicts, seen on
  # the scratch cluster: validationActions is a SET-typed list, and server-
  # side apply merges set members owned by different managers, so a kubectl
  # patch to ["Warn"] is DETECTED by plan but apply would produce
  # ["Warn","Deny"], which the API rejects. Heal that one with
  # `terraform apply -replace=kubernetes_manifest.workload_identity_policy_binding`.
  field_manager {
    force_conflicts = true
  }
}
