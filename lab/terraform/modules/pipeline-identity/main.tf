# =============================================================================
# modules/pipeline-identity :: main.tf
# -----------------------------------------------------------------------------
# GitHub Actions OIDC identities (NO client secrets - federated creds only):
#   * PLAN  identity - read-only Graph roles, trusted from PULL REQUESTS (and
#                      the main-branch ref, for the nightly config-drift run).
#   * APPLY identity - read/write Graph roles, trusted only from the protected
#                      "prod" GitHub ENVIRONMENT.
#   * HR-SYNC identity (opt-in, hr_sync_enabled) - uploads HR rows to the
#                      API-driven inbound provisioning app and reads the
#                      provisioning log, trusted only from the hr-feed BRANCH.
#   * EVIDENCE identity (opt-in, evidence_enabled) - reads the auditor
#                      evidence pack from Graph (read-only roles) and files it
#                      in the WORM evidence store, trusted only from MAIN.
#
# Why separate apps: PR runs can read/plan without ever being able to mutate
# the tenant; only a run inside the gated prod environment can obtain write
# scope; and an HR change never needs (or gets) either of those.
# Subject-claim scoping is the security boundary - see the federated creds.
#
# LICENSING: app registrations, service principals and federated credentials
# are FREE (Entra ID Free). The *actions these apps perform* need P1/P2/
# Governance (that is a property of the target resources, not these identities).
#
# WHERE THIS RUNS: only from envs/bootstrap, applied LOCALLY by a human admin.
# The pipeline these identities power (envs/dev) can therefore never widen its
# own Graph permissions or federation trust.
#
# HUMAN STEP: azuread_app_role_assignment grants application permissions, but a
# Global Admin / Privileged Role Admin must still have rights to create them,
# and in some tenants admin consent is surfaced separately. Confirm the grants
# show as "Granted" under Enterprise App > Permissions after apply. See README.
# =============================================================================

locals {
  # Well-known first-party Microsoft Graph application (client) id.
  microsoft_graph_app_id = "00000003-0000-0000-c000-000000000000"

  # GitHub OIDC issuer (fixed).
  github_oidc_issuer = "https://token.actions.githubusercontent.com"

  # Token audience Entra expects for GitHub federation.
  github_oidc_audience = "api://AzureADTokenExchange"

  # Subject claims. The PLAN identity trusts PR runs; the APPLY identity trusts
  # only the protected prod environment. Entra matches the subject exactly, and
  # GitHub.com issues the immutable form repo:OWNER@OWNER-ID/REPO@REPO-ID:...
  # for every repo created, renamed or transferred after 2026-07-15, so a
  # name-only subject never matches this repo. The ids are never reused, so a
  # recycled owner/repo name cannot mint a token these credentials accept.
  # verify: GitHub documents only the :ref: example of this form; confirm the
  # :pull_request and :environment: subjects with GitHub's OIDC subject preview
  # before the first pipeline run.
  github_repo_path  = "${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
  plan_subject      = "repo:${local.github_repo_path}:pull_request"
  plan_main_subject = "repo:${local.github_repo_path}:ref:refs/heads/main"
  apply_subject     = "repo:${local.github_repo_path}:environment:${var.prod_environment_name}"
  hr_sync_subject   = "repo:${local.github_repo_path}:ref:refs/heads/${var.hr_sync_branch}"
  evidence_subject  = "repo:${local.github_repo_path}:ref:refs/heads/main"
}

# -----------------------------------------------------------------------------
# Microsoft Graph service principal in THIS tenant - the resource we assign app
# roles against. Looked up by the well-known Graph app id. Its `app_role_ids`
# map lets us resolve role names to GUIDs instead of hardcoding them.
# -----------------------------------------------------------------------------
data "azuread_service_principal" "msgraph" {
  client_id = local.microsoft_graph_app_id
}

# Effective role sets = the reviewed baseline + the opt-in extras.
locals {
  plan_roles  = distinct(concat(var.plan_graph_roles, var.extra_plan_graph_roles))
  apply_roles = distinct(concat(var.apply_graph_roles, var.extra_apply_graph_roles))

  # Accountable human owners per identity (ADR 0018, nhi-standard N1), on the
  # app registration AND its service principal. null - not [] - when none is
  # named: the provider then plans no owners change for an identity nobody
  # has been named for yet (today APPLY and PLAN, both Tier 0: their owners
  # are the lead's decision, lab/iga/nhi-owners.json). Once a list is set,
  # this code is the only place it lives - an owner added in the portal is
  # removed by the next bootstrap apply, which is the point.
  owners = {
    for k, ids in var.owner_object_ids : k => length(ids) > 0 ? distinct(ids) : null
  }
}

# =============================================================================
# PLAN identity (read-only, pull_request)
# =============================================================================
resource "azuread_application" "plan" {
  display_name     = var.plan_app_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.owners.plan

  # Declare the delegated/app permissions the app needs (documentation + the
  # consent experience). The actual grant is the app_role_assignment below.
  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.plan_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role" # "Role" = application permission (vs "Scope" = delegated)
      }
    }
  }
}

resource "azuread_service_principal" "plan" {
  client_id = azuread_application.plan.client_id
  owners    = local.owners.plan
}

# Federated credential: trust GitHub tokens from PULL REQUESTS of this repo.
resource "azuread_application_federated_identity_credential" "plan_pr" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's pull_request events (local.plan_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  application_id = azuread_application.plan.id
  display_name   = "github-pr"
  description    = "GitHub Actions OIDC - pull_request runs (read-only plan)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.plan_subject
}

# The nightly config-drift workflow runs on main (schedule / workflow_dispatch),
# so the PLAN identity also needs the main-branch ref subject - still read-only.
# Without it every scheduled run fails azure/login with AADSTS700213 (no
# matching federated identity record for ...:ref:refs/heads/main). It widens
# nothing: main only holds reviewed, merged workflow code, while PLAN is
# already reachable from any same-repo pull request. Nothing else changes for
# PLAN - its roles stay the read-only allow-list (extra_plan_graph_roles).
resource "azuread_application_federated_identity_credential" "plan_main" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's main branch (local.plan_main_subject); the identity is read-only.
  application_id = azuread_application.plan.id
  display_name   = "github-main-drift"
  description    = "GitHub Actions OIDC - runs on main (config-drift, read-only)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.plan_main_subject
}

# Grant the read-only Graph app roles to the PLAN service principal.
resource "azuread_app_role_assignment" "plan" {
  for_each = toset(local.plan_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.plan.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# =============================================================================
# APPLY identity (read/write, environment:prod)
# =============================================================================
resource "azuread_application" "apply" {
  display_name     = var.apply_app_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.owners.apply

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.apply_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }
}

resource "azuread_service_principal" "apply" {
  client_id = azuread_application.apply.client_id
  owners    = local.owners.apply
}

# Federated credential: trust GitHub tokens ONLY from the protected prod
# environment. This is what stops a PR from obtaining write scope.
resource "azuread_application_federated_identity_credential" "apply_prod" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's prod environment (local.apply_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  application_id = azuread_application.apply.id
  display_name   = "github-env-prod"
  description    = "GitHub Actions OIDC - prod environment runs (write apply)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.apply_subject
}

# Grant the read/write Graph app roles to the APPLY service principal.
resource "azuread_app_role_assignment" "apply" {
  for_each = toset(local.apply_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.apply.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# =============================================================================
# HR-SYNC identity (HR feed upload, ref:refs/heads/<hr_sync_branch>) - OPT-IN
# =============================================================================
# .github/workflows/hr-feed.yml signs in as this app when a commit to the
# hr-feed branch changes lab/scripts/mock-hr/hr_feed.csv, sends ONLY the
# changed rows to the API-driven inbound provisioning app (HR -> AD), and
# reads the provisioning log back for the plain-English run summary.
#
# Why a third app instead of PLAN or APPLY: PLAN is reachable from any
# same-repo pull request and must stay read-only; APPLY is Tier 0 behind the
# prod reviewer, and an HR change is not a Terraform deploy. HR-SYNC holds
# exactly two kinds of Graph application permission:
#
#   upload  hr_sync_upload_scope = "owned" (default):
#             SynchronizationData-User.Upload.OwnedBy - the least-privileged
#             application permission in the bulkUpload permissions table. It
#             uploads only to provisioning apps HR-SYNC OWNS, so HR-SYNC is
#             made an owner of the HR provisioning app's registration below.
#             verify: on the first run. Microsoft documents .OwnedBy only for
#             the HR-ISV case where the caller CREATES the provisioning app
#             (and so owns both its registration and its service principal);
#             the bulkUpload URL is on the service principal. azuread cannot
#             add an owner to a service principal it does not manage, so the
#             bootstrap output hr_sync_service_principal_owner_command does
#             that once (an admin runs it). Still a 403? Set
#             hr_sync_upload_scope = "tenant".
#           hr_sync_upload_scope = "tenant":
#             SynchronizationData-User.Upload - every API-driven provisioning
#             app in the tenant (Microsoft's grant-access tutorial default).
#   read    hr_sync_log_read_graph_roles (default AuditLog.Read.All): the
#           provisioning-log read for the run summary. Its Graph page lists
#           AuditLog.Read.All + Directory.Read.All; Directory.Read.All is left
#           out on purpose (verify: the first run's summary reads the log; a
#           403 there names the missing role and nothing else fails).
#           Microsoft's inbound-provisioning tutorial grants the narrower
#           ProvisioningLog.Read.All instead (verify: whether
#           GET /auditLogs/provisioning accepts it alone, then swap).
#
# Owning the provisioning app gives HR-SYNC no write over that app: an
# app-only caller uses ownership only through an *.OwnedBy write permission
# (Application.ReadWrite.OwnedBy), which HR-SYNC never gets - the log roles
# are validated read-only and the upload role is fixed here.
#
# TRUST BOUNDARY: the hr-feed branch REF. Anyone who can push to that branch
# can run any workflow file on it as HR-SYNC: create, update or disable
# workforce accounts through the provisioning job (bounded by that job's own
# mappings: accounts matched on employeeID, the Workforce / Disabled OUs of
# its parentDistinguishedName expression). Protect the branch with a ruleset:
# only the HR owner pushes, no force-push, no deletion
# (lab/scripts/mock-hr/README.md, "HR changes through GitHub Actions").
# -----------------------------------------------------------------------------
locals {
  # The empty-id case is refused by the precondition on azuread_application.hr_sync
  # (a clear message) instead of a failed lookup.
  hr_sync_owns_app = var.hr_sync_enabled && var.hr_sync_upload_scope == "owned" && var.hr_provisioning_app_client_id != ""
  hr_sync_upload_role = (var.hr_sync_upload_scope == "owned"
    ? "SynchronizationData-User.Upload.OwnedBy"
  : "SynchronizationData-User.Upload")
  hr_sync_roles = var.hr_sync_enabled ? distinct(concat([local.hr_sync_upload_role], var.hr_sync_log_read_graph_roles)) : []
}

# The HR provisioning app (created by lab/scripts/mock-hr/New-InboundProvisioningApp.ps1,
# not by Terraform): looked up by client id so HR-SYNC can be made its owner.
data "azuread_application" "hr_provisioning" {
  count     = local.hr_sync_owns_app ? 1 : 0
  client_id = var.hr_provisioning_app_client_id
}

data "azuread_service_principal" "hr_provisioning" {
  count     = local.hr_sync_owns_app ? 1 : 0
  client_id = var.hr_provisioning_app_client_id
}

resource "azuread_application" "hr_sync" {
  count            = var.hr_sync_enabled ? 1 : 0
  display_name     = var.hr_sync_app_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.owners.hr_sync

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.hr_sync_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.hr_sync_upload_scope != "owned" || var.hr_provisioning_app_client_id != ""
      error_message = "hr_sync_upload_scope = \"owned\" needs hr_provisioning_app_client_id (the HR provisioning app's client id): SynchronizationData-User.Upload.OwnedBy only reaches an app HR-SYNC owns."
    }
  }
}

resource "azuread_service_principal" "hr_sync" {
  count     = var.hr_sync_enabled ? 1 : 0
  client_id = azuread_application.hr_sync[0].client_id
  owners    = local.owners.hr_sync
}

# Federated credential: trust GitHub tokens ONLY from runs on the hr-feed
# branch (push and workflow_dispatch both carry ref:refs/heads/<branch>).
resource "azuread_application_federated_identity_credential" "hr_sync_branch" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's hr-feed branch (local.hr_sync_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  count          = var.hr_sync_enabled ? 1 : 0
  application_id = azuread_application.hr_sync[0].id
  display_name   = "github-${replace(var.hr_sync_branch, "/", "-")}"
  description    = "GitHub Actions OIDC - runs on the ${var.hr_sync_branch} branch (HR feed upload)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.hr_sync_subject
}

resource "azuread_app_role_assignment" "hr_sync" {
  for_each = toset(local.hr_sync_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.hr_sync[0].object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# .OwnedBy reaches only what HR-SYNC owns: make it an owner of the HR
# provisioning app's registration (the service principal: see the header).
resource "azuread_application_owner" "hr_sync_owns_provisioning_app" {
  count           = local.hr_sync_owns_app ? 1 : 0
  application_id  = "/applications/${data.azuread_application.hr_provisioning[0].object_id}"
  owner_object_id = azuread_service_principal.hr_sync[0].object_id
}

# The HR provisioning app's accountable HUMAN owners (ADR 0018). HR-SYNC owning
# it is a technical need, not accountability: the inventory reports an app
# owned only by a service principal as OWNER-NO-HUMAN. One owner resource per
# person, like the HR-SYNC one above, so the app's other owners (set when the
# app was made) are left alone - unlike `owners` on an azuread_application,
# which would make this list the complete set.
resource "azuread_application_owner" "hr_provisioning_humans" {
  for_each        = local.hr_sync_owns_app ? toset(var.owner_object_ids.hr_provisioning) : toset([])
  application_id  = "/applications/${data.azuread_application.hr_provisioning[0].object_id}"
  owner_object_id = each.value
}

# =============================================================================
# EVIDENCE identity (evidence pack -> WORM store, ref:refs/heads/main) - OPT-IN
# =============================================================================
# .github/workflows/evidence-pack.yml (workflow_dispatch, main only) signs in
# as this app, runs lab/scripts/powershell/Export-EvidencePack.ps1 app-only
# (the seven read-only Graph collections + the SHA-256 manifest) and uploads
# the pack to the WORM evidence container under a dated prefix.
#
# Why a fourth app instead of PLAN: PLAN also trusts the main ref, but it is
# reachable from every same-repo pull request and holds a different read set
# (plan refresh); the evidence reads (audit log, access-review decisions, MFA
# registration, PIM-for-Groups history) are not Terraform's business, and the
# storage write must never be reachable from a PR. EVIDENCE has:
#
#   Graph  evidence_graph_roles - application READ roles only (validated
#          allow-list, like PLAN's extras): exactly what the script reads.
#            AuditLog.Read.All              directoryAudits (PIM activity log,
#                                           and the PIM-for-roles activation
#                                           history) + the
#                                           userRegistrationDetails report
#                                           (MFA coverage)
#            AccessReview.Read.All          access-review definitions,
#                                           instances, decisions
#            Policy.Read.All                Conditional Access policies
#            RoleManagement.Read.Directory  role definitions (beta
#                                           isPrivileged), role assignments
#            RoleAssignmentSchedule.Read.Directory
#                                           PIM-for-roles schedule INSTANCES
#                                           (Learn's least-privileged read for
#                                           them). Not the requests list: Learn
#                                           names RoleAssignmentSchedule.
#                                           ReadWrite.Directory as its least
#                                           privileged permission, and a write
#                                           role has no place here, so the
#                                           activation history comes from the
#                                           audit log instead (2026-11-05:
#                                           still PermissionScopeNotGranted
#                                           with this role)
#            PrivilegedAssignmentSchedule.Read.AzureADGroup
#                                           PIM-for-Groups schedule requests /
#                                           instances
#            Directory.Read.All             group lookups by mailNickname and
#                                           the expanded principal (user,
#                                           group or app) on role and PIM rows
#          verify: on the first run, that Directory.Read.All is needed for the
#          $expand=principal rows (the narrower set would be GroupMember.Read.All
#          + User.Read.All + Application.Read.All); a failed artifact names
#          its 403 in the manifest.
#   Azure  ONE data-plane grant, made in envs/bootstrap (azurerm, human
#          apply): Storage Blob Data Contributor on the evidence container
#          with an ABAC condition that allows creating NEW blobs and reading
#          them back, never overwriting, deleting or re-tiering one. No
#          subscription role, no Terraform state access.
#
# TRUST BOUNDARY: the main-branch REF. Any workflow file on main can sign in
# as EVIDENCE (main holds reviewed, merged code only; the same boundary as
# PLAN's config-drift credential). Worst case with this identity: read the
# directory and audit data above, and add files to the evidence container,
# which WORM keeps and the blob logs record. It cannot change the tenant,
# and it cannot remove or alter evidence.
# -----------------------------------------------------------------------------
locals {
  evidence_roles = var.evidence_enabled ? distinct(var.evidence_graph_roles) : []
}

resource "azuread_application" "evidence" {
  count            = var.evidence_enabled ? 1 : 0
  display_name     = var.evidence_app_display_name
  sign_in_audience = "AzureADMyOrg"
  owners           = local.owners.evidence

  required_resource_access {
    resource_app_id = local.microsoft_graph_app_id

    dynamic "resource_access" {
      for_each = toset(local.evidence_roles)
      content {
        id   = data.azuread_service_principal.msgraph.app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }
}

resource "azuread_service_principal" "evidence" {
  count     = var.evidence_enabled ? 1 : 0
  client_id = azuread_application.evidence[0].client_id
  owners    = local.owners.evidence
}

# Federated credential: trust GitHub tokens ONLY from runs on main
# (workflow_dispatch of main carries ref:refs/heads/main).
resource "azuread_application_federated_identity_credential" "evidence_main" {
  #checkov:skip=CKV_AZURE_249:The subject is pinned to this repository's main branch (local.evidence_subject, the immutable owner/repo form); Checkov's subject pattern does not recognise that form.
  count          = var.evidence_enabled ? 1 : 0
  application_id = azuread_application.evidence[0].id
  display_name   = "github-main-evidence"
  description    = "GitHub Actions OIDC - runs on main (evidence pack: read-only Graph, new files in the WORM store)"
  audiences      = [local.github_oidc_audience]
  issuer         = local.github_oidc_issuer
  subject        = local.evidence_subject
}

resource "azuread_app_role_assignment" "evidence" {
  for_each = toset(local.evidence_roles)

  app_role_id         = data.azuread_service_principal.msgraph.app_role_ids[each.value]
  principal_object_id = azuread_service_principal.evidence[0].object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}
