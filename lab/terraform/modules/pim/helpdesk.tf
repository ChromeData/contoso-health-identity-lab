# =============================================================================
# modules/pim :: helpdesk.tf
# -----------------------------------------------------------------------------
# HELP-DESK SCOPING (var.enable_helpdesk_au_scoping, default false; needs
# enable_pim_tiers).
#
#   PIM-Tier1-Helpdesk --(ACTIVE, at AU scope)--> Helpdesk Administrator
#                      --(ACTIVE, at AU scope)--> Authentication Administrator
#        scope: /administrativeUnits/<AU-Workforce-Standard>
#        membership: eligible-only, Tier-1 activation (MFA + justification, 8h)
#
# WHY: Microsoft already limits Authentication / Helpdesk / Password
# Administrator to NON-admin targets. The administrative unit narrows the
# population further: only HR-provisioned workforce members are in it, so the
# service desk cannot touch VIPs (restricted management AU, created by
# post-apply/New-RestrictedAdminUnit.ps1), service accounts, adm- admin
# accounts or break-glass - whatever the caller says (help-desk-identity-
# verification.md, Rules 1-3).
#
# PROVIDER LIMITS (azuread 3.10.0, schema + administrative_unit_resource.go):
#   * No isMemberManagementRestricted attribute (and it is immutable after
#     creation in Graph) - the VIP RMAU is a Graph POST, never this resource:
#     a replace would silently recreate it WITHOUT the restriction.
#   * No dynamic membership (membershipType / membershipRule are Graph-only).
#     Output workforce_au_membership_body renders the PATCH body; applying it
#     is a TENANT-TIME step (Graph: PATCH /directory/administrativeUnits/<id>,
#     AdministrativeUnit.ReadWrite.All). members is therefore ignored here,
#     like PIM-owned group membership. verify: a later provider update of the
#     AU (description change) leaves membershipType untouched.
#   * Role assignments use azuread_directory_role_assignment with an AU
#     directory_scope_id (unifiedRoleAssignment), not the older
#     azuread_administrative_unit_role_member (scopedRoleMembers, needs an
#     activated directory role object).
#
# CONDITIONAL ACCESS GAP: AU-scoped assignments are NOT evaluated by CA's
# directory-role condition (Learn), so CA002/CA020 must include
# PIM-Tier1-Helpdesk by GROUP (output privileged_review_targets ->
# modules/conditional-access admin_scope_group_object_ids).
#
# LICENSING: Entra ID P1 for each AU administrator; a DYNAMIC rule needs P1
# per member (both inside the E5 trial).
# =============================================================================

locals {
  au_scoped_group_keys = [for k, s in local.tier_group_settings : k if s.au_scoped]
  workforce_au_enabled = var.enable_helpdesk_au_scoping && length(local.au_scoped_group_keys) > 0
}

resource "azuread_administrative_unit" "workforce_standard" {
  count = local.workforce_au_enabled ? 1 : 0

  display_name            = var.workforce_au_display_name
  description             = "HR-provisioned workforce members only (no admin, service, VIP or break-glass accounts). Scope of the service desk's Helpdesk and Authentication Administrator roles (PIM-Tier1-Helpdesk)."
  prevent_duplicate_names = true

  # Members come from the dynamic rule (TENANT-TIME Graph PATCH,
  # output workforce_au_membership_body), never from Terraform.
  lifecycle {
    ignore_changes = [members]
  }
}

check "helpdesk_au_scoping_needs_tiers" {
  assert {
    condition     = !var.enable_helpdesk_au_scoping || local.workforce_au_enabled
    error_message = "enable_helpdesk_au_scoping = true plans nothing: it needs enable_pim_tiers = true and at least one au_scoped tier group (default: tier1_helpdesk)."
  }
}
