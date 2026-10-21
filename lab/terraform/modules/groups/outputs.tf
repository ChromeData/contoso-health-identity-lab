# =============================================================================
# modules/groups :: outputs.tf
# -----------------------------------------------------------------------------
# Object IDs are what every downstream module consumes (CA exclusions, PIM
# group policy, access-package resource associations).
# =============================================================================

output "break_glass_group_object_id" {
  description = "Object id of Break-Glass-Admins - excluded from every CA policy."
  value       = azuread_group.break_glass.object_id
}

output "break_glass_user_object_ids" {
  description = "Object ids of the cloud-only break-glass accounts."
  value       = [for u in azuread_user.break_glass : u.object_id]
}

output "break_glass_user_principal_names" {
  description = "UPNs of the break-glass accounts (feed the sign-in alert / watchlist)."
  value       = [for u in azuread_user.break_glass : u.user_principal_name]
}

output "all_nurses_group_object_id" {
  description = "Object id of the All-Nurses dynamic birthright group."
  value       = azuread_group.department["nursing"].object_id
}

output "all_icu_group_object_id" {
  description = "Object id of the All-ICU dynamic birthright group."
  value       = azuread_group.department["icu"].object_id
}

output "priv_iam_admins_group_object_id" {
  description = "Object id of the PIM-governed Privileged-IAM-Admins group."
  value       = azuread_group.priv_iam_admins.object_id
}

output "admin_accounts_group_object_id" {
  description = "Object id of Admin-Accounts (standing, role-assignable, no role): the admin passkey profile and registration campaign target. Membership (adm- accounts, build account) is set post-apply by New-AdminAccounts.ps1."
  value       = azuread_group.admin_accounts.object_id
}

output "ca005_pilot_group_object_id" {
  description = "Object id of CA005-Pilot-CompliantDevice (CA005 include, Intune compliance assignment, VM Administrator Login on modules/intune-vm)."
  value       = azuread_group.ca005_pilot.object_id
}

output "app_access_group_object_ids" {
  description = "Map of key => assigned access group object id (servicenow/aws/okta/icu_critical_care/pharmacy_dispensing)."
  value       = { for k, g in azuread_group.app_access : k => g.object_id }
}

output "app_consent_reviewers_group_object_id" {
  description = "Object id of App-Consent-Reviewers (admin consent workflow reviewers; Set-ConsentPolicy.ps1 finds it by mailNickname), or null while enable_nhi_governance is off."
  value       = one(azuread_group.app_consent_reviewers[*].object_id)
}

output "all_workforce_group_object_id" {
  description = "Object id of the dynamic All-Workforce group (staff passkey profile target), or null while enable_workforce_group is off."
  value       = one(azuread_group.all_workforce[*].object_id)
}
