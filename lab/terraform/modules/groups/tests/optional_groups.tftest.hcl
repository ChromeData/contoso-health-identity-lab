# Offline, mocked tests for the optional groups in modules/groups:
#   terraform init -backend=false && terraform test   (HashiCorp Terraform 1.16.5)
# Pins: nothing new exists by default; App-Consent-Reviewers is a plain
# (NOT role-assignable) security group; All-Workforce is dynamic and its rule
# can never match the cloud-only break-glass accounts or guests. Admin-Accounts
# (always created) is a standing, assigned, role-assignable group that holds
# no role - the admin passkey target.

mock_provider "azuread" {}
mock_provider "random" {}

variables {
  break_glass_domain = "contosohealthlab.onmicrosoft.com"
}

run "optional_groups_absent_by_default" {
  command = plan

  assert {
    condition     = length(azuread_group.app_consent_reviewers) == 0 && length(azuread_group.all_workforce) == 0
    error_message = "App-Consent-Reviewers / All-Workforce must not exist unless their flag is on"
  }
  assert {
    condition     = output.app_consent_reviewers_group_object_id == null && output.all_workforce_group_object_id == null
    error_message = "outputs must be null while the flags are off"
  }
}

run "consent_reviewers_is_a_plain_security_group" {
  command = plan

  variables {
    enable_nhi_governance = true
  }

  assert {
    condition     = azuread_group.app_consent_reviewers[0].mail_nickname == "app-consent-reviewers"
    error_message = "Set-ConsentPolicy.ps1 finds the reviewers by mailNickname app-consent-reviewers"
  }
  assert {
    condition     = azuread_group.app_consent_reviewers[0].assignable_to_role != true && azuread_group.app_consent_reviewers[0].security_enabled
    error_message = "reviewing consent requests confers no directory role: the group must not be role-assignable"
  }
}

run "all_workforce_never_matches_break_glass_or_guests" {
  command = plan

  variables {
    enable_workforce_group = true
  }

  assert {
    condition     = azuread_group.all_workforce[0].mail_nickname == "all-workforce" && contains(azuread_group.all_workforce[0].types, "DynamicMembership")
    error_message = "All-Workforce must be the dynamic group all-workforce (Set-AuthenticationMethodsPolicy.ps1 default)"
  }
  assert {
    # dirSyncEnabled excludes the cloud-only break-glass pair; userType Member
    # excludes B2B guests; accountEnabled drops leavers.
    condition = alltrue([for clause in ["(user.dirSyncEnabled -eq true)", "(user.userType -eq \"Member\")", "(user.accountEnabled -eq true)"] :
    strcontains(azuread_group.all_workforce[0].dynamic_membership[0].rule, clause)])
    error_message = "the All-Workforce rule must require dirSyncEnabled, Member and accountEnabled"
  }
}

run "admin_accounts_is_a_standing_role_assignable_group" {
  command = plan

  assert {
    condition     = azuread_group.admin_accounts.mail_nickname == "admin-accounts" && azuread_group.admin_accounts.assignable_to_role == true
    error_message = "Admin-Accounts must be role-assignable (only PRA/GA can remove an admin from the passkey target) with mail_nickname admin-accounts (Set-AuthenticationMethodsPolicy.ps1 default)"
  }
  assert {
    # Role-assignable groups cannot be dynamic; and a standing group is the
    # whole point (a PIM group has no members outside an activation).
    condition     = !contains(coalesce(azuread_group.admin_accounts.types, []), "DynamicMembership") && length(azuread_group.admin_accounts.dynamic_membership) == 0
    error_message = "Admin-Accounts must have assigned (standing) membership, never dynamic"
  }
}
