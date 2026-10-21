# Regression guard for CA004: Conditional Access expects the named location's
# bare object id (GUID). The azuread provider's `.id` is the path form
# ("/identity/conditionalAccess/namedLocations/<guid>"), which the policy
# would not match. Run offline: terraform init -backend=false && terraform test
#
# The authentication-strength mock is required: without a path-form id the
# provider rejects CA002's authentication_strength_policy_id during the
# mocked apply.

mock_provider "azuread" {
  mock_resource "azuread_authentication_strength_policy" {
    defaults = {
      id = "/policies/authenticationStrengthPolicies/44444444-4444-4444-4444-444444444444"
    }
  }
  mock_resource "azuread_named_location" {
    defaults = {
      id        = "/identity/conditionalAccess/namedLocations/11111111-1111-1111-1111-111111111111"
      object_id = "11111111-1111-1111-1111-111111111111"
    }
  }
}

variables {
  break_glass_group_object_id = "22222222-2222-2222-2222-222222222222"
  ca005_pilot_group_object_id = "33333333-3333-3333-3333-333333333333"
}

run "ca004_location_is_bare_guid" {
  command = apply

  assert {
    condition     = can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", azuread_conditional_access_policy.block_countries.conditions[0].locations[0].included_locations[0]))
    error_message = "CA004 included_locations must be the named location object_id (GUID), not the path-form id."
  }

  assert {
    condition     = output.blocked_named_location_id == "11111111-1111-1111-1111-111111111111"
    error_message = "blocked_named_location_id must output the bare object_id (GUID)."
  }
}
