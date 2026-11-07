# =============================================================================
# envs/operator :: workload-ca.tf
# -----------------------------------------------------------------------------
# DESIGNED, off (enable_operator_workload_ca = false). Conditional Access for
# the operator as a WORKLOAD identity: block every token request from outside
# the owner's network.
#
# Why it is off: Microsoft Learn (conditional-access/workload-identity):
# "Workload Identities Premium licenses are required to create or modify
# Conditional Access policies scoped to service principals." The lab tenant
# has no such licence (subscribedSkus, read as the operator 2026-11-07:
# INTUNE_A, SPE_E5, Microsoft_Entra_ID_Governance_Step_Up_for_Microsoft_Entra_ID_P2).
# The lab buys nothing. Microsoft offers a Workload ID Premium trial in the
# Entra admin center; starting it is an OWNER decision.
#
# Shape (from the same Learn page and its Graph sample): workload identity
# included by service principal object id, all resources, any location
# except the named location, grant = block (the only grant a workload policy
# allows). "users" must still be present in the azuread provider schema, so
# it names no user. The policy covers single-tenant service principals,
# which the operator is (main.tf: AzureADMyOrg).
#
# Applying it needs Conditional Access Administrator: the owner applies this
# root, never the operator (it holds Policy.Read.All only).
# This adds a NEW policy. It does not change any existing CA policy.
# =============================================================================

resource "azuread_named_location" "operator_network" {
  count        = var.enable_operator_workload_ca ? 1 : 0
  display_name = "Lab operator network (owner)"

  ip {
    ip_ranges = var.operator_allowed_ip_ranges
    trusted   = false
  }
}

resource "azuread_conditional_access_policy" "operator_location" {
  count        = var.enable_operator_workload_ca ? 1 : 0
  display_name = "CA090 - Lab operator: block outside the owner's network (workload identity)"
  state        = var.operator_workload_ca_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["None"]
    }

    client_applications {
      included_service_principals = [azuread_service_principal.operator.object_id]
    }

    locations {
      included_locations = ["All"]
      excluded_locations = [azuread_named_location.operator_network[0].id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
