# =============================================================================
# envs/dev :: imports.tf - adopt objects that exist in the tenant but not in
# state. Each block names the run that left the gap. Remove a block once an
# apply has imported it (the import is then a no-op, but the id is stale
# documentation).
# =============================================================================

# Round-3 apply, run 42527718010 (2026-11-08): the azuread provider created
# this catalog role assignment (Access package assignment manager on the
# Clinical catalog, for the leaver Logic App's managed identity), then failed
# its read-back with "Provider produced inconsistent result after apply: Root
# object was present, but now absent" (read-after-write replication lag), so
# Terraform did not record it. A Graph read on 2026-11-08 shows it exists:
# id 681ee67e-c3d3-41f7-837a-a1a18717d863. Without this block the next apply
# would try to create it a second time.
import {
  for_each = var.enable_premium && var.enable_governance && var.enable_lcw_leaver_extension && var.leaver_role_assignment_import_id != "" ? toset(["clinical"]) : toset([])
  to       = module.leaver_extension[0].azuread_access_package_catalog_role_assignment.assignment_manager[each.key]
  id       = var.leaver_role_assignment_import_id
}
