# =============================================================================
# aws :: lab-admin.tf
# -----------------------------------------------------------------------------
# WHAT: the AWS half of "AWS administration is just-in-time through Entra,
# not root" (ADR 0025). One permission set, LabAdministrator (AWS managed
# AdministratorAccess, 1-hour sessions), assigned in the lab account to ONE
# principal: the Identity Store copy of the Entra group PIM-AWS-Lab-Admins.
#
#   adm-labops --(PIM for Groups: activate, 2 h, MFA + reason)--> member of
#   PIM-AWS-Lab-Admins (Entra, modules/pim aws.tf; assigned to the AWS app,
#   modules/apps) --SCIM, 2-10 min--> Identity Store group of the same name
#   --(this file)--> LabAdministrator in var.target_account_id
#
# WHY THIS IS JUST-IN-TIME: the Entra group's members are ELIGIBLE only. At
# rest it has no active member, so SCIM keeps the AWS copy EMPTY and nobody
# holds this permission set. A member appears in AWS only while a PIM
# activation lasts; Entra also refuses the SAML sign-in to AWS outside one
# (assignment required on the app). Learn documents this exact shape for
# PIM + app provisioning (concept-pim-for-groups, "Privileged Identity
# Management and app provisioning", checked 2026-11-05).
#
# OWNERSHIP BOUNDARY: as in main.tf, Terraform READS the group and never
# creates one, and never touches membership. A Terraform-made Identity
# Store group would be an AWS-local admin group outside PIM: exactly what
# ADR 0025 removes (the console-made idlab-admin assignment).
#
# SESSION LENGTH: PT1H by default, PT2H at most - never longer than the
# 2-hour PIM activation (modules/pim aws_admin_activation_max_duration),
# so a session that starts inside an activation cannot outlast it by more
# than the session itself. AdministratorAccess in the management account is
# the most powerful thing in this root; a short session is its main limit.
#
# MANAGEMENT ACCOUNT, GROUP ASSIGNMENT (read main.tf's header): AWS
# recommends user assignments in the management account because whoever
# controls the group controls the account. Here the group's membership is
# PIM-governed and role-assignable in Entra (Tier 0 to change), which is the
# control that recommendation is after.
#
# WHO APPLIES: the first apply ran as the operator, before guardrails v2
# (entra-operator.tf) denied it Identity Center writes. From then on any
# change here is applied with a LabAdministrator session (aws_profile =
# idlab-labadmin, README "AWS admin without root"): the operator can read
# this permission set but no longer change it.
#
# STAGED: enable_lab_admin_jit defaults to false, like every new trust path
# in this root. Turned on with a targeted apply of the four addresses below.
# =============================================================================

locals {
  lab_admin_policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}

# The Entra group, as SCIM created it. Looked up by DisplayName (unique for
# Identity Store groups). If SCIM has not provisioned it yet the plan fails
# here - the same safe failure as main.tf: wait for the next cycle (or
# Provision on demand) and plan again.
data "aws_identitystore_group" "lab_admins" {
  count = var.enable_lab_admin_jit ? 1 : 0

  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.lab_admin_group_display_name
    }
  }

  lifecycle {
    postcondition {
      # Never grant AdministratorAccess to the staff group by a naming slip.
      condition     = self.group_id != data.aws_identitystore_group.aws_users.group_id
      error_message = "lab_admin_group_display_name resolves to the same Identity Store group as group_display_name (the ViewOnlyAccess staff group). LabAdministrator must only ever go to the PIM admin group."
    }
    postcondition {
      # Optional lineage pin, as in main.tf: the AWS principal must be the
      # SCIM copy of the Terraform-managed Entra group.
      condition = (
        var.lab_admin_entra_group_object_id == ""
        || contains([for e in self.external_ids : lower(e.id)], lower(var.lab_admin_entra_group_object_id))
      )
      error_message = "The Identity Store group named by lab_admin_group_display_name does not carry lab_admin_entra_group_object_id as an external id: it was not provisioned by SCIM from PIM-AWS-Lab-Admins. Do not grant it AdministratorAccess."
    }
  }
}

# A hand-made group (no external id) would be an AdministratorAccess group
# that PIM does not govern. A warning, like main.tf's check, because the
# lineage pin above is the hard gate.
check "lab_admin_group_is_scim_provisioned" {
  assert {
    condition     = !var.enable_lab_admin_jit || length(try(data.aws_identitystore_group.lab_admins[0].external_ids, [])) > 0
    error_message = "Identity Store group '${var.lab_admin_group_display_name}' has no external id - it may have been created by hand instead of by SCIM from the Entra PIM group. Only a PIM-governed group may hold LabAdministrator."
  }
}

resource "aws_ssoadmin_permission_set" "lab_admin" {
  count = var.enable_lab_admin_jit ? 1 : 0

  name             = "LabAdministrator"
  description      = "Contoso Health lab: AWS administration, just-in-time. Held only by PIM-AWS-Lab-Admins (Entra PIM for Groups, 2-hour activation, SCIM). ADR 0025. Managed by Terraform - lab/terraform/aws."
  instance_arn     = local.instance_arn
  session_duration = var.lab_admin_session_duration
}

resource "aws_ssoadmin_account_assignment" "lab_admins" {
  count = var.enable_lab_admin_jit ? 1 : 0

  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.lab_admin[0].arn

  principal_id   = data.aws_identitystore_group.lab_admins[0].group_id
  principal_type = "GROUP"

  target_id   = local.target_account_id
  target_type = "AWS_ACCOUNT"
}

# depends_on the assignment, for the reason main.tf gives: on create the
# assignment lands first with an empty permission set (no access - fails
# closed), then this attachment re-provisions it; on destroy the attachment
# goes first.
resource "aws_ssoadmin_managed_policy_attachment" "lab_admin" {
  count      = var.enable_lab_admin_jit ? 1 : 0
  depends_on = [aws_ssoadmin_account_assignment.lab_admins]

  instance_arn       = local.instance_arn
  managed_policy_arn = local.lab_admin_policy_arn
  permission_set_arn = aws_ssoadmin_permission_set.lab_admin[0].arn
}
