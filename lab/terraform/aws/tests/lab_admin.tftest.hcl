# Offline, mocked tests for the just-in-time AWS admin path (lab-admin.tf,
# ADR 0025). No AWS call is made:  terraform init -backend=false && terraform test
#
# What these pin: nothing is created unless enable_lab_admin_jit; the
# LabAdministrator permission set carries AWS managed AdministratorAccess and
# a session no longer than the 2-hour PIM activation; its ONE assignment is
# the SCIM copy of PIM-AWS-Lab-Admins in the target account, never the
# ViewOnlyAccess staff group; the optional lineage pin refuses a group that
# SCIM did not create from the Entra PIM group.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_data "aws_ssoadmin_instances" {
    defaults = {
      arns               = ["arn:aws:sso:::instance/ssoins-1111111111111111"]
      identity_store_ids = ["d-1234567890"]
    }
  }
  # The staff group (main.tf's lookup).
  mock_data "aws_identitystore_group" {
    defaults = {
      group_id     = "90676d1b-1111-2222-3333-444455556666"
      external_ids = [{ id = "55555555-5555-5555-5555-555555555555", issuer = "" }]
    }
  }
  mock_resource "aws_ssoadmin_permission_set" {
    defaults = { arn = "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::contoso-health-patient-portal-123456789012" }
  }
}

# The PIM admin group as SCIM created it: its own id and the Entra object id.
override_data {
  target = data.aws_identitystore_group.lab_admins
  values = {
    group_id     = "a0a0a0a0-1111-2222-3333-444455556666"
    external_ids = [{ id = "77777777-7777-7777-7777-777777777777", issuer = "" }]
  }
}

run "off_by_default" {
  command = plan

  assert {
    condition     = length(aws_ssoadmin_permission_set.lab_admin) == 0 && length(aws_ssoadmin_account_assignment.lab_admins) == 0 && length(aws_ssoadmin_managed_policy_attachment.lab_admin) == 0 && length(data.aws_identitystore_group.lab_admins) == 0
    error_message = "no AWS admin path may exist unless enable_lab_admin_jit = true"
  }
}

run "lab_administrator_goes_only_to_the_pim_group" {
  command = apply

  variables {
    enable_lab_admin_jit            = true
    lab_admin_entra_group_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition     = aws_ssoadmin_permission_set.lab_admin[0].name == "LabAdministrator" && aws_ssoadmin_permission_set.lab_admin[0].session_duration == "PT1H"
    error_message = "LabAdministrator, 1-hour sessions by default"
  }
  assert {
    condition     = aws_ssoadmin_managed_policy_attachment.lab_admin[0].managed_policy_arn == "arn:aws:iam::aws:policy/AdministratorAccess" && aws_ssoadmin_managed_policy_attachment.lab_admin[0].permission_set_arn == aws_ssoadmin_permission_set.lab_admin[0].arn
    error_message = "the permission set carries the AWS managed AdministratorAccess policy (partition-derived ARN)"
  }
  assert {
    condition = (
      aws_ssoadmin_account_assignment.lab_admins[0].principal_id == "a0a0a0a0-1111-2222-3333-444455556666" &&
      aws_ssoadmin_account_assignment.lab_admins[0].principal_type == "GROUP" &&
      aws_ssoadmin_account_assignment.lab_admins[0].target_id == "123456789012" &&
      aws_ssoadmin_account_assignment.lab_admins[0].target_type == "AWS_ACCOUNT" &&
      aws_ssoadmin_account_assignment.lab_admins[0].permission_set_arn == aws_ssoadmin_permission_set.lab_admin[0].arn
    )
    error_message = "the ONE assignment is the SCIM copy of PIM-AWS-Lab-Admins, in the target account"
  }
  assert {
    condition     = aws_ssoadmin_account_assignment.lab_admins[0].principal_id != aws_ssoadmin_account_assignment.view_only_users.principal_id
    error_message = "LabAdministrator must never be assigned to the ViewOnlyAccess staff group"
  }
  assert {
    condition     = length(output.lab_admin_group_external_ids) == 1 && contains(output.lab_admin_group_external_ids, "77777777-7777-7777-7777-777777777777")
    error_message = "output: the Entra lineage of the admin group, for the evidence pack"
  }
}

run "session_never_longer_than_the_activation" {
  command = plan

  variables {
    enable_lab_admin_jit       = true
    lab_admin_session_duration = "PT4H"
  }

  expect_failures = [var.lab_admin_session_duration]
}

run "lineage_pin_refuses_a_group_not_made_by_scim_from_the_pim_group" {
  command = plan

  variables {
    enable_lab_admin_jit            = true
    lab_admin_entra_group_object_id = "88888888-8888-8888-8888-888888888888"
  }

  expect_failures = [data.aws_identitystore_group.lab_admins]
}

run "staff_group_name_is_refused" {
  command = plan

  variables {
    enable_lab_admin_jit = true
  }

  # The admin lookup resolving to the staff group's id must stop the plan.
  override_data {
    target = data.aws_identitystore_group.lab_admins
    values = {
      group_id     = "90676d1b-1111-2222-3333-444455556666"
      external_ids = [{ id = "55555555-5555-5555-5555-555555555555", issuer = "" }]
    }
  }

  expect_failures = [data.aws_identitystore_group.lab_admins]
}

run "hand_made_group_warns" {
  command = plan

  variables {
    enable_lab_admin_jit = true
  }

  override_data {
    target = data.aws_identitystore_group.lab_admins
    values = {
      group_id     = "a0a0a0a0-1111-2222-3333-444455556666"
      external_ids = []
    }
  }

  expect_failures = [check.lab_admin_group_is_scim_provisioned]
}
