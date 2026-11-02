# Offline, mocked tests for the patient-portal stand-in (patient-portal.tf).
# No AWS call is made:  terraform init -backend=false && terraform test
#
# What these pin: the bucket is private (all four public-access blocks, ACLs
# off), versioned and KMS-encrypted; it carries the App / Owner / Environment
# tags; Terraform keeps exactly index.html and status.json in it, with no
# patient data; the bucket policy is TLS-only and its one Allow is
# s3:GetBucketLocation for ViewOnlyAccess sessions - never an object read.
#
# Mocks: the same data sources as github_oidc.tftest.hcl (main.tf's guards
# need them), plus a fixed bucket ARN so the policy can be read back.

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

run "portal_bucket_is_private_versioned_and_encrypted" {
  command = apply # mocked

  assert {
    condition     = aws_s3_bucket.patient_portal.bucket == "contoso-health-patient-portal-123456789012"
    error_message = "with no suffix the bucket name ends in the account id (globally unique without a random provider)"
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.patient_portal.block_public_acls &&
      aws_s3_bucket_public_access_block.patient_portal.block_public_policy &&
      aws_s3_bucket_public_access_block.patient_portal.ignore_public_acls &&
      aws_s3_bucket_public_access_block.patient_portal.restrict_public_buckets
    )
    error_message = "all four public-access blocks must be on"
  }
  assert {
    condition     = aws_s3_bucket_ownership_controls.patient_portal.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "ACLs must be disabled (BucketOwnerEnforced): access is by policy only"
  }
  assert {
    condition     = aws_s3_bucket_versioning.patient_portal.versioning_configuration[0].status == "Enabled"
    error_message = "the portal bucket must be versioned"
  }
  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.patient_portal.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms" &&
      one(aws_s3_bucket_server_side_encryption_configuration.patient_portal.rule).bucket_key_enabled == true
    )
    error_message = "default encryption must be SSE-KMS with an S3 Bucket Key"
  }
  assert {
    condition = (
      aws_s3_bucket.patient_portal.tags["App"] == "PatientPortal" &&
      aws_s3_bucket.patient_portal.tags["Owner"] == "CloudEngineering" &&
      aws_s3_bucket.patient_portal.tags["Environment"] == "lab"
    )
    error_message = "the bucket must be tagged App=PatientPortal, Owner=CloudEngineering, Environment=lab"
  }
}

run "portal_holds_two_small_objects_and_no_patient_data" {
  command = apply # mocked

  assert {
    condition     = jsonencode(output.patient_portal_object_keys) == jsonencode(["index.html", "status.json"])
    error_message = "Terraform must keep exactly index.html and status.json in the bucket"
  }
  assert {
    condition = (
      strcontains(aws_s3_object.patient_portal["index.html"].content, "Contoso Health patient portal (lab)") &&
      aws_s3_object.patient_portal["index.html"].content_type == "text/html; charset=utf-8"
    )
    error_message = "index.html must be the lab placeholder page"
  }
  assert {
    condition = (
      jsondecode(aws_s3_object.patient_portal["status.json"].content).patientData == false &&
      aws_s3_object.patient_portal["status.json"].content_type == "application/json"
    )
    error_message = "status.json must say there is no patient data"
  }
  assert {
    condition     = alltrue([for o in aws_s3_object.patient_portal : o.tags["Owner"] == "CloudEngineering"])
    error_message = "every object carries the portal tags"
  }
}

run "bucket_policy_is_tls_only_and_never_grants_object_reads" {
  command = apply # mocked

  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.patient_portal.policy).Statement :
      s.Effect == "Deny" && s.Action == "s3:*" && s.Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "the bucket policy must deny any request that is not over TLS"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.patient_portal.policy).Statement :
      s.Action == "s3:GetBucketLocation" if s.Effect == "Allow"
    ])
    error_message = "the only Allow is s3:GetBucketLocation: the bucket policy must never grant object reads or writes"
  }
  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.patient_portal.policy).Statement :
      s.Principal.AWS == "arn:aws:iam::123456789012:root" && strcontains(s.Condition.ArnLike["aws:PrincipalArn"], "AWSReservedSSO_${aws_ssoadmin_permission_set.view_only.name}_")
      if s.Effect == "Allow"
    ])
    error_message = "the Allow is for this account's sessions of the ViewOnlyAccess permission set (main.tf) only"
  }
}

run "suffix_overrides_the_account_id" {
  command = plan

  variables {
    patient_portal_bucket_suffix = "demo-01"
  }

  assert {
    condition     = aws_s3_bucket.patient_portal.bucket == "contoso-health-patient-portal-demo-01"
    error_message = "patient_portal_bucket_suffix replaces the account id in the bucket name"
  }
}

run "invalid_suffix_is_rejected" {
  command = plan

  variables {
    patient_portal_bucket_suffix = "Demo_01"
  }

  expect_failures = [var.patient_portal_bucket_suffix]
}
