# Offline, mocked tests for the audit trail (audit-trail.tf).
# No AWS call is made:  terraform init -backend=false && terraform test
#
# What these pin: nothing exists unless enable_audit_baseline; the trail
# covers every region and global services, validates its log files and
# logs management events only (no billed data events); the bucket is
# private, versioned, encrypted, TLS only and not force_destroy; CloudTrail
# may write ONLY for this trail (aws:SourceArn, and the ARN the policy is
# built with is the trail's real ARN); the analyzer is the free external
# access type; retention outside 90-3650 days is refused.
#
# Mocks: main.tf's guards need the same data sources as the other files;
# the trail, bucket and analyzer ARNs are fixed so the policy can be read.

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
    defaults = { arn = "arn:aws:s3:::contoso-health-audit-trail-123456789012" }
  }
  mock_resource "aws_cloudtrail" {
    defaults = { arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/contoso-lab-audit-trail" }
  }
  mock_resource "aws_accessanalyzer_analyzer" {
    defaults = { arn = "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/contoso-lab-external-access" }
  }
}

run "off_by_default" {
  command = plan

  assert {
    condition     = length(aws_cloudtrail.audit) == 0 && length(aws_s3_bucket.audit) == 0 && length(aws_accessanalyzer_analyzer.external_access) == 0
    error_message = "no trail, bucket or analyzer may exist unless enable_audit_baseline = true"
  }
}

run "trail_records_every_region_and_validates_its_files" {
  command = apply # mocked

  variables {
    enable_audit_baseline = true
  }

  assert {
    condition = (
      aws_cloudtrail.audit[0].is_multi_region_trail &&
      aws_cloudtrail.audit[0].include_global_service_events &&
      aws_cloudtrail.audit[0].enable_log_file_validation &&
      aws_cloudtrail.audit[0].enable_logging
    )
    error_message = "the trail must log every region and global services (IAM, STS), with log file integrity validation, and be logging"
  }
  assert {
    condition = (
      length(aws_cloudtrail.audit[0].event_selector) == 1 &&
      aws_cloudtrail.audit[0].event_selector[0].read_write_type == "All" &&
      aws_cloudtrail.audit[0].event_selector[0].include_management_events &&
      length(aws_cloudtrail.audit[0].event_selector[0].data_resource) == 0 &&
      length(aws_cloudtrail.audit[0].advanced_event_selector) == 0
    )
    error_message = "management events only, reads and writes: no data events (they are billed)"
  }
  assert {
    condition     = aws_cloudtrail.audit[0].s3_bucket_name == aws_s3_bucket.audit[0].id
    error_message = "the trail writes to the audit bucket"
  }
  # The policy builds the trail ARN by hand (dependency cycle otherwise); it
  # must be the real one, or CloudTrail is refused by its own bucket.
  assert {
    condition     = local.audit_trail_arn == aws_cloudtrail.audit[0].arn
    error_message = "the trail ARN in the bucket policy must equal the trail's real ARN"
  }
}

run "bucket_is_private_versioned_encrypted_and_kept" {
  command = apply # mocked

  variables {
    enable_audit_baseline = true
  }

  assert {
    condition     = aws_s3_bucket.audit[0].bucket == "contoso-health-audit-trail-123456789012" && aws_s3_bucket.audit[0].force_destroy == false
    error_message = "the bucket is named after the account and is not force_destroy (a plan must not delete logs)"
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.audit[0].block_public_acls &&
      aws_s3_bucket_public_access_block.audit[0].block_public_policy &&
      aws_s3_bucket_public_access_block.audit[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.audit[0].restrict_public_buckets &&
      aws_s3_bucket_ownership_controls.audit[0].rule[0].object_ownership == "BucketOwnerEnforced"
    )
    error_message = "all four public-access blocks on, ACLs off"
  }
  assert {
    condition     = aws_s3_bucket_versioning.audit[0].versioning_configuration[0].status == "Enabled"
    error_message = "the audit bucket must be versioned"
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.audit[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "default encryption must be SSE-S3"
  }
  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.audit[0].rule).expiration[0].days == 365
    error_message = "log files are kept one year by default"
  }
}

run "only_this_trail_may_write_and_only_over_tls" {
  command = apply # mocked

  variables {
    enable_audit_baseline = true
  }

  assert {
    condition = alltrue([
      for s in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement :
      s.Principal.Service == "cloudtrail.amazonaws.com" && s.Condition.StringEquals["aws:SourceArn"] == "arn:aws:cloudtrail:us-east-1:123456789012:trail/contoso-lab-audit-trail"
      if s.Effect == "Allow"
    ])
    error_message = "every Allow is for the CloudTrail service and scoped with aws:SourceArn to this one trail"
  }
  assert {
    condition = toset([
      for s in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement : s.Action if s.Effect == "Allow"
    ]) == toset(["s3:GetBucketAcl", "s3:PutObject"])
    error_message = "CloudTrail gets the ACL check and the write - nothing else, and nobody else"
  }
  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement :
      s.Action == "s3:PutObject" && s.Resource == "arn:aws:s3:::contoso-health-audit-trail-123456789012/AWSLogs/123456789012/*" && s.Condition.StringEquals["s3:x-amz-acl"] == "bucket-owner-full-control"
    ])
    error_message = "the write is limited to this account's AWSLogs prefix with bucket-owner-full-control"
  }
  assert {
    condition = anytrue([
      for s in jsondecode(aws_s3_bucket_policy.audit[0].policy).Statement :
      s.Effect == "Deny" && s.Action == "s3:*" && s.Condition.Bool["aws:SecureTransport"] == "false"
    ])
    error_message = "the bucket policy must deny any request that is not over TLS"
  }
}

run "analyzer_is_the_free_external_access_kind" {
  command = apply # mocked

  variables {
    enable_audit_baseline = true
  }

  assert {
    condition     = aws_accessanalyzer_analyzer.external_access[0].type == "ACCOUNT"
    error_message = "type ACCOUNT (external access) is free; the unused/internal access kinds are billed and are not built here"
  }
}

run "retention_below_event_history_is_refused" {
  command = plan

  variables {
    enable_audit_baseline    = true
    audit_log_retention_days = 30
  }

  expect_failures = [var.audit_log_retention_days]
}
