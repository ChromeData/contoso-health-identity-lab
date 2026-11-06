# =============================================================================
# aws :: audit-trail.tf
# -----------------------------------------------------------------------------
# WHAT: the AWS account's own record of who did what, kept somewhere the
# operator can't erase it. Three things, all behind enable_audit_baseline
# (default false, staged like the rest of this root):
#
#   * a CloudTrail TRAIL, contoso-lab-audit-trail: every management event
#     (console, CLI, Terraform) in every region, plus global services (IAM,
#     STS, Identity Center sign-ins), written to S3, with log file integrity
#     validation (a signed hourly digest file, so an edited or deleted log
#     file can be detected);
#   * the S3 bucket it writes to: private, versioned, encrypted, TLS only,
#     and a bucket policy that lets CloudTrail write ONLY for this one trail
#     (aws:SourceArn), so no other account's trail can use the bucket;
#   * an IAM Access Analyzer (type ACCOUNT) in var.aws_region: it lists
#     resources shared OUTSIDE the account (an S3 bucket, a role trust, a KMS
#     key policy...), so a leak like a public bucket shows up as a finding
#     instead of waiting for someone to notice. An analyzer covers the
#     regional resources of its own region: a bucket or key shared from
#     another region would not show here. This root builds everything in
#     aws_region (us-east-1); a second region needs its own analyzer.
#
# WHY: the lab already leans on CloudTrail (ADR 0024 and 0025 quote
# AssumeRoleWithWebIdentity and PutRolePolicy records as evidence) but never
# created a trail. Without one, those records come from CloudTrail "Event
# history": on by default, free, but 90 days only, one region at a time,
# and nothing an auditor can hold. A trail keeps a durable copy with
# integrity checks. Read 2026-11-06 as the operator: account 182002546409 had
# no trail (describe-trails --include-shadow-trails: empty) and no analyzer.
#
# PORTED FROM the owner's old AWS-Multi-Account-Baseline repo (trail, bucket,
# SourceArn-scoped policy, analyzer). Not ported: GuardDuty, Security Hub
# and the CIS/FSBP standards (they cost money every month and the lab has no
# one reading their findings yet), and the LocalStack switch.
#
# BUCKET POLICY: the two statements are AWS's documented ones, word for word
# apart from names (CloudTrail User Guide, "Amazon S3 bucket policy for
# CloudTrail", read 2026-11-06:
# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html).
# The trail ARN is BUILT from its parts, not read from the trail resource:
# CloudTrail refuses a bucket whose policy doesn't allow it yet, so the trail
# must depend on the policy, and the policy can't then depend on the trail.
# tests/audit_trail.tftest.hcl checks the built ARN matches the trail.
#
# ENCRYPTION: SSE-S3 (AES256). CloudTrail's docs ("Encrypting CloudTrail log
# files ... with AWS KMS keys", read 2026-11-06) give two options: SSE-S3 if
# SSE-KMS isn't enabled, or SSE-KMS with a KMS key you create and whose key
# policy grants cloudtrail.amazonaws.com. The second adds $1 a month and a
# key policy to get right, for a lab account. The integrity digest is what
# proves the logs weren't changed, not the encryption.
#
# WHO CAN TAMPER WITH IT: the lab operator (entra-operator.tf) has
# AdministratorAccess, so before this change it could stop or delete any
# trail and empty its bucket (checked 2026-11-06 with
# simulate-principal-policy: cloudtrail:StopLogging and DeleteTrail
# "allowed"). Guardrails v3 add a NoAuditTampering Deny: it can't stop,
# delete or reconfigure a trail, can't hide or delete Access Analyzer
# findings, and can't delete, overwrite or loosen anything in this bucket.
# Only a PIM-activated LabAdministrator can (ADR 0025).
#
# COST, from the AWS pricing pages read 2026-11-06:
#   * CloudTrail: the first copy of management events delivered to S3 is
#     free (this is the account's only trail). No data events, no Insights,
#     no CloudWatch Logs copy, so nothing else is billed by CloudTrail.
#   * S3: a quiet lab account writes a few MB of gzip logs a month: cents.
#   * Access Analyzer, external access: "no additional charge". The paid
#     kinds (unused access, internal access) are NOT created here.
#
# APPLY: with a LabAdministrator session (idlab-labadmin), not the operator.
# Creating the analyzer makes the service-linked role
# AWSServiceRoleForAccessAnalyzer (it didn't exist on 2026-11-06), which
# needs iam:CreateServiceLinkedRole: the operator gets "explicitDeny" for
# that (NoIamChanges). README "Audit trail" has the commands.
# =============================================================================

locals {
  audit_trail_name   = "contoso-lab-audit-trail"
  audit_bucket_name  = "contoso-health-audit-trail-${data.aws_caller_identity.current.account_id}"
  audit_bucket_arn   = "arn:${data.aws_partition.current.partition}:s3:::${local.audit_bucket_name}"
  audit_analyzer_tag = { Purpose = "audit" }

  # A multi-region trail's ARN carries its home region: the provider region.
  audit_trail_arn = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.audit_trail_name}"
}

resource "aws_s3_bucket" "audit" {
  #checkov:skip=CKV_AWS_18:Access logs for the access-log bucket would need a third bucket; CloudTrail itself records who changed this bucket.
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles the cost; the logs are integrity-checked and the operator cannot delete them (NoAuditTampering).
  #checkov:skip=CKV2_AWS_62:No consumer exists for event notifications on log delivery.
  #checkov:skip=CKV_AWS_145:SSE-S3 is one of CloudTrail's two documented options; the other, a customer-managed KMS key, adds a monthly charge and a key policy for a lab account.
  count = var.enable_audit_baseline ? 1 : 0

  bucket = local.audit_bucket_name

  # NOT force_destroy (unlike the patient portal): a plan that deletes the
  # audit bucket must fail while it still holds logs. Teardown is a
  # deliberate, manual emptying first.
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count  = var.enable_audit_baseline ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit" {
  count  = var.enable_audit_baseline ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    # ACLs off. S3 still accepts the bucket-owner-full-control ACL CloudTrail
    # sends with each log file (S3 User Guide, "Controlling ownership of
    # objects": that ACL is allowed under BucketOwnerEnforced).
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "audit" {
  count  = var.enable_audit_baseline ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count  = var.enable_audit_baseline ? 1 : 0
  bucket = aws_s3_bucket.audit[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  count      = var.enable_audit_baseline ? 1 : 0
  depends_on = [aws_s3_bucket_versioning.audit]

  bucket = aws_s3_bucket.audit[0].id

  rule {
    id     = "keep-audit-logs"
    status = "Enabled"

    filter {}

    # Log files expire after the retention period; the old version then
    # goes 30 days later. A delete marker can only shorten that if someone
    # deletes a log file, which the operator is denied (NoAuditTampering).
    expiration {
      days = var.audit_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  count      = var.enable_audit_baseline ? 1 : 0
  depends_on = [aws_s3_bucket_public_access_block.audit]

  bucket = aws_s3_bucket.audit[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit[0].arn
        Condition = { StringEquals = { "aws:SourceArn" = local.audit_trail_arn } }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.audit_trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.audit[0].arn, "${aws_s3_bucket.audit[0].arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "audit" {
  #checkov:skip=CKV_AWS_35:SSE-S3 on the bucket (see ENCRYPTION above); a customer-managed KMS key adds a monthly charge for a lab account.
  #checkov:skip=CKV_AWS_252:No SNS subscriber exists for delivery notifications.
  #checkov:skip=CKV2_AWS_10:A CloudWatch Logs copy is billed per GB; the logs are read from S3 (or Event history) instead.
  count = var.enable_audit_baseline ? 1 : 0

  # CloudTrail checks the bucket policy when the trail is created.
  depends_on = [aws_s3_bucket_policy.audit]

  name                          = local.audit_trail_name
  s3_bucket_name                = aws_s3_bucket.audit[0].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # Management events only, reads and writes (the default selector, written
  # out so a reviewer sees it): no data events, which are billed.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_accessanalyzer_analyzer" "external_access" {
  count = var.enable_audit_baseline ? 1 : 0

  analyzer_name = "contoso-lab-external-access"
  type          = "ACCOUNT" # external access, this account as the zone of trust: free
  tags          = local.audit_analyzer_tag
}
