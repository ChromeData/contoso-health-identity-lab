# =============================================================================
# aws :: patient-portal.tf
# -----------------------------------------------------------------------------
# WHAT: something real behind the AWS door. A stand-in for the hospital's
# patient portal, which the cloud engineering team runs in AWS: one private S3
# bucket holding two tiny objects (a placeholder page and a status file).
# Cloud engineers reach it the same way as everything else in this root:
#   HR -> Entra -> access package "IT - Cloud Engineering Apps"
#   -> App-AWS-IdentityCenter-Users -> SCIM -> ViewOnlyAccess -> this account.
#
# NO PATIENT DATA. Nothing here is PHI, and nothing here serves web traffic:
# no website hosting, no CloudFront, no compute.
#
# WHAT ViewOnlyAccess CAN DO HERE (AWS managed policy, v48, read 2026-11-02):
#   s3:ListAllMyBuckets + s3:ListBucket  -> the bucket and its object names
#                                           show in the S3 console.
#   no s3:GetObject                      -> opening or downloading an object
#                                           is AccessDenied. That is the
#                                           least-privilege line on purpose:
#                                           reading or changing the portal is
#                                           a stronger permission set (README
#                                           "Natural next step").
#   The bucket policy adds ONE read for ViewOnlyAccess sessions,
#   s3:GetBucketLocation, which the managed policy lacks and the console uses
#   when it opens a bucket (verify: whether the current console still needs it).
#
# SECURITY: all four public-access blocks on, ACLs disabled (bucket owner
# enforced), versioning on, SSE-KMS with the AWS managed key aws/s3 plus an
# S3 Bucket Key (no monthly key charge), TLS-only bucket policy.
#
# COST: a few hundred bytes of S3 Standard and a handful of requests, so
# effectively $0. Noncurrent versions expire after 30 days.
#
# APPLY: human-applied like the rest of this root (README "Patient portal").
# The bucket lives in the account the profile signs into.
# =============================================================================

locals {
  # Globally unique without a random provider: the account id (or the suffix
  # variable) is part of the name.
  patient_portal_bucket_name = "contoso-health-patient-portal-${var.patient_portal_bucket_suffix != "" ? var.patient_portal_bucket_suffix : data.aws_caller_identity.current.account_id}"

  patient_portal_tags = {
    App         = "PatientPortal"
    Owner       = "CloudEngineering"
    Environment = "lab"
  }

  patient_portal_objects = {
    "index.html" = {
      content_type = "text/html; charset=utf-8"
      content      = <<-EOT
        <!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Contoso Health patient portal (lab)</title></head>
        <body>
        <h1>Contoso Health patient portal (lab)</h1>
        <p>Lab stand-in, run by Cloud Engineering. No patient data is stored here.</p>
        </body>
        </html>
      EOT
    }
    "status.json" = {
      content_type = "application/json"
      content = jsonencode({
        app         = "PatientPortal"
        owner       = "CloudEngineering"
        environment = "lab"
        status      = "ok"
        patientData = false
        managedBy   = "lab/terraform/aws/patient-portal.tf"
      })
    }
  }

  # Sessions of the ViewOnlyAccess permission set (main.tf) in this account.
  # The name is written out instead of referencing the permission set, so an
  # apply that targets only the portal never touches the grant
  # (tests/patient_portal.tftest.hcl checks the two names match). The wildcard
  # covers the role path with or without a region segment.
  view_only_session_arn_pattern = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_ViewOnlyAccess_*"
}

# The inline Checkov skips below name checks that Checkov 3.3.20 (local) does
# not run on these resources; they stay as the documented trade-off in case
# CI's pinned 3.3.3 image does (terraform-plan.yml, verify: on the first run).
resource "aws_s3_bucket" "patient_portal" {
  #checkov:skip=CKV_AWS_18:Lab stand-in with no patient data; server access logs need a second bucket. CloudTrail management events already record who changed it.
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles the cost for a placeholder page; nothing here needs a second copy.
  #checkov:skip=CKV2_AWS_62:No consumer exists for event notifications; the objects change only through this reviewed Terraform.
  bucket = local.patient_portal_bucket_name

  # Lab only: lets `terraform destroy` remove the old object versions that
  # versioning keeps. Never set this on a bucket that holds real data.
  force_destroy = true

  tags = local.patient_portal_tags
}

resource "aws_s3_bucket_public_access_block" "patient_portal" {
  bucket = aws_s3_bucket.patient_portal.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "patient_portal" {
  bucket = aws_s3_bucket.patient_portal.id

  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs off: access is policy only
  }
}

resource "aws_s3_bucket_versioning" "patient_portal" {
  bucket = aws_s3_bucket.patient_portal.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "patient_portal" {
  bucket = aws_s3_bucket.patient_portal.id

  rule {
    # No kms_master_key_id = the AWS managed key aws/s3: KMS encryption with
    # no customer-managed key to pay for or lose.
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "patient_portal" {
  # Noncurrent-version rules need versioning in place first (provider docs).
  depends_on = [aws_s3_bucket_versioning.patient_portal]

  bucket = aws_s3_bucket.patient_portal.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "patient_portal" {
  # The public-access block must exist before any policy lands.
  depends_on = [aws_s3_bucket_public_access_block.patient_portal]

  bucket = aws_s3_bucket.patient_portal.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.patient_portal.arn, "${aws_s3_bucket.patient_portal.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "ViewOnlyConsoleCanOpenTheBucket"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "s3:GetBucketLocation"
        Resource  = aws_s3_bucket.patient_portal.arn
        Condition = { ArnLike = { "aws:PrincipalArn" = local.view_only_session_arn_pattern } }
      },
    ]
  })
}

resource "aws_s3_object" "patient_portal" {
  #checkov:skip=CKV_AWS_186:Encrypted by the bucket default (SSE-KMS, AWS managed key aws/s3); a customer-managed key adds a monthly charge for a placeholder page.
  for_each = local.patient_portal_objects

  # Land the objects after the bucket is locked down and encrypted.
  depends_on = [
    aws_s3_bucket_public_access_block.patient_portal,
    aws_s3_bucket_ownership_controls.patient_portal,
    aws_s3_bucket_server_side_encryption_configuration.patient_portal,
    aws_s3_bucket_versioning.patient_portal,
  ]

  bucket       = aws_s3_bucket.patient_portal.id
  key          = each.key
  content      = each.value.content
  content_type = each.value.content_type

  tags = local.patient_portal_tags
}
