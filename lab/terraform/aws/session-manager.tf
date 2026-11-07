# =============================================================================
# aws :: session-manager.tf
# -----------------------------------------------------------------------------
# WHAT: the server half of "AWS admin is just-in-time through Entra"
# (ADR 0025, its Session Manager section). One small Linux server that has NO
# inbound port, NO SSH key and NO public IP. The only way in is an AWS
# Systems Manager Session Manager shell, and the only PEOPLE who can open
# one are members of the Entra PIM-for-Groups group PIM-AWS-Lab-Admins,
# while their activation lasts, through the least-privileged permission set
# LabServerSession. The lab operator (standing AdministratorAccess) is kept
# out by guardrails v4 in entra-operator.tf (NoServerShell) - live only once
# that policy is applied; in the 2026-11-07 run it was not, and the operator
# could open a shell.
#
#   adm-labops --(PIM for Groups: activate, MFA + reason)--> member of
#   PIM-AWS-Lab-Admins --SCIM--> Identity Store group of the same name
#   --(this file)--> LabServerSession in the lab account
#   --ssm:StartSession, shell document only, tagged servers only-->
#   lab-ssm-node-01 (private subnet, no internet route)
#   --every keystroke and its output--> CloudWatch Logs /contoso-lab/session-manager
#
# WHY NO INBOUND PORT: the SSM Agent on the server dials OUT (HTTPS 443) to
# the Systems Manager endpoints and keeps that channel open; a user's session
# rides on it. So the security group needs no ingress rule at all, there is
# no SSH key to steal or rotate, and a network scan finds nothing to attack.
# Source: AWS Systems Manager User Guide, "AWS Systems Manager Session
# Manager" (no inbound ports, no bastion hosts, no SSH keys; read 2026-11-06).
#
# WHY NO PUBLIC IP EITHER: the subnet has no internet gateway and no NAT.
# The agent reaches Systems Manager through four interface VPC endpoints
# (ssm, ssmmessages, ec2messages, logs) with private DNS. Source: User Guide,
# "Improve the security of EC2 instances by using VPC endpoints for Systems
# Manager" (the three endpoints the agent needs, plus logs for CloudWatch
# session logging; read 2026-11-06).
#
# WHY THE SAME PIM GROUP AS LabAdministrator (read this): the lab already has
# exactly one PIM-for-Groups group that SCIM carries into AWS. Creating a new
# Entra group needs an envs/dev change (modules/pim + modules/apps) through
# the gated pipeline. So, for now, LabServerSession goes to the SAME group as
# LabAdministrator. Members pick LabServerSession at the access portal for
# server work. Plain consequence: an activated member could ALSO pick
# LabAdministrator. The least-privilege split by PERSON (a dedicated
# PIM-AWS-Server-Operators group that holds only LabServerSession) is a later
# step and is NOT built here. What IS proven here: the server path needs a
# PIM activation and nothing else opens it.
#
# WHAT LabServerSession ALLOWS (inline policy below), from the User Guide
# "Additional sample IAM policies for Session Manager" (read 2026-11-06):
#   * ssm:StartSession on EC2 instances ONLY when the instance carries the
#     tag var.session_target_tag_key = var.session_target_tag_value. The
#     condition key is ssm:resourceTag/<key> (Example 3), not
#     aws:ResourceTag. Seen live 2026-11-07: tagged server allowed, the
#     same server with the tag removed refused (E126).
#   * ssm:StartSession on ONE session document: SSM-SessionManagerRunShell
#     (a plain shell). Port forwarding and SSH tunnelling need other
#     documents (AWS-StartPortForwardingSession, AWS-StartSSHSession), which
#     are not allowed, so every session is a shell that Session Manager can
#     log. (Session Manager does not log inside port-forwarding or SSH
#     sessions: User Guide, "Logging session data".)
#   * ssmmessages:OpenDataChannel only on the caller's own sessions
#     (session/${aws:userid}-*), the form AWS's samples now carry. Note:
#     session ids start with the role SESSION NAME (adm-labops@...-<id>),
#     not with aws:userid (AROA...:adm-labops@...), and sessions opened
#     anyway on 2026-11-07, so this statement was not seen to restrict
#     anything. It is kept as AWS documents it; the tag + document +
#     identity checks above are the real limits.
#   * ssm:TerminateSession / ResumeSession only on sessions that AWS tagged
#     with the caller's own id (aws:ssmmessages:session-id = ${aws:userid}*,
#     "Method 2": the one AWS documents for federated / assumed-role users).
#   * Read-only describes to find the server and the sessions.
#   Nothing else: no ec2 writes, no SendCommand, no other accounts.
#
# SESSION LENGTH: PT1H. A session that starts inside an activation cannot
# outlast it by more than one hour (the ADR 0025 residual, also here).
# The preferences document ALSO caps every shell at 60 minutes and closes an
# idle one after 20.
#
# THE LOG: the account-wide preferences document SSM-SessionManagerRunShell
# (Session Manager reads its settings from a Session document of exactly
# that name; User Guide, "Create a Session Manager preferences document
# (command line)") streams every session to the log group below.
# cloudWatchEncryptionEnabled = false on purpose: true REFUSES a session
# unless the log group has a customer KMS key ($1/month). CloudWatch Logs
# still encrypts the data at rest with its own keys. The server's role may
# only write to this one log group.
#
# COST (us-east-1, read 2026-11-06): t4g.micro is the smallest
# free-tier-eligible type (`aws ec2 describe-instance-types --filters
# Name=free-tier-eligible,Values=true`; t3.micro is the same size and costs
# more). Interface endpoints are about $0.01 per hour EACH (4 = ~$1/day).
# CloudWatch Logs: 5 GB ingest free. Session Manager on EC2 has no charge.
# So: enable_session_manager = true only while capturing, then false again
# (destroys the server and the endpoints). session_node_running = false
# stops the server and keeps the rest.
#
# WHO APPLIES: IAM and Identity Center writes are denied to the operator
# (entra-operator.tf guardrails v2), so the apply runs with a LabAdministrator
# session (aws_profile = idlab-labadmin), like lab-admin.tf. Targeted apply:
# README "Session Manager (item 7)".
#
# STAGED: enable_session_manager defaults to false.
# =============================================================================

locals {
  ssm_enabled = var.enable_session_manager
  ssm_region  = var.aws_region
  ssm_account = data.aws_caller_identity.current.account_id
  ssm_part    = data.aws_partition.current.partition

  # Session Manager reads account-wide preferences from a Session document
  # with exactly this name (User Guide, "Create a Session Manager preferences
  # document (command line)"). Read live 2026-11-06: it did not exist in
  # 182002546409 (DescribeDocument InvalidDocument), so this root creates it.
  ssm_shell_document = "SSM-SessionManagerRunShell"

  # The agent's four endpoints (User Guide, VPC endpoints for Systems
  # Manager): ssm, ssmmessages (the session channel), ec2messages (older
  # agent channel; AWS still lists it) and logs (CloudWatch session logs).
  ssm_endpoint_services = toset(["ssm", "ssmmessages", "ec2messages", "logs"])
}

# AL2023 arm64 (t4g is Graviton). AWS's public parameter: the agent is
# preinstalled on Amazon Linux 2023 (User Guide, "Find AMIs with the SSM
# Agent preinstalled").
data "aws_ssm_parameter" "al2023_arm64" {
  count = local.ssm_enabled ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# One AZ that really offers the instance type (t4g is not in every AZ).
data "aws_ec2_instance_type_offerings" "ssm_node" {
  count         = local.ssm_enabled ? 1 : 0
  location_type = "availability-zone"
  filter {
    name   = "instance-type"
    values = [var.session_node_instance_type]
  }
  lifecycle {
    postcondition {
      condition     = length(self.locations) > 0
      error_message = "No availability zone in aws_region offers session_node_instance_type."
    }
  }
}

# The PIM group as SCIM created it. Same lineage pin as lab-admin.tf: the
# AWS principal must be the SCIM copy of the Entra PIM group.
data "aws_identitystore_group" "server_session" {
  count             = local.ssm_enabled ? 1 : 0
  identity_store_id = local.identity_store_id

  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = var.session_group_display_name
    }
  }

  lifecycle {
    postcondition {
      condition     = self.group_id != data.aws_identitystore_group.aws_users.group_id
      error_message = "session_group_display_name resolves to the staff group (group_display_name). LabServerSession must only go to a PIM-governed group."
    }
    postcondition {
      condition = (
        var.session_group_entra_object_id == ""
        || contains([for e in self.external_ids : lower(e.id)], lower(var.session_group_entra_object_id))
      )
      error_message = "The Identity Store group named by session_group_display_name does not carry session_group_entra_object_id as an external id: SCIM did not create it from the Entra PIM group. Do not grant it server access."
    }
  }
}

# -----------------------------------------------------------------------------
# Network: a private /24 with no internet route, and the four endpoints.
# -----------------------------------------------------------------------------
resource "aws_vpc" "ssm" {
  count = local.ssm_enabled ? 1 : 0
  #checkov:skip=CKV2_AWS_11:VPC flow logs are not enabled for this single-instance capture VPC; the session log and CloudTrail are the audit trail, and the VPC exists only while capturing.
  #checkov:skip=CKV2_AWS_12:The VPC's default security group is not used by anything here; the node and the endpoints have their own groups.
  cidr_block = var.session_vpc_cidr
  # Both are needed for interface endpoints with private DNS.
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "contoso-lab-ssm" }
}

resource "aws_subnet" "ssm" {
  count             = local.ssm_enabled ? 1 : 0
  vpc_id            = aws_vpc.ssm[0].id
  cidr_block        = var.session_vpc_cidr
  availability_zone = sort(data.aws_ec2_instance_type_offerings.ssm_node[0].locations)[0]
  # Never a public IP, even if launched by hand into this subnet.
  map_public_ip_on_launch = false
  tags                    = { Name = "contoso-lab-ssm-private" }
}

# No internet gateway and no NAT exist in this VPC: the main route table has
# only the local route. That is the "no way out except the endpoints" part.

resource "aws_security_group" "ssm_node" {
  count       = local.ssm_enabled ? 1 : 0
  name        = "contoso-lab-ssm-node"
  description = "Session Manager node: NO ingress. Egress HTTPS to the VPC only (the endpoints)."
  vpc_id      = aws_vpc.ssm[0].id
  # NO ingress block at all, on purpose (the whole point of this file).
  egress {
    description = "HTTPS to the Systems Manager / Logs interface endpoints in this VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.session_vpc_cidr]
  }
  tags = { Name = "contoso-lab-ssm-node" }
}

resource "aws_security_group" "ssm_endpoints" {
  count       = local.ssm_enabled ? 1 : 0
  name        = "contoso-lab-ssm-endpoints"
  description = "Interface endpoints: HTTPS in from the Session Manager node only."
  vpc_id      = aws_vpc.ssm[0].id
  ingress {
    description     = "HTTPS from the node security group"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ssm_node[0].id]
  }
  tags = { Name = "contoso-lab-ssm-endpoints" }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each            = local.ssm_enabled ? local.ssm_endpoint_services : toset([])
  vpc_id              = aws_vpc.ssm[0].id
  service_name        = "com.amazonaws.${local.ssm_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.ssm[0].id]
  security_group_ids  = [aws_security_group.ssm_endpoints[0].id]
  private_dns_enabled = true
  tags                = { Name = "contoso-lab-ssm-${each.key}" }
}

# -----------------------------------------------------------------------------
# The session log.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "ssm_sessions" {
  count = local.ssm_enabled ? 1 : 0
  #checkov:skip=CKV_AWS_158:No customer KMS key on purpose: cloudWatchEncryptionEnabled=true would refuse sessions without one ($1/month); CloudWatch Logs encrypts at rest with service keys.
  #checkov:skip=CKV_AWS_338:Retention is var.session_log_retention_days (default 30) for a lab capture, not one year.
  name              = "/contoso-lab/session-manager"
  retention_in_days = var.session_log_retention_days
}

resource "aws_ssm_document" "session_preferences" {
  count           = local.ssm_enabled ? 1 : 0
  name            = local.ssm_shell_document
  document_type   = "Session"
  document_format = "JSON"
  # Schema: User Guide, "Session document schema" (schemaVersion 1.0,
  # sessionType Standard_Stream, inputs). Times are minutes, as strings.
  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Contoso lab Session Manager preferences: stream every shell to CloudWatch Logs; 20 min idle, 60 min max. Managed by Terraform (lab/terraform/aws/session-manager.tf)."
    sessionType   = "Standard_Stream"
    inputs = {
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.ssm_sessions[0].name
      cloudWatchEncryptionEnabled = false
      cloudWatchStreamingEnabled  = true
      s3BucketName                = ""
      s3KeyPrefix                 = ""
      s3EncryptionEnabled         = false
      kmsKeyId                    = ""
      runAsEnabled                = false
      runAsDefaultUser            = ""
      idleSessionTimeout          = "20"
      maxSessionDuration          = "60"
      shellProfile                = { windows = "", linux = "" }
    }
  })
}

# -----------------------------------------------------------------------------
# The server's own identity: the agent's core rights, plus write to THIS log
# group only.
# -----------------------------------------------------------------------------
# Policies are jsonencode() locals, not aws_iam_policy_document data
# sources: they render offline, so tests/session_manager.tftest.hcl can read
# the exact statements this root sends.
locals {
  ssm_node_assume_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "ssm_node" {
  count              = local.ssm_enabled ? 1 : 0
  name               = "contoso-lab-ssm-node"
  description        = "Session Manager node: SSM agent core + write to /contoso-lab/session-manager. lab/terraform/aws/session-manager.tf"
  assume_role_policy = local.ssm_node_assume_policy
}

# AWS managed policy for the agent (User Guide, "Configure instance
# permissions required for Systems Manager").
resource "aws_iam_role_policy_attachment" "ssm_node_core" {
  count      = local.ssm_enabled ? 1 : 0
  role       = aws_iam_role.ssm_node[0].name
  policy_arn = "arn:${local.ssm_part}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Core does not include CloudWatch Logs writes; the agent needs these for
# session logging (User Guide, "Create a custom IAM role for Session
# Manager": logs:CreateLogStream, PutLogEvents, DescribeLogGroups,
# DescribeLogStreams). DescribeLogGroups has no resource-level scope.
resource "aws_iam_role_policy" "ssm_node_logs" {
  count = local.ssm_enabled ? 1 : 0
  name  = "session-log-write"
  role  = aws_iam_role.ssm_node[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteSessionLog"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "${aws_cloudwatch_log_group.ssm_sessions[0].arn}:*"
      },
      {
        Sid      = "FindLogGroup"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "ssm_node" {
  count = local.ssm_enabled ? 1 : 0
  name  = "contoso-lab-ssm-node"
  role  = aws_iam_role.ssm_node[0].name
}

# -----------------------------------------------------------------------------
# The server.
# -----------------------------------------------------------------------------
resource "aws_instance" "ssm_node" {
  count = local.ssm_enabled ? 1 : 0
  #checkov:skip=CKV_AWS_126:Detailed monitoring is billed and not needed for a capture server.
  #checkov:skip=CKV_AWS_135:t4g instances are EBS-optimized by default.
  #checkov:skip=CKV2_AWS_41:False positive guard: the instance profile is attached below.
  ami                         = data.aws_ssm_parameter.al2023_arm64[0].insecure_value
  instance_type               = var.session_node_instance_type
  subnet_id                   = aws_subnet.ssm[0].id
  vpc_security_group_ids      = [aws_security_group.ssm_node[0].id]
  iam_instance_profile        = aws_iam_instance_profile.ssm_node[0].name
  associate_public_ip_address = false
  # No key_name: there is no SSH key for this server, anywhere.

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  tags = {
    Name                         = "lab-ssm-node-01"
    (var.session_target_tag_key) = var.session_target_tag_value
  }

  # The preferences document must exist before anyone can open a session;
  # the endpoints before the agent first registers.
  depends_on = [aws_ssm_document.session_preferences, aws_vpc_endpoint.ssm]
}

# Stop without destroying (session_node_running = false).
resource "aws_ec2_instance_state" "ssm_node" {
  count       = local.ssm_enabled ? 1 : 0
  instance_id = aws_instance.ssm_node[0].id
  state       = var.session_node_running ? "running" : "stopped"
}

# -----------------------------------------------------------------------------
# LabServerSession: the least-privileged way in.
# -----------------------------------------------------------------------------
locals {
  server_session_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartShellOnTaggedServersOnly"
        Effect   = "Allow"
        Action   = "ssm:StartSession"
        Resource = "arn:${local.ssm_part}:ec2:${local.ssm_region}:${local.ssm_account}:instance/*"
        Condition = {
          StringEquals = { "ssm:resourceTag/${var.session_target_tag_key}" = var.session_target_tag_value }
        }
      },
      {
        Sid      = "ShellDocumentOnly"
        Effect   = "Allow"
        Action   = "ssm:StartSession"
        Resource = "arn:${local.ssm_part}:ssm:${local.ssm_region}:${local.ssm_account}:document/${local.ssm_shell_document}"
      },
      {
        Sid      = "OwnDataChannelOnly"
        Effect   = "Allow"
        Action   = "ssmmessages:OpenDataChannel"
        Resource = "arn:${local.ssm_part}:ssm:*:*:session/$${aws:userid}-*"
      },
      {
        Sid      = "EndOrResumeOwnSessionsOnly"
        Effect   = "Allow"
        Action   = ["ssm:TerminateSession", "ssm:ResumeSession"]
        Resource = "*"
        Condition = {
          StringLike = { "ssm:resourceTag/aws:ssmmessages:session-id" = "$${aws:userid}*" }
        }
      },
      {
        Sid    = "FindServersAndSessions"
        Effect = "Allow"
        Action = [
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus",
          "ssm:DescribeInstanceInformation",
          "ssm:DescribeInstanceProperties",
          "ec2:DescribeInstances",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_ssoadmin_permission_set" "server_session" {
  count            = local.ssm_enabled ? 1 : 0
  name             = "LabServerSession"
  description      = "Contoso lab: Session Manager shell on tagged servers only. Held only by PIM-AWS-Lab-Admins (Entra PIM for Groups, SCIM). ADR 0025 (Session Manager section). Terraform lab/terraform/aws."
  instance_arn     = local.instance_arn
  session_duration = "PT1H"
}

resource "aws_ssoadmin_permission_set_inline_policy" "server_session" {
  count              = local.ssm_enabled ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.server_session[0].arn
  inline_policy      = local.server_session_policy
}

resource "aws_ssoadmin_account_assignment" "server_session" {
  count              = local.ssm_enabled ? 1 : 0
  instance_arn       = local.instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.server_session[0].arn
  principal_id       = data.aws_identitystore_group.server_session[0].group_id
  principal_type     = "GROUP"
  # The server's account (the applying profile's), NOT local.target_account_id:
  # with a member-account target the role would land where the server isn't.
  target_id   = local.ssm_account
  target_type = "AWS_ACCOUNT"
  # Policy first, then the assignment provisions the role with it.
  depends_on = [aws_ssoadmin_permission_set_inline_policy.server_session]
}
