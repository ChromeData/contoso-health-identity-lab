# Offline, mocked tests for the Session Manager server path
# (session-manager.tf, ADR 0025 "Session Manager"). No AWS call is made:
#   terraform init -backend=false && terraform test
#
# What these pin: nothing exists unless enable_session_manager; the server
# has no public IP, no SSH key, IMDSv2 only and a security group with NO
# ingress; the agent reaches four interface endpoints with private DNS;
# LabServerSession allows StartSession only on servers with the access tag
# (ssm:resourceTag) and only the shell document, ends/resumes only the
# caller's own sessions, has no SendCommand or wildcard, and goes ONLY to the
# SCIM copy of the PIM group (never the staff group); the preferences
# document streams to the log group; the lineage pin refuses a group SCIM
# did not create.

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
  mock_data "aws_ec2_instance_type_offerings" {
    defaults = { locations = ["us-east-1b", "us-east-1a"], instance_types = ["t4g.micro", "t4g.micro"], location_types = ["availability-zone", "availability-zone"] }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "ami-0123456789abcdef0", value = "ami-0123456789abcdef0" }
  }
  mock_resource "aws_ssoadmin_permission_set" {
    defaults = { arn = "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-3333333333333333" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::contoso-health-patient-portal-123456789012" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/contoso-lab/session-manager" }
  }
}

# The PIM group as SCIM created it.
override_data {
  target = data.aws_identitystore_group.server_session
  values = {
    group_id     = "a0a0a0a0-1111-2222-3333-444455556666"
    external_ids = [{ id = "77777777-7777-7777-7777-777777777777", issuer = "" }]
  }
}

run "off_by_default" {
  command = plan

  assert {
    condition = (
      length(aws_instance.ssm_node) == 0 && length(aws_vpc.ssm) == 0 && length(aws_vpc_endpoint.ssm) == 0 &&
      length(aws_ssoadmin_permission_set.server_session) == 0 && length(aws_ssm_document.session_preferences) == 0
    )
    error_message = "nothing (no server, no endpoints, no permission set) may exist unless enable_session_manager = true"
  }
}

run "server_has_no_way_in_but_session_manager" {
  command = apply

  variables {
    enable_session_manager        = true
    session_group_entra_object_id = "77777777-7777-7777-7777-777777777777"
  }

  assert {
    condition     = aws_instance.ssm_node[0].associate_public_ip_address == false && aws_subnet.ssm[0].map_public_ip_on_launch == false
    error_message = "no public IP (no key_name is set in session-manager.tf; a mock fills computed key_name, so it is not asserted here)"
  }
  assert {
    condition     = aws_instance.ssm_node[0].metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 only"
  }
  assert {
    condition     = length(aws_security_group.ssm_node[0].ingress) == 0
    error_message = "the server's security group must have NO ingress rule"
  }
  assert {
    condition     = alltrue([for e in aws_security_group.ssm_node[0].egress : e.from_port == 443 && e.to_port == 443 && length(e.cidr_blocks) == 1 && contains(e.cidr_blocks, var.session_vpc_cidr)])
    error_message = "egress is HTTPS to the VPC (the endpoints) only"
  }
  assert {
    condition     = toset(keys(aws_vpc_endpoint.ssm)) == toset(["ssm", "ssmmessages", "ec2messages", "logs"]) && alltrue([for e in aws_vpc_endpoint.ssm : e.private_dns_enabled && e.vpc_endpoint_type == "Interface"])
    error_message = "the four interface endpoints with private DNS"
  }
  assert {
    condition     = aws_instance.ssm_node[0].instance_type == "t4g.micro" && aws_instance.ssm_node[0].tags["session-access"] == "lab-server-session"
    error_message = "t4g.micro, tagged for LabServerSession"
  }
  assert {
    condition     = aws_subnet.ssm[0].availability_zone == "us-east-1a"
    error_message = "the subnet goes in an AZ that offers the type (first, sorted)"
  }
  assert {
    condition     = aws_ssm_document.session_preferences[0].name == "SSM-SessionManagerRunShell" && aws_ssm_document.session_preferences[0].document_type == "Session"
    error_message = "the account-wide preferences document has the name Session Manager reads"
  }
  assert {
    condition = (
      jsondecode(aws_ssm_document.session_preferences[0].content).inputs.cloudWatchLogGroupName == "/contoso-lab/session-manager" &&
      jsondecode(aws_ssm_document.session_preferences[0].content).inputs.cloudWatchStreamingEnabled == true &&
      jsondecode(aws_ssm_document.session_preferences[0].content).inputs.cloudWatchEncryptionEnabled == false &&
      jsondecode(aws_ssm_document.session_preferences[0].content).inputs.maxSessionDuration == "60"
    )
    error_message = "every session streams to the log group (no KMS requirement that would refuse sessions), 60 min max"
  }
  assert {
    condition     = aws_ssoadmin_permission_set.server_session[0].name == "LabServerSession" && aws_ssoadmin_permission_set.server_session[0].session_duration == "PT1H"
    error_message = "LabServerSession, 1-hour sessions"
  }
  assert {
    condition = (
      aws_ssoadmin_account_assignment.server_session[0].principal_id == "a0a0a0a0-1111-2222-3333-444455556666" &&
      aws_ssoadmin_account_assignment.server_session[0].principal_type == "GROUP" &&
      aws_ssoadmin_account_assignment.server_session[0].target_id == "123456789012"
    )
    error_message = "LabServerSession goes only to the SCIM copy of the PIM group, in the lab account"
  }
  assert {
    condition     = aws_iam_role_policy_attachment.ssm_node_core[0].policy_arn == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "the agent's AWS managed core policy"
  }

  # The rendered inline policy (aws_iam_policy_document renders locally).
  assert {
    condition = anytrue([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.server_session[0].inline_policy).Statement :
      s.Sid == "StartShellOnTaggedServersOnly" && s.Action == "ssm:StartSession" &&
      s.Condition.StringEquals["ssm:resourceTag/session-access"] == "lab-server-session"
    ])
    error_message = "StartSession on instances only with ssm:resourceTag/<key> = <value> (AWS sample Example 3)"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.server_session[0].inline_policy).Statement :
      s.Sid == "ShellDocumentOnly" && s.Resource == "arn:aws:ssm:us-east-1:123456789012:document/SSM-SessionManagerRunShell"
    ])
    error_message = "the only session document allowed is the shell (no port forwarding)"
  }
  assert {
    condition = anytrue([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.server_session[0].inline_policy).Statement :
      s.Sid == "EndOrResumeOwnSessionsOnly" && s.Condition.StringLike["ssm:resourceTag/aws:ssmmessages:session-id"] == "$${aws:userid}*"
    ])
    error_message = "terminate/resume only sessions tagged with the caller's own id"
  }
  assert {
    condition = alltrue([for s in jsondecode(aws_ssoadmin_permission_set_inline_policy.server_session[0].inline_policy).Statement :
      length(setintersection(toset(flatten([s.Action])), toset(["ssm:SendCommand", "ssm:*", "ec2:*", "*", "iam:PassRole"]))) == 0
    ])
    error_message = "no SendCommand, no wildcards, no PassRole"
  }
}

run "lineage_pin_refuses_a_hand_made_group" {
  command = plan

  variables {
    enable_session_manager        = true
    session_group_entra_object_id = "99999999-9999-9999-9999-999999999999"
  }

  expect_failures = [data.aws_identitystore_group.server_session]
}

run "staff_group_is_refused" {
  command = plan

  variables {
    enable_session_manager = true
  }

  override_data {
    target = data.aws_identitystore_group.server_session
    values = {
      group_id     = "90676d1b-1111-2222-3333-444455556666"
      external_ids = [{ id = "55555555-5555-5555-5555-555555555555", issuer = "" }]
    }
  }

  expect_failures = [data.aws_identitystore_group.server_session]
}

run "empty_tag_value_refused" {
  command = plan

  variables {
    enable_session_manager   = true
    session_target_tag_value = ""
  }

  expect_failures = [var.session_target_tag_value]
}
