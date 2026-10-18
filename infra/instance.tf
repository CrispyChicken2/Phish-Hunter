# The instance (ADR 0001, ADR 0002 option A). Provisioning (Docker, uv, systemd) is
# P1.4 and is not here yet, so changing it later replaces the instance on purpose.

# Latest Amazon Linux 2023 image for arm64, owned by Amazon. Looked up with a read of
# the image catalogue (ec2:DescribeImages), which the read-only plan role is allowed.
# Reading the public SSM parameter instead needs ssm:GetParameter, which that role lacks.
data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-*-arm64"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# The role the instance assumes. Only the SSM core policy for now: it is the only way
# in, since there is no SSH. The rest of the least-privilege role is P1.8.
resource "aws_iam_role" "instance" {
  name = "lookalike-hunter-instance"

  # Only EC2 may assume this role, and only for an instance in this account. Without the
  # account condition, a confused-deputy mix-up could let another account use the role.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

# Session Manager only: the minimum AWS documents for a session, instead of the managed
# policy, which also lets the instance read every SSM parameter in the account (P1.8).
# The control-channel APIs take no resource, so the resource is "*" by necessity.
resource "aws_iam_role_policy" "instance_session" {
  # checkov:skip=CKV_AWS_355: the session APIs do not support resource-level permissions.
  # checkov:skip=CKV_AWS_290: these are the documented minimum for a session, not open write access.
  name = "session-manager-minimum"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SessionManager"
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
        "ssm:UpdateInstanceInformation",
        "ec2messages:AcknowledgeMessage",
        "ec2messages:DeleteMessage",
        "ec2messages:FailMessage",
        "ec2messages:GetEndpoint",
        "ec2messages:GetMessages",
        "ec2messages:SendReply",
      ]
      Resource = "*"
    }]
  })
}

# Logs for the CloudWatch agent (P1.9). Limited to one prefix; the group itself is
# created in P1.9, so nothing here can create or delete a group.
resource "aws_iam_role_policy" "instance_write_logs" {
  name = "write-own-log-groups-only"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "WriteLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
      ]
      Resource = [
        "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/lookalike-hunter/*",
        "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/lookalike-hunter/*:log-stream:*",
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "instance_ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "lookalike-hunter-instance"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "main" {
  # checkov:skip=CKV_AWS_46: the flagged text is the public commit id and the uv release
  # checksum (long hex strings), not credentials. The script was checked by reading: no
  # key, token or webhook value is in it. Secrets come from SSM in P1.5.
  # checkov:skip=CKV_AWS_126: detailed monitoring is a per-instance charge outside the
  # budget. Disk and memory alarms come from the CloudWatch agent in P1.9 instead.
  ami                    = data.aws_ami.al2023_arm64.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  ebs_optimized          = true

  # First-boot provisioning (P1.4). Pinned values only, no secret.
  user_data = templatefile("${path.module}/provision.sh.tftpl", {
    repo_commit            = var.repo_commit
    uv_version             = var.uv_version
    uv_sha256              = var.uv_sha256
    certstream_image       = var.certstream_image
    region                 = var.region
    mistral_parameter_name = var.mistral_parameter_name
    webhook_parameter_name = var.webhook_parameter_name
  })

  # user_data only runs at first boot. Changing it must replace the instance, or the
  # change would silently never run. Safe while the database is empty. Once P1.7 backups
  # exist, this becomes a deliberate decision.
  user_data_replace_on_change = true

  # No key pair: access is through SSM Session Manager only.
  key_name = null

  # IMDSv2 only, and a hop limit of 1: a container cannot reach the metadata service
  # through the bridge network. Defence in depth on top of the browser-level block.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # "standard" caps the CPU at its baseline. "unlimited" (the T4g default) bills any
  # surplus without a ceiling, which is outside the $20 budget. Slower under long load is
  # the accepted trade-off; the load test in ADR 0002 measures it.
  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "lookalike-hunter"
  }

  # The lookup above takes the newest image. Without this, a new Amazon Linux release
  # would make every later plan replace the instance, and the root disk holds the
  # database. Updating the image becomes a deliberate change, not a side effect.
  lifecycle {
    ignore_changes = [ami]
  }
}
