# The instance (ADR 0001, ADR 0002 option A). Provisioning (Docker, uv, systemd) is
# P1.4 and is not here yet, so changing it later replaces the instance on purpose.

# Latest Amazon Linux 2023 image for arm64, published by AWS as a public SSM parameter.
# Reading it needs a credential at plan time, but no change is made to AWS.
data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

# The role the instance assumes. Only the SSM core policy for now: it is the only way
# in, since there is no SSH. The rest of the least-privilege role is P1.8.
resource "aws_iam_role" "instance" {
  name = "lookalike-hunter-instance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
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
  # checkov:skip=CKV_AWS_126: detailed monitoring is a per-instance charge outside the
  # budget. Disk and memory alarms come from the CloudWatch agent in P1.9 instead.
  ami                    = data.aws_ssm_parameter.al2023_arm64.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name
  ebs_optimized          = true

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

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name = "lookalike-hunter"
  }
}
