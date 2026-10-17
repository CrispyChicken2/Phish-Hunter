# Network (ADR 0001): one VPC, one public subnet, no inbound port, no NAT Gateway.
#
# Why a public subnet: the instance needs an internet route to reach the Mistral API,
# the container registries, apt and the SSM service. Without a NAT Gateway (a fixed
# hourly charge), a public subnet with a public address is the cheapest way to get
# outbound access. Inbound access is blocked at the security group, not by the subnet.

resource "aws_vpc" "main" {
  # checkov:skip=CKV2_AWS_11: flow logs would add CloudWatch ingestion cost outside the
  # agreed $20 budget. Revisit if the owner wants network-level audit records.
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "lookalike-hunter"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "lookalike-hunter"
  }
}

resource "aws_subnet" "public" {
  # checkov:skip=CKV_AWS_130: public addresses are intended. They are the instance's
  # outbound route without a NAT Gateway (ADR 0001). Inbound is closed by the security group.
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "lookalike-hunter-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "lookalike-hunter-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Every VPC gets a default security group that accepts traffic from its own members.
# Nothing here uses it, and an empty definition removes its rules, so it cannot be
# used by accident.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
}

# The instance's only security group. No ingress block: nothing can connect in, not
# even from inside the VPC. SSM Session Manager works without inbound rules, because
# the SSM agent connects out to AWS.
#
# Egress is open on purpose. The capture container visits phishing sites, and some of
# them use unusual ports. Restricting outbound traffic to web ports would change what
# the measurement sees, so the limit is on inbound traffic, which is what matters.
resource "aws_security_group" "instance" {
  # checkov:skip=CKV2_AWS_5: attached to the instance in P1.3, which does not exist yet.
  # checkov:skip=CKV_AWS_382: outbound is open on purpose, see the note above the resource.
  name        = "lookalike-hunter-instance"
  description = "No inbound. Outbound open for updates, SSM, the model API and captures."
  vpc_id      = aws_vpc.main.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lookalike-hunter-instance"
  }
}
