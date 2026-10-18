# Secrets (P1.5). Terraform only grants permission to read two named parameters. The
# values are created by hand in SSM Parameter Store, so they never enter Terraform's
# state, the repository or the logs.

data "aws_caller_identity" "current" {}

locals {
  secret_parameter_arns = [
    "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.mistral_parameter_name}",
    "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.webhook_parameter_name}",
  ]
}

# The instance may read these two parameters and nothing else. No wildcard, no write.
resource "aws_iam_role_policy" "instance_read_secrets" {
  name = "read-two-named-secrets"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadNamedSecrets"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = local.secret_parameter_arns
    }]
  })
}
