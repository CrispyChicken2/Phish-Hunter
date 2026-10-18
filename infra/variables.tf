# Inputs. Values that identify the owner (such as the budget e-mail, added in P1.10)
# must never be written into this repository: pass them with TF_VAR_<name> or a
# git-ignored terraform.tfvars file (see .gitignore).

variable "region" {
  description = "AWS region for every resource (ADR 0001)."
  type        = string
  default     = "eu-north-1"
}

variable "vpc_cidr" {
  description = "Address range of the dedicated VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Address range of the single public subnet."
  type        = string
  default     = "10.0.0.0/24"
}

variable "availability_zone" {
  description = "Availability zone of the subnet (one zone, so no multi-AZ cost)."
  type        = string
  default     = "eu-north-1a"
}

variable "instance_type" {
  description = "EC2 instance type (ADR 0002, option A): Graviton, 2 GiB RAM."
  type        = string
  default     = "t4g.small"
}

variable "root_volume_gb" {
  description = "Encrypted gp3 volume for the OS, the DuckDB database and captures."
  type        = number
  default     = 20
}

variable "repo_commit" {
  description = "Exact repository commit the instance runs (pinned; updates are deliberate)."
  type        = string
  default     = "6e3925cd88ec7d40827e30c9fd854fc2cd583aa0"
}

variable "uv_version" {
  description = "uv release installed on the instance (same as the capture image)."
  type        = string
  default     = "0.11.21"
}

variable "uv_sha256" {
  description = "SHA-256 of the uv release tarball for arm64, from the official release."
  type        = string
  default     = "88e800834007cc5efd4675f166eb2a51e7e3ad19876d85fa8805a6fb5c922397"
}

variable "certstream_image" {
  description = "Certificate Transparency server image, same tag as docker-compose.yml."
  type        = string
  default     = "0rickyy0/certstream-server-go:v1.10.1"
}

variable "mistral_parameter_name" {
  description = "SSM SecureString holding the Mistral API key. Created by hand, never by Terraform."
  type        = string
  default     = "/lookalike-hunter/mistral-api-key"
}

variable "webhook_parameter_name" {
  description = "SSM SecureString holding the alert webhook URL. Created by hand, never by Terraform."
  type        = string
  default     = "/lookalike-hunter/alert-webhook-url"
}

variable "backup_retention_days" {
  description = "Days before a daily database backup expires in S3 (P1.7). About a month of history."
  type        = number
  default     = 30
}

variable "budget_limit_usd" {
  description = "Monthly cost ceiling in USD (ADR 0002, option A)."
  type        = number
  default     = 20
}

variable "capture_retention_days" {
  description = "Days before archived captures expire in S3 (ADR 0002, chosen 90)."
  type        = number
  default     = 90
}
