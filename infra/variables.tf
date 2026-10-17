# Inputs. Values that identify the owner (the budget e-mail) have no default and are
# never written into this repository: pass them with TF_VAR_<name> or a git-ignored
# terraform.tfvars file (see .gitignore).

variable "region" {
  description = "AWS region for every resource (ADR 0001)."
  type        = string
  default     = "eu-north-1"
}

variable "budget_limit_usd" {
  description = "Monthly cost ceiling in USD (ADR 0002, option A)."
  type        = number
  default     = 20
}

variable "budget_email" {
  description = "E-mail address for budget alerts. Not stored in the repository."
  type        = string
  sensitive   = true
}

variable "capture_retention_days" {
  description = "Days before archived captures expire in S3 (ADR 0002, chosen 90)."
  type        = number
  default     = 90
}
