# Terraform and provider versions. The lock file (.terraform.lock.hcl) pins the exact
# provider build, so every machine and every plan uses the same code.
#
# No credentials are written here. The AWS provider reads them from the environment
# (AWS_PROFILE selects a profile in ~/.aws), so the same code runs with any identity.

terraform {
  required_version = ">= 1.9, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Every resource carries these tags, so costs can be filtered in the billing console.
  default_tags {
    tags = {
      project    = "lookalike-hunter"
      managed_by = "terraform"
    }
  }
}
