terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50.0"
    }
  }

  required_version = "~> 1.3"
}

provider "aws" {
  region = var.aws_default_region
  assume_role {
    role_arn = "arn:aws:iam::ACCOUNT_ID:role/ASSUME_ROLE_NAME"
  }
}