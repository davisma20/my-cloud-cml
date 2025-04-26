#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

# Configure the AWS Provider for Secrets Manager
# This configuration will be used to manage secrets in AWS Secrets Manager
provider "aws" {
  region = local.aws_region

  # Default tags for all resources
  default_tags {
    tags = {
      Project     = local.aws_project_name
      Environment = local.aws_environment
      ManagedBy   = "terraform"
    }
  }
}

# Locals for AWS configuration
locals {
  aws_region       = try(yamldecode(file("config.yml")).aws.region, "us-east-2")
  aws_project_name = try(yamldecode(file("config.yml")).secret.aws.project_name, "cml-devnet")
  aws_environment  = try(yamldecode(file("config.yml")).secret.aws.environment, "production")
}
