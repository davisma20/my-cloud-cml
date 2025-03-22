#!/bin/bash
#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

# This script applies the Terraform configuration with AWS Secrets Manager
# It requires the AWS CLI to be installed and configured with appropriate permissions

set -e

# Check if AWS CLI is installed
command -v aws >/dev/null 2>&1 || { echo "Error: AWS CLI is required but not installed. Aborting." >&2; exit 1; }

# Verify AWS credentials are configured
if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "Error: AWS credentials not configured or invalid. Please configure AWS credentials."
  echo "You can use one of the following methods:"
  echo "1. Set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION"
  echo "2. Configure AWS CLI: aws configure"
  echo "3. Use an IAM role if running on EC2 instance"
  exit 1
fi

# Verify config.yml has AWS Secrets Manager configured
if ! grep -q "manager: aws" config.yml; then
  echo "Warning: AWS Secrets Manager is not configured in config.yml."
  echo "Your config.yml should include:"
  echo ""
  echo "secret:"
  echo "  manager: aws"
  echo ""
  echo "  aws:"
  echo "    project_name: \"cml-devnet\""
  echo "    environment: \"production\""
  echo ""
  read -p "Do you want to continue anyway? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Initialize Terraform if needed
if [ ! -d ".terraform" ]; then
  echo "Initializing Terraform..."
  terraform init
fi

# Apply Terraform configuration
echo "Applying Terraform configuration with AWS Secrets Manager..."
terraform apply
