#!/bin/bash
#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2025, Cisco Systems, Inc.
# All rights reserved.
#

# This script migrates existing secrets from Terraform state to AWS Secrets Manager
# It requires jq and the AWS CLI to be installed

set -e

# Check required tools
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed. Aborting." >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "Error: AWS CLI is required but not installed. Aborting." >&2; exit 1; }

# Read project configuration
if [ ! -f config.yml ]; then
  echo "Error: config.yml not found. Run this script from the project root directory."
  exit 1
fi

# Extract project name from config.yml
PROJECT_NAME=$(grep -A 5 "project_name" config.yml | grep -v "#" | head -1 | awk -F'"' '{print $2}')
if [ -z "$PROJECT_NAME" ]; then
  PROJECT_NAME="cml-devnet"
  echo "Using default project name: $PROJECT_NAME"
else
  echo "Using project name from config.yml: $PROJECT_NAME"
fi

# Function to create or update a secret in AWS Secrets Manager
create_or_update_secret() {
  local secret_name="$1"
  local secret_value="$2"
  local description="$3"
  
  echo "Creating/updating secret: $secret_name"
  
  # Check if secret exists
  if aws secretsmanager describe-secret --secret-id "$secret_name" 2>/dev/null; then
    # Secret exists, update it
    aws secretsmanager put-secret-value \
      --secret-id "$secret_name" \
      --secret-string "$secret_value"
    echo "Secret updated: $secret_name"
  else
    # Secret doesn't exist, create it
    aws secretsmanager create-secret \
      --name "$secret_name" \
      --description "$description" \
      --secret-string "$secret_value" 
    echo "Secret created: $secret_name"
  fi
}

# Extract secrets from Terraform state
echo "Extracting secrets from Terraform state..."
SECRETS=$(terraform output -json cml2secrets 2>/dev/null)

if [ -z "$SECRETS" ] || [ "$SECRETS" = "null" ]; then
  echo "No secrets found in Terraform state. Ensure you have run terraform apply with the dummy secrets manager first."
  exit 1
fi

# Process app secret
APP_SECRET=$(echo "$SECRETS" | jq -r '.app.secret')
if [ -n "$APP_SECRET" ] && [ "$APP_SECRET" != "null" ]; then
  create_or_update_secret "cml/$PROJECT_NAME/app" "$APP_SECRET" "CML application admin password"
fi

# Process sys secret
SYS_SECRET=$(echo "$SECRETS" | jq -r '.sys.secret')
if [ -n "$SYS_SECRET" ] && [ "$SYS_SECRET" != "null" ]; then
  create_or_update_secret "cml/$PROJECT_NAME/sys" "$SYS_SECRET" "CML system admin password"
fi

# Process smartlicense_token
LICENSE_TOKEN=$(echo "$SECRETS" | jq -r '.smartlicense_token.secret')
if [ -n "$LICENSE_TOKEN" ] && [ "$LICENSE_TOKEN" != "null" ]; then
  create_or_update_secret "cml/$PROJECT_NAME/smartlicense_token" "$LICENSE_TOKEN" "CML Smart Licensing token"
fi

# Process cluster secret if it exists
CLUSTER_SECRET=$(echo "$SECRETS" | jq -r '.cluster.secret // empty')
if [ -n "$CLUSTER_SECRET" ] && [ "$CLUSTER_SECRET" != "null" ]; then
  create_or_update_secret "cml/$PROJECT_NAME/cluster" "$CLUSTER_SECRET" "CML cluster secret"
fi

echo ""
echo "Migration complete! All secrets have been created/updated in AWS Secrets Manager."
echo ""
echo "You can now update your config.yml to use AWS Secrets Manager:"
echo ""
echo "secret:"
echo "  manager: aws"
echo ""
echo "  aws:"
echo "    project_name: \"$PROJECT_NAME\""
echo "    environment: \"production\""
echo ""
echo "Then run 'terraform apply' to use the AWS Secrets Manager for your CML deployment."
