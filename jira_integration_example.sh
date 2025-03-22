#!/usr/bin/env bash
# Integration example for my-cloud-cml and jira-integration
#
# This script demonstrates how to:
# 1. Create a Jira ticket for a new deployment
# 2. Deploy infrastructure using Terraform
# 3. Update the Jira ticket with deployment information
#
# Prerequisites:
# - Jira API credentials configured
# - AWS CLI configured
# - Terraform installed
# - jira-integration project cloned

set -e

# Configuration
JIRA_PROJECT_KEY="DEVNET"
DEPLOYMENT_NAME="DevNet-Workstation-$(date +%Y%m%d)"
JIRA_INTEGRATION_PATH="../jira-integration"
AWS_REGION="us-east-2"

echo "📝 Creating Jira ticket for deployment: $DEPLOYMENT_NAME"

# Create a Jira ticket for the deployment
TICKET_KEY=$(${JIRA_INTEGRATION_PATH}/jira_cli.py create-issue \
  --summary "Deployment: $DEPLOYMENT_NAME" \
  --description "Deploying a new DevNet workstation using Terraform and my-cloud-cml" \
  --project-key "$JIRA_PROJECT_KEY" | grep -o "$JIRA_PROJECT_KEY-[0-9]*")

if [ -z "$TICKET_KEY" ]; then
  echo "❌ Failed to create Jira ticket"
  exit 1
fi

echo "✅ Created Jira ticket: $TICKET_KEY"

# Initialize and apply Terraform
echo "🚀 Deploying infrastructure with Terraform"
terraform init
terraform apply -auto-approve

# Get the EC2 instance ID
INSTANCE_ID=$(terraform output -raw workstation_id)

if [ -z "$INSTANCE_ID" ]; then
  echo "❌ Failed to get workstation instance ID"
  exit 1
fi

echo "✅ Infrastructure deployed - Instance ID: $INSTANCE_ID"

# Update the Jira ticket with Terraform output
echo "📝 Updating Jira ticket with deployment information"
terraform output -json | ${JIRA_INTEGRATION_PATH}/jira_cli.py terraform \
  --name "$DEPLOYMENT_NAME" \
  --issue-key "$TICKET_KEY"

# Update with CML information if available
if terraform output -json cml2info >/dev/null 2>&1; then
  echo "📝 Updating Jira ticket with CML information"
  terraform output -json cml2info | ${JIRA_INTEGRATION_PATH}/jira_cli.py cml-update \
    --issue-key "$TICKET_KEY"
fi

# Update with workstation information
echo "📝 Updating Jira ticket with workstation information"
${JIRA_INTEGRATION_PATH}/jira_cli.py workstation-update \
  --issue-key "$TICKET_KEY" \
  --instance-id "$INSTANCE_ID" \
  --region "$AWS_REGION" \
  --username "admin" \
  --password "1234QWer!"

echo "
✅ Deployment complete and Jira ticket updated: $TICKET_KEY

Next steps:
1. Verify the deployment in AWS console
2. Check the Jira ticket for access information
3. Connect to the workstation using RDP
"
