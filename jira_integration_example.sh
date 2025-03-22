#!/usr/bin/env bash
# Integration example for my-cloud-cml and jira-integration
#
# This script demonstrates how to:
# 1. Create a Jira ticket for a new deployment
# 2. Deploy infrastructure using Terraform
# 3. Update the Jira ticket with deployment information
#
# Prerequisites:
# - AWS CLI configured
# - Terraform installed
# - jira-integration project cloned

set -e

# Configuration
JIRA_PROJECT_KEY="CAD"
DEPLOYMENT_NAME="DevNet-Workstation-$(date +%Y%m%d)"
JIRA_INTEGRATION_PATH="../jira-integration"
AWS_REGION="us-east-2"
AWS_SECRET_NAME="jira/cml-credentials"

echo "📝 Creating Jira ticket for deployment: $DEPLOYMENT_NAME"

# Create a Jira ticket for the deployment using AWS Secrets Manager
TICKET_KEY=$(${JIRA_INTEGRATION_PATH}/jira_cli.py --aws-secret "$AWS_SECRET_NAME" --region "$AWS_REGION" create-issue \
  --summary "Deployment: $DEPLOYMENT_NAME" \
  --description "# DevNet Workstation Deployment

This ticket tracks the deployment of a new DevNet Expert workstation in AWS.

## Deployment Details
* **Name**: $DEPLOYMENT_NAME
* **Timestamp**: $(date '+%Y-%m-%d %H:%M:%S')
* **Requested By**: $(whoami)

## Security Features
This deployment includes the following security features:
* Root volume encryption
* IMDSv2 requirement (prevents SSRF attacks)
* Restricted security groups
* Automatic security updates
* UFW firewall with default deny policy
* Fail2ban for brute force protection
* System hardening" \
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

# Update the ticket with deployment information
echo "📝 Updating Jira ticket with deployment information"
${JIRA_INTEGRATION_PATH}/jira_cli.py --aws-secret "$AWS_SECRET_NAME" --region "$AWS_REGION" aws-ec2 --action update \
  --issue-key "$TICKET_KEY" \
  --instance-id "$INSTANCE_ID" \
  --region "$AWS_REGION"

# Add workstation connection details
PUBLIC_IP=$(terraform output -raw workstation_public_ip)
${JIRA_INTEGRATION_PATH}/jira_cli.py --aws-secret "$AWS_SECRET_NAME" --region "$AWS_REGION" add-comment \
  --issue-key "$TICKET_KEY" \
  --comment "## Workstation Connection Information
* **RDP Connection**: $PUBLIC_IP:3389
* **Username**: admin
* **Password**: 1234QWer!

To connect using Remote Desktop:
1. Open Remote Desktop Connection
2. Enter server: $PUBLIC_IP:3389
3. Use the credentials above
4. Accept any certificate warnings"

echo "✅ Jira ticket updated with deployment details: $TICKET_KEY"

echo "
✨ Deployment process complete! ✨

DevNet Workstation details:
- Instance ID: $INSTANCE_ID
- Public IP: $PUBLIC_IP
- Jira Ticket: $TICKET_KEY

You can view the Jira ticket here: https://thea2sllc.atlassian.net/browse/$TICKET_KEY
"
