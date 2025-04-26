#!/bin/bash

# tf_apply_with_logs.sh
# Purpose: Run Terraform apply and automatically start log monitoring for CML installation
# This script runs terraform apply, then waits for the instance to be available,
# and finally starts monitoring logs automatically

set -e

# Create log directories
LOG_DIR="cml_deployment_logs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DEPLOY_LOG="${LOG_DIR}/deploy_${TIMESTAMP}.log"
INSTANCE_LOGS="${LOG_DIR}/instance_logs_${TIMESTAMP}"

# Create log directories
mkdir -p "$LOG_DIR"
mkdir -p "$INSTANCE_LOGS"

# Function to check if AWS CLI is installed
check_aws_cli() {
  if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI is not installed. Please install it first."
    exit 1
  fi
}

# Function to stream logs from the instance once it's up
stream_logs() {
  local instance_id=$1
  local log_file=$2
  
  echo "Attempting to stream logs from $log_file on instance $instance_id..."
  aws ssm send-command \
    --instance-ids "$instance_id" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"if [ -f $log_file ]; then cat $log_file; else echo '$log_file not found yet'; fi\"]" \
    --query "Command.CommandId" \
    --output text
}

# Function to get instance logs
get_instance_logs() {
  local instance_id=$1
  echo "Getting logs from instance $instance_id..."
  
  # List of important log files to retrieve
  LOG_FILES=(
    "/var/log/cloud-init.log"
    "/var/log/cloud-init-output.log"
    "/var/log/cml-provision.log"
    "/var/log/cml_reliable_install.log"
    "/var/log/cml_fix_install.log"
    "/var/log/syslog"
  )
  
  for log_file in "${LOG_FILES[@]}"; do
    echo "Retrieving $log_file..."
    log_name=$(basename "$log_file")
    
    # Get command ID
    cmd_id=$(aws ssm send-command \
      --instance-ids "$instance_id" \
      --document-name "AWS-RunShellScript" \
      --parameters "commands=[\"if [ -f $log_file ]; then cat $log_file; else echo '$log_file not found'; fi\"]" \
      --query "Command.CommandId" \
      --output text)
    
    # Wait a few seconds for command to complete
    sleep 3
    
    # Get command output
    aws ssm get-command-invocation \
      --command-id "$cmd_id" \
      --instance-id "$instance_id" \
      --query "StandardOutputContent" \
      --output text > "${INSTANCE_LOGS}/${log_name}"
      
    echo "Saved $log_file to ${INSTANCE_LOGS}/${log_name}"
  done
}

# Function to get and monitor CML Controller instance
monitor_cml_instance() {
  echo "Waiting for CML Controller instance to be available..."
  
  # It might take a while for the instance to be ready for SSM commands
  # We'll poll every 30 seconds for up to 15 minutes (30 attempts)
  for i in {1..30}; do
    echo "Attempt $i: Checking for CML controller instance..."
    
    # Try to find the instance ID by looking for tags with "cml-controller" in the name
    INSTANCE_ID=$(aws ec2 describe-instances \
      --filters "Name=tag:Name,Values=*cml-controller*" "Name=instance-state-name,Values=running" \
      --query "Reservations[].Instances[0].InstanceId" \
      --output text)
    
    if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ]; then
      echo "Found CML controller instance: $INSTANCE_ID"
      
      # Check if the instance is ready for SSM commands
      echo "Checking if instance is ready for SSM commands..."
      if aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$INSTANCE_ID" --query "InstanceInformationList[0].PingStatus" --output text 2>/dev/null | grep -q "Online"; then
        echo "Instance is ready for SSM commands!"
        echo "Instance ID: $INSTANCE_ID" > "${LOG_DIR}/instance_id_${TIMESTAMP}.txt"
        
        # Start capturing logs
        get_instance_logs "$INSTANCE_ID"
        
        echo "Logs retrieved successfully. To get updated logs later, run:"
        echo "./monitor_logs.sh $INSTANCE_ID"
        return 0
      else
        echo "Instance not yet ready for SSM commands, waiting..."
      fi
    else
      echo "CML controller instance not found yet, waiting..."
    fi
    
    # Wait 30 seconds before checking again
    sleep 30
  done
  
  echo "Timed out waiting for CML controller instance to be ready for monitoring."
  echo "You can manually check the instance status and run the monitoring script later:"
  echo "./monitor_logs.sh <INSTANCE_ID>"
  return 1
}

# Main script execution
echo "===== Starting Terraform Apply with Log Monitoring ====="
echo "Deployment log: $DEPLOY_LOG"
echo "Instance logs directory: $INSTANCE_LOGS"

# Check if AWS CLI is installed
check_aws_cli

# Run terraform apply and save output to log
echo "Running terraform apply..."
terraform apply -auto-approve | tee "$DEPLOY_LOG"

# Extract deployment info from terraform output
echo "Terraform apply completed. Waiting for instance to be available for monitoring..."
echo "This might take a few minutes..."

# Monitor the CML instance and get logs
monitor_cml_instance

echo "===== Deployment completed ====="
echo "Deployment log: $DEPLOY_LOG"
echo "Instance logs: $INSTANCE_LOGS"
echo ""
echo "To monitor logs again later, use:"
echo "./monitor_logs.sh \$(cat ${LOG_DIR}/instance_id_${TIMESTAMP}.txt)"
