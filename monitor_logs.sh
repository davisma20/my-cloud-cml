#!/bin/bash

# monitor_logs.sh - A simpler script to monitor CML installation logs
# Usage: ./monitor_logs.sh INSTANCE_ID

INSTANCE_ID="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="cml_logs"
LOG_FILE="${LOG_DIR}/cml_logs_${TIMESTAMP}.txt"

mkdir -p $LOG_DIR

if [ -z "$INSTANCE_ID" ]; then
  echo "Error: Instance ID required."
  echo "Usage: ./monitor_logs.sh INSTANCE_ID"
  exit 1
fi

echo "=== Capturing CML installation logs for instance $INSTANCE_ID ===" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

function check_logs() {
  local log_path="$1"
  echo "=== Checking $log_path ===" | tee -a "$LOG_FILE"
  
  CMD_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"if [ -f $log_path ]; then cat $log_path; else echo '$log_path not found'; fi\"]" \
    --query "Command.CommandId" \
    --output text)
  
  echo "Command ID: $CMD_ID" | tee -a "$LOG_FILE"
  sleep 3  # Wait for command to run
  
  aws ssm get-command-invocation \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "StandardOutputContent" \
    --output text | tee -a "$LOG_FILE"
  
  echo "" | tee -a "$LOG_FILE"
}

function check_cmd() {
  local cmd="$1"
  echo "=== Running: $cmd ===" | tee -a "$LOG_FILE"
  
  CMD_ID=$(aws ssm send-command \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"$cmd || echo 'Command failed'\"]" \
    --query "Command.CommandId" \
    --output text)
  
  echo "Command ID: $CMD_ID" | tee -a "$LOG_FILE"
  sleep 3  # Wait for command to run
  
  aws ssm get-command-invocation \
    --command-id "$CMD_ID" \
    --instance-id "$INSTANCE_ID" \
    --query "StandardOutputContent" \
    --output text | tee -a "$LOG_FILE"
  
  echo "" | tee -a "$LOG_FILE"
}

# Check installation logs
check_logs "/var/log/cloud-init.log"
check_logs "/var/log/cloud-init-output.log"
check_logs "/var/log/cml_reliable_install.log" 
check_logs "/var/log/cml_fix_install.log"
check_logs "/var/log/cml-provision.log"

# Check CML status
check_cmd "dpkg -l | grep -E 'cml2|iol-tools|patty'"
check_cmd "systemctl status virl2-controller.service"
check_cmd "systemctl status nginx"
check_cmd "ss -tunlp | grep -E '443|80'"
check_cmd "ls -la /etc/.virl2_*"

echo "Log capture completed at $(date)" | tee -a "$LOG_FILE"
echo "Logs saved to: $LOG_FILE" | tee -a "$LOG_FILE"
