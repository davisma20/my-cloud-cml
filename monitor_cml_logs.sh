#!/bin/bash

# monitor_cml_logs.sh
# Purpose: Stream and capture CML installation logs from AWS instance
# Usage: ./monitor_cml_logs.sh [INSTANCE_ID]

set -e

# Get instance ID from command line or get the CML instance automatically
if [ -n "$1" ]; then
    INSTANCE_ID="$1"
else
    echo "No instance ID provided, attempting to find CML controller instance automatically..."
    INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=*cml-controller*" --query "Reservations[].Instances[?State.Name=='running'].InstanceId" --output text)
    
    if [ -z "$INSTANCE_ID" ]; then
        echo "No running CML controller instance found. Please provide an instance ID."
        exit 1
    fi
    
    echo "Found CML controller instance: $INSTANCE_ID"
fi

# Create logs directory if it doesn't exist
LOGS_DIR="./cml_install_logs"
mkdir -p "$LOGS_DIR"

# Generate timestamp for log files
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOGS_DIR/cml_install_$TIMESTAMP.log"

echo "Starting log monitoring for instance $INSTANCE_ID"
echo "Logs will be saved to $LOG_FILE"
echo "Press Ctrl+C to stop monitoring"
echo ""

# Function to stream logs from the instance
stream_logs() {
    local log_file=$1
    echo "=== Streaming $log_file logs ===" | tee -a "$LOG_FILE"
    aws ssm send-command \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"tail -f $log_file\"]" \
        --output text

    # Wait a moment for the command to execute
    sleep 2
    
    # Get the command ID from the most recent command
    COMMAND_ID=$(aws ssm list-commands --filters "Key=status,Values=Pending,InProgress" --query "Commands[?InstanceIds[0]=='$INSTANCE_ID'].CommandId" --output text | head -1)
    
    if [ -n "$COMMAND_ID" ]; then
        echo "Streaming command ID: $COMMAND_ID" | tee -a "$LOG_FILE"
        
        # Poll for output until complete or user interrupt
        while true; do
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text | tee -a "$LOG_FILE"
                
            sleep 5
        done
    else
        echo "Failed to get command ID for log streaming" | tee -a "$LOG_FILE"
    fi
}

# Function to capture critical logs from the instance
capture_logs() {
    echo "=== Capturing key log files ===" | tee -a "$LOG_FILE"
    
    LOG_FILES=(
        "/var/log/cloud-init.log"
        "/var/log/cloud-init-output.log"
        "/var/log/cml_reliable_install.log"
        "/var/log/cml_fix_install.log"
        "/var/log/cml-provision.log"
        "/var/log/syslog"
    )
    
    for log_file in "${LOG_FILES[@]}"; do
        echo "=== Contents of $log_file ===" | tee -a "$LOG_FILE"
        aws ssm send-command \
            --instance-ids "$INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters "commands=[\"if [ -f $log_file ]; then cat $log_file; else echo 'Log file not found'; fi\"]" \
            --output text >> "$LOG_FILE" 2>&1
            
        # Wait for the command to complete
        sleep 2
        
        # Get the command ID from the most recent command
        COMMAND_ID=$(aws ssm list-commands --filters "Key=status,Values=Pending,InProgress,Success" --query "Commands[0].CommandId" --output text)
        
        if [ -n "$COMMAND_ID" ]; then
            # Wait for the command to complete
            aws ssm wait command-executed --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID"
            
            # Get the output
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text | tee -a "$LOG_FILE"
        fi
    done
}

# Function to check CML status
check_cml_status() {
    echo "=== Checking CML status ===" | tee -a "$LOG_FILE"
    
    STATUS_COMMANDS=(
        "dpkg -l | grep -E 'cml2|iol-tools|patty'"
        "systemctl status virl2-controller.service"
        "systemctl status nginx"
        "ss -tunlp | grep -E '443|80'"
        "ls -la /etc/.virl2_*"
    )
    
    for cmd in "${STATUS_COMMANDS[@]}"; do
        echo "=== Running: $cmd ===" | tee -a "$LOG_FILE"
        aws ssm send-command \
            --instance-ids "$INSTANCE_ID" \
            --document-name "AWS-RunShellScript" \
            --parameters "commands=[\"$cmd || echo 'Command failed with status \$?'\"]" \
            --output text >> "$LOG_FILE" 2>&1
            
        # Wait for the command to complete
        sleep 2
        
        # Get the command ID from the most recent command
        COMMAND_ID=$(aws ssm list-commands --filters "Key=status,Values=Pending,InProgress,Success" --query "Commands[0].CommandId" --output text)
        
        if [ -n "$COMMAND_ID" ]; then
            # Wait for the command to complete
            aws ssm wait command-executed --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID"
            
            # Get the output
            aws ssm get-command-invocation \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text | tee -a "$LOG_FILE"
        fi
    done
}

# Handle keyboard interrupt
trap 'echo "Script interrupted. Logs saved to $LOG_FILE"; exit 0' INT

# Main logic - determine whether to stream or capture logs
if [ "$2" = "stream" ]; then
    # Stream specific log
    stream_logs "$3"
elif [ "$2" = "capture" ]; then
    # Capture all logs
    capture_logs
elif [ "$2" = "status" ]; then
    # Check CML status
    check_cml_status
else
    # Default behavior: capture logs and check status
    capture_logs
    check_cml_status
fi

echo "Log monitoring completed. Logs saved to $LOG_FILE"
