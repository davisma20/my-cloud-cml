import boto3
import os
import sys
import time
import warnings

# --- Configuration ---
TARGET_INSTANCE_ID = "i-0c76d56bc8c75eaed"  # Failing CML Instance ID
AWS_REGION = "us-east-2"
COMMAND_TIMEOUT_SECONDS = 90 # Increased timeout for potentially longer commands
POLL_INTERVAL_SECONDS = 3    # Adjusted poll interval

# Commands to run on the target CML instance via SSM
COMMANDS_TO_RUN = [
    "echo '--- System Info ---'",
    "uname -a",
    "cat /etc/os-release || echo 'Failed to get OS release'",
    "echo; echo '--- Cloud-Init Logs (Last 500 lines) ---'",
    "sudo tail -n 500 /var/log/cloud-init.log || echo 'Failed to read cloud-init.log'",
    "echo; echo '--- Cloud-Init Output Log (Last 500 lines) ---'",
    "sudo tail -n 500 /var/log/cloud-init-output.log || echo 'Failed to read cloud-init-output.log'",
    "echo; echo '--- System Boot Log (Last 500 lines) ---'",
    "sudo journalctl -b --no-pager --lines=500 || echo 'Failed to get journalctl boot log'",
    "echo; echo '--- CML Service Status (virl2-controller) ---'",
    "sudo systemctl status virl2-controller --no-pager || echo 'Failed to get status for virl2-controller service'",
    "echo; echo '--- Network Configuration ---'",
    "ip a || echo 'Failed to get IP addresses'",
    "ip r || echo 'Failed to get IP routes'",
    "echo; echo '--- Disk Space ---'",
    "df -h || echo 'Failed to get disk usage'",
    "echo; echo '--- Checking ubuntu authorized_keys ---'",
    "sudo ls -al /home/ubuntu/.ssh/ || echo 'Could not list /home/ubuntu/.ssh'",
    "sudo cat /home/ubuntu/.ssh/authorized_keys || echo 'Could not read /home/ubuntu/.ssh/authorized_keys'",
    "echo; echo '--- Checking admin authorized_keys ---'",
    "sudo ls -al /home/admin/.ssh/ || echo 'Could not list /home/admin/.ssh'",
    "sudo cat /home/admin/.ssh/authorized_keys || echo 'Could not read /home/admin/.ssh/authorized_keys'",
    "echo; echo '--- Checking SSM Agent Error Log ---'", # Keep this from original list
    "sudo tail -n 50 /var/log/amazon/ssm/errors.log || echo 'Could not read /var/log/amazon/ssm/errors.log'"
]

# Suppress Boto3 warnings (optional)
# warnings.filterwarnings(action='ignore', module='.*boto3.*')
# warnings.filterwarnings(action='ignore', module='.*urllib3.*')

# --- SSM Execution --- 
def run_ssm_command(ssm_client, instance_id, command):
    """Sends a command via SSM Run Command and waits for its completion."""
    print(f"\n>>> Running Command: {command}")
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': [command]},
            TimeoutSeconds=COMMAND_TIMEOUT_SECONDS
        )
        command_id = response['Command']['CommandId']
        print(f"    Command sent. CommandId: {command_id}")

        # --- Add a small delay before polling --- #
        time.sleep(1)
        # ---------------------------------------- #

        start_time = time.time()
        while True:
            # Check if overall timeout exceeded
            if time.time() - start_time > COMMAND_TIMEOUT_SECONDS + 10: # Add buffer
                print(f"ERROR: Command {command_id} timed out after {COMMAND_TIMEOUT_SECONDS + 10} seconds (polling timeout).")
                return {
                    'status': 'PollingTimeout',
                    'stdout': '',
                    'stderr': 'Polling timed out before command completion.'
                }

            # Get command status
            invocation = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = invocation['Status']
            print(f"    Current status: {status} (Elapsed: {int(time.time() - start_time)}s)")

            if status in ['Success', 'Failed', 'TimedOut', 'Cancelled', 'Undeliverable', 'DeliveryTimedOut', 'ExecutionTimedOut']:
                print(f"--- Command Finished with Status: {status} --- ")
                return {
                    'status': status,
                    'stdout': invocation.get('StandardOutputContent', ''),
                    'stderr': invocation.get('StandardErrorContent', '')
                }

            time.sleep(POLL_INTERVAL_SECONDS)

    except ssm_client.exceptions.InvalidInstanceId:
        print(f"ERROR: Invalid Instance ID: {instance_id}")
        return None
    except Exception as e:
        print(f"ERROR: Failed to send/monitor command '{command}': {e}")
        return None

# --- Main Execution Logic ---
try:
    print(f"Initializing Boto3 SSM client for region {AWS_REGION}...")
    # Ensure AWS credentials are configured (e.g., via environment variables or ~/.aws/credentials)
    session = boto3.Session(region_name=AWS_REGION)
    ssm_client = session.client('ssm')
    print("SSM client initialized.")

    print(f"\n--- Executing Commands on Instance {TARGET_INSTANCE_ID} --- ")
    results = []
    for cmd in COMMANDS_TO_RUN:
        result = run_ssm_command(ssm_client, TARGET_INSTANCE_ID, cmd)
        results.append(result)
        if result is None: # Handle case where sending/monitoring failed
            print("Skipping remaining commands due to previous error.")
            break
        print("--- Output ---")
        print(result['stdout'] if result['stdout'] else "(No stdout)")
        if result['stderr']:
             print("--- Error --- ")
             print(result['stderr'])
        print("--------------")


except Exception as e:
    print(f"\nAn unexpected error occurred during script execution: {e}")
    sys.exit(1)

finally:
    print("\nScript finished.")

# Check if any command failed or errored during monitoring
if any(r is None or (r and r['status'] != 'Success') for r in results):
    print("\nERROR: One or more commands failed or encountered an error during execution.")
    sys.exit(1)
else:
    print("\nAll commands completed successfully.")
    sys.exit(0)
