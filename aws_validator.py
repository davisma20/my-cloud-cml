import boto3
import logging
import ipaddress
import argparse
import sys
import base64
import binascii
import subprocess
import shlex
import time 
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AWSNetworkValidator:
    """Validates AWS networking configurations for a specific EC2 instance."""

    def __init__(self, instance_id, region_name, expected_port=443, source_ip=None):
        """Initializes the validator."""
        if not instance_id or not region_name:
            raise ValueError("Instance ID and Region Name cannot be empty.")

        self.instance_id = instance_id
        self.region_name = region_name
        self.expected_port = expected_port
        self.source_ip = source_ip
        self.results = {}

        try:
            self.ec2_client = boto3.client('ec2', region_name=self.region_name)
            self.ssm_client = boto3.client('ssm', region_name=self.region_name)
            logging.info(f"Successfully initialized Boto3 clients for region {self.region_name}.")
            # Quick check to ensure clients are usable (optional, but good practice)
            self.ec2_client.describe_regions(RegionNames=[self.region_name])
            self.ssm_client.describe_parameters(MaxResults=1) # Check SSM client
            logging.info("Boto3 clients confirmed functional.")
            logging.warning("Ensure AWS credentials have necessary EC2 and SSM permissions (e.g., ssm:SendCommand, ssm:GetCommandInvocation).")

        except NoCredentialsError:
            logging.error("AWS credentials not found. Configure credentials (e.g., ~/.aws/credentials, environment variables, or IAM role).")
            raise ConnectionError("AWS credentials not found.")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            logging.error(f"AWS ClientError during initialization: {error_code} - {e}")
            if error_code == 'AuthFailure' or 'credentials' in str(e).lower():
                 raise ConnectionError(f"AWS authentication failed: {e}")
            elif error_code == 'AccessDenied':
                 raise ConnectionError(f"AWS access denied: {e}. Check IAM permissions.")
            else:
                 raise ConnectionError(f"AWS ClientError: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during Boto3 client initialization: {e}")
            raise ConnectionError(f"Unexpected error during Boto3 init: {e}")

    def _get_instance_details(self):
        """Internal helper to get instance details and IAM profile."""
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[self.instance_id])
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                logging.error(f"Instance {self.instance_id} not found in region {self.region_name}.")
                raise ValueError(f"Instance {self.instance_id} not found.")
            instance_data = response['Reservations'][0]['Instances'][0]
            iam_profile_arn = instance_data.get('IamInstanceProfile', {}).get('Arn')
            return instance_data, iam_profile_arn
        except ClientError as e:
            logging.error(f"AWS ClientError fetching instance details: {e}")
            raise RuntimeError(f"AWS error fetching instance details: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while fetching instance details: {e}")
            raise RuntimeError(f"Unexpected error fetching instance details: {e}")

    def get_system_log(self):
        """Fetches the system console output for the instance using AWS CLI."""
        logging.info(f"Attempting to fetch system log for {self.instance_id} using AWS CLI...")
        output = None
        log_file_name = f"{self.instance_id}_full_system_log.txt"

        try:
            # Construct the AWS CLI command
            command = [
                "aws", "ec2", "get-console-output",
                "--instance-id", self.instance_id,
                "--region", self.region_name,
                "--output", "text",
                "--latest"
            ]
            logging.info(f"Executing command: {' '.join(command)}")

            # Run the command using subprocess
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            logging.info(f"Successfully fetched system log via AWS CLI for {self.instance_id}.")

        except subprocess.CalledProcessError as e:
            logging.error(f"AWS CLI command failed: {e}")
            logging.error(f"Stderr: {e.stderr}")
            self.results['system_log_status'] = f"AWS CLI command failed: {e}"
            return None # Indicate failure
        except FileNotFoundError:
            logging.error("AWS CLI command not found. Ensure 'aws' is installed and in the system PATH.")
            self.results['system_log_status'] = "AWS CLI not found."
            return None # Indicate failure
        except Exception as e:
            logging.error(f"An unexpected error occurred while fetching system log via AWS CLI: {e}")
            self.results['system_log_status'] = f"Unexpected CLI error: {e}"
            return None # Indicate failure

        # Only save if output is not None and not empty
        if output:
            try:
                with open(log_file_name, 'w') as f:
                    f.write(output)
                logging.info(f"Full system log saved to '{log_file_name}'")
                self.results['system_log_saved_path'] = log_file_name
                self.results['system_log_status'] = f"Log fetched and saved to {log_file_name}."
            except IOError as e:
                logging.error(f"Failed to save system log to file {log_file_name}: {e}")
                self.results['system_log_status'] = f"Log fetched but failed to save: {e}"
        else:
            # Handle cases where AWS CLI returned empty output (e.g., instance just launched)
            logging.warning(f"System log for {self.instance_id} appears empty.")
            self.results['system_log_status'] = "Log retrieved but was empty."

        return output # Return the fetched output or None

    def get_instance_screenshot(self):
        """Fetches the latest instance screenshot."""
        try:
            logging.info(f"Attempting to fetch instance screenshot for {self.instance_id}...")
            response = self.ec2_client.get_console_screenshot(InstanceId=self.instance_id, WakeUp=True)
            image_data = response.get('ImageData')
            if image_data:
                filename = f"{self.instance_id}_screenshot.jpg"
                try:
                    with open(filename, "wb") as f:
                        f.write(base64.b64decode(image_data))
                    success_message = f"Successfully fetched and saved instance screenshot to '{filename}'."
                    logging.info(success_message)
                    return filename
                except Exception as e:
                    error_message = f"Failed to save screenshot for {self.instance_id} to file: {e}"
                    logging.error(error_message)
                    return None
            else:
                logging.warning(f"Screenshot data was empty for {self.instance_id}.")
                return None
        except Exception as e:
            error_message = f"Failed to get instance screenshot for {self.instance_id}: {e}"
            logging.error(error_message)
            return None

    def _run_ssm_command(self, commands, timeout_seconds=120):
        """Runs shell commands on the instance via SSM Run Command and waits for completion."""
        logging.info(f"Attempting to run SSM command(s) on {self.instance_id}: {commands}")
        command_id = None # Initialize command_id
        try:
            response = self.ssm_client.send_command(
                InstanceIds=[self.instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': commands},
                TimeoutSeconds=timeout_seconds
            )
            command_id = response['Command']['CommandId']
            logging.info(f"SSM command sent. Command ID: {command_id}")

            # Wait for the command to complete
            waiter = self.ssm_client.get_waiter('command_executed')
            try:
                waiter.wait(
                    CommandId=command_id,
                    InstanceId=self.instance_id,
                    WaiterConfig={'Delay': 5, 'MaxAttempts': timeout_seconds // 5}
                )
                logging.info(f"SSM command {command_id} completed.")
            except Exception as wait_error: # Catch specific waiter errors if needed
                logging.warning(f"Waiter failed or command timed out for {command_id}: {wait_error}")
                # Attempt to get invocation details even if waiter failed

            # Get command invocation details regardless of waiter outcome
            invocation = self.ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=self.instance_id
            )

            status = invocation.get('Status', 'Unknown')
            status_details = invocation.get('StatusDetails', 'N/A')
            stdout = invocation.get('StandardOutputContent', '')
            stderr = invocation.get('StandardErrorContent', '')

            logging.info(f"SSM Command Status: {status}, Details: {status_details}")
            if stdout:
                logging.info(f"SSM Command Stdout (truncated):\n{stdout[:500]}{'...' if len(stdout) > 500 else ''}")
            if stderr:
                logging.warning(f"SSM Command Stderr:\n{stderr}")

            return {
                'status': status,
                'status_details': status_details,
                'stdout': stdout,
                'stderr': stderr
            }

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            logging.error(f"AWS ClientError running SSM command: {error_code} - {e}")
            # Handle specific errors like InvalidInstanceId or throttling
            if error_code == 'InvalidInstanceId':
                 return {'status': 'Failed', 'status_details': 'InvalidInstanceId - Instance may be terminated, stopped, or not SSM-managed.', 'stdout': '', 'stderr': str(e)}
            # Add other specific error handling if needed
            return {'status': 'Failed', 'status_details': f'ClientError: {error_code}', 'stdout': '', 'stderr': str(e)}
        except Exception as e:
            logging.error(f"Unexpected error running SSM command {command_id or ''}: {e}")
            return {'status': 'Failed', 'status_details': 'Unexpected Exception', 'stdout': '', 'stderr': str(e)}

    def check_instance_status(self):
        """Checks instance state, status checks, IAM profile, SSM ping, and attempts log retrieval."""
        logging.info(f"Checking status for instance {self.instance_id}...")
        self.results['instance_status'] = {'pass': False, 'message': 'Check not fully completed.'}
        self.results['ssm_ping_status'] = 'Unknown'
        self.results['iam_profile'] = 'Not Retrieved'
        self.results['detailed_status'] = 'Not Retrieved'
        self.results['cloud_init_log'] = {'status': 'Not Attempted', 'output': ''}
        self.results['ssm_agent_log'] = {'status': 'Not Attempted', 'output': ''}

        instance_state = 'unknown'
        ssm_ping_status = 'Unknown'
        can_run_ssm = False

        try:
            # 1. Get basic instance details and IAM profile
            instance_details, iam_profile_arn = self._get_instance_details()
            instance_state = instance_details.get('State', {}).get('Name', 'unknown')
            self.results['iam_profile'] = iam_profile_arn if iam_profile_arn else 'None Attached'
            logging.info(f"Instance State: {instance_state}, IAM Profile: {self.results['iam_profile']}")

            if instance_state != 'running':
                self.results['instance_status']['message'] = f"Instance state is '{instance_state}', not 'running'. Cannot perform further checks."
                logging.warning(self.results['instance_status']['message'])
                return # Stop checks if not running

            # 2. Get Detailed Status Checks (Instance/System)
            try:
                status_response = self.ec2_client.describe_instance_status(InstanceIds=[self.instance_id], IncludeAllInstances=True)
                if status_response.get('InstanceStatuses'):
                    status_info = status_response['InstanceStatuses'][0]
                    instance_status = status_info.get('InstanceStatus', {}).get('Status', 'unknown')
                    system_status = status_info.get('SystemStatus', {}).get('Status', 'unknown')
                    self.results['detailed_status'] = f"Instance={instance_status}, System={system_status}"
                    logging.info(f"Detailed Status: {self.results['detailed_status']}")
                    instance_check_passed = instance_status == 'ok'
                    system_check_passed = system_status == 'ok'
                    if instance_check_passed and system_check_passed:
                        self.results['instance_status']['pass'] = True
                        self.results['instance_status']['message'] = "Instance is running and passed both status checks."
                    else:
                        self.results['instance_status']['pass'] = False
                        self.results['instance_status']['message'] = f"Instance is running but failed status checks (Instance: {instance_status}, System: {system_status})."
                else:
                    self.results['detailed_status'] = 'Status initializing or not available.'
                    self.results['instance_status']['message'] = "Instance is running, but status checks are initializing or unavailable."
                    logging.warning(self.results['instance_status']['message'])
                    # Allow continuing to SSM checks even if status is initializing

            except ClientError as e:
                logging.error(f"Failed to get detailed instance status: {e}")
                self.results['detailed_status'] = f"Error fetching status: {e}"
                self.results['instance_status']['message'] = "Failed to retrieve detailed status checks."

            # 3. Get SSM Agent Ping Status
            try:
                ssm_info_response = self.ssm_client.describe_instance_information(Filters=[{'Key': 'InstanceIds', 'Values': [self.instance_id]}])
                if ssm_info_response.get('InstanceInformationList'):
                    ssm_ping_status = ssm_info_response['InstanceInformationList'][0].get('PingStatus', 'Unknown')
                    self.results['ssm_ping_status'] = ssm_ping_status
                    logging.info(f"SSM Agent Ping Status: {ssm_ping_status}")
                    if ssm_ping_status == 'Online':
                         can_run_ssm = True # Mark that we can try SSM commands
                    else:
                         logging.warning(f"SSM Agent is not Online ({ssm_ping_status}). SSM commands may fail.")
                else:
                    self.results['ssm_ping_status'] = 'Not Reported by SSM'
                    logging.warning(f"Instance {self.instance_id} not found in SSM instance information.")

            except ClientError as e:
                logging.error(f"Failed to get SSM instance information: {e}")
                self.results['ssm_ping_status'] = f"Error fetching SSM status: {e}"

            # --- Attempt Log Retrieval via SSM (only if state=running and ping != ConnectionLost) ---
            if instance_state == 'running' and ssm_ping_status != 'ConnectionLost' and ssm_ping_status != 'Inactive':
                logging.info("Attempting to retrieve logs via SSM...")

                # 4. Attempt Cloud-Init Log Retrieval
                cloud_init_cmd = ['tail -n 50 /var/log/cloud-init-output.log']
                ssm_result_ci = self._run_ssm_command(cloud_init_cmd, timeout_seconds=60)
                if ssm_result_ci['status'] == 'Success':
                     self.results['cloud_init_log']['status'] = 'Retrieved'
                     self.results['cloud_init_log']['output'] = ssm_result_ci.get('stdout', 'No stdout')
                else:
                     self.results['cloud_init_log']['status'] = f"Failed ({ssm_result_ci['status_details']})"
                     self.results['cloud_init_log']['output'] = ssm_result_ci.get('stderr', 'No stderr')
                logging.info(f"Cloud-init log retrieval attempt status: {self.results['cloud_init_log']['status']}")

                # 5. Attempt SSM Agent Log Retrieval
                ssm_agent_cmd = ['tail -n 50 /var/log/amazon/ssm/amazon-ssm-agent.log']
                ssm_result_agent = self._run_ssm_command(ssm_agent_cmd, timeout_seconds=60)
                if ssm_result_agent['status'] == 'Success':
                     self.results['ssm_agent_log']['status'] = 'Retrieved'
                     self.results['ssm_agent_log']['output'] = ssm_result_agent.get('stdout', 'No stdout')
                else:
                     self.results['ssm_agent_log']['status'] = f"Failed ({ssm_result_agent['status_details']})"
                     self.results['ssm_agent_log']['output'] = ssm_result_agent.get('stderr', 'No stderr')
                logging.info(f"SSM Agent log retrieval attempt status: {self.results['ssm_agent_log']['status']}")

            else:
                 logging.warning(f"Skipping SSM log retrieval because instance state is '{instance_state}' and SSM ping status is '{ssm_ping_status}'.")
                 self.results['cloud_init_log']['status'] = 'Skipped'
                 self.results['ssm_agent_log']['status'] = 'Skipped'

            # -- Deprecated Hibinit Check --
            # Remove or comment out hibinit specific logic as it relies on SSM
            self.results['hibinit_agent_status'] = {'message': 'Hibinit check deprecated/removed.', 'pass': True}


        except ValueError as e: # Catch specific errors like instance not found
            self.results['instance_status']['message'] = str(e)
            logging.error(f"Instance validation failed early: {e}")
        except RuntimeError as e: # Catch other specific errors from helpers
            self.results['instance_status']['message'] = str(e)
            logging.error(f"Instance validation failed due to runtime error: {e}")
        except ClientError as e: # Catch Boto3 client errors during checks
            self.results['instance_status']['message'] = f"AWS API Error: {e}"
            logging.error(f"AWS ClientError during instance status check: {e}")
        except Exception as e:
            self.results['instance_status']['message'] = f"An unexpected error occurred: {e}"
            logging.error(f"Unexpected error during instance status check: {e}", exc_info=True)

        logging.info(f"Finished checking instance {self.instance_id}.")


    def run_validation(self):
        """Runs all validation checks and returns the overall status."""
        logging.info(f"Starting AWS network validation for instance: {self.instance_id}")
        # Run checks sequentially, stopping if a critical check fails early
        instance_status_result = self.check_instance_status()

        # --- The following checks depend on the instance being reachable and potentially SSM working ---
        # Example: Only proceed if instance passed basic checks
        instance_ok = self.results.get('instance_status', {}).get('pass', False)
        ssm_online = self.results.get('ssm_ping_status') == 'Online'

        # Get System Log (always attempt if instance exists)
        self.get_system_log()

        # Get Screenshot (always attempt if instance exists)
        self.get_instance_screenshot()

        # Retrieve CML Provision Log (attempt if SSM might work)
        if instance_ok or ssm_online:
            # This function was removed as it relied on _run_ssm_command which is now
            # called directly within check_instance_status for specific logs.
            # If you need a generic CML log check, re-implement using _run_ssm_command
            # self._get_cml_provision_log()
            pass # CML log retrieval logic is now part of check_instance_status if needed
        else:
            logging.warning("Skipping further diagnostics requiring SSM due to initial instance state or SSM status.")
            # Ensure related result fields reflect being skipped
            self.results['cml_provision_log_status'] = 'Skipped due to instance/SSM state'


        # Determine overall status based *primarily* on instance status checks
        # Other checks are considered diagnostic
        overall_pass = self.results.get('instance_status', {}).get('pass', False)
        self.results['overall_status'] = overall_pass # Store boolean overall status

        logging.info(f"Validation run complete for {self.instance_id}. Overall Pass: {overall_pass}")
        return self.results

    def print_results(self):
        """Prints the validation results in a formatted way."""
        print("\n--- AWS Instance Validation Results ---")
        print(f"Instance ID: {self.instance_id}")
        print(f"Region: {self.region_name}")
        # print(f"Target Port: {self.expected_port}") # Port check removed
        # print(f"Source IP: {self.source_ip}") # Source IP check removed
        print("-" * 38)

        # --- Core Status --- 
        instance_status_msg = self.results.get('instance_status', {}).get('message', 'Status Check Not Performed')
        instance_status_ok = self.results.get('instance_status', {}).get('pass', False)
        detailed_status = self.results.get('detailed_status', 'Not Retrieved')
        ssm_ping = self.results.get('ssm_ping_status', 'Unknown')
        iam_profile = self.results.get('iam_profile', 'Not Retrieved')

        print(f"[{'PASS' if instance_status_ok else 'FAIL'}] Instance Status: {instance_status_msg}")
        print(f"    Detailed EC2 Status: {detailed_status}")
        print(f"    SSM Agent Ping Status: {ssm_ping}")
        print(f"    IAM Instance Profile: {iam_profile}")

        # --- Diagnostics --- 
        print("--- Diagnostics ---")

        # Report on Full System Log
        if 'system_log_saved_path' in self.results:
            print(f"System Log: Saved to '{self.results['system_log_saved_path']}'")
        else:
            print(f"System Log: {self.results.get('system_log_status', 'Not retrieved or empty.')}")

        # Report on Instance Screenshot
        if 'screenshot_saved_path' in self.results:
            print(f"Screenshot: Saved to '{self.results['screenshot_saved_path']}'.")
        else:
            print(f"Screenshot: {self.results.get('screenshot_status', 'Failed or not attempted.')}")

        # Report on Cloud-Init Log Retrieval Attempt
        ci_log_status = self.results.get('cloud_init_log', {}).get('status', 'Not Attempted')
        ci_log_output = self.results.get('cloud_init_log', {}).get('output', '')
        print(f"Cloud-Init Log (via SSM): {ci_log_status}")
        if ci_log_status == 'Retrieved' and ci_log_output:
            print(f"  Output Tail:\n    | {ci_log_output.replace('\n', '\n    | ')}")
        elif 'Failed' in ci_log_status and ci_log_output:
             print(f"  Error: {ci_log_output}")

        # Report on SSM Agent Log Retrieval Attempt
        ssm_log_status = self.results.get('ssm_agent_log', {}).get('status', 'Not Attempted')
        ssm_log_output = self.results.get('ssm_agent_log', {}).get('output', '')
        print(f"SSM Agent Log (via SSM): {ssm_log_status}")
        if ssm_log_status == 'Retrieved' and ssm_log_output:
            print(f"  Output Tail:\n    | {ssm_log_output.replace('\n', '\n    | ')}")
        elif 'Failed' in ssm_log_status and ssm_log_output:
             print(f"  Error: {ssm_log_output}")

        # Deprecated Hibinit Check Result
        hibinit_check_result = self.results.get('hibinit_agent_status', {}).get('message', 'Deprecated/Removed')
        print(f"Hibinit-Agent Check Result: {hibinit_check_result}")

        # Deprecated CML Provision Log Check
        cml_log_status = self.results.get('cml_provision_log_status', 'Check Removed/Skipped')
        print(f"CML Provision Log Retrieval: {cml_log_status}")

        print("--------------------------------------")
        overall_status_bool = self.results.get('overall_status', False)
        overall_status_str = 'PASSED' if overall_status_bool else 'FAILED'
        print(f"Overall Validation Status: {overall_status_str}")
        print("--------------------------------------")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate AWS networking for an EC2 instance.")
    parser.add_argument("--instance-id", required=True, help="ID of the EC2 instance to validate.")
    parser.add_argument("--region", required=True, help="AWS region of the instance.")
    parser.add_argument("--port", type=int, default=443, help="Network port to check accessibility for (default: 443).")
    parser.add_argument("--source-ip", help="Source IP address expected to access the instance (optional).")
    
    args = parser.parse_args()

    try:
        validator = AWSNetworkValidator(
            instance_id=args.instance_id,
            region_name=args.region,
            expected_port=args.port,
            source_ip=args.source_ip
        )
        validation_results = validator.run_validation()
        validator.print_results()

        # Exit with non-zero code if validation failed
        if not validation_results.get('overall_status', False):
            sys.exit(1)

    except (ValueError, ConnectionError) as e:
        logging.error(f"Initialization or Validation failed: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)