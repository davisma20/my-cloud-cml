import boto3
import logging
import ipaddress
import sys
import base64
import binascii
import subprocess
import shlex
import time
import os
from botocore.exceptions import ClientError, NoCredentialsError
import requests

# Import specific helpers from other modules
from validators.iam_validator import get_instance_iam_details
from validators.route_validator import get_instance_security_groups

# Default log file path
DEFAULT_LOG_FILE = '/var/log/internal-validator.log'

# Define log_file path *before* using it as a default argument
log_file = DEFAULT_LOG_FILE

def setup_logging(log_file=log_file, debug_mode=False):
    log_level = logging.DEBUG if debug_mode else logging.INFO
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Get root logger and clear existing handlers
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Set level FIRST
    root_logger.setLevel(log_level)

    # Configure and add ONLY the console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    # Let handler inherit level from root logger
    root_logger.addHandler(console_handler)

    # Now attempt file handler setup (optional, for warning)
    try:
        file_handler = logging.FileHandler(log_file)
        # Set up formatter etc. if you were actually adding it
        # file_handler.setFormatter(formatter)
        # file_handler.setLevel(log_level)
        # root_logger.addHandler(file_handler)
    except IOError as e:
        # Use the configured logger to warn
        logging.warning(f"Could not create/access log file {log_file}: {e}. Logging to console only.")


# Restore the helper function
def _get_local_instance_id():
    """Fetches the instance ID from the EC2 metadata service."""
    metadata_url = "http://169.254.169.254/latest/meta-data/instance-id"
    try:
        response = requests.get(metadata_url, timeout=1) # Short timeout
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        instance_id = response.text
        logging.debug(f"Successfully retrieved local instance ID: {instance_id}")
        return instance_id
    except requests.exceptions.RequestException as e:
        logging.warning(f"Could not connect to metadata service to get local instance ID: {e}. Assuming not running on target EC2 instance.")
        return None
    except Exception as e:
        # Catch other potential errors like unexpected response format
        logging.error(f"Unexpected error retrieving local instance ID: {e}", exc_info=True)
        return None

# Restore the class definition and __init__
class AwsCmlValidator:
    """Validates AWS networking and internal status for a specific EC2 instance."""

    def __init__(self, instance_id, region_name, ec2_client, ssm_client, iam_client):
        """Initializes the validator."""
        if not instance_id or not region_name:
            # Should not happen with required args, but good practice
            raise ValueError("Instance ID and Region Name are required.")
        if not ec2_client or not ssm_client or not iam_client:
            raise ValueError("Boto3 clients (EC2, SSM, IAM) are required.")

        self.instance_id = instance_id
        self.region_name = region_name
        self.ec2_client = ec2_client
        self.ssm_client = ssm_client
        self.iam_client = iam_client # Store the IAM client

        # Initialize results structure, including the system_log key early
        self.results = {
            'aws_status': {
                'system_log': "Log retrieval not attempted yet.",
                'iam_details': None, # Placeholder for IAM info
                'security_group_details': None # Placeholder for SG info
            },
            'internal_checks': {}
        }

        self.local_instance_id = _get_local_instance_id() # Fetch local ID once during init
        self.is_on_target_instance = (self.local_instance_id == self.instance_id)
        logging.debug(f"Local Instance ID: {self.local_instance_id}, Target Instance ID: {self.instance_id}, Running on target: {self.is_on_target_instance}")

        # Boto3 clients are now passed in, no need to initialize here
        logging.info(f"Using provided Boto3 clients for region {self.region_name}.")

    def _run_local_command(self, command):
        """Runs a shell command locally and returns its output, error, and status."""
        if not self.is_on_target_instance:
            logging.warning("Attempted to run local command when not on the target instance. Skipping.")
            return {'stdout': '', 'stderr': 'Skipped: Not on target instance.', 'status': -1}

        try:
            logging.debug(f"Running local command: {command}")
            # Use shlex.split for safer command parsing
            process = subprocess.run(shlex.split(command), capture_output=True, text=True, check=False) # Don't check=True, handle status code manually
            logging.debug(f"Command '{command}' finished with status {process.returncode}")
            return {
                'stdout': process.stdout.strip(),
                'stderr': process.stderr.strip(),
                'status': process.returncode
            }
        except FileNotFoundError:
            logging.error(f"Command not found: {shlex.split(command)[0]}")
            return {'stdout': '', 'stderr': f"Command not found: {shlex.split(command)[0]}", 'status': 127}
        except Exception as e:
            logging.error(f"Error running command '{command}': {e}", exc_info=True)
            return {'stdout': '', 'stderr': str(e), 'status': -1}

    def run_internal_checks(self):
        """Runs various internal diagnostic checks if running on the target instance."""
        if not self.is_on_target_instance:
            logging.info("Not running on the target instance, skipping internal checks.")
            self.results['internal_checks'] = {'skipped': True, 'reason': 'Not running on target instance'}
            return

        logging.info("Running internal checks...")
        self.results['internal_checks'] = {} # Reset internal checks results

        # Define checks to run
        checks = {
            'os_release': {'command': 'cat /etc/os-release', 'description': 'OS Information'},
            'virl2_config': {'command': 'cat /etc/virl2-base-config.yml', 'description': 'VIRL2 Base Config'},
            'hostname': {'command': 'hostname -f', 'description': 'Full Hostname'},
            'ip_addr': {'command': 'ip addr', 'description': 'IP Address Configuration'},
            'ip_route': {'command': 'ip route', 'description': 'IP Routing Table'},
            'df_h': {'command': 'df -h', 'description': 'Filesystem Disk Space Usage'},
            'sysctl_net': {'command': 'sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding', 'description': 'IPv4/IPv6 Forwarding Status'},
            'cockpit_status': {'command': 'systemctl status cockpit.socket', 'description': 'Cockpit Service Status'},
            'virl2_controller_status': {'command': 'systemctl status virl2-controller.service', 'description': 'VIRL2 Controller Status'},
            'ssm_agent_status': {'command': 'systemctl status snap.amazon-ssm-agent.amazon-ssm-agent.service', 'description': 'SSM Agent Status (Snap)'},
            'resolv_conf': {'command': 'cat /etc/resolv.conf', 'description': 'DNS Resolver Configuration'},
            'ping_google_dns': {'command': 'ping -c 3 8.8.8.8', 'description': 'Ping Google DNS (Connectivity)'},
            # Add more checks as needed
        }

        for check_name, check_details in checks.items():
            logging.debug(f"Running internal check: {check_details['description']}")
            result = self._run_local_command(check_details['command'])
            self.results['internal_checks'][check_name] = {
                'status': 'PASS' if result['status'] == 0 else 'FAIL',
                'exit_code': result['status'],
                'stdout': result['stdout'],
                'stderr': result['stderr']
            }
            # Log failures immediately
            if result['status'] != 0:
                logging.warning(f"Internal check '{check_name}' failed (Exit Code: {result['status']}). Stderr: {result['stderr']}")

        logging.info("Finished internal checks.")

    def check_aws_status(self):
        """Checks AWS EC2 and SSM status for the instance."""
        logging.info(f"Checking AWS status for instance {self.instance_id}...")
        self.results['aws_status'] = {} # Reset AWS status results

        # Check if clients are initialized
        if not self.ec2_client or not self.ssm_client:
            msg = "Boto3 clients not initialized (check credentials/region). Cannot perform AWS checks."
            logging.error(msg)
            self.results['aws_status']['error'] = msg
            # Ensure system_log reflects the skip
            self.results['aws_status']['system_log'] = "Skipped due to Boto3 client initialization failure."
            return

        # --- Instance Status --- 
        try:
            response = self.ec2_client.describe_instance_status(
                InstanceIds=[self.instance_id],
                IncludeAllInstances=True # Include instances in other states
            )
            if response.get('InstanceStatuses'):
                status = response['InstanceStatuses'][0]
                self.results['aws_status']['instance_state'] = status.get('InstanceState', {}).get('Name', 'N/A')
                self.results['aws_status']['instance_status'] = status.get('InstanceStatus', {}).get('Status', 'N/A')
                self.results['aws_status']['system_status'] = status.get('SystemStatus', {}).get('Status', 'N/A')
                logging.info(f"Instance State: {self.results['aws_status']['instance_state']}, Status: {self.results['aws_status']['instance_status']}, System Status: {self.results['aws_status']['system_status']}")
            else:
                logging.warning(f"describe_instance_status returned no status for {self.instance_id}. Might be stopped or terminated.")
                self.results['aws_status']['instance_state'] = 'not_found_or_stopped'
                self.results['aws_status']['instance_status'] = 'N/A'
                self.results['aws_status']['system_status'] = 'N/A'
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                 logging.error(f"Instance ID {self.instance_id} not found.")
                 self.results['aws_status']['error'] = f"Instance ID {self.instance_id} not found."
            else:
                 logging.error(f"Error describing instance status: {e}", exc_info=True)
                 self.results['aws_status']['error'] = f"Error describing instance status: {e}"
            # Ensure system_log reflects the skip
            self.results['aws_status']['system_log'] = "Skipped due to error checking instance status."
            return # Stop AWS checks if instance not found or error

        # --- System Log (Console Output) --- 
        try:
            # Only proceed if instance status check didn't error out
            if 'error' not in self.results['aws_status']:
                log_output_response = self.ec2_client.get_console_output(InstanceId=self.instance_id)
                raw_log = log_output_response.get('Output', '')
                if raw_log:
                    logging.debug(f"Raw console output received (length: {len(raw_log)}). Attempting base64 decode.")
                    try:
                        # 1. Encode raw string to ASCII bytes, ignoring non-ASCII chars
                        ascii_bytes = raw_log.encode('ascii', errors='ignore')
                        # 2. Decode the ASCII bytes from Base64
                        decoded_bytes = base64.b64decode(ascii_bytes)
                        # 3. Try decoding the resulting bytes as UTF-8, replacing errors
                        self.results['aws_status']['system_log'] = decoded_bytes.decode('utf-8', errors='replace')
                        logging.debug("System log decoded successfully (potentially lossy due to non-ASCII chars).")
                    except (binascii.Error, ValueError) as b64_error: # Catch specific base64 errors
                        error_msg = f"Could not decode system log. Base64 decode error: {b64_error}. Raw data length: {len(raw_log)}"
                        logging.error(error_msg, exc_info=False) # Don't need full traceback for expected decode error
                        logging.debug(f"Raw log snippet (first 100 chars): {raw_log[:100]}")
                        self.results['aws_status']['system_log'] = error_msg
                    except Exception as decode_err: # Catch other potential decoding errors
                        error_msg = f"Unexpected error processing system log: {decode_err}"
                        logging.error(error_msg, exc_info=True)
                        self.results['aws_status']['system_log'] = error_msg
                else:
                    logging.warning(f"No console output returned for instance {self.instance_id}.")
                    self.results['aws_status']['system_log'] = "No console output available."

            # Get System Log (Console Output) via AWS CLI for comparison
            self.results['aws_status']['system_log_cli'] = "CLI check not run yet."
            try:
                cli_command = [
                    'aws', 'ec2', 'get-console-output',
                    '--instance-id', self.instance_id,
                    '--region', self.region_name,
                    '--output', 'text' # Get raw text output
                ]
                logging.debug(f"Running AWS CLI command: {' '.join(cli_command)}")
                process = subprocess.run(cli_command, capture_output=True, text=True, check=False, timeout=30)
                
                if process.returncode == 0:
                    raw_cli_output = process.stdout
                    self.results['aws_status']['system_log_cli'] = raw_cli_output
                    logging.debug(f"AWS CLI console output retrieved (length: {len(raw_cli_output)}).")
                else:
                    error_msg = f"AWS CLI get-console-output failed (Code {process.returncode}): {process.stderr}"
                    logging.error(error_msg)
                    self.results['aws_status']['system_log_cli'] = error_msg

            except FileNotFoundError:
                 error_msg = "AWS CLI command not found. Make sure 'aws' is in your PATH."
                 logging.error(error_msg)
                 self.results['aws_status']['system_log_cli'] = error_msg
            except subprocess.TimeoutExpired:
                error_msg = "AWS CLI get-console-output command timed out."
                logging.error(error_msg)
                self.results['aws_status']['system_log_cli'] = error_msg
            except Exception as cli_err:
                error_msg = f"Error running AWS CLI get-console-output: {cli_err}"
                logging.error(error_msg, exc_info=True)
                self.results['aws_status']['system_log_cli'] = error_msg

        except ClientError as e:
            logging.error(f"Error getting console output: {e}", exc_info=True)
            self.results['aws_status']['system_log'] = f"Error getting console output: {e}"
        except Exception as e: # Catch potential non-ClientError exceptions during decoding
            logging.error(f"Unexpected error processing system log: {e}", exc_info=True)
            self.results['aws_status']['system_log'] = f"Unexpected error processing system log: {e}"

        # --- Fetch IAM and Security Group Details --- 
        # Call the helper functions using the stored clients
        iam_info = get_instance_iam_details(self.ec2_client, self.iam_client, self.instance_id)
        sg_info = get_instance_security_groups(self.ec2_client, self.instance_id)

        self.results['aws_status']['iam_details'] = iam_info
        self.results['aws_status']['security_group_details'] = sg_info

        logging.info("Finished checking AWS status.")

    def _format_results(self):
        """Formats the collected results into a readable string."""
        output_lines = ["\n=== AWS Validator Results ==="]
        output_lines.append(f"Instance ID: {self.instance_id}")
        output_lines.append(f"Region: {self.region_name}")
        output_lines.append(f"Running on Target Instance: {self.is_on_target_instance}")
        output_lines.append("\n--- AWS Status ---")

        aws_status = self.results.get('aws_status', {})
        if aws_status.get('error'):
            output_lines.append(f"ERROR: {aws_status['error']}")
        else:
            output_lines.append(f"  Instance State: {aws_status.get('instance_state', 'N/A')}")
            output_lines.append(f"  Instance Reachability: {aws_status.get('instance_status', 'N/A')}")
            output_lines.append(f"  System Reachability: {aws_status.get('system_status', 'N/A')}")
            output_lines.append(f"  SSM Agent Status: {aws_status.get('ssm_ping_status', 'N/A')}")

            # Log Status interpretation
            system_log_val = aws_status.get('system_log', None)
            log_status = "Unknown"
            
            # Define known error/skip messages
            error_prefixes = [
                "Could not decode system log.", 
                "Error getting console output", 
                "Unexpected error processing system log"
            ]
            skip_messages = [
                 "Log retrieval not attempted yet.",
                 "Skipped due to Boto3 client initialization failure.",
                 "Skipped due to error checking instance status.",
                 "Skipped due to previous error.",
                 "No console output available.",
                 "Skipped (Instance not found)" # Added this from error handling
            ]
            
            if isinstance(system_log_val, str):
                is_error = any(system_log_val.startswith(prefix) for prefix in error_prefixes)
                is_skipped = system_log_val in skip_messages
                
                if not is_error and not is_skipped and system_log_val:
                    log_status = f"Retrieved (Length: {len(system_log_val)})"
                    is_printable_log = True # Mark as printable only if successfully retrieved
                elif system_log_val is None:
                     log_status = "Not Available (None)"
                else: # Covers error messages, skip messages, and empty string
                     log_status = f"Not Retrieved ({system_log_val})"
            elif system_log_val is None:
                log_status = "Not Available (None)"

            output_lines.append(f"  System Log (Boto3): {log_status}")

            # Display Raw CLI output status
            cli_log_val = aws_status.get('system_log_cli', 'Not Checked')
            cli_log_status = "Unknown"
            cli_error_prefixes = [
                "AWS CLI get-console-output failed",
                "AWS CLI command not found.",
                "AWS CLI get-console-output command timed out.",
                "Error running AWS CLI get-console-output"
            ]
            cli_skip_messages = [
                "CLI check not run yet.",
                "Skipped (Instance not found)"
            ]

            if isinstance(cli_log_val, str):
                 is_cli_error = any(cli_log_val.startswith(prefix) for prefix in cli_error_prefixes)
                 is_cli_skipped = cli_log_val in cli_skip_messages
                 if not is_cli_error and not is_cli_skipped and cli_log_val:
                     cli_log_status = f"Retrieved (Raw Length: {len(cli_log_val)})"
                 else:
                     cli_log_status = f"Not Retrieved ({cli_log_val})"
            output_lines.append(f"  System Log (AWS CLI): {cli_log_status}")

        output_lines.append("\n--- IAM Details ---")
        iam_details = aws_status.get('iam_details')
        if iam_details:
            if iam_details.get("error"):
                output_lines.append(f"  Error: {iam_details['error']}")
            else:
                output_lines.append(f"  Instance Profile ARN: {iam_details.get('profile_arn', 'N/A')}")
                output_lines.append(f"  Role Name:            {iam_details.get('role_name', 'N/A')}")
                output_lines.append("  Attached Policies:")
                attached = iam_details.get('attached_policies', [])
                if attached:
                    for policy_arn in attached:
                        output_lines.append(f"    - {policy_arn}")
                else:
                    output_lines.append("    (None)")
                output_lines.append("  Inline Policies:")
                inline = iam_details.get('inline_policies', [])
                if inline:
                    for policy_name in inline:
                         output_lines.append(f"    - {policy_name}")
                else:
                    output_lines.append("    (None)")
        elif aws_status.get('error'):
             output_lines.append("  Skipped due to earlier AWS API error.")
        else:
            output_lines.append("  Not retrieved.") # Should not happen if check ran

        output_lines.append("\n--- Security Group Details ---")
        sg_details_result = aws_status.get('security_group_details')
        if sg_details_result:
            if sg_details_result.get("error"):
                output_lines.append(f"  Error: {sg_details_result['error']}")
            else:
                groups = sg_details_result.get('groups', [])
                if groups:
                    for sg in groups:
                        output_lines.append(f"  Group ID:   {sg.get('GroupId', 'N/A')}")
                        output_lines.append(f"  Group Name: {sg.get('GroupName', 'N/A')}")
                        output_lines.append("    Inbound Rules:")
                        if sg.get('IpPermissions'):
                            for rule in sg['IpPermissions']:
                                output_lines.append(f"      - {self._format_ip_permission(rule)}")
                        else:
                            output_lines.append("      (None)")
                        output_lines.append("    Outbound Rules:")
                        if sg.get('IpPermissionsEgress'):
                            for rule in sg['IpPermissionsEgress']:
                                output_lines.append(f"      - {self._format_ip_permission(rule)}")
                        else:
                            output_lines.append("      (None)")
                        output_lines.append("") # Spacer between groups
                else:
                    output_lines.append("  (None Attached)")
        elif aws_status.get('error'):
             output_lines.append("  Skipped due to earlier AWS API error.")
        else:
            output_lines.append("  Not retrieved.") # Should not happen if check ran


        output_lines.append("\n--- Internal Checks ---")
        internal_checks = self.results.get('internal_checks', {})
        if internal_checks.get('skipped'):
            output_lines.append(f"  Skipped: {internal_checks.get('reason', 'Unknown')}")
        elif internal_checks.get('error'):
             output_lines.append(f"  ERROR: {internal_checks['error']}")
        elif not internal_checks:
            output_lines.append("  No internal checks run or results available.")
        else:
            for check, details in internal_checks.items():
                # Ensure details is a dict before accessing keys
                if isinstance(details, dict):
                    status = details.get('status', 'UNKNOWN')
                    output_lines.append(f"  [{status}] {check}")
                    if status == 'FAIL':
                        output_lines.append(f"    Exit Code: {details.get('exit_code', 'N/A')}")
                        if details.get('stderr'):
                            output_lines.append(f"    Stderr: {details['stderr']}")
                        # Optionally print stdout for failed checks too?
                        # if details.get('stdout'):
                        #     output_lines.append(f"    Stdout: {details['stdout']}")
                else:
                    # Handle case where a check result wasn't a dictionary (unexpected)
                    output_lines.append(f"  [UNKNOWN] {check}: Invalid result format - {details}")

        output_lines.append("\n=========================")
        return "\n".join(output_lines)

    def print_results(self, debug_mode=False):
        """Prints the formatted results and optionally the system log."""
        formatted_output = self._format_results()
        print(formatted_output)

        # Handle system log printing based on debug mode or specific errors
        system_log = self.results.get('aws_status', {}).get('system_log', '')

        # Check if log exists, is a string, and doesn't represent an error/empty state before printing
        is_printable_log = (
            isinstance(system_log, str) and
            system_log != "" and # Explicitly check for non-empty
            system_log != "Log retrieval not attempted yet." and
            system_log != "Skipped due to Boto3 client initialization failure." and
            system_log != "Skipped due to error checking instance status." and
            system_log != "Could not decode system log." and
            not system_log.startswith("Could not decode system log. Raw data length:") and # Handle decode error msg
            not system_log.startswith("Error getting console output") and # Handle API error msg
            not system_log.startswith("Unexpected error processing system log") and # Handle other errors
            system_log != "Skipped due to previous error."
        )


        if debug_mode and is_printable_log:
            print("\n--- System Log (Console Output) ---")
            # Limit printing very large logs even in debug? Maybe first/last N lines?
            max_log_chars = 5000 # Limit output size
            print(system_log[:max_log_chars])
            if len(system_log) > max_log_chars:
                print(f"... (log truncated at {max_log_chars} characters) ...")
        elif debug_mode and not is_printable_log and isinstance(system_log, str):
             # If debug mode is on but log isn't printable (empty, error msg), say why
             print(f"\n--- System Log (Console Output) Not Printed (Reason: {system_log if system_log else 'Empty'}) ---")

        # Print raw CLI log if available
        cli_log_val = self.results.get('aws_status', {}).get('system_log_cli', None)
        if cli_log_val and isinstance(cli_log_val, str) and not any(cli_log_val.startswith(p) for p in ["AWS CLI get-console-output failed", "AWS CLI command not found.", "AWS CLI get-console-output command timed out.", "Error running AWS CLI get-console-output"]) and cli_log_val not in ["CLI check not run yet.", "Skipped (Instance not found)"]:
             print("\n--- System Log (Console Output - Raw AWS CLI) ---")
             print(cli_log_val)
        else:
             print("\n--- System Log (Console Output - Raw AWS CLI) --- Not Available or Error ---")

        # Internal Checks Section
        internal_checks = self.results.get('internal_checks', {})
        if not internal_checks.get('skipped', True) and not internal_checks.get('error'):
            for check, details in internal_checks.items():
                if isinstance(details, dict) and details.get('status') == 'FAIL':
                    print(f"\n--- Internal Check '{check}' Failed ---")
                    print(f"Exit Code: {details.get('exit_code', 'N/A')}")
                    if details.get('stderr'):
                        print(f"Stderr: {details['stderr']}")
                    # Optionally print stdout for failed checks too?
                    # if details.get('stdout'):
                    #     print(f"Stdout: {details['stdout']}")

    # Method to determine overall success/failure based on results
    def get_exit_code(self):
        """Determines the overall exit code based on checks."""
        # Default to success
        exit_code = 0

        # Check AWS Status for critical failures
        aws_status = self.results.get('aws_status', {})
        if aws_status.get('error'):
            logging.debug("get_exit_code: Setting exit code to 1 due to AWS status error.")
            return 1 # Immediate failure on AWS check error
        if aws_status.get('instance_state') == 'not_found_or_stopped':
             logging.debug("get_exit_code: Setting exit code to 1 due to instance not found/stopped.")
             return 1
        if aws_status.get('instance_status') == 'impaired' or aws_status.get('system_status') == 'impaired':
            logging.debug("get_exit_code: Setting exit code to 1 due to impaired status.")
            exit_code = 1 # Failure, but continue checking internal
        # Note: SSM offline might be a warning, not necessarily a script failure unless required
        # if aws_status.get('ssm_ping_status') != 'Online':
        #     exit_code = 1

        # Check Internal Checks for failures (only if run)
        internal_checks = self.results.get('internal_checks', {})
        if not internal_checks.get('skipped', True) and not internal_checks.get('error'):
            for check, details in internal_checks.items():
                if isinstance(details, dict) and details.get('status') == 'FAIL':
                    logging.debug(f"get_exit_code: Setting exit code to 1 due to failed internal check '{check}'.")
                    exit_code = 1
                    break # One failed internal check is enough to signal failure

        logging.debug(f"get_exit_code: Final determined exit code: {exit_code}")
        return exit_code

    # Helper to format SG rules nicely
    def _format_ip_permission(self, rule):
        proto = rule.get('IpProtocol', 'all')
        if proto == '-1': proto = 'all'
        f_port = rule.get('FromPort', 'N/A')
        t_port = rule.get('ToPort', 'N/A')
        ports = f"{f_port}-{t_port}" if f_port != 'N/A' else 'all'
        if f_port == t_port: ports = str(f_port)

        sources = []
        for ip_range in rule.get('IpRanges', []):
            sources.append(ip_range.get('CidrIp', 'N/A'))
        for ipv6_range in rule.get('Ipv6Ranges', []):
             sources.append(ipv6_range.get('CidrIpv6', 'N/A'))
        for sg_source in rule.get('UserIdGroupPairs', []):
             sources.append(f"sg:{sg_source.get('GroupId', 'N/A')}")
        if not sources: sources.append('N/A')

        return f"Proto: {proto:<4} | Ports: {ports:<11} | Sources: {', '.join(sources)}"
