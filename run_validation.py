import argparse
import logging
import json
import sys
import os
import time
import datetime
import base64
import subprocess
import textwrap
import binascii

import boto3
import paramiko # Keep for potential direct use or type hinting, though check is moved
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, NoRegionError

# Import functions from the new utility modules
from cml_validator_utils.aws_setup import (
    setup_logging,
    initialize_aws_session, # Corrected name
    get_ec2_client,
    get_instance_details,
)
from cml_validator_utils.iam_checks import (
    get_iam_client,
    check_iam_permissions,
    REQUIRED_PERMISSIONS, 
    OPTIONAL_PERMISSIONS # Import OPTIONAL_PERMISSIONS
)
from cml_validator_utils.network_checks import (
    check_security_groups,
    find_nacl_for_subnet,
    check_nacl_rules
)
from cml_validator_utils.connectivity_checks import (
    check_ssm_agent,
    check_ssh_connection
)
from cml_validator_utils.log_utils import (
    get_system_log_boto3,
    get_system_log_cli,
    format_log_output
)
from cml_validator_utils.results_utils import (
    format_results_summary,
    save_results_to_file
)
# --- Forensic Validator Import ---
from validators.forensic_validator import ForensicEbsValidator
# --- Network Diagnostics Import ---
from validators.network_diagnostics import NetworkDiagnostics
# --- NAT Gateway Validator Import ---
from validators.nat_gateway_validator import get_nat_gateways_for_subnet, check_nat_gateway_health

# --- Configuration (Consider moving to a config file or class attributes) ---
# Logging Configuration
LOG_LEVEL = logging.INFO # Default log level
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Required IAM Permissions (Can be moved to iam_checks.py if preferred)
REQUIRED_PERMISSIONS = [
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeSubnets", # Needed to find VPC for default NACL
    "ec2:GetConsoleOutput",
    "iam:SimulatePrincipalPolicy",
    "sts:GetCallerIdentity",
    "ssm:SendCommand", # For SSM agent check
    "ssm:GetCommandInvocation" # For SSM agent check result
]

# Default SSH Configuration (Can be moved to connectivity_checks.py or config)
DEFAULT_SSH_USERNAME = "ubuntu"
DEFAULT_SSH_TIMEOUT = 10

# --- Main Validator Class ---

class AwsCmlValidator:
    """Validates various aspects of an AWS CML instance."""

    def __init__(self, instance_id, region=None, profile=None, ssh_key=None, log_level=LOG_LEVEL, use_cli_log=False, endpoint_url=None):
        """Initializes the validator.

        Args:
            instance_id (str): The EC2 instance ID to validate.
            region (str, optional): The AWS region. Defaults to None (uses profile default).
            profile (str, optional): The AWS credentials profile name. Defaults to None (uses default profile).
            ssh_key (str, optional): Path to the SSH private key file. Defaults to None.
            log_level (int, optional): The logging level (e.g., logging.INFO). Defaults to LOG_LEVEL.
            use_cli_log (bool, optional): Whether to use AWS CLI for system log retrieval. Defaults to False.
            endpoint_url (str, optional): Custom endpoint URL for AWS services (e.g., for LocalStack). Defaults to None.
        """
        self.instance_id = instance_id
        self.profile = profile
        self.ssh_key_path = ssh_key
        self.use_cli_log = use_cli_log
        self.endpoint_url = endpoint_url # Store endpoint URL
        self.region = region # Added assignment for self.region

        # Setup logging using the utility function
        log_file = f'{self.instance_id}_validation.log'
        # Determine debug flag based on log_level
        debug_flag = log_level == logging.DEBUG
        self.logger = setup_logging(log_file, debug=debug_flag)

        self.logger.info(f"--- Initializing CML Validator --- ")
        self.logger.info(f"Instance ID: {self.instance_id}")
        self.logger.info(f"Profile: {self.profile if self.profile else 'Default'}")
        self.logger.info(f"SSH Key Path: {self.ssh_key_path if self.ssh_key_path else 'Not Provided'}")
        self.logger.info(f"Use CLI for logs: {self.use_cli_log}")
        self.logger.info(f"Custom Endpoint URL: {self.endpoint_url if self.endpoint_url else 'None'}")

        # Initialize AWS session and clients using utility functions
        self.session = initialize_aws_session(region=self.region, profile=self.profile, endpoint_url=self.endpoint_url)
        self.ec2_client = get_ec2_client(self.session, self.endpoint_url)
        self.iam_client = get_iam_client(self.session, self.endpoint_url) # IAM client for permission checks

        # Fetch instance details early on
        self.instance_details = None
        self.instance_state = 'unknown' # Initialize state
        self.subnet_id = None
        self.vpc_id = None # Initialize vpc_id
        self.security_group_ids = []
        self.public_ip = None

        if self.ec2_client:
            # Unpack the full tuple returned by the utility function
            self.instance_details, self.subnet_id, self.vpc_id, _sg_details_list, self.security_group_ids = \
                get_instance_details(self.ec2_client, self.instance_id)
            
            # Check if the actual instance_details dictionary was successfully fetched
            if self.instance_details is not None:
                # Extract State and Public IP (Subnet, SG IDs are already unpacked)
                self.instance_state = self.instance_details.get('State', {}).get('Name', 'unknown') # Extract state safely
                self.public_ip = self.instance_details.get('PublicIpAddress')
                self.logger.info(f"Fetched Instance Details: State={self.instance_state}, Subnet={self.subnet_id}, VPC={self.vpc_id}, SGs={self.security_group_ids}, IP={self.public_ip}")
            else:
                self.logger.error("Failed to fetch initial instance details. Some checks may fail.")
        else:
             self.logger.error("EC2 Client setup failed. Cannot fetch instance details.")

        # Dictionary to store results from various checks
        self.results = {}

    # --------------------------------------------------------------------------
    # Core Validation Logic - Calls utility functions
    # --------------------------------------------------------------------------

    def run_all_checks(self):
        """Runs all validation checks sequentially."""
        self.logger.info("--- Starting All Validation Checks --- ")

        if not self.session or not self.ec2_client:
            self.logger.critical("AWS session or EC2 client not initialized. Cannot run checks.")
            return

        # Instance state was already determined and logged in __init__ using self.instance_state
        # Store the state in results for the summary formatting later.
        self.results['instance_status'] = {
            'status': 'Details Found' if self.instance_state != 'unknown' else 'Error Finding State',
            'state': self.instance_state,
            'details': {} # Keep details structure for summary compatibility
        }

        # 1. Check IAM Permissions
        if self.session:
            # Pass the session object, required_permissions, optional_permissions, and endpoint_url
            self.results['iam_permissions'] = check_iam_permissions(self.session, 
                                                                    REQUIRED_PERMISSIONS, 
                                                                    OPTIONAL_PERMISSIONS, 
                                                                    self.endpoint_url)
        else:
             self.logger.error("Boto3 session not available, skipping IAM checks.")
             self.results['iam_permissions'] = {'status': 'Skipped (No Boto3 Session)', 'details': {}}

        # 2. Check Security Groups
        if self.instance_details:
             self.results['security_groups'] = check_security_groups(self.ec2_client, self.security_group_ids)
        else:
             self.logger.warning("Instance details not available, skipping Security Group check.")
             self.results['security_groups'] = {'status': 'Skipped (No Instance Details)', 'details': {}, 'ids_found': []}

        # 3. Check Network ACLs
        nacl_finding_status = 'Not Checked'
        nacl_id = None
        nacl_details = None
        nacl_rule_check_results = {'status': 'Not Checked', 'details': {}}
        if self.instance_details and self.subnet_id:
            nacl_finding_status, nacl_id, nacl_details = find_nacl_for_subnet(self.ec2_client, self.subnet_id)
            if nacl_details:
                nacl_rule_check_results = check_nacl_rules(nacl_details)
            else:
                nacl_rule_check_results['status'] = 'Skipped (NACL Not Found/Error)'
        else:
            self.logger.warning("Instance details or Subnet ID not available, skipping Network ACL check.")
            nacl_finding_status = 'Skipped (No Instance/Subnet Details)'
        
        # Store combined NACL results
        self.results['nacls'] = {
            'finding_status': nacl_finding_status,
            'nacl_id': nacl_id,
            'rule_check_status': nacl_rule_check_results.get('status'),
            'rule_details': nacl_rule_check_results.get('details'),
            'raw_nacl_details': nacl_details # Optional: Store raw details if needed
        }

        # --- New: Security Group and NACL Rule Dump ---
        # Retrieve and log raw security group rules
        if self.instance_details and self.security_group_ids:
            try:
                sg_details = self.ec2_client.describe_security_groups(GroupIds=self.security_group_ids)
                self.results['raw_security_group_rules'] = sg_details['SecurityGroups']
                print("\n--- Security Group Rules ---")
                for sg in sg_details['SecurityGroups']:
                    print(f"Security Group: {sg['GroupId']} ({sg.get('GroupName', '')})")
                    print(f"Inbound Rules: {sg.get('IpPermissions', [])}")
                    print(f"Outbound Rules: {sg.get('IpPermissionsEgress', [])}\n")
            except Exception as e:
                print(f"Error retrieving security group rules: {e}")
                self.results['raw_security_group_rules_error'] = str(e)

        # Retrieve and log raw NACL rules
        if self.subnet_id:
            try:
                nacl_response = self.ec2_client.describe_network_acls(Filters=[{'Name': 'association.subnet-id', 'Values': [self.subnet_id]}])
                self.results['raw_nacl_rules'] = nacl_response['NetworkAcls']
                print("\n--- NACL Rules ---")
                for nacl in nacl_response['NetworkAcls']:
                    print(f"NACL: {nacl['NetworkAclId']}")
                    print(f"Entries: {nacl.get('Entries', [])}\n")
            except Exception as e:
                print(f"Error retrieving NACL rules: {e}")
                self.results['raw_nacl_rules_error'] = str(e)

        # --- VPC/NAT Gateway Diagnostics ---
        subnet_id = self.instance_details.get('SubnetId')
        vpc_id = self.instance_details.get('VpcId')
        if subnet_id:
            nat_gateway_ids = get_nat_gateways_for_subnet(self.ec2_client, subnet_id)
            self.logger.info(f"NAT Gateways in subnet {subnet_id}: {nat_gateway_ids}")
            nat_gw_results = {}
            for nat_gw_id in nat_gateway_ids:
                nat_gw_results[nat_gw_id] = check_nat_gateway_health(self.ec2_client, nat_gw_id)
            self.results['nat_gateway'] = {
                'subnet_id': subnet_id,
                'nat_gateway_ids': nat_gateway_ids,
                'details': nat_gw_results
            }
        else:
            self.logger.warning("No subnet_id found for instance; skipping NAT Gateway diagnostics.")

        # 4. Check SSM Agent
        # Only run if instance appears to be running
        # Use self.instance_state directly
        if self.instance_state == 'running':
            self.results['ssm_check'] = check_ssm_agent(self.session, self.instance_id, self.endpoint_url)
        else:
             self.logger.warning(f"Instance state is '{self.instance_state}', skipping SSM Agent check.")
             self.results['ssm_check'] = {'status': f'Skipped (Instance State: {self.instance_state})', 'details': {}}

        # 5. Check SSH Connection
        # Only run if instance appears running and has a public IP
        # Use self.instance_state directly
        if self.instance_state == 'running' and self.public_ip:
            self.results['ssh_check'] = check_ssh_connection(self.public_ip, self.ssh_key_path, username=DEFAULT_SSH_USERNAME, timeout=DEFAULT_SSH_TIMEOUT)
        elif self.instance_state != 'running':
             self.logger.warning(f"Instance state is '{self.instance_state}', skipping SSH check.")
             self.results['ssh_check'] = {'status': f'Skipped (Instance State: {self.instance_state})', 'details': {}}
        elif not self.public_ip:
             self.logger.warning(f"Instance has no public IP, skipping SSH check.")
             self.results['ssh_check'] = {'status': 'Skipped (No Public IP)', 'details': {}}
        else:
             self.logger.warning("Skipping SSH check for unknown reason.") # Should not happen
             self.results['ssh_check'] = {'status': 'Skipped (Unknown)', 'details': {}}

        # 6. Get System Log
        log_check_results = {}
        raw_log_content = None
        if self.use_cli_log:
            log_check_results, raw_log_content = get_system_log_cli(self.instance_id, self.region, self.profile)
        elif self.ec2_client: # Only use Boto3 if not using CLI and client exists
            log_check_results, raw_log_content = get_system_log_boto3(self.ec2_client, self.instance_id)
        else:
            log_check_results['status'] = 'Skipped (No EC2 Client/CLI not selected)'
            log_check_results['details'] = {'error': 'Cannot retrieve log.'}

        self.results['system_log'] = log_check_results
        # Raw log content is handled separately for saving if needed

        # --- CML SSM Diagnostics ---
        self.logger.info("--- Starting CML SSM Diagnostics ---")
        ssm_client = None
        try:
            # Get SSM client using the established session
            ssm_client = self.session.client('ssm', region_name=self.region, endpoint_url=self.endpoint_url)
        except Exception as e:
             self.logger.error(f"Failed to create SSM client: {e}")

        if ssm_client:
            # Run diagnostics via SSM
            self.results['cml_ssm_diagnostics'] = self.run_cml_diagnostics_via_ssm(ssm_client, self.instance_id, self.logger)
        else:
            self.results['cml_ssm_diagnostics'] = {'status': 'Error', 'error': 'Failed to initialize SSM client.'}
        self.logger.info("--- Finished CML SSM Diagnostics ---")

        # --- Forensic EBS Checks (Example Integration) ---
        # TODO: Integrate ForensicEbsValidator class for EBS volume analysis

        self.logger.info("--- Finished All Validation Checks ---")

    def run_cml_diagnostics_via_ssm(self, ssm_client, instance_id, logger):
        """Run CML service, port, and log diagnostics via SSM Run Command."""
        diagnostics = {}
        # Define commands
        cmd_virl2_service = "systemctl status virl2.target || systemctl status virl2-controller.service"
        cmd_journal_logs = "journalctl -u virl2-controller.service -n 50 --no-pager"
        other_commands = {
            'port_443': "ss -tunlp | grep 443 || netstat -tlnp | grep 443 || echo 'Nothing on 443'",
            'virl2_logs': "ls -l /var/log/virl2/ || echo 'No /var/log/virl2 directory'",
            'syslog_tail': "tail -40 /var/log/syslog || echo 'No syslog'"
        }

        # Helper function to run a single SSM command and wait
        def run_ssm_command(key, cmd):
            command_result = {}
            try:
                logger.info(f"[CML SSM] Running: {cmd}")
                response = ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': [cmd]},
                    TimeoutSeconds=60
                )
                command_id = response['Command']['CommandId']
                # Wait for command to complete (adjust timeout/retries as needed)
                for _ in range(15):
                    time.sleep(2) # time is imported globally
                    invocation = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                    if invocation['Status'] in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                        break
                command_result = {
                    'status': invocation['Status'],
                    'stdout': invocation.get('StandardOutputContent', '').strip(),
                    'stderr': invocation.get('StandardErrorContent', '').strip()
                }
            except Exception as e:
                command_result = {'status': 'Error', 'error': str(e)}
            return command_result

        # 1. Check virl2 service status
        diagnostics['virl2_service'] = run_ssm_command('virl2_service', cmd_virl2_service)

        # 2. If service check failed, get journal logs
        # Note: The 'systemctl status' command returns 'Failed' if the service is inactive, even if it's expected.
        # So, we fetch logs if the status isn't strictly 'Success'.
        if diagnostics['virl2_service'].get('status') != 'Success':
            logger.info("[CML SSM] virl2 service status was not 'Success', attempting to get journal logs.")
            diagnostics['virl2_journal_logs'] = run_ssm_command('virl2_journal_logs', cmd_journal_logs)

        # 3. Run other diagnostic commands
        for key, cmd in other_commands.items():
            diagnostics[key] = run_ssm_command(key, cmd)

        return diagnostics

    def display_results(self):
        """Formats and prints the results summary."""
        print("\n--- Validation Results --- ")
        if not self.results:
            print("No results generated.")
            return

        # --- Instance Details ---
        print("\n--- Instance Details ---")
        if 'instance_details' in self.results:
            details = self.results['instance_details']
            print(f"Instance ID: {self.instance_id}")
            print(f"State: {details.get('state')}")
            print(f"Private IP: {details.get('private_ip')}")
            print(f"Public IP: {details.get('public_ip')}")
            print(f"Subnet ID: {details.get('subnet_id')}")
            print(f"VPC ID: {details.get('vpc_id')}")
            print(f"Security Groups: {details.get('security_groups')}")
            print(f"IAM Role: {details.get('iam_role')}")
            print(f"Region: {self.region}")
            print(f"AMI ID: {details.get('ami_id')}")
            print(f"Instance Type: {details.get('instance_type')}")
        else:
            print("Instance details not available.")

        # --- IAM Permissions ---
        if 'iam_check' in self.results:
            print("\n--- IAM Permission Checks ---")
            iam_res = self.results['iam_check']
            status = iam_res.get('status', 'Unknown')
            print(f"Status: {status}")
            if 'details' in iam_res:
                print("Checked Permissions:")
                for perm, allowed in iam_res['details'].items():
                    print(f"  - {perm}: {'Allowed' if allowed else 'Denied'}")
            if 'error' in iam_res:
                print(f"Error: {iam_res['error']}")

        # --- Security Group Checks ---
        if 'sg_check' in self.results:
            print("\n--- Security Group Checks ---")
            sg_res = self.results['sg_check']
            print(f"Status: {sg_res.get('status')}")
            if 'checked_rules' in sg_res:
                print("Required Rules Found:")
                for rule, found in sg_res['checked_rules'].items():
                    print(f"  - {rule}: {'Found' if found else 'Missing'}")
            if 'checked_groups' in sg_res:
                print(f"Checked Security Groups: {', '.join(sg_res['checked_groups'])}")

        # --- NACL Checks ---
        if 'nacl_check' in self.results:
            print("\n--- Network ACL Checks ---")
            nacl_res = self.results['nacl_check']
            print(f"NACL ID: {nacl_res.get('nacl_id')}")
            print(f"Status: {nacl_res.get('status')}")
            if 'checked_rules' in nacl_res:
                print("Required Rules Found:")
                for rule, found in nacl_res['checked_rules'].items():
                    print(f"  - {rule}: {'Found' if found else 'Missing'}")

        # --- SSM Agent Check ---
        if 'ssm_check' in self.results:
            print("\n--- SSM Agent Check ---")
            ssm_res = self.results['ssm_check']
            print(f"Status: {ssm_res.get('status')}")
            if 'details' in ssm_res:
                print(f"Details: {ssm_res['details']}")
            if 'error' in ssm_res:
                print(f"Error: {ssm_res['error']}")

        # --- SSH Connection Check ---
        if 'ssh_check' in self.results:
            print("\n--- SSH Connection Check ---")
            ssh_res = self.results['ssh_check']
            print(f"Status: {ssh_res.get('status')}")
            if 'error' in ssh_res:
                print(f"Error: {ssh_res['error']}")

        # --- System Log Check (Boto3) ---
        if 'system_log_boto3' in self.results:
            print("\n--- System Log (Boto3 Method) ---")
            log_res = self.results['system_log_boto3']
            print(f"Status: {log_res.get('status')}")
            if log_res.get('log_length', 0) > 0:
                print(f"Retrieved {log_res['log_length']} characters.")
            if 'error' in log_res:
                print(f"Error: {log_res['error']}")

        # --- CML Connectivity Check ---
        if 'cml_connectivity' in self.results:
            print("\n--- CML Connectivity Check (HTTPS) ---")
            conn_res = self.results['cml_connectivity']
            print(f"Target URL: {conn_res.get('url')}")
            print(f"Status: {conn_res.get('status')}")
            if 'error' in conn_res:
                print(f"Error: {conn_res['error']}")

        # --- CML SSM Diagnostics ---
        if 'cml_ssm_diagnostics' in self.results:
            print("\n--- CML SSM Diagnostics ---")
            for key, result in self.results['cml_ssm_diagnostics'].items():
                # Skip printing journal logs here, handle below virl2_service
                if key == 'virl2_journal_logs':
                    continue

                print(f"[{key}] Status: {result.get('status')}")
                if result.get('stdout'):
                    print(f"  STDOUT:\n{textwrap.indent(result['stdout'], '    ')}")
                if result.get('stderr'):
                    print(f"  STDERR:\n{textwrap.indent(result['stderr'], '    ')}")
                if result.get('error'):
                    print(f"  ERROR: {result.get('error')}")

                # If this is the virl2 service check and journal logs exist, print them
                if key == 'virl2_service' and 'virl2_journal_logs' in self.results['cml_ssm_diagnostics']:
                    journal_result = self.results['cml_ssm_diagnostics']['virl2_journal_logs']
                    print(f"  [virl2_journal_logs] Status: {journal_result.get('status')}")
                    if journal_result.get('stdout'):
                        print(f"    Journal STDOUT:\n{textwrap.indent(journal_result['stdout'], '      ')}")
                    if journal_result.get('stderr'):
                        print(f"    Journal STDERR:\n{textwrap.indent(journal_result['stderr'], '      ')}")
                    if journal_result.get('error'):
                        print(f"    Journal ERROR: {journal_result.get('error')}")

        # --- Additional Checks ---
        # Add display logic for cloudinit_logs, iam_role_and_policy, etc., if implemented and present
        # Example:
        # if 'cloudinit_logs' in self.results:
        #     print("\n--- Cloud-Init & Boot Logs ---")
        #     # ... display logic ...

        # --- Save Results ---
        print("\n--- Save Results ---")
        if 'save_results' in self.results:
            save_res = self.results['save_results']
            print(f"Status: {save_res.get('status')}")
            if 'error' in save_res:
                print(f"Error: {save_res['error']}")

    def save_results(self, filename_prefix="validation_results"):
        """Saves the results to a JSON file."""
        save_results_to_file(self.results, self.instance_id, filename_prefix)

# --- SSM Troubleshooting Module ---
class SsmTroubleshooter:
    """Modular troubleshooting for SSM agent registration and diagnostics."""
    def __init__(self, instance_id, region, logger, reference_instance_id=None):
        self.instance_id = instance_id
        self.region = region
        self.logger = logger
        self.reference_instance_id = reference_instance_id
        self.ec2 = boto3.client("ec2", region_name=region)
        self.ssm = boto3.client("ssm", region_name=region)
        self.iam = boto3.client("iam", region_name=region)

    def check_ssm_registration(self):
        """Check if the instance is registered with SSM."""
        paginator = self.ssm.get_paginator("describe_instance_information")
        for page in paginator.paginate():
            for info in page["InstanceInformationList"]:
                if info["InstanceId"] == self.instance_id:
                    self.logger.info(f"[SSM] Instance {self.instance_id} registration: {info['PingStatus']}, Agent: {info['AgentVersion']}, Last ping: {info['LastPingDateTime']}")
                    return info
        self.logger.error(f"[SSM] Instance {self.instance_id} is NOT registered with SSM in {self.region}.")
        return None

    def check_iam_role(self):
        """Check IAM role and SSM policy attachment."""
        try:
            reservations = self.ec2.describe_instances(InstanceIds=[self.instance_id])["Reservations"]
            instance = reservations[0]["Instances"][0]
            profile = instance.get("IamInstanceProfile", {})
            arn = profile.get("Arn", "")
            if not arn:
                self.logger.error("[IAM] No IAM instance profile attached.")
                return None
            role_name = arn.split('/')[-1]
            attached = False
            policies = []
            try:
                role = self.iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]
                for r in role["Roles"]:
                    attached = any(p["PolicyName"] == "AmazonSSMManagedInstanceCore" for p in self.iam.list_attached_role_policies(RoleName=r["RoleName"])['AttachedPolicies'])
                    policies = [p["PolicyName"] for p in self.iam.list_attached_role_policies(RoleName=r["RoleName"])['AttachedPolicies']]
            except Exception as e:
                self.logger.error(f"[IAM] Error fetching policies: {e}")
            self.logger.info(f"[IAM] Role: {role_name}, SSM Policy Attached: {attached}, Policies: {policies}")
            return {"role_name": role_name, "ssm_policy_attached": attached, "policies": policies}
        except Exception as e:
            self.logger.error(f"[IAM] Error: {e}")
            return None

    def fetch_logs(self):
        """Fetch cloud-init and SSM logs via EC2 console output."""
        try:
            log = self.ec2.get_console_output(InstanceId=self.instance_id, Latest=True)
            output = log.get("Output", "")
            if output:
                self.logger.info(f"[LOG] Retrieved EC2 console output for {self.instance_id}.")
                # Look for SSM/cloud-init errors
                ssm_lines = [l for l in output.splitlines() if "ssm" in l.lower() or "cloud-init" in l.lower() or "error" in l.lower()]
                for line in ssm_lines[-20:]:
                    self.logger.info(f"[LOG] {line}")
                return ssm_lines
            else:
                self.logger.warning(f"[LOG] No EC2 console output available.")
                return []
        except Exception as e:
            self.logger.error(f"[LOG] Error fetching EC2 console output: {e}")
            return []

    def check_network(self):
        """Check security groups, NACLs, and outbound HTTPS."""
        try:
            reservations = self.ec2.describe_instances(InstanceIds=[self.instance_id])["Reservations"]
            instance = reservations[0]["Instances"][0]
            sg_ids = [sg["GroupId"] for sg in instance["SecurityGroups"]]
            subnet_id = instance["SubnetId"]
            sgs = self.ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
            nacls = self.ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}])["NetworkAcls"]
            # Check outbound HTTPS (port 443)
            https_ok = any(
                any(r.get("FromPort", -1) <= 443 <= r.get("ToPort", -1) and r.get("IpProtocol") in ["tcp", "-1"] and any(ip.get("CidrIp", "") == "0.0.0.0/0" for ip in r.get("IpRanges", [])) for r in sg["IpPermissionsEgress"])
                for sg in sgs
            )
            self.logger.info(f"[NET] Outbound HTTPS allowed: {https_ok}")
            return {"sg_ids": sg_ids, "nacl_ids": [n["NetworkAclId"] for n in nacls], "https_out": https_ok}
        except Exception as e:
            self.logger.error(f"[NET] Error: {e}")
            return None

    def compare_with_reference(self):
        """Compare with a reference instance (if provided)."""
        if not self.reference_instance_id:
            self.logger.info("[REF] No reference instance provided.")
            return None
        # Compare IAM, SG, subnet, AMI, etc.
        try:
            ref = self.ec2.describe_instances(InstanceIds=[self.reference_instance_id])["Reservations"][0]["Instances"][0]
            cur = self.ec2.describe_instances(InstanceIds=[self.instance_id])["Reservations"][0]["Instances"][0]
            diffs = {}
            for field in ["ImageId", "SubnetId", "InstanceType", "IamInstanceProfile"]:
                ref_val = ref.get(field)
                cur_val = cur.get(field)
                if ref_val != cur_val:
                    diffs[field] = {"current": cur_val, "reference": ref_val}
            self.logger.info(f"[REF] Differences: {diffs}")
            return diffs
        except Exception as e:
            self.logger.error(f"[REF] Error: {e}")
            return None

    def run_all(self):
        """Run all troubleshooting steps and return a summary dict."""
        results = {}
        results["ssm_registration"] = self.check_ssm_registration()
        results["iam_role"] = self.check_iam_role()
        results["logs"] = self.fetch_logs()
        results["network"] = self.check_network()
        results["reference_compare"] = self.compare_with_reference()
        return results

# --- Script Execution --- 

def main():
    parser = argparse.ArgumentParser(description="Validate AWS CML Instance Configuration.")
    parser.add_argument("-i", "--instance-id", required=False, help="EC2 instance ID of the CML controller.")
    parser.add_argument("-r", "--region", help="AWS region (optional, overrides profile default).", default=None)
    parser.add_argument("-p", "--profile", help="AWS credential profile name (optional).", default=None)
    parser.add_argument("-k", "--ssh-key", help="Path to the SSH private key for connectivity tests (optional).", default=None)
    parser.add_argument("--use-cli-log", action="store_true", help="Use AWS CLI to retrieve system log instead of Boto3.")
    parser.add_argument("--endpoint-url", help="Custom AWS endpoint URL (for LocalStack, etc.).", default=None)
    parser.add_argument("-v", "--verbose", action="store_const", const=logging.DEBUG, default=LOG_LEVEL, help="Enable verbose (DEBUG) logging.")
    parser.add_argument("-o", "--output-prefix", help="Prefix for the output JSON results file.", default="validation_results")
    # Forensic mode
    parser.add_argument("--forensic-mount", help="Path to mounted EBS root volume for forensic log analysis.", default=None)
    # SSM forensic options
    parser.add_argument("--forensic-ssm-instance-id", help="EC2 instance ID for SSM forensic analysis.", default=None)
    parser.add_argument("--forensic-ssm-region", help="AWS region for SSM forensic analysis.", default=None)
    parser.add_argument("--forensic-ssm-profile", help="AWS CLI profile for SSM forensic analysis.", default=None)
    parser.add_argument("--ssh", action="store_true", help="SSH into the instance after validation using the discovered public IP.")
    parser.add_argument("--ssm-diag", action="store_true", help="Run network diagnostics via SSM after validation.")
    parser.add_argument("--ssm-troubleshoot", action="store_true", help="Run modular SSM registration troubleshooting steps.")

    args = parser.parse_args()

    # Forensic EBS log analysis mode (local mount or SSM)
    if args.forensic_mount or args.forensic_ssm_instance_id:
        log_file = "forensic_"
        if args.forensic_mount:
            log_file += f"{os.path.basename(args.forensic_mount.strip('/'))}_analysis.log"
        elif args.forensic_ssm_instance_id:
            log_file += f"ssm_{args.forensic_ssm_instance_id}_analysis.log"
        logger = setup_logging(log_file, debug=(args.verbose == logging.DEBUG))
        if args.forensic_ssm_instance_id:
            validator = ForensicEbsValidator(
                mount_point=None,
                logger=logger,
                ssm_instance_id=args.forensic_ssm_instance_id,
                ssm_region=args.forensic_ssm_region,
                ssm_profile=args.forensic_ssm_profile
            )
        else:
            validator = ForensicEbsValidator(args.forensic_mount, logger=logger)
        summary = validator.run()
        print(validator.format_summary())
        output_json = f"{args.output_prefix}_forensic.json"
        validator.save_results(output_json)
        print(f"\nForensic analysis results saved to: {output_json}")
        sys.exit(0)

    # Hardcode default SSH key path if not provided via argument
    ssh_key_to_use = args.ssh_key
    if not ssh_key_to_use:
        default_key_path = "/Users/miked/Documents/Projects/python_project/my-cloud-cml/terraform-key.pem"
        # Temporarily set up a basic logger for this message before full setup in class
        temp_logger = logging.getLogger('ValidatorSetup')
        temp_logger.setLevel(args.verbose) # Use the verbosity level from args
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        temp_logger.addHandler(handler)
        
        if os.path.exists(default_key_path):
            ssh_key_to_use = default_key_path
            temp_logger.info(f"SSH key argument not provided. Using default key: {default_key_path}")
        else:
            temp_logger.warning(f"SSH key argument not provided and default key not found at: {default_key_path}")
        # Avoid duplicate handlers if logger is reconfigured later
        temp_logger.removeHandler(handler)

    # Instantiate and run the validator
    validator = AwsCmlValidator(
        instance_id=args.instance_id,
        region=args.region,
        profile=args.profile,
        ssh_key=ssh_key_to_use, # Use the potentially updated key path
        log_level=args.verbose,
        use_cli_log=args.use_cli_log,
        endpoint_url=args.endpoint_url
    )

    if not validator.session or not validator.ec2_client:
         # Error messages already logged during init
         print("\nInitialization failed. Cannot proceed with validation checks.")
         sys.exit(1)

    validator.run_all_checks()
    validator.display_results()
    validator.save_results(filename_prefix=args.output_prefix)

    # --- SSH into instance if requested ---
    if args.ssh:
        if hasattr(validator, 'public_ip') and validator.public_ip:
            print("\n[INFO] Running deep network diagnostics over SSH...\n")
            NetworkDiagnostics.run_over_ssh(ssh_key_to_use, validator.public_ip)
        else:
            print("[ERROR] No public IP found for SSH connection.")

    # --- SSM diagnostics if requested ---
    if getattr(args, "ssm_diag", False):
        import boto3
        ssm_client = boto3.client("ssm", region_name=args.region or "us-east-2")
        print("\n[INFO] Running deep network diagnostics over SSM...\n")
        NetworkDiagnostics.run_over_ssm(ssm_client, args.instance_id, region=args.region or "us-east-2")

    # --- SSM Troubleshooting if requested ---
    if getattr(args, "ssm_troubleshoot", False):
        print("\n[INFO] Running modular SSM registration troubleshooting...\n")
        # Use ubuntu-cloudinit-test as reference if available
        reference_instance = "i-0deaa80b55b97a056"
        troubleshooter = SsmTroubleshooter(args.instance_id, args.region or "us-east-2", validator.logger, reference_instance_id=reference_instance)
        summary = troubleshooter.run_all()
        print("\n--- SSM Troubleshooting Summary ---\n")
        print(json.dumps(summary, indent=2, default=str))

if __name__ == "__main__":
    main()
