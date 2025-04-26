import os
import sys

# Ensure the parent directory is in sys.path for local imports
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

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
# (Assuming these imports exist and are correct in the original file)
from cml_validator_utils.aws_setup import (
    setup_logging,
    initialize_aws_session,
    get_ec2_client,
    get_instance_details,
)
from cml_validator_utils.iam_checks import (
    get_iam_client,
    check_iam_permissions,
    REQUIRED_PERMISSIONS,
    OPTIONAL_PERMISSIONS
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
# --- Forensic Validator Import --- (Assuming exists)
# from validators.forensic_validator import ForensicEbsValidator
# --- Networ...

def main():
    # Existing argument parsing and setup code ...
    parser = argparse.ArgumentParser(description='Run validation checks on an instance')
    parser.add_argument('--instance-id', required=True, help='ID of the instance to validate')
    parser.add_argument('--region', required=False, help='AWS region where the instance is located (defaults to AWS_REGION env var)')
    parser.add_argument('--profile', required=False, help='AWS profile to use for authentication')
    parser.add_argument('--log-level', required=False, default='INFO', help='Log level for the script')
    parser.add_argument('--check-cml-services', action='store_true', help='Check CML services status via SSM')
    parser.add_argument('--ssh-key-path', required=False, default='../keys/cml-validation-key.pem', help='Path to the SSH private key for connection checks (default: ../keys/cml-validation-key.pem)')
    parser.add_argument('--check-security-groups', action='store_true', help='Check instance security group configuration')
    parser.add_argument('--check-nacl', action='store_true', help='Check NACL rules for the instance subnet')
    parser.add_argument('--check-ssm', action='store_true', help='Check SSM agent connectivity')
    parser.add_argument('--check-ssh', action='store_true', help='Check SSH connectivity to the instance')
    parser.add_argument('--all', action='store_true', help='Run all validation checks')
    args = parser.parse_args()

    # Resolve region from argument or environment, default to us-east-2
    region = args.region or os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-2'
    if not region:
        print('ERROR: AWS region must be specified via --region or AWS_REGION/AWS_DEFAULT_REGION environment variable.')
        sys.exit(2)

    # Setup logging and AWS session as before
    logger = setup_logging(args.log_level)
    aws_session = initialize_aws_session(region, args.profile)

    # All previous code from main body goes here, using logger as local
    logger.info("Validation checks started.")
    ec2_client = get_ec2_client(aws_session)
    # Unpack instance details tuple
    instance_details, subnet_id, vpc_id, security_groups, security_group_ids = get_instance_details(ec2_client, args.instance_id)
    iam_client = get_iam_client(aws_session)
    check_iam_permissions(iam_client, REQUIRED_PERMISSIONS, OPTIONAL_PERMISSIONS)

    # Determine which checks to run
    run_sg = args.check_security_groups or args.all
    run_nacl = args.check_nacl or args.all
    run_ssm = args.check_ssm or args.all or args.check_cml_services
    run_ssh = args.check_ssh or args.all
    run_cml_services = args.check_cml_services or args.all

    # Modular results dictionary for summary compatibility
    results = {}
    if run_sg:
        sg_result = check_security_groups(ec2_client, security_group_ids)
        results['security_groups'] = sg_result
    if run_nacl:
        nacl_id, nacl_dict = find_nacl_for_subnet(ec2_client, subnet_id)
        nacl_result = check_nacl_rules(nacl_dict, port=22, protocol='tcp', cidr='0.0.0.0/0')
        results['nacl'] = nacl_result
    if run_ssm:
        instance_id = instance_details['InstanceId'] if isinstance(instance_details, dict) else args.instance_id
        ssm_result = check_ssm_agent(aws_session, instance_id)
        results['ssm'] = ssm_result
    if run_ssh:
        # Extract IP and username for SSH check
        instance_ip = instance_details.get('PublicIpAddress') or instance_details.get('PrivateIpAddress')
        username = 'ec2-user'  # TODO: Make dynamic or configurable
        ssh_result = check_ssh_connection(instance_ip, username, args.ssh_key_path)
        results['ssh'] = ssh_result
    if run_cml_services:
        # Placeholder for CML services check result
        results['cml_services'] = {'status': 'Not Implemented', 'details': {}}

    logger.info("Validation checks complete.")
    try:
        from cml_validator_utils.results_utils import format_results_summary
        region = os.environ.get('AWS_REGION', 'unknown')
        print("\n--- Validation Summary ---")
        print(format_results_summary(results, args.instance_id, region))
    except Exception as e:
        print(f"[WARN] Could not print summary to console: {e}")
    logger.info("Script finished.")

if __name__ == "__main__":
    main()
