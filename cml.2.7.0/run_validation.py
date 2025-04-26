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
# --- Network Diagnostics Import --- (Assuming exists)
# from validators.network_diagnostics import NetworkDiagnostics
# --- NAT Gateway Validator Import --- (Assuming exists)
# from validators.nat_gateway_validator import get_nat_gateways_for_subnet, check_nat_gateway_health

# Assume AwsCmlValidator class definition exists here
class AwsCmlValidator:
    def __init__(self, ec2_client, ssm_client, iam_client, sts_client, logger, region_name, use_cli_logs, session, endpoint_url=None):
        """Initializes the validator with necessary AWS clients and configuration."""
        self.ec2_client = ec2_client
        self.ssm_client = ssm_client
        self.iam_client = iam_client
        self.sts_client = sts_client
        self.logger = logger
        self.region_name = region_name
        self.use_cli_logs = use_cli_logs
        self.session = session # Store the session
        self.endpoint_url = endpoint_url # Store endpoint_url
        self.public_ip = None # Initialize public_ip attribute
        # Add any other attributes that were previously expected

    def run_all_checks(self, instance_id, ssh_key_path):
        """Runs all core validation checks."""
        # ... (existing core check logic) ...
        # Example: Fetching instance details, checking IAM, SG, NACL, SSM, SSH, Logs
        all_results = {}
        self.logger.info(f"--- Starting Core Validation Checks for {instance_id} ---")

        # Get instance details (uses self.ec2_client)
        try:
            instance_info = self.ec2_client.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
            all_results['instance_details'] = instance_info
            # Extract public IP if available
            self.public_ip = instance_info.get('PublicIpAddress')
            self.logger.info("Successfully fetched instance details.")
        except ClientError as e:
            self.logger.error(f"Failed to fetch instance details: {e}")
            all_results['instance_details_error'] = str(e)
            return all_results # Stop if basic details fail
        except Exception as e:
            self.logger.error(f"Unexpected error fetching instance details: {e}")
            all_results['instance_details_error'] = str(e)
            return all_results

        # --- Add calls to other check functions here using instance_info ---
        # e.g., Check IAM
        # e.g., Check Security Groups
        # e.g., Check NACL
        # e.g., Check SSM Agent status (basic ping) - uses self.session, self.endpoint_url
        # Ensure check_ssm_agent function is correctly defined or imported
        ssm_status = check_ssm_agent(self.session, instance_id, self.endpoint_url)
        all_results['ssm_agent_status'] = ssm_status

        # Placeholder for other core checks...
        self.logger.info(f"--- Finished Core Validation Checks for {instance_id} ---")
        return all_results

    def check_cml_services_via_ssm(self, instance_id):
        """Checks the status of critical CML systemd services via SSM Run Command."""
        self.logger.info(f"--- Starting CML Service Status Check via SSM for {instance_id} ---")
        command = "sudo systemctl status virl2-controller.service virl2-uwm.service virl2-lowlevel-driver.service --no-pager"
        command_id = None
        try:
            # Use self.ssm_client
            response = self.ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': [command]},
                TimeoutSeconds=60
            )
            command_id = response['Command']['CommandId']
            self.logger.info(f"SSM Run Command sent (ID: {command_id}) to check CML services.")

            # Wait for the command to complete
            waiter = self.ssm_client.get_waiter('command_executed')
            try:
                self.logger.info(f"Waiting for SSM command {command_id} to complete...")
                waiter.wait(
                    CommandId=command_id,
                    InstanceId=instance_id,
                    WaiterConfig={'Delay': 5, 'MaxAttempts': 12} # Wait up to 60 seconds
                )
                self.logger.info(f"SSM command {command_id} completed.")
                output = self.ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )

                if output['Status'] == 'Success':
                    self.logger.info("CML Service Status Check Command executed successfully.")
                    self.logger.info("--- CML Service Status Output ---")
                    print(output['StandardOutputContent'])
                    self.logger.info("--- End CML Service Status Output ---")
                    # Basic check for active state (can be refined)
                    if "Active: active (running)" not in output['StandardOutputContent']:
                         self.logger.warning("One or more CML services might not be 'active (running)'. Review the status output.")
                    elif "ERROR" in output['StandardOutputContent'].upper() or "FAILED" in output['StandardOutputContent'].upper():
                         self.logger.warning("Potential errors detected in CML service status. Review the output.")
                    else:
                        self.logger.info("All checked CML services appear to be active based on basic string check.")
                else:
                    self.logger.error(f"SSM command to check CML services failed with status: {output['Status']}")
                    self.logger.error(f"Standard Error:\n{output.get('StandardErrorContent', 'N/A')}")

            except ClientError as e: # Changed from WaiterError to broader ClientError for waiter issues
                self.logger.error(f"Waiter failed or timed out waiting for SSM command {command_id}: {e}")
                # Attempt to get invocation details even if waiter failed
                try:
                    output = self.ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                    self.logger.error(f"Final command status: {output.get('Status', 'Unknown')}")
                    self.logger.error(f"Final Standard Error:\n{output.get('StandardErrorContent', 'N/A')}")
                except ClientError as inner_e:
                    self.logger.error(f"Could not retrieve invocation details after waiter error: {inner_e}")
                except Exception as inner_e: # Catch other potential errors
                    self.logger.error(f"Unexpected error retrieving invocation details after waiter error: {inner_e}")
            except Exception as e: # Catch unexpected errors during waiting/retrieval
                 self.logger.error(f"An unexpected error occurred while waiting for or processing SSM command {command_id}: {e}")
                 # Attempt to get invocation details even if waiter failed unexpectedly
                 if command_id: # Check if command_id was successfully obtained
                     try:
                         output = self.ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
                         self.logger.error(f"Final command status: {output.get('Status', 'Unknown')}")
                         self.logger.error(f"Final Standard Error:\n{output.get('StandardErrorContent', 'N/A')}")
                     except ClientError as inner_e:
                         self.logger.error(f"Could not retrieve invocation details after unexpected waiter error: {inner_e}")
                     except Exception as inner_e:
                          self.logger.error(f"Unexpected error retrieving invocation details after unexpected waiter error: {inner_e}")

        except ClientError as e:
            self.logger.error(f"Failed to send SSM command to check CML services: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during CML service check setup: {e}")
        finally:
            self.logger.info("--- Finished CML Service Status Check via SSM ---")

    def save_results(self, results_data, instance_id):
        """Saves the validation results to a JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"validation_results_{instance_id}_{timestamp}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(results_data, f, indent=4, default=str) # Use default=str for non-serializable types
            self.logger.info(f"Results successfully saved to {filename}")
        except IOError as e:
            self.logger.error(f"Error saving results to {filename}: {e}")
        except TypeError as e:
            self.logger.error(f"Error serializing results to JSON: {e}")

# --- End of AwsCmlValidator class ---

if __name__ == "__main__":
    # Original argparse setup (assuming it includes all necessary args like instance-id, profile, region, key-path etc.)
    parser = argparse.ArgumentParser(description="Validate AWS CML Instance Connectivity and Setup.")
    parser.add_argument("-i", "--instance-id", help="EC2 Instance ID of the CML controller.")
    parser.add_argument("-p", "--profile", help="AWS profile name to use.")
    parser.add_argument("-k", "--key-path", help="Path to the SSH private key.")
    parser.add_argument("--use-cli-logs", action="store_true", help="Use AWS CLI for logs instead of Boto3.")
    parser.add_argument("--endpoint-url", help="Custom AWS endpoint URL (for LocalStack, etc.).")
    parser.add_argument("--check-cml-services", action="store_true", help="Run CML service status checks via SSM.")
    parser.add_argument("-r", "--region", help="AWS region (optional, overrides profile default).", default=None)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Set the logging level.")
    parser.add_argument("--forensic-cml-deb", action="store_true", help="Download and inspect CML .deb packages from S3 for systemd service files.")
    parser.add_argument("--forensic-cml-deb-output", default="forensic_cml_deb_results.json", help="Output file for forensic CML .deb inspection results (JSON)")
    # Ensure other args used by the original script are here, e.g., output-prefix if needed
    # parser.add_argument("-o", "--output-prefix", help="Prefix for the output JSON results file.", default="validation_results")

    args = parser.parse_args()

    # Initialize logging (basic setup)
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR
    }
    log_level = log_level_map.get(args.log_level.upper(), logging.INFO)

    log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(log_formatter)
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(log_handler)
    # Suppress excessive boto3 logging
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    logger = logging.getLogger("CMLValidatorScript")

    # Determine Instance ID (example of how it might have been handled)
    instance_id = args.instance_id
    if not instance_id:
        logger.error("Instance ID must be provided with -i flag.")
        sys.exit(1)

    # Determine SSH Key Path (example, might differ from original)
    ssh_key_path = args.key_path
    if not ssh_key_path:
        logger.warning("SSH Key path not provided with -k. Some checks might be skipped.")

    # Initialize AWS Session
    session = None
    try:
        logger.info(f"Initializing AWS session using profile '{args.profile}' and region '{args.region or 'default'}'")
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        # Verify credentials early
        sts_client_check = session.client('sts', endpoint_url=args.endpoint_url)
        sts_client_check.get_caller_identity()
        logger.info("AWS session initialized successfully.")
        # Get the actual region name being used
        region_name = session.region_name
        if not region_name:
            region_name = 'us-east-2' # Fallback or get from config
            logger.warning(f"Region not explicitly set, defaulting to {region_name}")

    except (NoCredentialsError, PartialCredentialsError):
        logger.error("AWS credentials not found. Configure credentials (e.g., ~/.aws/credentials) or use --profile.")
        sys.exit(1)
    except NoRegionError:
        logger.error("AWS region not configured. Specify with --region or configure a default region.")
        sys.exit(1)
    except ClientError as e:
        if "InvalidClientTokenId" in str(e) or "SignatureDoesNotMatch" in str(e):
            logger.error(f"AWS authentication failed: {e}. Check your credentials.")
        else:
            logger.error(f"Failed to verify AWS credentials/region via STS: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during AWS session initialization: {e}")
        sys.exit(1)

    # Initialize clients
    try:
        ec2_client = session.client('ec2', endpoint_url=args.endpoint_url)
        ssm_client = session.client('ssm', endpoint_url=args.endpoint_url)
        # Initialize other clients as needed by the validator class (IAM, STS, etc.)
        iam_client = session.client('iam', endpoint_url=args.endpoint_url)
        sts_client = session.client('sts', endpoint_url=args.endpoint_url)
        logger.info("AWS clients initialized.")
    except Exception as e:
        logger.error(f"Failed to initialize AWS clients: {e}")
        sys.exit(1)

    # Instantiate Validator
    validator = AwsCmlValidator(
        ec2_client=ec2_client,
        ssm_client=ssm_client,
        iam_client=iam_client, # Pass initialized clients
        sts_client=sts_client,
        logger=logger,
        region_name=region_name,
        use_cli_logs=args.use_cli_logs,
        session=session, # Pass session to __init__
        endpoint_url=args.endpoint_url # Pass endpoint_url to __init__
    )

    if args.forensic_cml_deb:
        import subprocess
        import tempfile
        import shutil
        import json
        import shutil as pyshutil
        # Pre-flight check for dpkg
        if not pyshutil.which("dpkg"):
            logger.error("'dpkg' is required for forensic inspection but was not found in your PATH. Please install dpkg (e.g., 'brew install dpkg' on macOS) and re-run.")
            sys.exit(1)
        forensic_results = []
        logger.info("Running automated CML .deb forensic inspection from S3...")
        s3_bucket = "s3://cml-ova-import/cml-2.7.0-debs/"
        with tempfile.TemporaryDirectory() as local_dir:
            logger.info(f"Downloading all CML .deb packages from {s3_bucket} to {local_dir}...")
            try:
                subprocess.run(["aws", "s3", "cp", "--recursive", s3_bucket, local_dir], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download .deb files from S3: {e}")
                sys.exit(1)
            # Filter for CML .deb packages only
            debs = [f for f in os.listdir(local_dir) if f.startswith("cml2_") and f.endswith(".deb")]
            if not debs:
                logger.error(f"No CML .deb files (cml2_*.deb) found in {local_dir}. Please check your S3 bucket for the correct CML application packages.")
                sys.exit(1)
            for deb in debs:
                deb_path = os.path.join(local_dir, deb)
                logger.info(f"Inspecting {deb_path} for systemd service files...")
                deb_result = {"deb": deb, "virl2-uwm.service": False, "virl2-controller.service": False, "service_entries": [], "postinst": None, "errors": []}
                try:
                    out = subprocess.check_output(["dpkg", "-c", deb_path], text=True)
                    deb_result["virl2-uwm.service"] = any("virl2-uwm.service" in line for line in out.splitlines())
                    deb_result["virl2-controller.service"] = any("virl2-controller.service" in line for line in out.splitlines())
                    deb_result["service_entries"] = [line for line in out.splitlines() if ".service" in line]
                    logger.info(f"virl2-uwm.service present: {deb_result['virl2-uwm.service']}")
                    logger.info(f"virl2-controller.service present: {deb_result['virl2-controller.service']}")
                    logger.info("Relevant .service file entries:\n" + '\n'.join(deb_result["service_entries"]))
                    extract_dir = os.path.join(local_dir, deb + "-extract")
                    try:
                        subprocess.run(["dpkg-deb", "-e", deb_path, extract_dir], check=True)
                        postinst_path = os.path.join(extract_dir, "postinst")
                        if os.path.exists(postinst_path):
                            with open(postinst_path) as f:
                                postinst_lines = f.readlines()
                                deb_result["postinst"] = ''.join(postinst_lines[:20])
                                logger.info(f"postinst script for {deb} (first 20 lines):\n" + deb_result["postinst"])
                        else:
                            logger.info(f"No postinst script found in {deb}.")
                    finally:
                        shutil.rmtree(extract_dir, ignore_errors=True)
                except Exception as e:
                    deb_result["errors"].append(str(e))
                    logger.error(f"Error inspecting {deb}: {e}")
                forensic_results.append(deb_result)
        # Save results to JSON
        output_file = args.forensic_cml_deb_output
        try:
            with open(output_file, "w") as f:
                json.dump(forensic_results, f, indent=2)
            logger.info(f"Forensic inspection results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save forensic results to {output_file}: {e}")
        # Print summary to console
        logger.info("--- Forensic CML .deb Summary ---")
        for res in forensic_results:
            logger.info(f"{res['deb']}: virl2-uwm.service={res['virl2-uwm.service']}, virl2-controller.service={res['virl2-controller.service']}, errors={res['errors']}")
        logger.info("--- Forensic inspection complete. Review log and JSON for details. ---")
        sys.exit(0)

    # Run core checks
    logger.info(f"Starting validation for instance: {instance_id}")
    all_results = validator.run_all_checks(instance_id, ssh_key_path)

    # Optionally run CML service checks
    if args.check_cml_services:
        logger.info("Running CML service checks via SSM...")
        # Call the method without passing ssm_client or logger
        validator.check_cml_services_via_ssm(instance_id)
        # Consider adding results to all_results if needed

    # Display/Save results (assuming save_results method exists)
    logger.info("Validation checks complete. Saving results...")
    validator.save_results(all_results, instance_id)
    # Optional: Add display logic back if needed
    # print("--- Validation Summary ---")
    # print(json.dumps(all_results, indent=4, default=str))

    logger.info("Script finished.")
