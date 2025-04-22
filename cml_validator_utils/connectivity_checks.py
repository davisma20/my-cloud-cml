import logging
import time
import paramiko
from botocore.exceptions import ClientError

# --- SSM Agent Check ---

def get_ssm_client(session, endpoint_url=None):
    """Returns an SSM client from the session."""
    logger = logging.getLogger('AwsCmlValidator')
    if not session:
        logger.error("Cannot create SSM client: Boto3 session is not available.")
        return None
    logger.debug(f"Creating SSM client with endpoint URL: {endpoint_url if endpoint_url else 'Default'}")
    try:
        return session.client('ssm', endpoint_url=endpoint_url)
    except ClientError as e:
        logger.error(f"Failed to create SSM client: {e}")
        return None

def check_ssm_agent(session, instance_id, endpoint_url=None):
    """Checks if the SSM agent is running via a simple command."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Starting SSM Agent Check ---")
    results = {'status': 'Not Checked', 'details': {}}
    ssm_client = get_ssm_client(session, endpoint_url)

    if not ssm_client:
        results['status'] = 'Error (Client Setup Failed)'
        results['details']['error'] = 'SSM client could not be initialized.'
        return results
    
    command = "echo 'SSM Agent is responding'" # Simple command to test connectivity
    
    try:
        logger.info(f"Sending test command to instance {instance_id} via SSM Run Command.")
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
            TimeoutSeconds=60 # Allow some time for command execution
        )
        command_id = response['Command']['CommandId']
        logger.info(f"SSM Command sent. Command ID: {command_id}")

        # Wait for the command to complete
        status = 'Pending'
        output = ''
        wait_time = 5 # Initial wait time
        max_wait_cycles = 12 # ~60 seconds total max wait
        cycle = 0
        
        while status in ['Pending', 'InProgress'] and cycle < max_wait_cycles:
            time.sleep(wait_time)
            invocation = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            status = invocation['Status']
            output = invocation.get('StandardOutputContent', '')
            logger.debug(f"SSM command status check ({cycle+1}/{max_wait_cycles}): {status}")
            cycle += 1

        results['details']['ssm_status'] = status
        results['details']['output'] = output.strip()

        if status == 'Success':
            logger.info("SSM agent check successful.")
            results['status'] = 'Passed'
        elif status == 'TimedOut':
            logger.error("SSM command timed out. Agent might be stopped or unreachable.")
            results['status'] = 'Failed (Timeout)'
        elif status == 'Failed':
             logger.error(f"SSM command failed to execute on instance. StatusDetails: {invocation.get('StatusDetails')}")
             results['status'] = 'Failed (Execution)'
        else:
            logger.warning(f"SSM command finished with unexpected status: {status}")
            results['status'] = f'Warning ({status})'

    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceId':
            logger.error(f"SSM Error: Instance {instance_id} not found or not managed by SSM.")
            results['status'] = 'Failed (InvalidInstanceId)'
        elif e.response['Error']['Code'] == 'InstanceNotConnected':
             logger.error(f"SSM Error: Instance {instance_id} is not connected to SSM.")
             results['status'] = 'Failed (NotConnected)'
        else:
            logger.error(f"AWS ClientError during SSM check: {e}")
            results['status'] = 'Error (AWS ClientError)'
        results['details']['error'] = str(e)
    except Exception as e:
        logger.error(f"An unexpected error occurred during SSM check: {e}")
        results['status'] = 'Error (Unexpected)'
        results['details']['error'] = str(e)

    logger.info("--- Finished SSM Agent Check ---")
    return results

# --- SSH Connection Check ---

SSH_USERNAME = "ubuntu" # Default username, can be overridden if needed
DEFAULT_SSH_TIMEOUT = 10 # Seconds

def check_ssh_connection(instance_ip, ssh_key_path, username=SSH_USERNAME, timeout=DEFAULT_SSH_TIMEOUT):
    """Attempts to establish an SSH connection to the instance."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Starting SSH Connection Check ---")
    results = {'status': 'Not Checked', 'details': {}}
    
    if not instance_ip:
        logger.warning("Instance IP address not available. Skipping SSH check.")
        results['status'] = 'Skipped (No IP)'
        return results

    if not ssh_key_path:
         logger.error("SSH private key path not provided. Cannot attempt SSH connection.")
         results['status'] = 'Error (Key Missing)'
         results['details']['error'] = 'SSH Key path configuration missing.'
         return results

    logger.info(f"Attempting SSH connection to {instance_ip} as user '{username}' with key {ssh_key_path}")
    
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Or WarningPolicy

    try:
        # Load private key
        try:
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
            # If using Ed25519 keys, use: 
            # private_key = paramiko.Ed25519Key.from_private_key_file(ssh_key_path)
            logger.debug("SSH private key loaded successfully.")
        except IOError as e:
            logger.error(f"Failed to read SSH private key file {ssh_key_path}: {e}")
            results['status'] = 'Error (Key Read Failed)'
            results['details']['error'] = f"Cannot read key file: {e}"
            return results
        except paramiko.PasswordRequiredException:
            logger.error(f"SSH private key file {ssh_key_path} is encrypted (password protected). Passwordless keys are required for this check.")
            results['status'] = 'Error (Key Encrypted)'
            results['details']['error'] = "SSH key is password protected."
            return results
        except paramiko.SSHException as e:
            logger.error(f"Error loading SSH private key {ssh_key_path}: {e}")
            results['status'] = 'Error (Key Load Failed)'
            results['details']['error'] = f"Key loading error: {e}"
            return results
            
        # Connect
        ssh_client.connect(
            hostname=instance_ip,
            username=username,
            pkey=private_key,
            timeout=timeout,
            allow_agent=False, # Ensure we use the provided key
            look_for_keys=False # Ensure we use the provided key
        )
        logger.info("SSH connection successful.")
        results['status'] = 'Passed'
        results['details']['message'] = 'Connection successful.'

    except paramiko.AuthenticationException as e:
        logger.error(f"SSH Authentication failed for user '{username}': {e}")
        results['status'] = 'Failed (Authentication)'
        results['details']['error'] = str(e)
    except paramiko.SSHException as e:
        logger.error(f"SSH connection error: {e}")
        results['status'] = 'Failed (Connection Error)'
        results['details']['error'] = str(e)
    except TimeoutError:
        logger.error(f"SSH connection timed out after {timeout} seconds.")
        results['status'] = 'Failed (Timeout)'
        results['details']['error'] = f"Connection timed out ({timeout}s)."
    except Exception as e:
        logger.error(f"An unexpected error occurred during SSH check: {e}")
        results['status'] = 'Error (Unexpected)'
        results['details']['error'] = str(e)
    finally:
        if ssh_client:
            ssh_client.close()
            logger.debug("SSH client closed.")

    logger.info("--- Finished SSH Connection Check ---")
    return results
