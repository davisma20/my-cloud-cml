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
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]},
        )
        command_id = response['Command']['CommandId']
        logger.debug(f"Sent SSM command: {command_id}")
        # Wait for command to finish
        waiter = ssm_client.get_waiter('command_executed')
        waiter.wait(CommandId=command_id, InstanceId=instance_id, WaiterConfig={'Delay': 2, 'MaxAttempts': 10})
        invocation = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        if invocation['Status'] == 'Success':
            results['status'] = 'Passed'
            results['details']['message'] = invocation['StandardOutputContent']
        else:
            results['status'] = 'Failed'
            results['details']['error'] = invocation['StandardErrorContent']
    except Exception as e:
        logger.error(f"Error during SSM agent check: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    logger.info("--- Finished SSM Agent Check ---")
    return results

# --- SSH Connection Check ---
def check_ssh_connection(instance_ip, username, key_path, timeout=10):
    """Checks SSH connectivity to the instance."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info(f"--- Starting SSH Connection Check to {instance_ip} ---")
    results = {'status': 'Not Checked', 'details': {}}
    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Load private key
        try:
            private_key = paramiko.RSAKey.from_private_key_file(key_path)
        except Exception as e:
            logger.error(f"Could not load SSH key: {e}")
            results['status'] = 'Error (Key Load Failed)'
            results['details']['error'] = f"Could not load SSH key: {e}"
            return results
        # Connect
        ssh_client.connect(instance_ip, username=username, pkey=private_key, timeout=timeout)
        results['status'] = 'Passed'
        results['details'] = {'message': 'SSH connection successful.'}
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
