import logging
import base64
import subprocess
import textwrap
import binascii # For catching specific base64 errors
from botocore.exceptions import ClientError

def get_system_log_boto3(ec2_client, instance_id):
    """Retrieves the system log using Boto3 ec2_client.get_console_output."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Retrieving System Log (Boto3 Method) ---")
    results = {'status': 'Not Checked', 'details': {}}
    raw_log = None

    if not ec2_client:
        results['status'] = 'Error (Client Setup Failed)'
        results['details']['error'] = 'EC2 client could not be initialized.'
        return results, raw_log
    
    try:
        response = ec2_client.get_console_output(InstanceId=instance_id, Latest=True)
        logger.debug(f"get_console_output response keys: {response.keys()}")
        if 'Output' in response:
            # The output is Base64 encoded, need to decode it
            encoded_log = response['Output']
            logger.debug("Attempting to decode Base64 log output...")
            try:
                # Ensure encoded_log is bytes. If it's str, encode first using UTF-8.
                if isinstance(encoded_log, str):
                    encoded_log_bytes = encoded_log.encode('utf-8') # Changed from 'ascii'
                else:
                    encoded_log_bytes = encoded_log
                decoded_log = base64.b64decode(encoded_log_bytes).decode('utf-8', errors='replace')
                raw_log = decoded_log
                results['status'] = 'Passed'
                results['details']['decoded_log'] = decoded_log[:5000] # Limit for display
            except (binascii.Error, Exception) as e:
                logger.error(f"Failed to decode Base64 system log: {e}")
                results['status'] = 'Error (Decode Failed)'
                results['details']['error'] = str(e)
        else:
            logger.warning("No 'Output' key in get_console_output response.")
            results['status'] = 'No Output'
    except ClientError as e:
        logger.error(f"Error retrieving system log: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error retrieving system log: {e}")
        results['status'] = 'Error'
        results['details']['error'] = str(e)
    logger.info("--- Finished Retrieving System Log (Boto3 Method) ---")
    return results, raw_log

def get_system_log_cli(instance_id, region):
    """Retrieves the system log using the AWS CLI."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Retrieving System Log (AWS CLI Method) ---")
    results = {'status': 'Not Checked', 'details': {}}
    raw_log = None
    try:
        cli_command = [
            'aws', 'ec2', 'get-console-output',
            '--instance-id', instance_id,
            '--region', region,
            '--output', 'text',
            '--query', 'Output'
        ]
        logger.debug(f"Running AWS CLI command: {' '.join(cli_command)}")
        cli_output = subprocess.check_output(cli_command, stderr=subprocess.STDOUT, timeout=10)
        # Output is Base64 encoded, decode it
        decoded_log = base64.b64decode(cli_output).decode('utf-8', errors='replace')
        raw_log = decoded_log
        results['status'] = 'Passed'
        results['details']['decoded_log'] = decoded_log[:5000]
    except subprocess.CalledProcessError as e:
        logger.error(f"AWS CLI command failed: {e.output}")
        results['status'] = 'Error (CLI Failed)'
        results['details']['error'] = str(e.output)
    except FileNotFoundError:
        logger.error("AWS CLI executable not found.")
        results['status'] = 'Error (CLI Not Found)'
        results['details']['error'] = 'AWS CLI executable not found.'
    except Exception as e:
        logger.error(f"An unexpected error occurred running AWS CLI: {e}")
        results['status'] = 'Error (Unexpected)'
        results['details']['error'] = str(e)
    logger.info("--- Finished Retrieving System Log (AWS CLI Method) ---")
    return results, raw_log

def format_log_output(log_content, max_lines=50, line_length=100):
    """Formats the log output for display, limiting lines and wrapping text."""
    logger = logging.getLogger('AwsCmlValidator')
    if not log_content:
        return "  Log content is empty or was not retrieved.\n"
    lines = log_content.strip().split('\n')
    num_lines = len(lines)
    if num_lines > max_lines:
        display_lines = lines[-max_lines:]
        log_snippet = f"(Showing last {max_lines} of {num_lines} lines)\n"
    else:
        display_lines = lines
        log_snippet = f"(Total {num_lines} lines)\n"
    wrapped_lines = []
    for line in display_lines:
        wrapped = textwrap.wrap(line, width=line_length, replace_whitespace=False)
        if not wrapped:
            wrapped_lines.append("")
        else:
            wrapped_lines.extend(wrapped)
    log_snippet += "\n".join([f"  | {line}" for line in wrapped_lines])
    log_snippet += "\n"
    logger.debug(f"Formatted log snippet created. Original lines: {num_lines}, Displayed lines (approx): {len(wrapped_lines)}")
    return log_snippet
