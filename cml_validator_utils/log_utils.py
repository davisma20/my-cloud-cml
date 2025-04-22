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
                    # If it's already bytes (less common for get_console_output), use as is
                    # This branch might need adjustment if boto3 changes behavior
                    encoded_log_bytes = encoded_log
                
                decoded_bytes = base64.b64decode(encoded_log_bytes)
                raw_log = decoded_bytes.decode('utf-8', errors='ignore') # Decode bytes to string, ignore errors
                logger.info("System log retrieved and decoded successfully via Boto3.")
                results['status'] = 'Retrieved'
                results['details']['log_content'] = raw_log
            except (binascii.Error, TypeError, ValueError) as decode_error:
                logger.error(f"Base64 decoding failed: {decode_error}")
                logger.debug(f"Problematic encoded data (first 100 chars): {encoded_log[:100]}")
                results['status'] = 'Error (Decoding Failed)'
                results['details']['error'] = f"Base64 decoding error: {decode_error}"
                results['details']['raw_encoded_output'] = encoded_log # Store raw for inspection
            except Exception as e:
                 logger.error(f"Unexpected error during decoding: {e}")
                 results['status'] = 'Error (Decoding Failed)'
                 results['details']['error'] = f"Unexpected decoding error: {e}"
        else:
            logger.warning("No 'Output' key found in get_console_output response.")
            results['status'] = 'Warning (No Output)'
            results['details']['message'] = 'Console output might not be available yet or instance is stopped.'

    except ClientError as e:
        logger.error(f"AWS ClientError retrieving system log via Boto3: {e}")
        results['status'] = 'Error (AWS ClientError)'
        results['details']['error'] = str(e)
    except Exception as e:
        logger.error(f"An unexpected error occurred retrieving system log via Boto3: {e}")
        results['status'] = 'Error (Unexpected)'
        results['details']['error'] = str(e)

    logger.info("--- Finished Retrieving System Log (Boto3 Method) ---")
    return results, raw_log # Return raw_log which might be None

def get_system_log_cli(instance_id, region, profile):
    """Retrieves the system log using AWS CLI.
    Handles potential decoding errors more robustly.
    """
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Retrieving System Log (AWS CLI Method) ---")
    results = {'status': 'Not Checked', 'details': {}}
    raw_log = None

    command = [
        "aws", "ec2", "get-console-output",
        "--instance-id", instance_id,
        "--region", region
    ]
    if profile:
        command += ["--profile", profile]
    command += ["--latest", "--output", "text"]

    try:
        logger.info(f"Executing command: {' '.join(map(str, command))}")
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            logger.error(f"AWS CLI command failed with exit code {proc.returncode}: {proc.stderr}")
            results['status'] = f'Error (Exit {proc.returncode})'
            results['details']['error'] = proc.stderr
            return results, raw_log
        raw_log = proc.stdout
        results['status'] = 'Retrieved'
        results['details']['message'] = 'System log retrieved via AWS CLI.'
    except subprocess.TimeoutExpired:
        logger.error("AWS CLI command timed out.")
        results['status'] = 'Error (Timeout)'
        results['details']['error'] = 'AWS CLI command timed out.'
    except FileNotFoundError:
        logger.error("AWS CLI command not found. Is it installed and in the system PATH?")
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
    
    # Take the last max_lines
    if num_lines > max_lines:
        display_lines = lines[-max_lines:]
        log_snippet = f"(Showing last {max_lines} of {num_lines} lines)\n"
    else:
        display_lines = lines
        log_snippet = f"(Total {num_lines} lines)\n"

    # Wrap long lines
    wrapped_lines = []
    for line in display_lines:
        wrapped = textwrap.wrap(line, width=line_length, replace_whitespace=False)
        if not wrapped: # Handle empty lines
            wrapped_lines.append("")
        else:
            wrapped_lines.extend(wrapped)
            
    log_snippet += "\n".join([f"  | {line}" for line in wrapped_lines])
    log_snippet += "\n"
    logger.debug(f"Formatted log snippet created. Original lines: {num_lines}, Displayed lines (approx): {len(wrapped_lines)}")
    return log_snippet
