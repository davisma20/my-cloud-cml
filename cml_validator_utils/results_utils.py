import json
import logging
import datetime
import os

from .log_utils import format_log_output

def format_results_summary(results, instance_id, region):
    """Formats the collected results into a human-readable summary string."""
    logger = logging.getLogger('AwsCmlValidator')
    logger.info("--- Formatting Results Summary ---")
    summary = f"\n=== CML Instance Validation Summary ({datetime.datetime.now().isoformat()}) ===\n"
    summary += f"Instance ID: {instance_id}\n"
    summary += f"Region:      {region}\n"
    summary += "---\n\n"

    # Instance Status
    summary += "--- Instance Status ---\n"
    if 'instance_status' in results:
        status_results = results['instance_status']
        summary += f"  Instance State: {status_results.get('state', 'Unknown')}\n"
        summary += f"  Status Checks: {status_results.get('summary', 'Unknown')}\n"
        if 'details' in status_results:
            summary += f"    - System Status: {status_results['details'].get('SystemStatus', {}).get('Status', 'N/A')}\n"
            summary += f"    - Instance Status: {status_results['details'].get('InstanceStatus', {}).get('Status', 'N/A')}\n"
    else:
        summary += "  Status not checked or results missing.\n"
    summary += "\n"

    # Security Groups
    summary += "--- Security Group Checks ---\n"
    if 'security_groups' in results:
        sg_results = results['security_groups']
        summary += f"  HTTP:  {sg_results['details'].get('http', 'N/A')}\n"
        summary += f"  HTTPS: {sg_results['details'].get('https', 'N/A')}\n"
        summary += f"  SSH:   {sg_results['details'].get('ssh', 'N/A')}\n"
        summary += f"  Status: {sg_results.get('status', 'Unknown')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # NACL Checks
    summary += "--- NACL Checks ---\n"
    if 'nacl' in results:
        nacl_results = results['nacl']
        summary += f"  Status: {nacl_results.get('status', 'Unknown')}\n"
        if 'details' in nacl_results:
            summary += f"    - Allowed: {nacl_results['details'].get('allowed', 'N/A')}\n"
            summary += f"    - Denied:  {nacl_results['details'].get('denied', 'N/A')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # SSM Agent
    summary += "--- SSM Agent Check ---\n"
    if 'ssm_agent' in results:
        ssm_results = results['ssm_agent']
        summary += f"  Status: {ssm_results.get('status', 'Unknown')}\n"
        if 'details' in ssm_results:
            summary += f"    - Message: {ssm_results['details'].get('message', 'N/A')}\n"
            summary += f"    - Error:   {ssm_results['details'].get('error', 'N/A')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # SSH Connection
    summary += "--- SSH Connection Check ---\n"
    if 'ssh_connection' in results:
        ssh_results = results['ssh_connection']
        summary += f"  Status: {ssh_results.get('status', 'Unknown')}\n"
        if 'details' in ssh_results:
            summary += f"    - Message: {ssh_results['details'].get('message', 'N/A')}\n"
            summary += f"    - Error:   {ssh_results['details'].get('error', 'N/A')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # System Log
    summary += "--- System Log ---\n"
    if 'system_log' in results:
        log_results = results['system_log']
        summary += f"  Status: {log_results.get('status', 'Unknown')}\n"
        if 'details' in log_results:
            summary += format_log_output(log_results['details'].get('decoded_log', ''), max_lines=10)
            if 'error' in log_results['details']:
                summary += f"    - Error: {log_results['details']['error']}\n"
            if 'raw_encoded_output' in log_results['details']:
                 summary += f"    - Raw Output (partial): {log_results['details']['raw_encoded_output'][:200]}...\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    summary += "=== End of Summary ===\n"
    logger.info("--- Finished Formatting Results Summary ---")
    return summary

def save_results_to_file(results, instance_id, filename_prefix="validation_results"):
    """Saves the validation results dictionary to a JSON file."""
    logger = logging.getLogger('AwsCmlValidator')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{instance_id}_{timestamp}.json"
    logger.info(f"Saving validation results to: {filename}")
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        logger.info(f"Results successfully saved to {filename}")
        return True
    except IOError as e:
        logger.error(f"Failed to write results to file {filename}: {e}")
    except TypeError as e:
        logger.error(f"Failed to serialize results to JSON: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred saving results to {filename}: {e}")
    return False
