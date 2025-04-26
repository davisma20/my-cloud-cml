import json
import logging
import datetime
import os

# Import the log formatting utility
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

    # IAM Permissions
    summary += "--- IAM Permissions ---\n"
    if 'iam_permissions' in results:
        iam_results = results['iam_permissions']
        summary += f"  Check Status: {iam_results.get('status', 'Unknown')}\n"
        # Optionally list checked permissions and their status from details
        # if 'details' in iam_results:
        #     for perm, status in iam_results['details'].items():
        #         summary += f"    - {perm}: {status}\n"
    else:
        summary += "  Not checked or results missing.\n"
    summary += "\n"

    # Security Groups
    summary += "--- Security Groups ---\n"
    if 'security_groups' in results:
        sg_results = results['security_groups']
        # Use the ids_found list which should be stored during the check
        raw_ids = sg_results.get('ids_found', []) 
        summary += f"  Groups Found (IDs): {', '.join(raw_ids) if raw_ids else 'None'}\n"
        summary += f"  Check Status: {sg_results.get('status', 'Unknown')}\n" 
        if sg_results.get('status') == 'Checked' and 'details' in sg_results:
            details = sg_results['details']
            summary += f"    - Outbound HTTP (80): {details.get('outbound_http', 'Not Checked')}\n"
            summary += f"    - Outbound HTTPS (443): {details.get('outbound_https', 'Not Checked')}\n"
            summary += f"    - Inbound SSH (22): {details.get('inbound_ssh', 'Not Checked')}\n"
        elif 'details' in sg_results and 'error' in sg_results['details']:
             summary += f"    - Error: {sg_results['details']['error']}\n"    
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # Network ACLs
    summary += "--- Network ACLs ---\n"
    if 'nacls' in results:
        nacl_results = results['nacls']
        summary += f"  Finding Status: {nacl_results.get('finding_status', 'Unknown')}\n"
        summary += f"  NACL ID Found: {nacl_results.get('nacl_id', 'Not Found')}\n"
        summary += f"  Rule Check Status: {nacl_results.get('rule_check_status', 'Not Checked')}\n"
        if nacl_results.get('rule_check_status') == 'Checked' and 'rule_details' in nacl_results:
            details = nacl_results['rule_details']
            summary += f"    - Outbound HTTP (80): {details.get('outbound_http', 'Not Checked')}\n"
            summary += f"    - Outbound HTTPS (443): {details.get('outbound_https', 'Not Checked')}\n"
            summary += f"    - Inbound Ephemeral (1024-65535): {details.get('inbound_ephemeral', 'Not Checked')}\n"
        elif 'details' in nacl_results and 'error' in nacl_results['details']:
             summary += f"    - Error: {nacl_results['details']['error']}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # SSM Agent
    summary += "--- SSM Agent Check ---\n"
    if 'ssm_check' in results:
        ssm_results = results['ssm_check']
        summary += f"  Status: {ssm_results.get('status', 'Unknown')}\n"
        if 'details' in ssm_results:
            details = ssm_results['details']
            summary += f"    - SSM Status: {details.get('ssm_status', 'N/A')}\n"
            if 'output' in details:
                summary += f"    - Output: {details.get('output', '')}\n"
            if 'error' in details:
                summary += f"    - Error: {details.get('error', '')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # SSH Connection
    summary += "--- SSH Connection Check ---\n"
    if 'ssh_check' in results:
        ssh_results = results['ssh_check']
        summary += f"  Status: {ssh_results.get('status', 'Unknown')}\n"
        if 'details' in ssh_results:
            details = ssh_results['details']
            if 'message' in details:
                summary += f"    - Message: {details.get('message', '')}\n"
            if 'error' in details:
                 summary += f"    - Error: {details.get('error', '')}\n"
    else:
        summary += "  Not checked or no results.\n"
    summary += "\n"

    # System Log
    summary += "--- System Log ---\n"
    if 'system_log' in results:
        log_results = results['system_log']
        summary += f"  Retrieval Status: {log_results.get('status', 'Unknown')}\n"
        if log_results.get('status') == 'Retrieved':
            log_content = log_results.get('details', {}).get('log_content', '')
            summary += format_log_output(log_content) # Use the imported formatter
        elif 'details' in log_results and 'error' in log_results['details']:
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
        # Ensure parent directory exists (optional, if prefix includes path)
        # dirname = os.path.dirname(filename)
        # if dirname:
        #     os.makedirs(dirname, exist_ok=True)
            
        with open(filename, 'w') as f:
            # Use default=str to handle non-serializable types like datetime if they sneak in
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
