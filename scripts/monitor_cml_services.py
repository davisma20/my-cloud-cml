#!/usr/bin/env python3
"""
CML Service Monitoring Script

This script monitors the status of Cisco Modeling Labs (CML) services in AWS
using the AWS SDK for Python (boto3). It can be used to automate the verification
of service status during and after CML deployment.

Usage:
  python monitor_cml_services.py --instance-id <aws-instance-id> --region <aws-region> [--interval <seconds>]

Author: Mike Davis (davisma20@gmail.com)
Date: March 22, 2025
Version: 1.0.0
"""

import argparse
import time
import json
import boto3
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

# Configure colored output for better readability
try:
    from colorama import init, Fore, Style
    init()
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    print("Note: Install colorama for colored output: pip install colorama")

# Service definitions
CML_SERVICES = [
    "cml_install.service",
    "cml.service",
    "virl2-uwsgi.service",
    "virl2-nginx.service"
]

def print_colored(text: str, color_code: str, bold: bool = False) -> None:
    """Print colored text if colorama is available."""
    if COLOR_ENABLED:
        style = Style.BRIGHT if bold else ""
        print(f"{style}{color_code}{text}{Style.RESET_ALL}")
    else:
        print(text)

def run_ssm_command(ssm_client, instance_id: str, command: str) -> Dict:
    """Run a command on an EC2 instance using SSM and return the command details."""
    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]}
        )
        command_id = response['Command']['CommandId']
        return command_id
    except Exception as e:
        print_colored(f"Error sending command: {str(e)}", Fore.RED if COLOR_ENABLED else "")
        sys.exit(1)

def get_command_output(ssm_client, command_id: str, instance_id: str) -> Dict:
    """Get the output of a command run through SSM."""
    time.sleep(1)  # Brief pause to allow command to execute
    max_attempts = 10
    attempts = 0
    
    while attempts < max_attempts:
        try:
            result = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            if result['Status'] in ['Success', 'Failed']:
                return result
            attempts += 1
            time.sleep(2)
        except ssm_client.exceptions.InvocationDoesNotExist:
            attempts += 1
            time.sleep(2)
    
    print_colored("Command timed out waiting for response", Fore.YELLOW if COLOR_ENABLED else "")
    return {"Status": "Timeout", "StatusDetails": "Timed out waiting for response"}

def check_service_status(ssm_client, instance_id: str, service_name: str) -> Dict:
    """Check the status of a specific service."""
    command_id = run_ssm_command(ssm_client, instance_id, f"systemctl status {service_name}")
    result = get_command_output(ssm_client, command_id, instance_id)
    
    status = {
        "service": service_name,
        "running": False,
        "status": "Unknown",
        "details": "",
    }
    
    if result['Status'] == 'Success':
        output = result.get('StandardOutputContent', '')
        if "Active: active (running)" in output:
            status["running"] = True
            status["status"] = "Running"
        elif "Active: inactive (dead)" in output:
            status["status"] = "Inactive"
        elif "Active: failed" in output:
            status["status"] = "Failed"
        elif "could not be found" in output:
            status["status"] = "Not Found"
        else:
            status["status"] = "Unknown"
        
        # Extract additional details
        status["details"] = output.strip()
    else:
        error = result.get('StandardErrorContent', '')
        status["status"] = "Error"
        status["details"] = error or "Failed to get service status"
    
    return status

def check_cml_package(ssm_client, instance_id: str) -> Dict:
    """Check if the CML package is installed."""
    command_id = run_ssm_command(ssm_client, instance_id, "dpkg -l | grep cml2")
    result = get_command_output(ssm_client, command_id, instance_id)
    
    if result['Status'] == 'Success' and result.get('StandardOutputContent', ''):
        return {
            "installed": True,
            "details": result['StandardOutputContent'].strip()
        }
    else:
        return {
            "installed": False,
            "details": "CML package not found in dpkg database"
        }

def check_network_connectivity(ssm_client, instance_id: str) -> Dict:
    """Check network connectivity and ports."""
    command_id = run_ssm_command(ssm_client, instance_id, "ss -tulpn | grep -E ':80|:443'")
    result = get_command_output(ssm_client, command_id, instance_id)
    
    if result['Status'] == 'Success' and result.get('StandardOutputContent', ''):
        return {
            "web_ports_open": True,
            "details": result['StandardOutputContent'].strip()
        }
    else:
        return {
            "web_ports_open": False,
            "details": "No web server ports detected"
        }

def check_root_files(ssm_client, instance_id: str) -> Dict:
    """Check CML related files in the root directory."""
    command_id = run_ssm_command(ssm_client, instance_id, "ls -la /root/cml2*")
    result = get_command_output(ssm_client, command_id, instance_id)
    
    if result['Status'] == 'Success' and result.get('StandardOutputContent', ''):
        return {
            "files_found": True,
            "details": result['StandardOutputContent'].strip()
        }
    else:
        return {
            "files_found": False,
            "details": "No CML files found in /root/"
        }

def display_status_summary(status_data: Dict) -> None:
    """Display a summary of the status information."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("\n" + "="*80)
    print_colored(f"CML SERVICE STATUS SUMMARY (as of {now})", Fore.CYAN if COLOR_ENABLED else "", bold=True)
    print("="*80)
    
    # Display service status
    print_colored("\nSERVICE STATUS:", Fore.CYAN if COLOR_ENABLED else "", bold=True)
    for service in status_data["services"]:
        service_name = service["service"]
        status = service["status"]
        
        # Determine color based on status
        if service["running"]:
            status_color = Fore.GREEN if COLOR_ENABLED else ""
        elif status in ["Failed", "Error"]:
            status_color = Fore.RED if COLOR_ENABLED else ""
        elif status == "Not Found":
            status_color = Fore.YELLOW if COLOR_ENABLED else ""
        else:
            status_color = Fore.WHITE if COLOR_ENABLED else ""
        
        print(f"  {service_name:25} : ", end="")
        print_colored(f"{status}", status_color)
    
    # Display package status
    print_colored("\nPACKAGE STATUS:", Fore.CYAN if COLOR_ENABLED else "", bold=True)
    if status_data["package"]["installed"]:
        print_colored("  CML Package is installed", Fore.GREEN if COLOR_ENABLED else "")
        print(f"  {status_data['package']['details']}")
    else:
        print_colored("  CML Package is NOT installed", Fore.RED if COLOR_ENABLED else "")
    
    # Display network status
    print_colored("\nNETWORK STATUS:", Fore.CYAN if COLOR_ENABLED else "", bold=True)
    if status_data["network"]["web_ports_open"]:
        print_colored("  Web server ports are open", Fore.GREEN if COLOR_ENABLED else "")
    else:
        print_colored("  Web server ports are NOT open", Fore.YELLOW if COLOR_ENABLED else "")
    
    # Display file status
    print_colored("\nINSTALLATION FILES:", Fore.CYAN if COLOR_ENABLED else "", bold=True)
    if status_data["files"]["files_found"]:
        print_colored("  CML files found in /root/", Fore.GREEN if COLOR_ENABLED else "")
        print(f"  {status_data['files']['details']}")
    else:
        print_colored("  No CML files found in /root/", Fore.RED if COLOR_ENABLED else "")
    
    print("\n" + "="*80)

def monitor_cml_services(instance_id: str, region: str, interval: int = 60) -> None:
    """Monitor CML services and display status periodically."""
    try:
        ssm_client = boto3.client('ssm', region_name=region)
        
        while True:
            # Collect status information
            services_status = []
            for service in CML_SERVICES:
                status = check_service_status(ssm_client, instance_id, service)
                services_status.append(status)
            
            package_status = check_cml_package(ssm_client, instance_id)
            network_status = check_network_connectivity(ssm_client, instance_id)
            file_status = check_root_files(ssm_client, instance_id)
            
            # Compile full status data
            status_data = {
                "instance_id": instance_id,
                "timestamp": datetime.now().isoformat(),
                "services": services_status,
                "package": package_status,
                "network": network_status,
                "files": file_status
            }
            
            # Display status summary
            display_status_summary(status_data)
            
            # Check if installation is complete
            cml_service_status = next((s for s in services_status if s["service"] == "cml.service"), None)
            if cml_service_status and cml_service_status["running"]:
                print_colored("\nCML INSTALLATION COMPLETE! Services are running successfully.", 
                             Fore.GREEN if COLOR_ENABLED else "", bold=True)
                break
            
            # If not running and interval specified, wait and check again
            if interval > 0:
                print(f"\nWaiting {interval} seconds before next check...\n")
                time.sleep(interval)
            else:
                break
    
    except KeyboardInterrupt:
        print_colored("\nMonitoring stopped by user.", Fore.YELLOW if COLOR_ENABLED else "")
    except Exception as e:
        print_colored(f"\nError during monitoring: {str(e)}", Fore.RED if COLOR_ENABLED else "")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Monitor CML services in AWS.")
    parser.add_argument("--instance-id", "-i", required=True, help="AWS Instance ID")
    parser.add_argument("--region", "-r", required=True, help="AWS Region")
    parser.add_argument("--interval", "-t", type=int, default=60, 
                        help="Interval between checks in seconds (0 for one-time check)")
    
    args = parser.parse_args()
    
    print_colored(f"Starting CML service monitoring for instance {args.instance_id} in region {args.region}",
                 Fore.CYAN if COLOR_ENABLED else "", bold=True)
    
    monitor_cml_services(args.instance_id, args.region, args.interval)

if __name__ == "__main__":
    main()
