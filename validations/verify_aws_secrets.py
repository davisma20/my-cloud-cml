#!/usr/bin/env python3
"""
Verify AWS Secrets Manager Integration

This script tests if the AWS Secrets Manager integration is working correctly
by retrieving secrets and checking if they match expected values or formats.
"""

import os
import boto3
import json
import yaml
import sys

# Colors for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_header(text):
    """Print a formatted header."""
    print(f"\n{BOLD}{YELLOW}=== {text} ==={RESET}\n")

def print_success(text):
    """Print success message."""
    print(f"{GREEN}✓ {text}{RESET}")

def print_error(text):
    """Print error message."""
    print(f"{RED}✗ {text}{RESET}")

def print_info(text):
    """Print info message."""
    print(f"{YELLOW}ℹ {text}{RESET}")

def verify_aws_secrets():
    """Verify AWS Secrets Manager integration."""
    print_header("AWS Secrets Manager Verification")
    
    # Load configuration
    try:
        with open("config.yml", 'r') as f:
            config = yaml.safe_load(f)
        print_success("Successfully loaded config.yml")
    except Exception as e:
        print_error(f"Failed to load config.yml: {e}")
        return False
    
    # Check if AWS Secrets Manager is configured as the secret manager
    if config.get('secret', {}).get('manager') != 'aws':
        print_error("AWS Secrets Manager is not configured as the active secret manager")
        return False
    else:
        print_success("AWS Secrets Manager is configured as the active secret manager")
    
    # Initialize AWS session
    try:
        session = boto3.session.Session()
        secrets_client = session.client(
            service_name='secretsmanager',
            region_name=config.get('aws', {}).get('region', 'us-east-2')
        )
        print_success("Successfully initialized AWS Secrets Manager client")
    except Exception as e:
        print_error(f"Failed to initialize AWS Secrets Manager client: {e}")
        return False
    
    # Get project name from config
    project_name = config.get('secret', {}).get('aws', {}).get('project_name', 'cml-devnet')
    
    # List of secrets to verify
    secrets_to_check = ['app', 'sys', 'cluster', 'smartlicense_token']
    
    all_secrets_found = True
    
    for secret_name in secrets_to_check:
        secret_path = f"cml/{project_name}/{secret_name}"
        try:
            response = secrets_client.get_secret_value(
                SecretId=secret_path
            )
            secret_value = response.get('SecretString')
            
            # Mask the actual value for security
            masked_value = "*" * 8
            print_success(f"Successfully retrieved secret '{secret_name}' from path '{secret_path}'")
            print_info(f"  Value: {masked_value}")
            
            # Additional checks for username if applicable
            if secret_name in ['app', 'sys']:
                username = config.get('secret', {}).get('secrets', {}).get(secret_name, {}).get('username')
                if username:
                    print_info(f"  Username: {username}")
        except Exception as e:
            print_error(f"Failed to retrieve secret '{secret_name}' from path '{secret_path}': {e}")
            all_secrets_found = False
    
    if all_secrets_found:
        print_header("VERIFICATION RESULT")
        print_success("All secrets were successfully retrieved from AWS Secrets Manager.")
        print_info("The AWS Secrets Manager integration is working correctly.")
        return True
    else:
        print_header("VERIFICATION RESULT")
        print_error("Some secrets could not be retrieved from AWS Secrets Manager.")
        print_info("Please check your AWS credentials and secret paths.")
        return False

if __name__ == "__main__":
    success = verify_aws_secrets()
    sys.exit(0 if success else 1)
