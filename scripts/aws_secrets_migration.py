#!/usr/bin/env python3
"""
AWS Secrets Manager Migration Tool

This script helps migrate secrets to AWS Secrets Manager for the CML project.
It can create or update secrets in AWS Secrets Manager.

Usage:
    python aws_secrets_migration.py [--project-name PROJECT_NAME] [--region REGION]

Options:
    --project-name PROJECT_NAME    The project name to use for AWS Secrets Manager (default: cml-devnet)
    --region REGION                The AWS region to use (default: us-east-2)
"""

import argparse
import boto3
import json
import os
import sys
import yaml
import getpass
from botocore.exceptions import ClientError

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

def create_or_update_secret(client, secret_name, secret_value, tags=None):
    """
    Create or update a secret in AWS Secrets Manager.
    """
    if tags is None:
        tags = []
    
    try:
        # Check if the secret already exists
        client.get_secret_value(SecretId=secret_name)
        
        # If no exception, the secret exists, so update it
        client.update_secret(
            SecretId=secret_name,
            SecretString=secret_value
        )
        return f"Updated existing secret '{secret_name}'"
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # Secret doesn't exist, create it
            client.create_secret(
                Name=secret_name,
                Description=f"Secret for CML deployment: {secret_name}",
                SecretString=secret_value,
                Tags=tags
            )
            return f"Created new secret '{secret_name}'"
        else:
            raise e

def main():
    parser = argparse.ArgumentParser(description='Migrate secrets to AWS Secrets Manager for CML project')
    parser.add_argument('--project-name', type=str, default='cml-devnet', 
                        help='Project name to use for AWS Secrets Manager paths')
    parser.add_argument('--region', type=str, default='us-east-2', 
                        help='AWS region to use')
    args = parser.parse_args()
    
    print_header("AWS Secrets Manager Migration Tool")
    
    try:
        # Initialize AWS session
        session = boto3.session.Session(region_name=args.region)
        client = session.client('secretsmanager')
        print_success(f"Connected to AWS Secrets Manager in region {args.region}")
    except Exception as e:
        print_error(f"Failed to connect to AWS Secrets Manager: {e}")
        return 1
    
    # Define the secrets to migrate
    secrets = {
        'app': None,
        'sys': None,
        'cluster': None,
        'smartlicense_token': None,
    }
    
    # Get the values for each secret
    print_header("Secret Values")
    print_info("Please provide the value for each secret (or press Enter to skip):")
    
    for secret_name in secrets.keys():
        if secret_name in ['app', 'sys']:
            username = input(f"  {secret_name} username [Default: {'admin' if secret_name == 'app' else 'sysadmin'}]: ") or ('admin' if secret_name == 'app' else 'sysadmin')
            password = getpass.getpass(f"  {secret_name} password: ")
            if password:
                secrets[secret_name] = password
        else:
            value = getpass.getpass(f"  {secret_name}: ")
            if value:
                secrets[secret_name] = value
    
    # Confirm with the user
    print_header("Review")
    print_info(f"The following secrets will be created/updated in AWS Secrets Manager:")
    for secret_name, value in secrets.items():
        status = "Will be updated" if value else "Skipped (no value provided)"
        print(f"  - cml/{args.project_name}/{secret_name}: {status}")
    
    confirmation = input(f"\nProceed with migration? (y/n): ").lower().strip()
    if confirmation != 'y':
        print_info("Migration cancelled by user.")
        return 0
    
    # Migrate the secrets
    print_header("Migration")
    tags = [
        {'Key': 'Project', 'Value': args.project_name},
        {'Key': 'Environment', 'Value': 'production'},
        {'Key': 'ManagedBy', 'Value': 'terraform'}
    ]
    
    for secret_name, value in secrets.items():
        if value:
            try:
                aws_secret_path = f"cml/{args.project_name}/{secret_name}"
                result = create_or_update_secret(client, aws_secret_path, value, tags)
                print_success(result)
            except Exception as e:
                print_error(f"Failed to create/update secret '{secret_name}': {e}")
    
    print_header("Migration Complete")
    print_success("AWS Secrets Manager migration completed successfully.")
    print_info("Update your config.yml to use AWS Secrets Manager:")
    print("""
    secret:
      manager: aws
      aws:
        project_name: """ + args.project_name + """
        environment: production
      
      # Define your secrets in this section
      secrets:
        app:
          username: admin
        sys:
          username: sysadmin
        cluster:
          # Empty placeholder, actual value will come from AWS Secrets Manager
        smartlicense_token:
          # Empty placeholder, actual value will come from AWS Secrets Manager
    """)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
