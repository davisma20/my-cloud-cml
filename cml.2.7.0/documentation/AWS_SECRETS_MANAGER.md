# AWS Secrets Manager Integration

This document describes how to work with AWS Secrets Manager integration for the CML deployment.

## Overview

AWS Secrets Manager provides a secure way to store and manage sensitive information such as passwords, API keys, and other secrets needed for CML deployment. The integration in this project uses AWS Secrets Manager as the primary secret storage mechanism, retrieving secrets during deployment and avoiding the need to store sensitive information in configuration files or repositories.

## Configuration

### Prerequisites

1. **AWS Account**: You need an AWS account with necessary permissions to create and manage secrets in AWS Secrets Manager.
2. **IAM Permissions**: The IAM user or role used by Terraform should have the following permissions:
   ```
   secretsmanager:GetSecretValue
   secretsmanager:DescribeSecret
   ```

### Setup

1. **Configure AWS Credentials**: Ensure your AWS credentials are configured locally using one of these methods:
   - AWS CLI configuration (`aws configure`)
   - Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
   - AWS credentials file (`~/.aws/credentials`)

2. **Update config.yml**: Set AWS Secrets Manager as the active secret manager:
   ```yaml
   secret:
     manager: aws
     aws:
       project_name: cml-devnet
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
   ```

## Secret Naming Convention

The AWS Secrets Manager integration uses the following naming convention for secrets:

```
cml/<project_name>/<secret_name>
```

Where:
- `project_name` is defined in the `config.yml` (default: `cml-devnet`)
- `secret_name` is one of:
  - `app` - Application admin password
  - `sys` - System admin password
  - `cluster` - Cluster secret for CML clustering
  - `smartlicense_token` - Smart licensing token for CML

## Using the Migration Tool

A migration tool is provided to help migrate secrets to AWS Secrets Manager:

```bash
python scripts/aws_secrets_migration.py --project-name cml-devnet --region us-east-2
```

The tool will:
1. Connect to AWS Secrets Manager
2. Prompt for secret values
3. Create or update secrets in AWS Secrets Manager
4. Display a summary of the migration

## Verification

To verify that the AWS Secrets Manager integration is working correctly:

```bash
python verify_aws_secrets.py
```

This script will:
1. Check that AWS Secrets Manager is the active secret manager in the configuration
2. Verify that all required secrets can be retrieved
3. Output a summary of the verification results

## IAM Policy

The following IAM policy can be used to grant the necessary permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:cml/*"
    }
  ]
}
```

## Troubleshooting

### Common Issues

1. **Secret Not Found**: Ensure that the secret exists in AWS Secrets Manager with the correct naming convention.
2. **Permission Denied**: Verify that your IAM user or role has the necessary permissions to access the secrets.
3. **Region Mismatch**: Ensure that you're using the same AWS region for both creating and accessing secrets.

### Debugging

To debug issues with AWS Secrets Manager integration:

1. **Check AWS Secrets Manager Console**: Verify that the secrets exist in the correct region.
2. **Run the Verification Script**: Use `verify_aws_secrets.py` to diagnose specific issues.
3. **Check AWS Credentials**: Ensure your AWS credentials are valid and have not expired.
4. **Enable AWS SDK Logging**: Set the environment variable `AWS_SDK_LOAD_CONFIG=1` to enable more detailed logging.

## Best Practices

1. **Rotate Secrets Regularly**: Implement a process for regular rotation of secrets in AWS Secrets Manager.
2. **Use Encryption**: AWS Secrets Manager encrypts secrets by default, but consider using customer-managed KMS keys for additional control.
3. **Limit Access**: Use IAM policies with the principle of least privilege to limit who can access the secrets.
4. **Monitor Access**: Enable AWS CloudTrail to monitor access to your secrets.
