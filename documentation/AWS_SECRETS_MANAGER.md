# AWS Secrets Manager Integration Guide

This guide explains how to set up and use AWS Secrets Manager with your CML deployment.

## Prerequisites

1. An AWS account with appropriate permissions
2. AWS CLI installed and configured
3. Terraform installed (version 1.1.0 or higher)

## Setup Steps

### 1. Configure AWS Credentials

Ensure your AWS credentials are properly configured. You can use one of the following methods:

#### Environment Variables

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-2"  # Same as your CML deployment region
```

#### AWS CLI Configuration

```bash
aws configure
```

#### IAM Role (if running on EC2)

If your deployment is running on an EC2 instance, you can attach an IAM role with the appropriate permissions.

### 2. IAM Permissions

Ensure your AWS user or role has the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:ListSecrets",
        "secretsmanager:TagResource"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:cml/*"
    }
  ]
}
```

You can create a dedicated IAM policy with these permissions and attach it to your user or role.

### 3. Migrate Existing Secrets (Optional)

If you have existing secrets in Terraform state (using the dummy provider), you can migrate them to AWS Secrets Manager using the provided script:

```bash
cd /Users/miked/Documents/Projects/python_project/my-cloud-cml
./scripts/migrate_to_aws_secrets.sh
```

### 4. Configure CML to Use AWS Secrets Manager

Update your `config.yml` file to use AWS Secrets Manager:

```yaml
secret:
  manager: aws
  
  aws:
    project_name: "cml-devnet"  # Used as a prefix for secret names
    environment: "production"   # Used for tagging secrets
    
  # Your existing secrets configuration
  secrets:
    app:
      username: admin
      # raw_secret: "your-password"  # Optional, will be generated if not specified
      
    sys:
      username: sysadmin
      # raw_secret: "your-password"  # Optional, will be generated if not specified
      
    smartlicense_token:
      raw_secret: "your-smart-licensing-token"  # Required
      
    cluster:
      # Will be auto-generated if clustering is enabled
```

### 5. Apply the Terraform Configuration

You can use the provided helper script to apply the Terraform configuration:

```bash
cd /Users/miked/Documents/Projects/python_project/my-cloud-cml
./scripts/apply_with_aws_secrets.sh
```

Or manually apply the configuration:

```bash
cd /Users/miked/Documents/Projects/python_project/my-cloud-cml
terraform init
terraform apply
```

## Secret Naming Convention

By default, secrets will be created with the following naming pattern:

```
cml/<project_name>/<secret_name>
```

For example, with the default configuration:
- `cml/cml-devnet/app`
- `cml/cml-devnet/sys`
- `cml/cml-devnet/smartlicense_token`
- `cml/cml-devnet/cluster`

You can override this naming convention by specifying a custom `path` for each secret in your configuration.

For more detailed information about the AWS Secrets Manager module implementation, see [AWS Secrets Manager Module Documentation](AWS_SECRETS_MODULE.md).

## Troubleshooting

### Cannot Access AWS Secrets Manager

If you encounter errors accessing AWS Secrets Manager, check the following:

1. Verify AWS credentials are correctly configured
2. Confirm the AWS region is set correctly (should match your CML deployment region)
3. Ensure the IAM user or role has the necessary permissions

### Terraform Apply Fails

If `terraform apply` fails with errors related to AWS Secrets Manager:

1. Run `terraform init` to ensure all providers are properly initialized
2. Verify the AWS provider configuration in the `provider_aws.tf` file
3. Check the AWS credentials being used by Terraform

### Secret Not Found

If Terraform complains about not finding a secret:

1. Verify the secret exists in AWS Secrets Manager with the expected name
2. Check if the path specified in your configuration matches the actual path in AWS Secrets Manager
3. Confirm the AWS region being used matches where the secrets are stored
