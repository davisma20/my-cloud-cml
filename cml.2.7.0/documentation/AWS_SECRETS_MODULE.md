# AWS Secrets Manager Integration

This document describes how to use AWS Secrets Manager with the CML deployment.

## Overview

The AWS Secrets Manager integration allows you to securely store and manage sensitive information 
related to your CML deployment in AWS Secrets Manager. This includes credentials, tokens, and other 
sensitive data needed for your CML instances.

## Configuration

### 1. Configure the config.yml File

```yaml
secret:
  manager: aws
  
  aws:
    project_name: "cml-devnet"  # Used as a prefix for secret names
    environment: "production"   # Used for tagging secrets
    
  secrets:
    app:
      username: admin
      # If raw_secret is specified, it will be used to create the secret in AWS
      # If not specified, a random password will be generated
      #raw_secret: "your-secret-password"
      
    sys:
      username: sysadmin
      
    smartlicense_token:
      # For existing secrets, you can specify the path where they are stored
      path: "cml/licenses/smartlicense-token"
      
    cluster:
      # Custom path for cluster secret
      path: "cml/clusters/primary/secret"
```

### 2. AWS Credentials

Ensure your AWS credentials are properly configured. You can use:

- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- AWS credentials file: `~/.aws/credentials`
- IAM roles for EC2 instances

### 3. Required IAM Permissions

The following IAM permissions are required for the AWS Secrets Manager integration:

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

## Migrating from Existing Secrets

To migrate from existing secrets:

1. Export your existing secrets (if using the dummy provider, these will be in the Terraform state)
2. Configure the AWS Secrets Manager backend
3. Import the secrets into AWS Secrets Manager using the AWS CLI:

```bash
aws secretsmanager create-secret --name cml/cml-devnet/app --secret-string "your-app-password"
aws secretsmanager create-secret --name cml/cml-devnet/sys --secret-string "your-sys-password"
aws secretsmanager create-secret --name cml/cml-devnet/smartlicense_token --secret-string "your-license-token"
aws secretsmanager create-secret --name cml/cml-devnet/cluster --secret-string "your-cluster-secret"
```

4. Run Terraform with the AWS Secrets Manager backend enabled
