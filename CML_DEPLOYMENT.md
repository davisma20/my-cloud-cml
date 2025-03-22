# CML Deployment with DevNet Workstation

This document outlines the configuration for deploying Cisco Modeling Labs (CML) in AWS using the AMI created from the CML OVA, along with a DevNet workstation for connectivity verification.

## Overview

This feature branch configures both:
1. A CML instance using a custom AMI that needs to be created by importing the CML OVA
2. A DevNet workstation using the DevNet Expert AMI (ami-0a0e4ef95325270c9), which comes pre-configured with all necessary tools

The deployment includes security hardening measures for both instances and provides tools to verify connectivity between them.

## Configuration Details

### Security Features

Both the CML instance and DevNet workstation are configured with:
- Root volume encryption
- IMDSv2 requirement (prevents SSRF attacks)
- Automatic security updates
- UFW firewall with default deny policy
- Fail2ban for brute force protection
- Secure SSH configuration
- System hardening and password complexity requirements

### CML Configuration

- Requires a custom AMI created from importing the CML OVA file
- The AMI ID should be set in the `config.yml` file under `aws.cml_ami`
- Instance type: c5.2xlarge (configurable in config.yml)
- Deployed with CML Enterprise license
- Accessible via HTTPS and SSH (port 1122)

### DevNet Workstation

- Uses DevNet Expert AMI: ami-0a0e4ef95325270c9 (Ubuntu 20.04 based)
- Instance type: t3.large (configurable in config.yml)
- Accessible via RDP (port 3389)
- Credentials: admin/1234QWer!

## Deployment Steps

1. Check out the feature branch:
   ```
   git checkout feature/deploy-cml
   ```

2. Initialize Terraform:
   ```
   terraform init
   ```

3. Apply the configuration:
   ```
   terraform apply -auto-approve
   ```

4. After deployment, Terraform will output the connection details for both the CML instance and DevNet workstation.

## Connectivity Verification

To verify connectivity between the DevNet workstation and CML (meeting the requirements for CAD-7):

1. Connect to the DevNet workstation using RDP with the following credentials:
   - Host: [Terraform output IP address]
   - Port: 3389
   - Username: admin
   - Password: 1234QWer!

2. Once connected, open a terminal and run the verification script:
   ```
   wget -O verify.sh https://raw.githubusercontent.com/davisma20/my-cloud-cml/feature/deploy-cml/scripts/verify_connectivity.sh
   chmod +x verify.sh
   ./verify.sh [CML IP address]
   ```

The script will perform:
- ICMP ping test
- TCP port connectivity tests for essential ports
- HTTPS certificate validation
- Web UI accessibility check

## Troubleshooting

If connectivity verification fails, check:
1. Security groups in AWS console to ensure all required ports are open
2. Network ACLs to ensure traffic is allowed between the instances
3. Instance health status in AWS console
4. System logs on both instances for any errors

## References

- Original CML Cloud repository: https://github.com/CiscoDevNet/cloud-cml
- Custom fork: https://github.com/davisma20/my-cloud-cml
- Jira ticket: CAD-7 (Verify reachability between DevNet workstation and CML)
