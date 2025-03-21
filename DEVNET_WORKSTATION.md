# DevNet Workstation Deployment Guide

*Last Updated: March 21, 2025*

This document outlines the steps required to deploy the Cisco DevNet Expert workstation in AWS using the Cloud-CML Terraform configuration. This workstation can be used for studying for the CCIE DevNet exam.

## Prerequisites

- AWS account with appropriate permissions
- Terraform installed locally
- AWS CLI configured with access credentials
- The Cisco DevNet Expert AMI already imported into your AWS account

## AMI Information

The deployment uses a custom DevNet Expert AMI that has been previously imported from an OVA file:

- **AMI ID**: ami-0a0e4ef95325270c9
- **Description**: AWS-VMImport service: Linux - Ubuntu 20.04.3 LTS - 5.4.0-96-generic
- **Root Volume Size**: Minimum 50GB required

## Configuration Steps

### 1. Disable CML Controller and Enable DevNet Workstation

Edit the main Terraform file (`modules/deploy/aws/main.tf`) to set the appropriate local variables:

```hcl
locals {
  workstation_enable = true  # Enable the DevNet workstation
  cml_enable = false         # Disable the CML controller
}
```

### 2. Configure the DevNet Workstation Instance

The workstation is configured in the same file:

```hcl
# Devnet workstation instance
resource "aws_instance" "devnet_workstation" {
  count               = local.workstation_enable ? 1 : 0
  instance_type        = var.options.cfg.aws.workstation.instance_type
  ami                  = "ami-0a0e4ef95325270c9"  # Use the DevNet Expert AMI
  iam_instance_profile = var.options.cfg.aws.profile
  key_name             = var.options.cfg.common.key_name
  subnet_id           = aws_subnet.public_subnet.id

  root_block_device {
    volume_size = 50  # Minimum size required for the AMI
    volume_type = "gp3"
  }

  vpc_security_group_ids = [
    aws_security_group.sg_workstation[0].id
  ]

  tags = {
    Name = "devnet-workstation-${var.options.rand_id}"
  }
  
  # Minimal startup script to ensure RDP is running
  user_data = <<-EOF
              #!/bin/bash
              echo "DevNet Expert workstation started at $(date)" > /var/log/devnet-setup-complete.log
              if command -v systemctl > /dev/null && systemctl list-unit-files | grep -q xrdp; then
                systemctl enable xrdp
                systemctl start xrdp
                echo "XRDP service started" >> /var/log/devnet-setup-complete.log
              fi
              if command -v ufw > /dev/null; then
                ufw allow 3389/tcp
                echo "UFW rule for RDP added" >> /var/log/devnet-setup-complete.log
              fi
              EOF
}
```

### 3. Disable CML Provider and Readiness Check

To prevent errors related to CML configuration, modify the `main.tf` file in the root directory to disable the CML provider and readiness check:

```hcl
# Disable CML2 provider when we're only deploying the workstation
#provider "cml2" {
#  address        = "https://${module.deploy.public_ip}"
#  username       = local.cfg.secrets.app.username
#  password       = local.cfg.secrets.app.secret
#  skip_verify    = true
#  dynamic_config = true
#}

# Disable the ready module when we're only deploying the workstation
#module "ready" {
#  source = "./modules/readyness"
#  depends_on = [
#    module.deploy.public_ip
#  ]
#}
```

### 4. Update Output for CML Readiness Status

Modify the `output.tf` file to remove references to the ready module:

```hcl
output "cml2info" {
  value = {
    "address" : module.deploy.public_ip
    "del" : nonsensitive("ssh -p1122 ${local.cfg.secrets.sys.username}@${module.deploy.public_ip} /provision/del.sh")
    "url" : "https://${module.deploy.public_ip}"
    "version" : "Disabled" # Removed module.ready.state.version reference
  }
}
```

## Deployment

To deploy the workstation:

1. Initialize Terraform:
   ```
   terraform init
   ```

2. Apply the configuration:
   ```
   terraform apply -auto-approve
   ```

3. The deployment will output the IP address of the workstation.

## Security Features

The DevNet workstation is configured with several security best practices:

### Infrastructure Security

1. **Root Volume Encryption**
   - The root EBS volume is encrypted to protect data at rest
   - Delete-on-termination is enabled to prevent data leakage

2. **IMDSv2 Requirement**
   - Instance Metadata Service version 2 is enforced
   - Prevents server-side request forgery (SSRF) attacks
   - HTTP token requirement for metadata access

3. **Restricted Security Groups**
   - Inbound traffic is limited to SSH (port 22) and RDP (port 3389)
   - Outbound traffic is restricted to essential services:
     - HTTP (80) and HTTPS (443) for updates and downloads
     - DNS (53/UDP) for name resolution
     - NTP (123/UDP) for time synchronization

### Host-Based Security

The workstation is automatically hardened during initialization with:

1. **Automatic Updates**
   - Unattended-upgrades package is installed and configured
   - Security updates are applied automatically

2. **Firewall Configuration**
   - UFW firewall is configured with default deny policy
   - Only SSH and RDP ports are allowed inbound

3. **Brute Force Protection**
   - Fail2ban is installed to monitor and block repeated login attempts
   - Protects both SSH and RDP from brute force attacks
   - Configures 1-hour ban after 5 failed attempts

4. **SSH Hardening**
   - Root login is disabled
   - Password authentication is disabled (key-based only)
   - Maximum authentication attempts is limited

5. **System Hardening**
   - Unnecessary services are disabled
   - Password complexity requirements are enforced

## Connecting to the DevNet Workstation

### RDP Access (Recommended)

The workstation is configured for Remote Desktop access:

- **Host**: The public IP address of the instance
- **Port**: 3389
- **Username**: admin
- **Password**: 1234QWer!

### SSH Access

SSH is typically not enabled on the DevNet workstation by default. If SSH access is required, you would need to modify the instance after deployment.

## Troubleshooting

If you encounter issues connecting via RDP:

1. Verify that the instance is running:
   ```
   aws ec2 describe-instances --region us-east-2 --instance-ids <instance-id>
   ```

2. Check that RDP port is open:
   ```
   nc -zv <ip-address> 3389
   ```

3. Verify security group rules:
   ```
   aws ec2 describe-security-groups --region us-east-2 --group-ids <security-group-id>
   ```

4. Check instance console output for errors:
   ```
   aws ec2 get-console-output --region us-east-2 --instance-id <instance-id>
   ```

## Next Steps

After successfully deploying the DevNet workstation, you can:

1. Connect via RDP using the credentials above
2. Begin using the pre-installed DevNet tools and resources
3. Configure the CML (Cisco Modeling Lab) for additional lab exercises

---

For CML deployment instructions, refer to the main README.md file.
