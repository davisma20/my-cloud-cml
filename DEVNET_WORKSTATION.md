# DevNet Workstation Deployment Guide

*Last Updated: March 22, 2025*

This document outlines the steps required to deploy the Cisco DevNet Expert workstation in AWS using the Cloud-CML Terraform configuration. This workstation can be used for studying for the CCIE DevNet exam.

## CML Version Compatibility

This DevNet workstation deployment is compatible with CML version 2.8.1-14 and has been tested with the package file `cml2_2.8.1-14_amd64.deb`.

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
     - DNS (53) for name resolution
     - NTP (123) for time synchronization

### Host-Based Security

1. **Automatic Updates**
   - Unattended-upgrades package is installed and configured
   - Security updates are applied automatically

2. **Firewall Configuration**
   - UFW (Uncomplicated Firewall) with default deny policy
   - Only required ports (22, 3389) are allowed inbound

3. **Brute Force Protection**
   - Fail2ban installed and configured
   - Protection for both SSH and RDP services
   - 5 failed attempts results in a 1-hour ban

4. **SSH Hardening**
   - Root login disabled
   - Password authentication disabled
   - Maximum authentication attempts limited

5. **System Hardening**
   - Password complexity requirements enforced
   - Unnecessary services disabled (Bluetooth, CUPS)

### Security Validation

The workstation includes a built-in security validation script that verifies all security features are properly implemented:

1. **Location**
   - Script path: `/home/admin/validate_security.sh`
   - Report path: `/home/admin/security_validation_report.txt`

2. **Automatic Validation**
   - The script runs automatically 5 minutes after each boot
   - Results are saved to the report file

3. **Manual Validation**
   - You can run the script manually at any time:
     ```bash
     sudo /home/admin/validate_security.sh
     ```

4. **Validation Checks**
   - Volume encryption status
   - IMDSv2 requirement
   - Firewall configuration
   - Fail2ban status
   - SSH security settings
   - Automatic updates
   - Password policies
   - System hardening measures

This validation helps ensure the workstation maintains its security posture and provides documentation for security compliance.

## Connecting to the DevNet Workstation

### RDP Access (Recommended)

The workstation is configured for Remote Desktop access:

- **Host**: The public IP address of the instance
- **Port**: 3389
- **Username**: admin
- **Password**: 1234QWer!

### SSH Access

SSH is typically not enabled on the DevNet workstation by default. If SSH access is required, you would need to modify the instance after deployment.

## Connecting to CML from the DevNet Workstation

When deployed alongside CML, the DevNet workstation is configured to access the CML environment for lab exercises.

### Accessing CML Web Interface

1. **From the DevNet Workstation RDP session**:
   - Launch a web browser (Firefox or Chrome)
   - Navigate to the CML URL shown in your Terraform output (typically `https://<cml-public-ip>`)
   - **Login Credentials**:
     - Username: `admin`
     - Password: Either your configured password or a randomly generated one (see note below)

> [!IMPORTANT]
> **About CML Password Management**
>
> By default, CML uses randomly generated passwords unless explicitly configured in the `config.yml` file.
>
> If you can't access the CML GUI with expected credentials:
>
> 1. Check if you explicitly set the password in `config.yml` (under `secrets.app.raw_secret`)
> 2. Try common default passwords: `cisco`, `C1sco12345`
> 3. You may need to reset the password using SSH/SSM access to the CML instance
>
> See the [TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md#cml-authentication-issues) guide for detailed help.

### Verifying CML Connectivity

The DevNet workstation includes a verification script to test connectivity with CML:

```bash
# From the DevNet workstation terminal
cd ~/scripts
./verify_connectivity.sh
```

This script tests:
- Network connectivity to the CML instance
- Web service availability 
- API accessibility (if credentials are provided)

### Troubleshooting CML Connectivity

If you experience issues connecting to CML from the DevNet workstation:

1. **Verify Network Connectivity**:
   ```bash
   ping <cml-private-ip>
   ```

2. **Check Security Group Rules**:
   Ensure security groups allow traffic between the DevNet workstation and CML (ports 80, 443, and any other required ports).

3. **Verify CML Services**:
   Make sure all CML services are running properly:
   ```bash
   # From CML instance via SSH or SSM
   systemctl status cml
   ```

4. **Review System Logs**:
   ```bash
   # From CML instance
   journalctl -u cml
   ```

For additional troubleshooting steps, refer to the [Troubleshooting Guide](documentation/TROUBLESHOOTING.md).

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
