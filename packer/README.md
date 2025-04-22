# CML Packer Build

This directory contains Packer templates and scripts to build Amazon Machine Images (AMIs) with Cisco Modeling Labs (CML) 2.7.0 pre-installed.

## Overview

This directory contains the configuration files and scripts necessary to build a custom Amazon Machine Image (AMI) for Cisco Modeling Labs (CML) 2.7.0 using HashiCorp Packer.

The build process automates the installation and configuration of CML and its dependencies onto a base Ubuntu 20.04 LTS AMI.

## Current AMI

*   **Latest Golden AMI:** `Build in progress (2025-04-15)`. Previous AMI (`ami-032d7958a238a2977`) had deployment issues.
*   **Build Date:** 2025-04-15 (In Progress)
*   **Key Features/Fixes:**
    *   Uses `.deb` package for `amazon-ssm-agent` installation (resolves cloud-init conflicts).
    *   Corrected build sequence ensures CML services restart *after* installation.

## Prerequisites

1. [Packer](https://www.packer.io/downloads) (version 1.8.0+ recommended)
2. AWS CLI configured with appropriate credentials (permissions to manage EC2, AMIs, SGs, etc.)
3. CML 2.7.0 installation package (`.pkg` file) accessible (e.g., uploaded to an S3 bucket referenced in the Packer variables, or locally if modifying the build process).

### IAM Permissions

The IAM role or temporary instance profile used by Packer to build the AMI requires specific permissions beyond basic EC2 actions. Crucially, it needs permissions equivalent to the `AmazonSSMManagedInstanceCore` managed policy (including `ssm:UpdateInstanceInformation`) to allow the installed `amazon-ssm-agent` to successfully register with the AWS SSM service during the build process. Without these permissions, the agent will be installed but instances launched from the resulting AMI will not be manageable via SSM.

It also requires permissions to read secrets from Secrets Manager if configured (`secretsmanager:GetSecretValue`, etc.) and potentially S3 access depending on how CML bundles are sourced.

## Directory Structure (CML 2.7.0 Build)

```
packer/
├── README.md                     # This documentation file
├── cml-2.7.0.pkr.hcl             # Main Packer template for CML 2.7.0
├── build_cml_2.7.0.sh            # Recommended script to run the build
├── bootstrap_cml.sh              # Core CML installation script executed by Packer
├── install_cml_2.7.0.sh          # Script to install CML .deb packages
├── test_cml_login.py             # Python script to test CML UI availability (run by Packer)
└── network_validated_ami.auto.tfvars # Example .tfvars file for deploying the built AMI
```

## Building the CML 2.7.0 AMI

1.  **Review Configuration:** Check the variables within `cml-2.7.0.pkr.hcl`. Key variables include `cml_admin_password`, `aws_region`, `source_ami_filter`, and S3 bucket/key variables if loading the installer from S3.
2.  **Execute Build:**
    *   Navigate to this `packer` directory.
    *   Run the provided build script:
        ```bash
        bash build_cml_2.7.0.sh
        ```
    *   This script runs `packer build` using the configurations defined in `cml-2.7.0.pkr.hcl` and associated variable files.
3.  **Output:** Upon success, Packer will display the new AMI ID.

## Build Process

1.  **Instance Setup:** Launches a temporary EC2 instance using a base Ubuntu 20.04 AMI.
2.  **Prerequisites & System Config:** Runs `bootstrap_cml.sh` to install necessary dependencies (KVM, libvirt, nginx, Python, etc.), configure system settings (networking, cloud-init), and apply basic hardening. This script lays the groundwork for the CML installation by preparing the system environment.
3.  **CML Package Installation:** Runs `install_cml_2.7.0.sh` which downloads the required CML `.deb` files from S3 and then triggers their installation using `apt-get install`. This script is specifically responsible for installing the CML packages. **Note (2025-04-12):** A fix was applied to ensure that failures during the CML `.deb` package installation step correctly cause the Packer build to fail, improving error detection.
4.  **User/Password Setup:** Ensures the OS `admin` user exists and sets the CML admin password.
5.  **Service Check & Cleanup:** Verifies basic UI accessibility, performs cleanup, and creates the final AMI.

Refer to `documentation/PACKER_BUILD.md` for more granular details.

## Packer Build Logs and AMI Tracking

All canonical records of AMI builds created by Packer are stored in the `packer-manifest.json` file in this directory. This manifest tracks every AMI built, including:
- AMI IDs and regions
- Build times (UNIX epoch)
- Packer run UUIDs

**How to use:**
- To map an EC2 instance to its AMI build, check the AMI ID in AWS, then search for it in `packer-manifest.json`.
- For troubleshooting, always verify that the AMI you are using appears in this manifest. If not, the build may not have completed successfully.

**Best Practice:**
- Reference this manifest for all troubleshooting, validation, and documentation workflows related to AMI provenance and build history.

## Using the Built AMI in Terraform

1.  **Update AMI ID:** Copy the AMI ID generated by the Packer build.
2.  **Edit `.tfvars`:** Update the `cml_ami` variable in the `network_validated_ami.auto.tfvars` file (or your own Terraform variables file) with the new AMI ID. Also ensure the `aws_region` matches the region where the AMI was built.
    ```hcl
    # packer/network_validated_ami.auto.tfvars
    cml_ami = "ami-032d7958a238a2977" # Replace with your new AMI ID
    aws_region = "us-east-2"         # Ensure this matches
    # ... other vars
    ```
3.  **Deploy:** Run `terraform init` and `terraform apply -var-file=packer/network_validated_ami.auto.tfvars` from the root project directory (`my-cloud-cml`).

## Network Diagnostics & Cloud-Init Troubleshooting (April 2025)

### Current State
- SSH diagnostics failed on AMI instances due to likely cloud-init or SSH misconfiguration.
- Security groups and NACLs are correct; root cause is inside the AMI (user/key/sshd/cloud-init).
- Diagnostic shell provisioners have been added to the Packer build to check:
  - cloud-init presence and status
  - SSH service status
  - Existence of /home/ubuntu/.ssh/authorized_keys
  - User info and relevant logs
  - Basic network diagnostics (ip addr, ip route, ping, metadata curl)

### Troubleshooting Workflow
1. **Destroy**: Clean up all AWS resources (terraform destroy).
2. **Packer Build**: Build the AMI with diagnostics enabled.
3. **Review Logs**: Carefully check Packer output for any errors in the diagnostic blocks.
4. **Fix & Repeat**: If diagnostics fail, fix issues in Packer/cloud-init/bootstrap scripts and repeat.
5. **Deploy & Validate**: If diagnostics pass, deploy with Terraform and run validation.

### Network-Related Best Practices
- Always use DHCP for the primary interface in netplan.
- Do not hardcode static IPs in the AMI.
- Ensure outbound HTTP/HTTPS is allowed for SSM and diagnostics.
- Confirm metadata service is reachable from instance.

### Example Diagnostic Provisioner
```hcl
provisioner "shell" {
  inline = [
    "ip addr show",
    "ip route",
    "ping -c 3 8.8.8.8 || echo 'Ping to 8.8.8.8 failed'",
    "curl -s http://169.254.169.254/latest/meta-data/ || echo 'Metadata service unavailable'"
  ]
}
```

## Troubleshooting

Refer to the main documentation files for detailed troubleshooting:
*   `documentation/TROUBLESHOOTING.md`
*   `documentation/CML_INSTALLATION.md`
*   `documentation/PACKER_BUILD.md`
