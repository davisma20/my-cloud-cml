# CML Packer Build

This directory contains Packer templates to build Amazon Machine Images (AMIs) with Cisco Modeling Labs (CML) pre-installed.

## Overview

Instead of installing CML during instance startup (which can be error-prone), these Packer templates create ready-to-use AMIs with CML already installed and configured. This approach provides several benefits:

- **Reliability**: Installation happens once during AMI creation, not on every instance startup
- **Speed**: Instances launch faster as they don't need to install software
- **Consistency**: All instances are identical and pre-tested
- **Versioning**: Maintain different AMI versions as you update CML

## Prerequisites

1. [Packer](https://www.packer.io/downloads) (version 1.8.0+)
2. AWS CLI configured with appropriate credentials
3. CML installation package (`cml2_*.deb`) accessible via S3 or other source

## Directory Structure

```
packer/
├── README.md                       # This documentation file
├── cml-controller.pkr.hcl          # Packer template for CML controller
├── cml-network-validated.pkr.hcl   # Network-validated CML template
├── variables.pkr.hcl               # Packer variables declaration
├── scripts/                        # Installation scripts
│   ├── install_cml.sh              # Main CML installation script
│   ├── install_cml_prereqs.sh      # CML prerequisites installer
│   ├── security_hardening.sh       # Security hardening script
│   ├── post_launch_validation.sh   # Post-launch validation script
│   └── cleanup.sh                  # Cleanup script to reduce AMI size
└── files/                          # Files to be copied to the instance
    └── 99-cml-settings.conf        # CML system settings
```

## Building the AMI

1. Place your CML package in an S3 bucket or update the template to use your preferred source
2. Update variables in `variables.pkr.hcl` if needed
3. Run the build:

```bash
cd packer
packer build cml-controller.pkr.hcl
```

## Building the Network-Validated AMI

The `cml-network-validated.pkr.hcl` template creates an AMI with comprehensive network validation built in:

1. Validates basic network connectivity during the build
2. Tests CML GUI accessibility before finalizing the AMI
3. Includes post-launch validation scripts to verify proper operation
4. Applies security hardening measures similar to the DevNet workstation

To build the network-validated AMI:

```bash
cd packer
packer build cml-network-validated.pkr.hcl
```

## Using the AMI in Terraform

After building, update your Terraform code to use the generated AMI ID instead of installing CML via cloud-init.

## Using the Network-Validated AMI in Terraform

After building, use the provided Terraform variables file to deploy with the new AMI:

1. Update the AMI ID in `network_validated_ami.auto.tfvars`
2. Run Terraform as usual from the project root

```bash
# Update AMI ID in the vars file first
terraform init
terraform apply
```

## Network Validation Features

The network-validated AMI includes several important improvements:

- **Build-time Network Testing**: Validates connectivity during Packer build
- **Mock CML GUI Testing**: Verifies web server functionality works properly
- **Post-Launch Validation**: Scripts to verify accessibility after deployment
- **Improved Cloud-Init Scripts**: Fixed syntax issues in user-data scripts
- **Security Hardening**: Implements best practices for secure deployment

## Security Note

The resulting AMI will have CML pre-installed but not pre-configured with initial passwords. The security hardening applied to the generated AMI follows AWS best practices for public images.

## Troubleshooting

If you encounter issues with the CML deployment:

1. Check the validation logs at `/var/log/cml_validation.log`
2. Verify security group settings allow necessary ports (80, 443, 1122, etc.)
3. Run the post-launch validation script manually: `sudo /provision/post_launch_validation.sh`
