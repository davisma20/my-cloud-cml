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
├── README.md               # This documentation file
├── cml-controller.pkr.hcl  # Packer template for CML controller
├── variables.pkr.hcl       # Packer variables declaration
├── scripts/                # Installation scripts
│   ├── install_cml.sh      # Main CML installation script
│   └── cleanup.sh          # Cleanup script to reduce AMI size
└── files/                  # Files to be copied to the instance
    └── 99-cml-settings.conf # CML system settings
```

## Building the AMI

1. Place your CML package in an S3 bucket or update the template to use your preferred source
2. Update variables in `variables.pkr.hcl` if needed
3. Run the build:

```bash
cd packer
packer build cml-controller.pkr.hcl
```

## Using the AMI in Terraform

After building, update your Terraform code to use the generated AMI ID instead of installing CML via cloud-init.

## Security Note

The resulting AMI will have CML pre-installed but not pre-configured with initial passwords. The security hardening applied to the generated AMI follows AWS best practices for public images.
