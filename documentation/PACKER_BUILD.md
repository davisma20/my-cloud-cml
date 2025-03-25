# CML Packer Build Process

This document describes the process of building Cisco Modeling Labs (CML) AMIs using Packer.

## Overview

The Packer build process creates custom Amazon Machine Images (AMIs) with CML pre-installed and properly configured. This approach offers several advantages:

- **Consistent Deployment**: Every CML instance starts from an identical, properly initialized state
- **Faster Provisioning**: Much of the installation and configuration is done during AMI creation
- **Enhanced Security**: Security hardening is applied during image creation
- **Improved Reliability**: Reduces deployment failures by ensuring proper initialization

## Security Features

The CML AMIs built with this process include:

- **Infrastructure Security**:
  - Root volume encryption
  - IMDSv2 requirement (prevents SSRF attacks)
  - Restricted security groups with specific inbound/outbound rules

- **Host-based Security**:
  - Automatic security updates
  - UFW firewall with default deny policy
  - Fail2ban for brute force protection on SSH and RDP
  - Secure SSH configuration (disabled root login, password auth)
  - System hardening and password complexity requirements

## CML Controller Initialization

The build process includes several steps to ensure proper CML controller initialization:

1. **Installation Preparation**:
   - Necessary packages are installed
   - System is configured for virtualization

2. **CML Package Extraction**:
   - The CML installation package is downloaded from S3
   - Package is extracted and prepared for installation

3. **Service Configuration**:
   - Services are initialized in the proper order (controller → UI → nginx)
   - MongoDB is properly configured for the CML database
   - Default admin user is created with proper permissions

4. **Verification Process**:
   - All services are checked for proper startup
   - Web interface accessibility is verified
   - Authentication is tested with the default admin account

## Default Credentials

The default administrator credentials for the AMI are:

- **Username**: admin
- **Password**: admin

> **Important**: For production deployments, change these default credentials immediately after deployment.

## Building a CML AMI

To build a custom CML AMI:

1. Ensure CML package is uploaded to S3 bucket:
   ```
   ./upload-images-to-aws.sh
   ```

2. Run the build script:
   ```
   cd packer
   ./build_cml_2.7.0.sh
   ```

3. The AMI ID will be output at the end of the build process
4. Update the `cml_ami` value in your `config.yml` with the new AMI ID

## Troubleshooting

If you encounter issues with the CML initialization during the Packer build:

1. Check the Packer build logs for any error messages
2. Look for failed service initializations
3. Verify that MongoDB started properly
4. Ensure the CML controller initialization was successful

For more detailed diagnostics, you can enable debug mode in the Packer build by editing the `build_cml_2.7.0.sh` script.
