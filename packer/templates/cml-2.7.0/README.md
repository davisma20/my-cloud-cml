# CML 2.7.0 Enhanced Deployment Template

This directory contains the enhanced Packer template and supporting scripts for building a CML 2.7.0 AMI with robust security features and improved initialization.

## Key Enhancements

### Security Hardening

- **Root Volume Encryption**: All EBS volumes are encrypted to protect data at rest
- **IMDSv2 Requirement**: Prevents SSRF attacks by requiring token-based metadata service requests
- **Restricted Security Groups**: Precisely defined inbound/outbound rules
- **Host-Based Security**: 
  - UFW firewall with default deny policy
  - Fail2ban for brute force protection
  - Secure SSH configuration (no root login, key-based auth only)
  - Automatic security updates

### Improved CML Controller Initialization

- **MongoDB Initialization**: Proper database setup with validation checks
- **Nginx Configuration**: Custom configuration for the CML web interface
- **Service Sequencing**: Correct order for service startup (controller → UI → web server)
- **Default User Creation**: Creates admin user with appropriate permissions
- **Diagnostic Logging**: Detailed logs for troubleshooting

### Deployment Process

1. The build script (`scripts/build_cml_2.7.0.sh`) initiates the Packer build
2. MongoDB is properly installed and initialized
3. CML package is extracted and installed 
4. Controller is initialized with proper service sequencing
5. Admin user is created with appropriate permissions
6. Web interface is validated and tested

## Usage

To build the AMI:

```bash
cd scripts
./build_cml_2.7.0.sh
```

For a detailed walkthrough of the build process, see our [PACKER_BUILD.md](../../../documentation/PACKER_BUILD.md) documentation.

## Troubleshooting

If you encounter issues during the build process:

1. Check the Packer logs in the `logs` directory
2. Examine the CML controller logs for initialization errors
3. Verify that MongoDB is running properly
4. Ensure the CML package was properly extracted and installed