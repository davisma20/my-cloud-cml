# Security Hardening Features

This directory contains documentation and implementation details for the comprehensive security hardening features added to this fork of the cloud-cml repository.

## Infrastructure Security Features

- **Root Volume Encryption**: All EBS volumes are encrypted to protect data at rest
- **IMDSv2 Requirement**: Prevents SSRF (Server Side Request Forgery) attacks by requiring token-based metadata service requests
- **Restricted Security Groups**: Precisely defined inbound and outbound rules to minimize attack surface

## Host-Based Security Hardening

- **Automatic Security Updates**: System is configured for automatic security patches
- **UFW Firewall**: Implemented with default deny policy, allowing only necessary services
- **Fail2ban**: Protects against brute force attacks targeting SSH and RDP services
- **Secure SSH Configuration**:
  - Root login disabled
  - Password authentication disabled (key-based only)
  - Strong ciphers and MAC algorithms
- **System Hardening**:
  - Password complexity requirements
  - Account lockout policies
  - System auditing enabled

## Implementation Details

The security hardening features are implemented in the following places:

1. **Packer Templates**: Security configurations applied during AMI creation
2. **Terraform Modules**: Infrastructure security settings enforced via IaC
3. **Bootstrap Scripts**: Runtime hardening applied during instance initialization

## Validation

Security measures have been validated against industry best practices and common vulnerability frameworks.

For more details on the DevNet workstation security features, see the main [DEVNET_WORKSTATION.md](../../DEVNET_WORKSTATION.md) documentation.