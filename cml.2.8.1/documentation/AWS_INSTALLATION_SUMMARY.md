# AWS Installation Summary for CML 2.8.1

## Overview
This document summarizes the steps required to deploy Cisco Modeling Labs 2.8.1 on AWS using Packer and Terraform.

## Steps
1. **Download Required Files:** Place CML ISO and reference platform ISO in `CISCO_DOWNLOADS/`.
2. **Build AMI with Packer:**
   - Use Ubuntu 24.04 LTS as the base AMI.
   - Mount and install CML from the ISO.
   - Mount/copy reference platform ISO.
   - Validate CML installation and harden the image.
3. **Deploy with Terraform:**
   - Use the AMI built by Packer.
   - Configure networking, security groups, and EC2 instance.
   - Validate deployment and access CML UI/API.

## References
- See MIGRATION_PLAN.md and RELEASE_NOTES_SUMMARY.md for more details.
