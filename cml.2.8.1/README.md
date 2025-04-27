# CML 2.8.1 Build System

This directory contains all scripts, configs, and documentation for deploying Cisco Modeling Labs 2.8.1 using Packer and Terraform on AWS.

- Follows best practices for modularity, security, and maintainability.
- Compatible with Ubuntu 24.04 and CML 2.8.1 cloud deployment requirements.

See the documentation folder for migration notes, release notes, and AWS deployment instructions.

## Packer Build Logs

All CML 2.8.1 Packer build logs are written to `logs/packer_build_latest.log` within this version directory. Older logs are archived in the same directory with a timestamped filename. Always check this log after running the build script for troubleshooting and validation.

## Directory Structure (Document Map)

- `CISCO_DOWNLOADS/` — Staging area for CML images and downloads
- `documentation/` — Project documentation (automation, secrets, migration, release notes, etc.)
- `logs/` — Build and validation logs
- `network_validated_ami.auto.tfvars` — Auto-updated AMI ID for Terraform
- `packer/` — Packer build scripts, configs, and snapshot cleanup tools
    - `README.md` — Packer build and cleanup instructions
    - `build_cml_2.8.1.sh` — Main Packer build script
    - `cml2.8.1-aws.pkr.hcl` — Packer config for CML 2.8.1
    - `provision_cml2.8.1.sh` — Provisioning logic
    - `ssm_install.sh` — SSM agent installation script
    - `packer-manifest.json` — Build manifest
    - `user-data`, `meta-data` — Cloud-init seed files
    - `*_snapshots.txt` — Snapshot cleanup helpers
- `terraform/` — Terraform modules and configs
    - `main.tf`, `provider_aws.tf`, `variables.tf`, etc.
    - `cml_lab_example.tf` — Example CML lab deployment
    - `devnet_workstation.tf` — DevNet workstation deployment
    - `iam_policy_aws_secrets_manager.json` — IAM policy for secrets
- `validations/` — Validation scripts and results

For detailed automation, secrets, and migration documentation, see the `documentation/` directory.

---
