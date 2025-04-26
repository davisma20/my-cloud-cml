# CHANGELOG

> **Note:** This file was moved from the project root to documentation/ on 2025-04-25.

---

# Cisco CML2 Cloud provisioning tooling

Lists the changes for the tool releases.

## Recent Development (April 2025)

*   **Packer Build for CML 2.7.0:**
    *   Successfully built a stable AMI for CML 2.7.0 (`ami-0aef6f8637c4c6500` in `us-east-2`).
    *   Resolved issue where the `admin` user was not reliably created by the CML bootstrap process. Added explicit `useradd -g admin admin` provisioner step in `packer/cml-2.7.0.pkr.hcl`.
    *   Added debug provisioners to dump logs and `/etc/passwd` during Packer build.
    *   Added conditional logic for password setting (`admin` or `cml2`).
*   **Terraform:**
    *   Fixed warnings about undeclared variables (`cml_ami`, `aws_region`, etc.) by adding declarations to root `variables.tf`.
*   **Documentation:**
    *   Updated `README.md`, `documentation/PACKER_BUILD.md`, `documentation/TROUBLESHOOTING.md`, `documentation/CML_INSTALLATION.md`, and `packer/README.md` to reflect the CML 2.7.0 build process, AMI ID, user creation fix, and deployment steps.

## [Unreleased]

## [2025-04-15]
### Fixed
- **Packer Build / Terraform Deployment:** Removed custom Netplan configuration (`packer/50-cml-netplan.yaml`) from the Packer build process (`packer/cml-2.7.0.pkr.hcl`). This custom config was suspected of causing cloud-init failures during the `package_update_upgrade_install` stage in Terraform deployments, likely due to interference with early boot network setup. Reverted to default cloud-init network handling.

## [2025-04-13]
### Fixed
- **Packer Build:** Resolved persistent instance impairment and SSM agent failures (InvalidInstanceId errors) by changing the `amazon-ssm-agent` installation method in `packer/bootstrap_cml.sh` from `snap` (which conflicted with cloud-init) to the recommended `.deb` package method.
- **Packer Build:** Corrected the build sequence in `packer/cml-2.7.0.pkr.hcl` and `packer/install_cml_2.7.0.sh` to ensure CML services (`virl2-controller`, `virl2-uwm`) are restarted *after* installation, fixing 'Unit not found' errors during the build.
- **AMI:** Created new golden AMI `ami-032d7958a238a2977` (us-east-2) incorporating these fixes.

## [2025-04-12]
### Added
*   **Packer Build for CML 2.7.0:**
    *   Successfully built a stable AMI for CML 2.7.0 (`ami-0aef6f8637c4c6500` in `us-east-2`).
    *   Resolved issue where the `admin` user was not reliably created by the CML bootstrap process. Added explicit `useradd -g admin admin` provisioner step in `packer/cml-2.7.0.pkr.hcl`.
    *   Added debug provisioners to dump logs and `/etc/passwd` during Packer build.
    *   Added conditional logic for password setting (`admin` or `cml2`).
*   **Terraform:**
    *   Fixed warnings about undeclared variables (`cml_ami`, `aws_region`, etc.) by adding declarations to root `variables.tf`.
*   **Documentation:**
    *   Updated `README.md`, `documentation/PACKER_BUILD.md`, `documentation/TROUBLESHOOTING.md`, `documentation/CML_INSTALLATION.md`, and `packer/README.md` to reflect the CML 2.7.0 build process, AMI ID, user creation fix, and deployment steps.

## Version 2.8.1-DevNet (Fork)

- Custom fork configured specifically for CML 2.8.1-14 deployment
- Added DevNet Expert workstation deployment support
- Fixed CML service initialization issues by aligning config with correct package version (cml2_2.8.1-14_amd64.deb)
- Improved documentation with explicit version requirements
- Enhanced security hardening for both instances
- Added connectivity verification tools

## Version 2.8.0

- using "aws_" and "azure_" prefixes to provide tokens and IDs in the environment (see `.envrc.example`)
- adapt tooling to work with 2.8.0 (move base OS from 20.04 to 24.04)
- allow to use the `allowed_ipv4_subnets` also for Azure
- improve network manager handling while provisioning
- licensing now uses the PCL instead of curl and bash
- documentation improvements and fixes

## Version 2.7.2

- added the AWS mini variant which does not manage any network resources, the
  subnet and security group ID
- change elastic IP allocation for AWS from dynamic to static to make it work
  again
- this is the last release to support CML 2.7 and before
- changed the versioning to match the CML version so that it's easier to find the proper version / release of cloud-cml which works with the CML version to be used

## Version 2.7.0

- allow cluster deployments on AWS.
  - manage and use a non-default VPC
  - optionally allow to use an already existing VPC and gateway
  - allow to enable EBS encryption (fixes #8)
  - a `cluster` section has been added to the config file.  Some keywords have changed (`hostname` -> `controller_hostname`).  See also a new "Cluster" section in the [AWS documentation](documentation/AWS.md)
- introduce secret managers for storing secrets.
  - supported are dummy (use raw_secrets, as before), Conjur and Vault
  - also support randomly generated secrets
  - by default, the dummy module with random secrets is configured
  - the license token secret needs to be configured regardless
- use the CML .pkg software distribution file instead of multiple .deb packages (this is a breaking change -- you need to change the configuration and upload the .pkg to cloud storage instead of the .deb. `deb` -> `software`.
- the PaTTY customization script has been removed.  PaTTY is included in the .pkg. Its installation and configuration is now controlled by a new keyword `enable_patty` in the `common` section of the config.
> [!NOTE]
> Poll time is hard-coded to 5 seconds in the `cml.sh` script.  If a longer poll time and/or additional options like console and VNC access are needed then this needs to be changed manually in the script.
- add a common script file which has currently a function to determine whether the instance is a controller or not.  This makes it easier to install only controller relevant elements and omit them on computes (usable within the main `cml.sh` file as well as in the customization scripts).
- explicitly disable bridge0 and also disable the virl2-bridge-setup.py script by inserting `exit()` as the 2nd line.  This will ensure that service restarts will not try to re-create the bridge0 interface. This will be obsolete / a no-op with 2.7.1 which includes a "skip bridge creation" flag.
- each instance will be rebooted at the end of cloud-init to come up with newly installed software / kernel and in a clean state.
- add configuration option `cfg.aws.vpc_id` and `cfg.aws.gw_id` to specify the VPC and gateway ID that should be used. If left empty, then a custom VPC ID will be created (fixes #9)

## Version 0.3.0

- allow cluster deployments on AWS.
  - manage and use a non-default VPC
  - optionally allow to use an already existing VPC and gateway
  - allow to enable EBS encryption (fixes #8)
  - a `cluster` section has been added to the config file.  Some keywords have changed (`hostname` -> `controller_hostname`).  See also a new "Cluster" section in the [AWS documentation](documentation/AWS.md)
- introduce secret managers for storing secrets.
  - supported are dummy (use raw_secrets, as before), Conjur and Vault
  - also support randomly generated secrets
  - by default, the dummy module with random secrets is configured
  - the license token secret needs to be configured regardless
