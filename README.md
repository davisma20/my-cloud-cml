# README

Version 2.8.1-DevNet, March 22, 2025

> **This is a customized fork of the [Cisco DevNet cloud-cml repository](https://github.com/CiscoDevNet/cloud-cml) with added support for DevNet Expert workstation deployment and enhanced security features.**

CML instances can run on Azure and AWS cloud infrastructure.  This repository provides automation tooling using Terraform to deploy and manage CML in the cloud.  We have tested CML deployments using this tool chain in both clouds.  **The use of this tool is considered BETA**.  The tool has certain requirements and prerequisites which are described in this README and in the [documentation](documentation) directory.

*It is very likely that this tool chain can not be used "as-is"*.  It should be forked and adapted to specific customer requirements and environments.

> [!IMPORTANT]
>
> **CML Version Information**
>
> This fork is configured to use CML version 2.8.1-14. While CML 2.8 has been released, this deployment specifically targets the 2.8.1-14 release using the package file `cml2_2.8.1-14_amd64-20.pkg`. If you need to use a different CML version, you will need to update the configuration and ensure the appropriate package file is available.
>
> **Support:**
>
> - For customers with a valid service contract, CML cloud deployments are supported by TAC within the outlined constraints.  Beyond this, support is done with best effort as cloud environments, requirements and policy can differ to a great extent.
> - With no service contract, support is done on a best effort basis via the issue tracker.
>
> **Features and capabilities:** Changes to the deployment tooling will be considered like any other feature by adding them to the product roadmap.  This is done at the discretion of the CML team.
>
> **Error reporting:** If you encounter any errors or problems that might be related to the code in this repository then please open an issue on the [Github issue tracker for this repository](https://github.com/davisma20/my-cloud-cml/issues).

> [!IMPORTANT]
> Read the section below about [cloud provider selection](#important-cloud-provider-selection) (prepare script).

> [!NOTE]
> For instructions on deploying only the DevNet Expert workstation (without CML), see [DEVNET_WORKSTATION.md](DEVNET_WORKSTATION.md).

## Current Status (as of 2025-04-16)

**Troubleshooting Paused - Infrastructure Destroyed**

Deployment is currently blocked by an issue where EC2 instances consistently fail cloud-init during the `package_update_upgrade_install` stage (specifically `apt-get update` hangs/fails). This leads to Terraform timeouts waiting for instance status checks.

**Investigation Summary:**
*   **Root Cause:** Suspected network connectivity issue preventing `apt-get` from reaching repositories.
*   **Ruled Out:** Custom Netplan configuration in Packer AMI.
*   **Security Group:** Verified to allow outbound HTTP/HTTPS.
*   **NACLs:** Most likely cause. The default NACL is suspected of blocking outbound traffic. `run_validation.py` was enhanced to check NACLs.
*   **IAM Blocker:** The AWS credentials used (`root`) lack `ec2:DescribeNetworkAcls` permission, preventing the script from verifying NACL rules.

**Update:** The persistent `terraform destroy` error related to `templatefile` evaluation and the `custom_scripts_yaml` variable has been **resolved**. The fix involved modifying `modules/deploy/aws/main.tf` to assign the pre-rendered `local.cloud_config` variable directly to the `aws_instance.cml_controller`'s `user_data`, avoiding a problematic secondary template evaluation during the destroy phase.

The infrastructure is currently **destroyed**.

**Next Steps:**
1.  Re-run `terraform apply` to provision the infrastructure.
2.  Resume troubleshooting the original cloud-init boot issues, focusing on potential NACL restrictions or IAM permission problems identified previously using `run_validation.py`.

## Versioned Infrastructure Layout

This repository now uses a versioned folder structure for CML infrastructure code and assets:

- `cml.2.7.0/`: Contains all Terraform, Packer, scripts, documentation, and supporting files for the CML 2.7.0 release. This folder is a complete, working snapshot for that version.
- `cml.2.8.1/`: (In progress) Use this folder to begin building and testing the next CML release. Start by copying only what you need from `cml.2.7.0/` and adapt for 2.8.1 changes. This approach supports clean, iterative upgrades and easy rollbacks.

**Best Practice:** Always add new version folders for major upgrades. Never overwrite or delete previous version folders—this preserves traceability and enables parallel development or hotfixes if needed.

## Custom AMI Building with Packer

This repository includes support for building custom CML AMIs using Packer. The Packer templates and scripts are located in the `packer` directory and provide the following benefits:

- **Customizable AMI**: Build a CML AMI with all required dependencies pre-installed
- **Security Hardening**: Includes security best practices like automatic updates, UFW firewall, and fail2ban protection
- **Reproducible Builds**: Create consistent AMIs across different AWS regions

To build a custom CML AMI:

1. Navigate to the packer directory:
   ```bash
   cd packer
   ```

2. Run the Packer build command:
   ```bash
   packer build cml-simple.pkr.hcl
   ```

3. After the build completes (approximately 15 minutes), the new AMI ID will be displayed in the output.

4. Update the `cml_ami` value in the `config.yml` file with the new AMI ID.

> **Detailed Instructions**: For comprehensive documentation on the CML Packer build process, including troubleshooting and security features, see [PACKER_BUILD.md](documentation/PACKER_BUILD.md).

The custom AMI includes:
- All required dependencies for CML virtualization
- Security hardening features (UFW, fail2ban, automatic updates)
- Performance optimizations for KVM and networking
- Properly initialized CML controller with default admin credentials

## Password Configuration

CML deployments require proper password configuration to ensure successful authentication after installation. The default admin and sysadmin passwords are configured in the `config.yml` file:

```yaml
secret:
  manager: dummy  # Using 'dummy' for direct password configuration
  secrets:
    app:
      username: admin
      raw_secret: '1234QWer!'  # Default admin password
    sys:
      username: sysadmin
      raw_secret: '1234QWer!'  # Default sysadmin password
```

> [!IMPORTANT]
> If you encounter authentication issues after deployment, it's recommended to perform a complete rebuild with `terraform destroy` followed by `terraform apply`. This ensures passwords are properly set during initial installation. See [TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md#authentication-and-password-issues) for more information.

## General requirements

The tooling uses Terraform to deploy CML instances in the Cloud. It's therefore required to have a functional Terraform installation on the computer where this tool chain should be used.

Furthermore, the user needs to have access to the cloud service. E.g. credentials and permissions are needed to create and modify the required resources. Required resources are

- service accounts
- storage services
- compute and networking services

The tool chain / build scripts and Terraform can be installed on the on-prem CML controller or, when this is undesirable due to support concerns, on a separate Linux instance.

That said, the tooling also runs on macOS with tools installed via [Homebrew](https://brew.sh/). Or on Windows with WSL. However, Windows hasn't been tested by us.

### Preparation

Some of the steps and procedures outlined below are preparation steps and only need to be done once. Those are

- cloning of the repository
- installation of software (Terraform, cloud provider CLI tooling)
- creating and configuring of a service account, including the creation of associated access credentials
- creating the storage resources and uploading images and software into it
- creation of an SSH key pair and making the public key available to the cloud service
- editing the `config.yml` configuration file including the selection of the cloud service, an instance flavor, region, license token and other parameters

#### Important: Cloud provider selection

The tooling supports multiple cloud providers (currently AWS and Azure).  Not everyone wants both providers.  The **default configuration is set to use AWS only**.  If Azure should be used either instead or in addition then the following steps are mandatory:

1. Run the `prepare.sh` script to modify and prepare the tool chain.  If on Windows, use `prepare.bat`.  You can actually choose to use both, if that's what you want.
2. Configure the proper target ("aws" or "azure") in the configuration file

The first step is unfortunately required, since it is impossible to dynamically select different cloud configurations within the same Terraform HCL configuration.  See [this SO link](https://stackoverflow.com/questions/70428374/how-to-make-the-provider-configuration-optional-and-based-on-the-condition-in-te) for more some context and details.

The default "out-of-the-box" configuration is AWS, so if you want to run on Azure, don't forget to run the prepare script.

#### Managing secrets

> [!WARNING]
> It is a best practice to **not** keep your CML secrets and passwords in Git!

CML cloud supports these storage methods for the required platform and application secrets:

- Raw secrets in the configuration file (as supported with previous versions)
- Random secrets by not specifiying any secrets
- [Hashicorp Vault](https://www.vaultproject.io/)
- [CyberArk Conjur](https://www.conjur.org/)

See the sections below for additional details how to use and manage secrets.

##### Referencing secrets

You can refer to the secret maintained in the secrets manager by updating `config.yml` appropriately.  If you use the `dummy` secrets manager, it will use the `raw_secret` as specified in the `config.yml` file, and the secrets will **not** be protected.

```yaml
secret:
  manager: conjur
  secrets:
    app:
      username: admin
      # Example using Conjur
      path: example-org/example-project/secret/admin_password
```

Refer to the `.envrc.example` file for examples to set up environment variables to use an external secrets manager.

##### Random secrets

If you want random passwords to be generated when applying, based on [random_password](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password), leave the `raw_secret` undefined:

```yaml
secret:
  manager: dummy
  secrets:
    app:
      username: admin
      # raw_secret: # Undefined
```

> [!NOTE]
>
> You can retrieve the generated passwords after applying with `terraform output cml2secrets`.

The included default `config.yml` configures generated passwords for the following secrets:

- App password (for the UI)
- System password for the OS system administration user
- Cluster secret when clustering is enabled

Regardless of the secret manager in use or whether you use random passwords or not:  You **must** provide a valid Smart Licensing token for the sytem to work, though.

##### CyberArk Conjur installation

> [!IMPORTANT]
> CyberArk Conjur is not currently in the Terraform Registry.  You must follow its [installation instructions](https://github.com/cyberark/terraform-provider-conjur?tab=readme-ov-file#terraform-provider-conjur) before running `terraform init`.

These steps are only required if using CyberArk Conjur as an external secrets manager.

1. Download the [CyberArk Conjur provider](https://github.com/cyberark/terraform-provider-conjur/releases).
2. Copy the custom provider to `~/.terraform.d/plugins/localhost/cyberark/conjur/<version>/<architecture>/terraform-provider-conjur_v<version>`

   ```bash
   $ mkdir -vp ~/.terraform.d/plugins/localhost/cyberark/conjur/0.6.7/darwin_arm64/
   $ unzip ~/terraform-provider-conjur_0.6.7-4_darwin_arm64.zip -d ~/.terraform.d/plugins/localhost/cyberark/conjur/0.6.7/darwin_arm64/
   $
   ```

3. Create a `.terraformrc` file in the user's home:

   ```hcl
   provider_installation {
     filesystem_mirror {
       path    = "/Users/example/.terraform.d/plugins"
       include = ["localhost/cyberark/conjur"]
     }
     direct {
       exclude = ["localhost/cyberark/conjur"]
     }
   }
   ```

## CML Password Management

> [!IMPORTANT]
> **Understanding CML Credentials**
>
> CML uses two different sets of credentials:
> 
> 1. **System Administration (sysadmin)**: For accessing the system administration cockpit at `https://<cml-ip>:9090`
> 2. **CML Application (admin)**: For accessing the main CML GUI at `https://<cml-ip>`
>
> **Password Configuration:**
>
> By default, if you don't explicitly set passwords in `config.yml`, random 16-character passwords will be generated during deployment. To set specific passwords:
>
> ```yaml
> # In config.yml
> secrets:
>   app:
>     username: admin
>     raw_secret: your-admin-password  # Uncomment and set this
>
>   sys:
>     username: sysadmin
>     raw_secret: your-sysadmin-password  # Uncomment and set this
> ```
>
> For troubleshooting password issues, see the [TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md#cml-authentication-issues) guide.

## Cloud specific instructions

See the documentation directory for cloud specific instructions:

- [Amazon Web Services (AWS)](documentation/AWS.md)
- [Microsoft Azure](documentation/Azure.md)

## Customization

There's two Terraform variables which can be defined / set to further customize the behavior of the tool chain:

- `cfg_file`: This variable defines the configuration file.  It defaults to `config.yml`.
- `cfg_extra_vars`: This variable defines the name of a file with additional variable definitions.  The default is "none".

Here's an example of an `.envrc` file to set environment variable.  Note the last two lines which define the configuration file to use and the extra shell file which defines additional environment variables.

```bash
export TF_VAR_aws_access_key="aws-something"
export TF_VAR_aws_secret_key="aws-somethingelse"

# export TF_VAR_azure_subscription_id="azure-something"
# export TF_VAR_azure_tenant_id="azure-something-else"

export TF_VAR_cfg_file="config-custom.yml"
export TF_VAR_cfg_extra_vars="extras.sh"
```

A typical extra vars file would look like this (as referenced by `extras.sh` in the code above):

```plain
CFG_UN="username"
CFG_PW="password"
CFG_HN="domainname"
CFG_EMAIL="noone@acme.com"
```

In this example, four additional variables are defined which can be used in customization scripts during deployment to provide data (usernames, passwords, ...) for specific services like configuring DNS.  See the `03-letsencrypt.sh` file which installs a valid certificate into CML, using LetsEncrypt and DynDNS for domain name services.

See the AWS specific document for additional information how to define variables in the environment using tools like `direnv`  or `mise`.

## Additional customization scripts

The deploy module has a couple of extra scripts which are not enabled / used by default.  They are:

- request/install certificates from LetsEncrypt (`03-letsencrypt.sh`)
- customize additional settings, here: add users and resource pools (`04-customize.sh`).

These additional scripts serve mostly as an inspiration for customization of the system to adapt to local requirements.

### Requesting a cert

The letsencrypt script requests a cert if there's none already present.  The cert can then be manually copied from the host to the cloud storage with the hostname as a prefix.  If the host with the same hostname is started again at a later point in time and the cert files exist in cloud storage, then those files are simply copied back to the host without requesting a new certificate.  This avoids running into any certificate request limits.

Certificates are stored in `/etc/letsencrypt/live` in a directory with the configured hostname.

## Limitations

Extra variable definitions and additional scripts will all be stored in the user-data that is provided via cloud-init to the cloud host.  There's a limitation in size for the user-data in AWS.  The current limit is 16KB.  Azure has a much higher limit (unknown what the limit actually is, if any).

All scripts are copied as they are including all comments which will require even more space.

Cloud-cml currently uses the cloud-init Terraform provider which allows compressed storage of this data.  This allows to store more scripts and configuration due to the compression.  The 16KB limit is still in place for the compressed data, though.

## Cisco Modeling Labs - AWS Deployment

This repository contains Terraform configurations for deploying Cisco Modeling Labs (CML) on AWS. It includes support for both standalone and clustered deployments, along with a DevNet workstation for GUI access.

## Prerequisites

1. AWS Account with appropriate permissions
2. Terraform >= 1.1.0
3. AWS CLI configured with your credentials
4. CML software package (version 2.8.1-14)
5. Reference platform files (compatible with your CML version)
6. SSH key pair in your target AWS region

## Required Files

### CML Software Package
The CML package should contain:
- Main package file (e.g., `cml2_2.8.1-14_amd64-20.pkg`)
- Digital signature file (`.signature`)
- Certificate file (`.pem`)
- Verification script (`cisco_x509_verify_release.py3`)

### Reference Platform Files
The reference platform package includes:
- ISO file (e.g., `refplat-20241223-fcs.iso`)
- Digital signature and verification files
- Node definitions and images (if any)

## Quick Start

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd Cloud-cml
   ```

2. Prepare your configuration:
   ```bash
   cp config.yml.example config.yml
   ```

3. Edit `config.yml` with your settings:
   - AWS region and availability zone
   - S3 bucket name
   - Instance types and SSH key name
   - Network CIDR ranges
   - CML software package name (must match exactly)
   - Reference platform configuration

4. Verify package signatures (recommended):
   ```bash
   # For CML package
   ./cisco_x509_verify_release.py3 -e CML-IMG-REL-CCO_RELEASE.pem -i your-cml-package.pkg -s your-cml-package.signature

   # For reference platform
   ./cisco_x509_verify_release.py3 -e CML-IMG-REL-CCO_RELEASE.pem -i your-refplat.iso -s your-refplat.signature
   ```

5. Upload required files to S3:
   ```bash
   # Upload CML software package
   aws s3 cp cml2_2.8.1-14_amd64-20.pkg s3://your-bucket/

   # Create refplat directory and upload reference platform files
   aws s3 cp refplat/ s3://your-bucket/refplat/ --recursive
   ```

6. Initialize and apply Terraform:
   ```bash
   terraform init
   terraform apply
   ```

## Architecture

The deployment creates:
1. CML Controller instance (c5.2xlarge)
   - Root volume: 64GB
   - CML software package
   - Reference platform files
2. DevNet workstation (t3.large)
   - Ubuntu 22.04 LTS
   - Browser access to CML
3. VPC with public subnet
4. Security groups for CML and workstation
5. Optional compute nodes for clustering

## Documentation Map

All project documentation is now centralized in the `documentation/` folder. Below is a map of the most important documents and their purposes:

### Core Documentation
- [README.md](documentation/README.md): Overview of the documentation structure and getting started.
- [CHANGELOG.md](documentation/CHANGELOG.md): Full project changelog and release history.
- [TODO.md](documentation/TODO.md): Project TODOs and planned features.
- [NEXT_STEPS.md](documentation/NEXT_STEPS.md): Immediate next actions and recommendations.

### Specialized Documentation Subfolders
- [documentation/packer/README.md](documentation/packer/README.md): Packer-specific usage, troubleshooting, and build notes.
- [documentation/packer/NEXT_STEPS_README.md](documentation/packer/NEXT_STEPS_README.md): Next steps for Packer-based builds.
- [documentation/packer/NETWORK_DIAGNOSTICS_README.md](documentation/packer/NETWORK_DIAGNOSTICS_README.md): Network diagnostics and troubleshooting for Packer builds.
- [documentation/security/hardening/README.md](documentation/security/hardening/README.md): Security hardening documentation and best practices.

### Cloud and Deployment Guides
- [AWS.md](documentation/AWS.md): AWS-specific deployment instructions.
- [CML_DEPLOYMENT.md](documentation/CML_DEPLOYMENT.md): General CML deployment overview.
- [CML_INSTALLATION.md](documentation/CML_INSTALLATION.md): Step-by-step CML installation guide.
- [PACKER_BUILD.md](documentation/PACKER_BUILD.md): Building custom AMIs with Packer.

### Troubleshooting & Forensics
- [TROUBLESHOOTING.md](documentation/TROUBLESHOOTING.md): Troubleshooting common issues.
- [CML_Forensic_Troubleshooting.md](documentation/CML_Forensic_Troubleshooting.md): Forensic analysis and advanced troubleshooting.
- [SERVICE_MONITORING.md](documentation/SERVICE_MONITORING.md): Monitoring CML services and health.

### Connectivity & Workstation
- [CML_DEVNET_CONNECTIVITY.md](documentation/CML_DEVNET_CONNECTIVITY.md): CML and DevNet connectivity setup.
- [DEVNET_WORKSTATION.md](documentation/DEVNET_WORKSTATION.md): DevNet Expert workstation setup and usage.

---

All new documentation should be added to the `documentation/` folder and referenced here for consistency and discoverability.

## Project Root File Map

```
/
├── .git/ (Git internal directory)
├── .gitignore
├── .terraform/ (Terraform internal directory)
├── .terraform.lock.hcl
├── CHANGELOG.md
├── CML-IMG-REL-CCO_RELEASE.pem
├── CML_DEPLOYMENT.md
├── DEVNET_WORKSTATION.md
├── LICENSE
├── NEXT_STEPS.md
├── None_validation.log
├── README.md
├── TODO.md
├── aws_cli_system_log.txt
├── check_ssm_registration.py
├── cisco_x509_verify_release.py3
├── cloud-init-test.yaml
├── cml-access-key.pem
├── cml-assets/
├── cml-cloudinit-test_*.json
├── cml-controller-*.json
├── cml-network-fix.tfplan
├── cml2_2.7.0-4_amd64-20-pkg.zip
├── cml2_2.7.0-4_amd64-20.pkg.README
├── cml2_2.7.0-4_amd64-20.pkg.signature
├── cml2_2.8.1-14_amd64-35_SHA256-disk1.vmdk
├── cml_controller_screenshot.json
├── cml_controller_system_log.txt
├── cml_validator_utils/
│   └── ... (Utility scripts and modules)
├── compare_validation_results.py
├── config.yml
├── config.yml.example
├── console_screenshot_*.jpg
├── decode_screenshot.py
├── devicecheck_forensic.json
├── devnet_*.json
├── documentation/
│   └── ... (Project documentation files)
├── forensic_*.log
├── i-*.log (Instance-specific logs/validation results)
├── i-*.txt (Instance-specific system logs)
├── i-*.jpg (Instance-specific screenshots)
├── images/
│   └── ... (Image files, e.g., diagrams)
├── import-cml.json
├── logs/
├── main.tf
├── modules/
│   └── ... (Terraform modules)
├── monitor_cml_logs.sh
├── monitor_logs.sh
├── network_validated_ami.auto.tfvars
├── output.tf
├── packer/
│   └── ... (Packer templates, scripts, and logs)
├── prepare.bat
├── prepare.sh
├── quicktest_forensic_forensic.json
├── refplat/
│   └── ... (Reference platform files)
├── refplat2.8/
├── refplat_p-*.zip
├── requirements.txt
├── run_validation.py
├── screenshot_*.jpg
├── scripts/
│   └── ... (General utility scripts)
├── security/
│   └── ... (Security-related files)
├── serial_log_*.txt
├── sessionmanager-bundle/
├── sessionmanager-bundle.zip
├── ssh_jump_connect.py
├── terraform/
├── terraform-key.pem
├── terraform.auto.tfvars
├── terraform.options-cfg.example.tfvars
├── terraform.tf
├── terraform.tfstate
├── terraform.tfstate.backup
├── terraform.tfvars
├── tf_apply_with_logs.sh
├── tfplan
├── ubuntu-cloudinit-test_*.json
├── upload-images-to-aws.sh
├── validation_results_*.json
├── validator.log
├── validators/
│   └── ... (Validation scripts and helpers)
└── variables.tf
```

## Validation Scripts

All validation scripts are now located in the top-level `validations/` directory. To validate your CML deployment, use:

```sh
cd validations
python3 run_validation.py --instance-id <INSTANCE_ID> --check-cml-services
```

Replace `<INSTANCE_ID>` with your actual AWS EC2 instance ID (e.g., `i-0e0bc211293ebad69`).

This structure allows you to reuse validation scripts across all CML versions (e.g., `cml.2.7.0`, `cml.2.8.1`).

## Recent Updates

### CML Service Check Feature (April 20, 2025)

Successfully implemented and debugged the `--check-cml-services` flag in `run_validation.py`. This feature allows direct verification of core CML service status via SSM, crucial for post-deployment validation. The implementation involved adding a new method (`check_cml_services_via_ssm`), updating the argument parser, fixing class initialization (`__init__` method addition), and refining error handling for SSM command execution.

This feature was instrumental in diagnosing that the CML instance `i-0cdb562a0ff8c9206` was missing the `virl2-uwm.service`, confirming an incomplete installation originating from an older AMI build.

## Next Steps (Troubleshooting CML Installation)

The validation script confirmed that the currently deployed CML instance (`i-0cdb562a0ff8c9206`) was built from an AMI where CML services were not installed correctly due to an issue in the Packer build script (`packer/install_cml_2.7.0.sh`) that has since been fixed (problematic `setup.sh` execution was commented out).

To resolve this and get a correctly functioning CML instance, the following steps are required:

1.  **Rebuild AMI:**
    *   Navigate to the `packer` directory: `cd /Users/miked/Documents/Projects/python_project/my-cloud-cml/packer`
    *   Run the Packer build: `packer build .`
    *   Monitor the build process for successful completion.
2.  **Update AMI Variable:**
    *   After the Packer build succeeds, verify that the new AMI ID has been automatically written to `/Users/miked/Documents/Projects/python_project/my-cloud-cml/network_validated_ami.auto.tfvars`.
3.  **Redeploy Instance with Terraform:**
    *   Navigate to the project root directory: `cd /Users/miked/Documents/Projects/python_project/my-cloud-cml`
    *   Apply the Terraform configuration to destroy the old instance and create a new one with the updated AMI: `terraform apply -auto-approve`
4.  **Final Validation:**
    *   Identify the new instance ID from the Terraform output.
    *   Run the validation script against the new instance, including the service check: `python run_validation.py -i <new-instance-id> --check-cml-services`
    *   Confirm that the output shows all CML services as `active (running)`. 

## Artifacts, Keys, and Scripts

- All PEM keys are now in `cml.2.7.0/keys/`
- All log and artifact files are in `cml.2.7.0/artifacts/`
- All scripts (e.g., `prepare.sh`, `prepare.bat`) are in `cml.2.7.0/scripts/`
- All configuration and asset files are in `cml.2.7.0/assets/`
- All validator utilities are in `cml.2.7.0/validators/`
- CML 2.8.1 disk image is in `cml.2.8.1/`

**The project root is now clean and all files are organized by version and function.**
