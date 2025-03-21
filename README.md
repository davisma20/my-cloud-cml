# README

Version 2.8.0-DevNet, March 21, 2025

> **This is a customized fork of the [Cisco DevNet cloud-cml repository](https://github.com/CiscoDevNet/cloud-cml) with added support for DevNet Expert workstation deployment.**

CML instances can run on Azure and AWS cloud infrastructure.  This repository provides automation tooling using Terraform to deploy and manage CML in the cloud.  We have tested CML deployments using this tool chain in both clouds.  **The use of this tool is considered BETA**.  The tool has certain requirements and prerequisites which are described in this README and in the [documentation](documentation) directory.

*It is very likely that this tool chain can not be used "as-is"*.  It should be forked and adapted to specific customer requirements and environments.

> [!IMPORTANT]
>
> **Version 2.7 vs 2.8**
>
> CML2 version 2.8 has been released in November 2024.  As CML 2.8 uses Ubuntu 24.04 as the base operating system, cloud-cml needs to accommodate for that during image selection when bringing up the VM on the hosting service (AWS, Azure, ...).  This means that going forward, cloud-cml supports 2.8 and not 2.7 anymore.  If CML versions earlier than CML 2.8 should be used then please select the release with the tag `v2.7.2` that still supports CML 2.7!
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

### Terraform installation

Terraform can be downloaded for free from [here](https://developer.hashicorp.com/terraform/downloads). This site has also instructions how to install it on various supported platforms.

Deployments of CML using Terraform were tested using the versions mentioned below on Ubuntu Linux.

```bash
$ terraform version
Terraform v1.10.4
on linux_amd64
+ provider registry.terraform.io/ciscodevnet/cml2 v0.8.1
+ provider registry.terraform.io/hashicorp/aws v5.83.0
+ provider registry.terraform.io/hashicorp/cloudinit v2.3.5
+ provider registry.terraform.io/hashicorp/random v3.6.1
$
```

It is assumed that the CML cloud repository was cloned to the computer where Terraform was installed. The following command are all executed within the directory that has the cloned repositories. In particular, this `README.md`, the `main.tf` and the `config.yml` files, amongst other files.

When installed, run `terraform init` to initialize Terraform. This will download the required providers and create the state files.

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
4. CML software package (version 2.7.0 or later)
5. Reference platform files (compatible with your CML version)
6. SSH key pair in your target AWS region

## Required Files

### CML Software Package
The CML package should contain:
- Main package file (e.g., `cml2_2.7.0-4_amd64-20.pkg`)
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
   aws s3 cp cml2_2.7.0-4_amd64-20.pkg s3://your-bucket/

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

## Configuration Guide

### AWS Configuration
- `region`: AWS region for deployment
- `availability_zone`: Specific AZ for instances
- `bucket`: S3 bucket for CML files
- `flavor`: Instance type for CML controller
- `profile`: IAM instance profile

### Network Configuration
- `public_vpc_ipv4_cidr`: VPC CIDR range
- `allowed_ipv4_subnets`: IP ranges allowed to access CML
- Optional: Use existing VPC/Gateway with `vpc_id` and `gw_id`

### CML Configuration
- `disk_size`: Root volume size
- `controller_hostname`: CML hostname
- `key_name`: SSH key pair name
- `enable_patty`: Enable terminal access
- `software`: Exact name of CML package file
- `refplat.iso`: Exact name of reference platform ISO

### Security Best Practices
1. Use environment variables for AWS credentials
2. Restrict `allowed_ipv4_subnets` in production
3. Enable EBS encryption if required
4. Use secrets management in production
5. Verify package signatures before deployment
6. Keep sensitive files out of version control

## Accessing CML

1. Connect to DevNet workstation:
   ```bash
   ssh -i your-key.pem ubuntu@workstation-ip
   ```

2. Access CML GUI:
   - Open browser on workstation
   - Navigate to https://cml-controller
   - Default credentials in documentation
   - Change passwords on first login

## Troubleshooting

### CML Controller Instance Reachability Issues

If you encounter "Instance reachability check failed" errors with the CML controller:

1. **Check Instance Size**: Ensure you're using a sufficiently powerful instance type (c5.4xlarge or larger recommended).

2. **Examine Logs**: SSH into the instance and check the logs:
   ```bash
   ssh -i your-key.pem ubuntu@<instance-ip>
   sudo cat /var/log/cml-provision.log
   sudo cat /var/log/cloud-init-output.log
   ```

3. **Monitor Resources**: Check resource usage during initialization:
   ```bash
   ssh -i your-key.pem ubuntu@<instance-ip>
   htop
   ```

4. **Increase Timeouts**: If the instance is timing out during initialization, consider increasing the timeouts in:
   - `modules/deploy/data/cml.sh`
   - `modules/deploy/data/cloud-config.txt`

5. **Check Network Configuration**: Ensure the security groups and network settings allow proper connectivity.

### RDP Access to DevNet Workstation

If you're having trouble accessing the DevNet workstation via RDP:

1. **Verify Security Group**: Ensure port 3389 is open in the security group.

2. **Check RDP Service**: SSH into the workstation and verify the RDP service:
   ```bash
   ssh -i your-key.pem ubuntu@<workstation-ip>
   sudo systemctl status xrdp
   ```

3. **RDP Credentials**: Use the following default credentials:
   - Username: `devnet`
   - Password: `devnet123`

4. **Restart RDP Service**: If needed, restart the service:
   ```bash
   sudo systemctl restart xrdp
   ```

## Support

For issues with:
- Deployment: Open an issue in this repository
- CML software: Contact Cisco support
- AWS services: Contact AWS support

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the terms of the LICENSE file included in this repository.
