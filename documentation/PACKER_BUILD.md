# Packer Build Process for CML AMI

This document outlines the steps and configuration for building a custom Cisco Modeling Labs (CML) AMI using HashiCorp Packer.

## Current Build: CML 2.7.0

*   **Packer Configuration:** `packer/cml-2.7.0.pkr.hcl`
*   **Build Script:** `packer/build_cml_2.7.0.sh` (Recommended way to run the build)
*   **Latest AMI (us-east-2):** `ami-032d7958a238a2977` (Built 2025-04-13) (Previous: `ami-07d20a2e50f3607e9` Built 2025-04-12 - Verify AMI ID after current build completes)

## Build Steps

1.  **Prerequisites:**
    *   Packer installed.
    *   AWS CLI configured with credentials having permissions to create EC2 instances, AMIs, security groups, roles, etc.
    *   CML 2.7.0 `.pkg` installer file accessible (e.g., in an S3 bucket specified in variables, or modify the script to upload/use a local file).

2.  **Configuration:**
    *   Review variables within `packer/cml-2.7.0.pkr.hcl`. Key variables include:
        *   `cml_admin_password`: The desired initial password for the CML `admin` user.
        *   `aws_region`: The target AWS region for the build.
        *   `source_ami` / `source_ami_filter`: The base Ubuntu AMI to use.
        *   `cml_installer_s3_bucket`, `cml_installer_s3_key`: If loading the installer from S3.
    *   Variables can be overridden using a `.pkrvars.hcl` file or command-line `-var` arguments.

3.  **Execute Build:**
    *   Navigate to the `packer` directory in your terminal.
    *   Run the build script: `bash build_cml_2.7.0.sh`
    *   The script handles cache cleaning and logs the Packer output to a timestamped file (e.g., `packer_build_YYYYMMDDHHMMSS.log`) as well as to `packer_build.log`.
    *   Monitor the output for progress and any errors.

4.  **Output:**
    *   Upon successful completion, Packer will output the ID of the newly created AMI.
    *   Update the `cml_ami` variable in your Terraform configuration (e.g., `packer/network_validated_ami.auto.tfvars`) with this new AMI ID.

## Build Process Details

*   **Source AMI:** Ubuntu 20.04 LTS (Focal Fossa) - Selected automatically by Packer based on filters.
*   **Instance Type:** `c5.2xlarge` (default, configurable via variables).
*   **Region:** `us-east-2` (default, configurable via variables).
*   **Key Scripts:**
    *   `cml-2.7.0.pkr.hcl`: Main Packer template defining variables, builder, and provisioner steps.
    *   `bootstrap_cml.sh`: Performs initial system setup, dependency installation, user creation, security hardening, and **installs the `amazon-ssm-agent` using the `.deb` package method** (this replaced the previous `snap` method to avoid conflicts with cloud-init).
    *   `install_cml_2.7.0.sh`: Handles the core CML 2.7.0 installation using downloaded `.deb` files and **performs CML service restarts *after* installation is complete** (this was moved from `cml-2.7.0.pkr.hcl` to fix build sequence errors).
*   **Output:** A private AMI tagged appropriately (e.g., `CML-2.7.0-AMI`, `Builder=Packer`).

## Recent Changes

*   **2025-04-15:** Removed the custom Netplan configuration (`packer/50-cml-netplan.yaml`) from the build process. This was done to troubleshoot cloud-init failures observed during Terraform deployments where package installations failed, likely due to network issues caused by the custom config interfering with early boot network setup.
*   **2025-04-13:** Modified `install_cml_2.7.0.sh` to ensure build fails correctly if CML `.deb` package installation encounters an error.
*   **2025-04-13:** Switched `amazon-ssm-agent` installation to use the official `.deb` package downloaded via `curl` instead of relying on potentially outdated repository versions, resolving conflicts observed during cloud-init.

## Latest Successful Build

*   **AMI ID:** `ami-032d7958a238a2977`
*   **Region:** `us-east-2`
*   **Date:** 2025-04-13
*   **Key Fixes Included:** SSM Agent `.deb` installation, corrected CML service restart sequence.

## Running the Build

1.  **Prerequisites:**
    *   Packer installed.
    *   AWS CLI configured with credentials having permissions to create EC2 instances, AMIs, security groups, roles, etc.
    *   CML 2.7.0 `.pkg` installer file accessible (e.g., in an S3 bucket specified in variables, or modify the script to upload/use a local file).

2.  **Configuration:**
    *   Review variables within `packer/cml-2.7.0.pkr.hcl`. Key variables include:
        *   `cml_admin_password`: The desired initial password for the CML `admin` user.
        *   `aws_region`: The target AWS region for the build.
        *   `source_ami` / `source_ami_filter`: The base Ubuntu AMI to use.
        *   `cml_installer_s3_bucket`, `cml_installer_s3_key`: If loading the installer from S3.
    *   Variables can be overridden using a `.pkrvars.hcl` file or command-line `-var` arguments.

3.  **Execute Build:**
    *   Navigate to the `packer` directory in your terminal.
    *   Run the build script: `bash build_cml_2.7.0.sh`
    *   The script handles cache cleaning and logs the Packer output to a timestamped file (e.g., `packer_build_YYYYMMDDhhmmss.log`) as well as to `packer_build.log`.
    *   Monitor the output for progress and any errors.

4.  **Output:**
    *   Upon successful completion, Packer will output the ID of the newly created AMI.
    *   Update the `cml_ami` variable in your Terraform configuration (e.g., `packer/network_validated_ami.auto.tfvars`) with this new AMI ID.

## Key Build Logic & Fixes (CML 2.7.0)

The `cml-2.7.0.pkr.hcl` file orchestrates several steps:

1.  **Instance Launch:** Launches a temporary EC2 instance from the specified source Ubuntu AMI.
2.  **Prerequisites Installation:** Installs necessary packages (`apt-get update`, `unzip`, `python3`, etc.).
3.  **Bootstrap Script Execution:** Executes `bootstrap_cml.sh`.
    *   This script installs CML dependencies (KVM, libvirt, Nginx, Python packages, etc.), configures the system (networking, cloud-init), and performs basic hardening. It does **not** install the core CML `.deb` package itself.
    *   **Known Issue:** It was observed during builds (April 2025) that the `admin` user creation within CML (if attempted by this script or the `.pkg` installer it might trigger) was unreliable.
4.  **Download and Prepare CML Installation:** Executes `install_cml_2.7.0.sh`.
    *   This script downloads the CML `.deb` files from S3 to a temporary location.
5.  **CML .deb Package Installation:** Executes a shell provisioner that runs `apt-get install` on the downloaded `.deb` files.
    *   **Important Fix (2025-04-12):** Error suppression (`|| true`) was removed from the `apt-get install ./cml*.deb` command within the installation logic triggered by `install_cml_2.7.0.sh`. This ensures that if the core CML package fails to install, the Packer build will now correctly fail instead of potentially producing a broken AMI.
6.  **Debugging Output (Optional but Recommended):** Dumps `/var/log/cml_install.log` and `/etc/passwd` to the Packer log to aid troubleshooting user/install issues.
7.  **Explicit Admin User Creation:** A dedicated `shell` provisioner runs *after* bootstrap/install to ensure the CML `admin` user exists within the OS (if needed by CML components outside the main package). It uses `sudo useradd -m -s /bin/bash -g admin admin` to handle cases where the `admin` group might already exist.
8.  **Password Setting:** Conditionally checks for `admin` or `cml2` user existence and uses `chpasswd` to set the password provided in the `cml_admin_password` variable.
9.  **Service Restart:** Restarts CML services.
10. **UI Check:** Performs a basic check to see if the CML web UI responds on HTTPS.
11. **Cleanup & AMI Creation:** Stops the instance, creates the AMI, and cleans up temporary resources (key pair, security group, instance).

## Troubleshooting Build Failures

*   **Check Packer Logs:** Detailed logs are saved to `packer/packer_build_YYYYMMDDhhmmss.log` and linked via `packer/packer_build.log`. Review these for specific error messages from provisioner scripts.
*   **SSM Agent Issues:** Previously, using `snap` to install `amazon-ssm-agent` caused conflicts during instance boot (related to cloud-init). This has been resolved by switching to the official `.deb` package installation method within `bootstrap_cml.sh`.
*   **Service Not Found Errors:** Previously, `virl2-controller` or `virl2-uwm` might fail to restart during the build because the restart command in `cml-2.7.0.pkr.hcl` ran *before* `install_cml_2.7.0.sh` installed the services. This has been fixed by removing the premature restart from the HCL file and adding the restart logic to the end of `install_cml_2.7.0.sh`.
*   **Dependency Issues:** Ensure base OS packages (`apt-get update`, `apt-get upgrade`) run successfully early in the build. Network connectivity issues can sometimes cause failures here.
*   **S3 Bucket Access:** Verify the temporary IAM role created by Packer has the necessary `s3:GetObject` and `s3:ListBucket` permissions for the specified CML bucket (`var.cml_bucket`).
*   **Disk Space:** Ensure the `volume_size` variable provides sufficient space for the OS, CML, and temporary files.

## Troubleshooting

Refer to the main `documentation/TROUBLESHOOTING.md` and `documentation/CML_INSTALLATION.md` files for common issues and detailed troubleshooting steps, including the user creation problem detailed above.
