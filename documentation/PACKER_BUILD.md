# Packer Build Process for CML AMI

This document outlines the steps and configuration for building a custom Cisco Modeling Labs (CML) AMI using HashiCorp Packer.

## Current Build: CML 2.7.0

*   **Packer Configuration:** `packer/cml-2.7.0.pkr.hcl`
*   **Build Script:** `packer/build_cml_2.7.0.sh` (Recommended way to run the build)
*   **Latest AMI (us-east-2):** `ami-0a8303fee58aa8f54` (Built 2025-04-13) (Previous: `ami-07d20a2e50f3607e9` Built 2025-04-12 - Verify AMI ID after current build completes)

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

## Troubleshooting

Refer to the main `documentation/TROUBLESHOOTING.md` and `documentation/CML_INSTALLATION.md` files for common issues and detailed troubleshooting steps, including the user creation problem detailed above.
