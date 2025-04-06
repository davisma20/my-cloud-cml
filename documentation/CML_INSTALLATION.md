# CML Installation Improvements

This document describes improvements made to the CML installation process to address common installation issues.

## Background

The original CML installation process sometimes failed due to several issues:

1. **Escape sequence errors** in the systemd service file (`cml_install.service`)
2. **Improper handling of non-interactive commands** like wireshark-common configuration
3. **Insufficient logging** making it difficult to diagnose installation failures
4. **Timeout issues** during the installation process

## Implementation Details

### Improved Installation Service

We've created a more robust `cml_install.service` file that:

- Adds comprehensive logging to `/var/log/cml_install.log` with timestamps
- Properly escapes all commands to avoid systemd parsing errors
- Uses non-interactive installation methods to prevent hanging
- Has a generous timeout (30 minutes) to ensure completion
- Properly creates the `/etc/.virl2_unconfigured` flag file to trigger the initial setup process

### Enhanced Installation Fix Script

The `cml_install_fix.sh` script has been updated to:

- Replace the problematic service file with our improved version
- Better handle the case where the service file doesn't exist
- Add proper waiting for the service to complete
- Ensure the first-time configuration flag is set
- Provide more detailed status information

### Reliable Installation Script

Based on production troubleshooting, we've added a more reliable direct installation script
(`cml_install_reliable.sh`) that:

- Bypasses the systemd service approach entirely to avoid escape sequence issues
- Directly installs the CML package using non-interactive commands
- Sets up proper logging in `/var/log/cml_install.log`
- Creates the first-time configuration flag file (`/etc/.virl2_unconfigured`)
- Properly configures wireshark without interactive prompts
- Sets appropriate log levels in the configuration
- Starts the CML controller service directly

This reliable installation script is now the preferred method used in the Terraform deployment
and provides a more robust installation process.

## Troubleshooting

If you encounter CML installation issues:

1. **Check the installation logs**:
   ```
   cat /var/log/cml_install.log
   ```

2. **View the systemd service status**:
   ```
   systemctl status cml_install.service
   ```

3. **View journal logs for the service**:
   ```
   journalctl -u cml_install.service
   ```

4. **Verify first-time setup flag exists**:
   ```
   ls -la /etc/.virl2_unconfigured
   ```

5. **Check if the CML package is installed**:
   ```
   dpkg -l | grep cml2
   ```

## Common Issues

### Authentication Failures

If you can access the CML GUI but cannot log in:

1. Check which users exist in the database:
   ```
   sudo sqlite3 /var/local/virl2/config/controller.db "SELECT id, username FROM user;"
   ```

2. Note that the default user might be "cml2" rather than "admin"

3. If needed, reset the password directly (replace with actual commands for your CML version)

### Uncompleted Installation

If the CML services are not running correctly:

1. Verify the CML package is installed:
   ```
   dpkg -l | grep cml2
   ```

2. Restart the controller service:
   ```
   systemctl restart virl2-controller
   ```

### Issue: Packer build fails during password setting for 'admin' user

*   **Symptoms:** Packer logs show errors like "user 'admin' does not exist" or attempts to set the password fail, even after correcting the bootstrap script path.
*   **Root Cause Analysis (Build 2025-04-06):**
    *   The CML bootstrap process (`bootstrap_cml.sh`) successfully completed basic setup but failed to create the `admin` *user* account.
    *   Further investigation revealed that an `admin` *group* was being created, likely by a dependency installed during bootstrap.
    *   Initial attempts to explicitly add the `admin` user with `useradd admin` failed because the command implicitly tries to create a matching group, which already existed (`useradd: group admin exists...`).
*   **Fix Applied (in `cml-2.7.0.pkr.hcl`):**
    *   Added a dedicated Packer `shell` provisioner **after** the main bootstrap script but **before** the password setting step.
    *   This provisioner explicitly creates the `admin` user, telling `useradd` to use the *existing* `admin` group:
        ```hcl
        provisioner "shell" {
          inline = [
            "echo 'Explicitly creating admin user...'",
            "sudo useradd -m -s /bin/bash -g admin admin || echo 'WARN: useradd -g admin admin command failed...'"
          ]
        }
        ```
    *   Added log/debug provisioners to dump `/etc/passwd` and `cml_install.log` to aid diagnostics.
    *   Modified the password provisioner to conditionally check for `admin` or `cml2` before attempting `chpasswd`.

### Issue: CML Web UI unreachable after deployment

*   **Check Security Groups:** Ensure the AWS security group associated with the CML instance allows inbound traffic on HTTPS (port 443) from your IP address.
*   **Check CML Services:** SSH into the instance (`ubuntu` user with your key pair) and check service status:
    ```bash
    sudo systemctl status cml-controller
    sudo systemctl status cml-compute
    # Check other relevant services if needed
    ```
*   **Review Logs:** Check CML logs on the instance, typically in `/var/log/`. Check `/var/log/cml_install.log` for installation issues.

### Potential User Discrepancy (`admin` vs. `cml2`)

*   Early CML versions or documentation might suggest `cml2` as the default user. The current build process explicitly targets and creates the `admin` user. If issues arise, checking `/etc/passwd` (as done by the debug provisioner) is the first step.

## References

- [CML 2.8 Documentation](https://www.cisco.com/c/en/us/td/docs/cloud-systems-management/cisco-modeling-labs/cisco-modeling-labs-2-8/admin/b_admin_guide_2-8.html)

## Current Stable AMI (CML 2.7.0)

*   **AMI ID:** `ami-0aef6f8637c4c6500`
*   **Region:** `us-east-2`
*   **Build Date:** 2025-04-06
*   **Notes:** This build incorporates fixes for user creation issues encountered during the Packer process (see Troubleshooting section).

## Packer Build Process (CML 2.7.0)

The Packer configuration is defined in `packer/cml-2.7.0.pkr.hcl`.

1.  **Prerequisites:**
    *   Packer installed.
    *   AWS CLI configured with appropriate credentials.
    *   CML 2.7.0 `.pkg` installer downloaded (ensure it's referenced correctly, e.g., via an S3 bucket or local path in the Packer vars).
2.  **Variables:** Review and update variables in `packer/cml-2.7.0.pkr.hcl` or provide them via `-var` or a `.pkrvars.hcl` file (e.g., `cml_admin_password`, `aws_region`, `source_ami`).
3.  **Run Build:** Navigate to the `packer` directory and execute:
    ```bash
    bash build_cml_2.7.0.sh
    ```
    This script handles cache cleaning and logging.

## Terraform Deployment

To deploy CML using the built AMI with Terraform:

1.  **Update AMI Variable:** Ensure the `cml_ami` variable in `packer/network_validated_ami.auto.tfvars` matches the **Current Stable AMI ID** listed above.
    ```hcl
    # packer/network_validated_ami.auto.tfvars
    cml_ami = "ami-0aef6f8637c4c6500"
    aws_region = "us-east-2" # Ensure this matches the AMI region
    # ... other variables
    ```
2.  **Initialize and Apply:** Navigate to the root Terraform directory (`my-cloud-cml`) and run:
    ```bash
    terraform init
    terraform apply -var-file=packer/network_validated_ami.auto.tfvars
    ```
    *(Adjust `-var-file` path if needed or rely on auto-loading)*
