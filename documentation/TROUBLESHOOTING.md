# CML Deployment Troubleshooting Guide

*Last Updated: March 22, 2025*

This document provides troubleshooting steps for common issues encountered during CML deployment and installation in cloud environments.

## Package Format Issues

### Issue: CML Installation Service Failure

**Symptom:** The `cml_install.service` fails to start or completes with errors. You may see this in systemd logs or when checking service status.

**Possible Causes:**
1. Package format mismatch between configuration and actual file
2. Incorrect package path or permissions
3. Package not properly uploaded to storage bucket

**Resolution:**

1. **Verify the package format and name:**
   ```bash
   # On the CML instance
   ls -la /root/cml2*
   ```
   The output should show your CML package (e.g., `cml2_2.8.1-14_amd64.deb`).

2. **Check your configuration file:**
   Ensure the `software` parameter in `config.yml` matches the actual package name:
   ```yaml
   app:
     software: cml2_2.8.1-14_amd64.deb
   ```

3. **Inspect the installation service:**
   ```bash
   # Check the service definition
   cat /etc/systemd/system/cml_install.service
   
   # Check service status
   systemctl status cml_install.service
   
   # View service logs
   journalctl -u cml_install.service
   ```

4. **Manually install the package if needed:**
   ```bash
   apt-get -y install /root/cml2*.deb
   ```

## CML Service Issues

### Issue: CML Service Not Found or Not Starting

**Symptom:** After installation, the `cml.service` cannot be found or fails to start.

**Resolution:**
1. Verify the package was successfully installed:
   ```bash
   dpkg -l | grep cml2
   ```

2. Check for installation errors:
   ```bash
   journalctl -u cml_install.service
   ```

3. If the package was installed but the service isn't starting:
   ```bash
   systemctl daemon-reload
   systemctl start cml
   systemctl status cml
   ```

## Connectivity Issues

### Issue: Cannot Connect to CML Web Interface

**Symptom:** Unable to access the CML web interface after deployment.

**Resolution:**
1. Check if the CML service is running:
   ```bash
   systemctl status cml
   ```

2. Verify security group settings allow traffic on port 443 (HTTPS)

3. Test connectivity:
   ```bash
   # From your local machine
   curl -k -I https://<cml-instance-ip>
   ```

4. Check CML service logs:
   ```bash
   journalctl -u cml.service
   ```

## Authentication and Password Issues

### Issue: Unable to Log in to CML Web Interface

**Symptom:** Login attempts to the CML web interface fail with authentication errors, despite using credentials configured during deployment.

**Possible Causes:**
1. Password not properly set during installation
2. Password hash format issues in the database
3. User account not created correctly
4. Configuration mismatch between what was specified and what was applied

**Prevention:**
1. **Ensure correct password configuration in `config.yml`:**
   ```yaml
   secret:
     manager: dummy  # Use 'dummy' for direct password configuration
     secrets:
       app:
         username: admin
         raw_secret: 'YourPasswordHere'  # Make sure to use quotation marks for passwords with special characters
       sys:
         username: sysadmin
         raw_secret: 'YourPasswordHere'
   ```

2. **Always use a clean deployment:**
   If encountering persistent authentication issues after modifying a deployment, it's often more reliable to:
   ```bash
   # Destroy and recreate the environment
   terraform destroy -auto-approve
   terraform apply -auto-approve
   ```

**Resolution:**
1. **Verify the admin credentials being used match what was configured**

2. **Check CML controller logs for authentication issues:**
   ```bash
   sudo journalctl -u virl2-controller | grep -i auth
   sudo journalctl -u virl2-controller | grep -i password
   ```

3. **Verify the database contains the expected user accounts:**
   ```bash
   sudo sqlite3 /var/local/virl2/config/controller.db "SELECT username, fullname FROM user;"
   ```

4. **If all else fails, rebuild the environment with the correct password configuration**

### Issue: Password Hash Format Issues

**Symptom:** Authentication fails, and database inspection shows incorrect or malformed password hash formats.

**Resolution:**
1. **For new deployments:** Use a clean `terraform apply` with properly configured passwords in `config.yml`

2. **For existing deployments:** If the controller is accessible via SSH/SSM:
   ```bash
   # Reset admin password via CML CLI (if accessible)
   sudo virl2 user set admin password NewPassword123
   ```

**Important:** If you need to modify an existing deployment's password, it's generally more reliable to destroy and recreate the environment rather than attempting to modify the running instance. This ensures that passwords are properly set during the initial installation process.

## AWS SSM Access Issues

If you're having trouble accessing your instance via AWS SSM:

1. Verify the instance has the SSM agent installed and running:
   ```bash
   systemctl status amazon-ssm-agent
   ```

2. Check that the instance has an IAM role with AmazonSSMManagedInstanceCore permissions

3. If needed, reinstall the SSM agent:
   ```bash
   sudo yum install -y amazon-ssm-agent
   sudo systemctl enable amazon-ssm-agent
   sudo systemctl start amazon-ssm-agent
   ```

## CML Authentication Issues

### Issue: Unknown CML Default or Initial Password

**Symptom:** Unable to log in to CML GUI with default or expected credentials.

**Cause:** 
The initial CML admin password is determined by your configuration in `config.yml`. By default, if you don't explicitly set `raw_secret` under the `app` section, a random 16-character password is generated during deployment.

**Resolution:**

1. **Check configuration for password setting:**
   In `config.yml`, check if you've set an explicit password:
   ```yaml
   secrets:
     app:
       username: admin
       # If this is commented out, a random password was generated
       #raw_secret: your-password-here
   ```

2. **Find the generated password:**
   If you have access to the Terraform state, try:
   ```bash
   terraform state show 'module.secrets.module.dummy[0].random_password.random_secret["app"]'
   ```
   Note: The password is stored as a sensitive value and may not be easily retrievable from Terraform output.

3. **Try common default passwords:**
   - admin/C1sco12345
   - admin/cisco
   - admin/Cisco123

4. **Reset the password:**
   If you have SSH or SSM access to the CML instance:
   ```bash
   # SSH to the instance
   ssh -p 1122 sysadmin@<cml-instance-ip>
   
   # Reset admin password
   sudo /usr/local/bin/cml_passwd admin <new-password>
   ```

5. **Prevent random passwords in future deployments:**
   Update your `config.yml` to explicitly set the admin password:
   ```yaml
   secrets:
     app:
       username: admin
       raw_secret: your-chosen-password  # Uncomment and set this
   ```

### Issue: Accessing System Administration vs Application GUI

**Symptom:** Confusion about different authentication systems for CML.

**Explanation:**
CML has two separate authentication systems:

1. **System Administration (Cockpit):**
   - Used for OS-level system management
   - Default username: `sysadmin` (password set during deployment)
   - Accessed via: `https://<cml-ip>:9090`

2. **CML Application GUI:**
   - Used for managing network simulations
   - Default username: `admin` (password as per configuration)
   - Accessed via: `https://<cml-ip>`

## Packer Build Issues

### Issue: `admin` User Not Created During CML 2.7.0 Build

**Symptoms:**
*   Packer build fails during the password setting step.
*   Packer logs (specifically the output of `cat /etc/passwd` dumped by a provisioner) show that neither the `admin` nor `cml2` user exists after the `bootstrap_cml.sh` script runs.
*   Attempts to log into the CML UI after a seemingly successful build fail (if the build didn't explicitly fail).

**Root Cause:**
*   The CML 2.7.0 installation process executed via `bootstrap_cml.sh` does not reliably create the primary administrative user (`admin` or `cml2`) on the base Ubuntu 20.04 AMI used for the build (as of April 2025).
*   The script *might* create the `admin` group, leading to conflicts if a later step tries to create the `admin` user without accounting for the existing group.

**Resolution:**
*   The `packer/cml-2.7.0.pkr.hcl` configuration includes specific provisioners *after* the main bootstrap script runs:
    1.  **Dump Logs/User Info:** A provisioner dumps `/var/log/cml_install.log` and `/etc/passwd` to the Packer logs to help diagnose this issue.
    2.  **Explicit User Creation:** A shell provisioner explicitly creates the `admin` user using `sudo useradd -m -s /bin/bash -g admin admin || echo 'User add attempt finished.'`.
        *   The `-g admin` flag ensures it uses the existing `admin` group if present, avoiding errors.
        *   The `|| echo ...` ensures the build doesn't fail if the user somehow *did* get created earlier.
    3.  **Conditional Password Set:** The password setting provisioner checks for the existence of `admin` or `cml2` before attempting `chpasswd`.

**Verification:**
*   Check the Packer build logs for successful execution of the explicit user creation and password setting steps.
*   After deploying an instance from the resulting AMI, verify you can log in with the `admin` user and the password specified during the Packer build (`cml_admin_password` variable).

### Packer Build Completes but AMI Fails (dpkg/Service Errors in Log)

*   **Symptom:** The Packer build process appears to complete successfully (or with non-fatal errors) and produces an AMI, but instances launched from this AMI fail Instance Status checks or exhibit unexpected behavior (like SSM agent not running).
*   **Diagnosis (Observed April 12, 2025):**
    *   Examination of a previous Packer build log (`packer_build_20250406213824.log`) revealed multiple errors during the execution phase corresponding to the `install_cml_2.7.0.sh` script (which installs the CML `.deb` packages).
    *   Errors included `dpkg: error processing package cml2-server (--configure)` and subsequent failures to start related services (`mongod`, `virl2-controller.service`, `nginx.service`).
    *   Crucially, the shell command executing the `apt-get install ./cml2*.deb` step had error suppression enabled (`|| true`). This allowed the Packer build to continue *despite* the critical CML installation failure, resulting in a broken AMI.
*   **Fix (Applied April 12, 2025):**
    *   The error suppression (`|| true`) was removed from the `apt-get install ./cml2*.deb` command within the installation logic triggered by `install_cml_2.7.0.sh` (specifically, the section handling `.deb` installation).
    *   With this fix, any failure during the core CML package installation should now cause the Packer build itself to fail immediately, preventing the creation of unusable AMIs.
    *   **Action:** Re-run the Packer build (`bash packer/build_cml_2.7.0.sh`). If the build now fails, the error message from `apt-get`/`dpkg` will indicate the root cause of the installation problem. If it succeeds, the resulting AMI should be functional (pending verification).

### CML Admin User Creation Fails

*   **Symptom:** The `admin` user for CML is not created during the Packer build, or login fails after deployment.
*   **Resolution:**
    *   Verify that Terraform `user_data` is minimal and not conflicting with configurations baked into the AMI (e.g., avoid running `apt upgrade` or installing conflicting packages in user_data if the AMI is already configured).

## Debugging Tools

Use `terraform apply -var-file=secrets/dev/aws_secret_creds.auto.tfvars` for AWS deployments.

## Packer Build Failures

... (rest of the document remains the same)
