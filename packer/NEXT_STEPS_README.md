# Next Steps After Successful CML AMI Build (April 2025)

This document outlines the precise workflow and actions to take once the AMI build is successful and the diagnostics pass.

---

## 1. Deploy with Terraform
- Use the validated AMI ID from the Packer build output.
- Run `terraform init` and `terraform apply` in the project root (`my-cloud-cml`).
- Pass the new AMI ID as a variable or update your `terraform.tfvars` as needed.

## 2. Validate Instance Functionality
- Use the `run_validation.py` script with the required `--instance-id` argument to validate the deployed instance.
- Example:
  ```sh
  python3 run_validation.py --instance-id <INSTANCE_ID> --region us-east-2
  ```
- Check for any errors or warnings in the validation output.

## 3. Post-Deployment Checklist
- **SSH Access:**
  - Confirm you can SSH to the instance as the expected user (default: `ubuntu`) with the correct key.
  - If SSH fails, use SSM to debug logs and configuration.
- **Cloud-Init:**
  - Confirm cloud-init ran successfully and injected the SSH key.
  - Review `/var/log/cloud-init.log` and `/var/log/cloud-init-output.log` for errors.
- **Network Diagnostics:**
  - Ensure instance has outbound connectivity (ping, curl metadata, etc.).
  - Confirm SSM agent is running and instance is reachable via AWS Systems Manager.

## 4. If Issues Are Detected
- Use SSM to access the instance and gather logs.
- Review the Packer diagnostic provisioner output for root cause clues.
- Update Packer or bootstrap scripts as needed and rebuild the AMI.

## 5. Network Diagnostics & SSM Troubleshooting (April 2025)
- Automated validation with `run_validation.py` confirms:
  - Security groups and NACLs are correctly configured for outbound HTTP/HTTPS and inbound ephemeral ports.
  - Despite this, broken CML instances fail SSM registration and SSH connection due to actual outbound connectivity failure (likely VPC routing or NAT gateway issue).
  - `curl` to port 443 on public IP times out with SSL_ERROR_SYSCALL, confirming network path is broken beyond security group/NACL config.
  - System logs are retrievable, but instances are not present in SSM describe-instance-information output.
- Cloud-init and EC2 console logs show repeated DNS resolution errors and failed attempts to reach Ubuntu package mirrors and AWS endpoints. SSM agent is installed and started, but cannot register due to lack of outbound network connectivity.
- Next step: Review VPC routing, NAT gateway health, and subnet route tables for proper outbound internet access.

## 6. Automated NAT Gateway Diagnostics (v2.8.1+)

A new NAT Gateway diagnostics module is now integrated into `run_validation.py`.
- The script will automatically:
  - Detect NAT Gateway(s) associated with the instance's subnet.
  - Check NAT Gateway health, state, and public IP allocation.
  - Summarize findings in the validation output.

### What to Look For
- **State should be `available`**. Any other state (e.g., `pending`, `failed`, `deleted`) indicates a problem.
- **At least one public IP** must be present for outbound connectivity.
- If no NAT Gateway is found for a private subnet, outbound internet will not work (unless routed via IGW).

### Next Steps for Network/SSM Troubleshooting
1. **Review the NAT Gateway diagnostics section** in the validation results for:
    - State: Must be `available`.
    - Public IP(s): At least one must be present.
2. If the NAT Gateway is missing, unhealthy, or lacks a public IP:
    - Check AWS Console for NAT Gateway status and subnet routing.
    - Ensure route table for the subnet points 0.0.0.0/0 to the NAT Gateway.
    - Verify Elastic IP allocation and association with the NAT Gateway.
3. If all diagnostics pass but outbound connectivity still fails:
    - Review VPC route tables, NACLs, and security groups again.
    - Use AWS VPC Reachability Analyzer for advanced troubleshooting.

## 7. Optimization for Future Builds
- Reference the Packer Build Optimization Checklist for ideas to reduce build time and AMI size.
- Document any new issues and their resolutions in this file for future reference.

## 8. Current Troubleshooting Location (April 2025)

- **Focus:** Comparing network configuration between working DevNet workstation and broken CML instance in the same subnet.
- **Key Actions:**
  - Validated that both reside in the same subnet and share the same NACLs.
  - Security groups are identical for controlled tests.
  - SSM works for DevNet workstation but not for CML instance, despite similar network path.
  - **Critical finding:** DevNet workstation is launched with `associate_public_ip_address = true` (auto-assigned public IP), while the CML controller may lack a public IP if launched with a custom ENI or if subnet settings change.
  - **Remediation:** Terraform now explicitly allocates and associates an Elastic IP (EIP) to the CML controller instance to guarantee public internet access, regardless of ENI or subnet configuration. See `aws_eip.cml_controller_eip` and `aws_eip_association.cml_controller_eip_assoc` in `modules/deploy/aws/main.tf`.

### April 2025: Recent Infrastructure Fixes

- Updated `aws_eip.cml_controller_eip` to use `domain = "vpc"` instead of deprecated `vpc = true` (Terraform 1.0+ best practice).
- Fixed deployment error by setting CML controller disk size to use `var.options.cfg.common.disk_size` (was incorrectly referencing a missing attribute).
- These changes ensure successful deployment and public access to the CML controller.

### AWS CLI Commands to Assign CML Instance to DevNet Security Group

1. **Add CML Instance to DevNet Workstation Security Group:**
   ```sh
   aws ec2 modify-instance-attribute --instance-id i-0bcaf461ec352f206 --groups sg-04f32dc696d422bbc
   ```
   _If you want to keep both groups for testing, add both IDs:_
   ```sh
   aws ec2 modify-instance-attribute --instance-id i-0bcaf461ec352f206 --groups sg-04f32dc696d422bbc sg-0b67d0699966fd83d
   ```
2. **(Optional) Remove from old group for strict test:**
   ```sh
   aws ec2 modify-instance-attribute --instance-id i-0bcaf461ec352f206 --groups sg-04f32dc696d422bbc
   ```

3. **Re-run validation after changes:**
   ```sh
   python3 run_validation.py --instance-id i-0bcaf461ec352f206 --region us-east-2 --output-prefix validation_results_i-0bcaf461ec352f206
   ```

## 9. Packer and Terraform AMI Handoff Workflow

- **Packer Build:**
  - After building a new CML controller AMI, Packer writes the AMI ID to `network_validated_ami.auto.tfvars` in the project root.
  - This file is automatically loaded by Terraform.
- **Terraform Usage:**
  - The root module expects configuration via YAML (default: `config.yml`).
  - The only AMI variable set by Packer and used by Terraform is `cml_ami` (or `cml_ami_id`).
  - Do NOT set `options` or `cfg` objects in root tfvars; these are handled internally via YAML and locals.
  - To override the AMI manually, set `cml_ami` in `terraform.auto.tfvars`.
- **Best Practice:**
  - Always use the AMI from `network_validated_ami.auto.tfvars` for the CML controller.
  - Only the CML controller and DevNet workstation should be running; all other instances should be stopped in config.

## 10. Next Steps & Troubleshooting Guide

### Troubleshooting Common Issues

1.  **Terraform Apply Fails (AMI Not Found/Permissions):**
    *   Ensure the `network_validated_ami.auto.tfvars` file exists in the *root* project directory (`../`) and contains the correct `cml_ami_id` from the latest successful Packer build.
    *   Verify your AWS CLI credentials and configured region (`us-east-2` by default).
    *   Check Terraform Cloud/State permissions if applicable.

2.  **CML Instance Launches but is Unreachable/SSM Agent Not Running:**
    *   **Initial Check:** Verify Security Group rules in AWS allow SSH (port 22) and HTTPS (port 443) from your IP.
    *   **SSM Agent Status:**
        *   Check the AWS Console -> Systems Manager -> Fleet Manager. If the instance appears but is listed as 'Connection Lost' or never appears, it indicates an SSM agent issue.
        *   **Root Cause (Identified 2025-04-20):** The `amazon-ssm-agent` might install correctly during the Packer build but fail to *register* with the SSM service if the temporary IAM role/profile used by Packer lacks necessary permissions (like `ssm:UpdateInstanceInformation`, included in `AmazonSSMManagedInstanceCore`).
        *   **Verification:** Examine the Packer build logs (e.g., `packer_build_*.log` or `packer-build-no-upgrade.log` in this directory) for `AccessDeniedException` errors related to `ssm:UpdateInstanceInformation` shortly after the agent starts.
        *   **Solution:** Ensure the IAM role/profile used by Packer (either specified via `iam_instance_profile` or generated temporarily) has the `AmazonSSMManagedInstanceCore` policy attached or equivalent permissions.
    *   **Rebuild Required:** If the SSM registration failed during the build due to permissions, a new AMI must be built after correcting the permissions. The standard workflow is:
        1.  Run `terraform destroy` in the root project directory to remove infrastructure built with the faulty AMI.
        2.  Correct the IAM permissions for the Packer build role/profile.
        3.  Run the Packer build script (e.g., `./build_cml_2.7.0.sh`) from this directory.
        4.  Run `terraform apply` in the root project directory to deploy using the new, correctly built AMI.
    *   **Other Checks:** If SSM permissions were correct, examine the `bootstrap_cml.sh` output within the Packer logs for other errors during installation or configuration.

3.  **Packer Build Fails:**
    *   Consult the Packer build log (`packer_build_*.log`) for specific errors (e.g., package download failures, script execution errors).
    *   Ensure the source AMI specified in `cml-2.7.0.pkr.hcl` is available in your region (`us-east-2`).
    *   Check network connectivity from the temporary Packer instance (VPC/Subnet settings).

## 11. Future Steps

- If both instances in the same security group still show different SSM/SSM connectivity, check:
  - Public IP assignment (DevNet likely has public IP, CML may not; **now always enforced via EIP for CML**)
  - IAM role/policy differences
  - SSM agent health (restart if needed)
  - Instance metadata and launch configuration
- If NAT Gateway is required for private subnets, follow Section 6 for NAT Gateway setup and routing.
- Document all findings and remediation steps here for future troubleshooting.

---
_Last updated: 2025-04-20_

**Reminder:** All findings and troubleshooting steps must be documented in this file and the main README for future reference. The canonical Packer AMI build log remains `packer-manifest.json` in the packer directory.
