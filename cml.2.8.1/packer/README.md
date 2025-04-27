# Packer for CML 2.8.1

This folder contains all Packer scripts, HCL files, and build logic for creating the CML 2.8.1 AMI for AWS.

- Update scripts for Ubuntu 24.04 compatibility
- Reference the CISCO_DOWNLOADS folder for required ISOs/images
- See MIGRATION_PLAN.md and RELEASE_NOTES_SUMMARY.md for requirements

## AWS Packer Build Plan (Ubuntu 24.04 + CML 2.8.1)

1. **Base AMI:** Use the latest official Ubuntu 24.04 LTS AMI from AWS Marketplace (Canonical).
2. **Download/Stage CML ISOs:** Place `cml2_p_2.8.1-14_amd64-35-iso.zip` and `refplat_p-20241223-fcs-iso.zip` in `CISCO_DOWNLOADS/`.
3. **Unzip ISOs:** Unzip both files as part of the build process.
4. **Mount CML ISO:** Attach/mount the CML ISO, run the installer (refer to install guide for flags).
5. **Mount Reference Platform ISO:** Mount/copy node images as required by installer.
6. **Configure System:** Set hostname, networking, SSH, cloud-init, and any AWS-specific settings.
7. **Validate Install:** Ensure CML services are running, check `/etc/virl2/virl.conf`, and validate API/UI access.
8. **Security Hardening:** Remove temporary files, lock down SSH, ensure no secrets are present.
9. **AMI Creation:** Clean up and create the AMI for Terraform use.

## Cloud-Init NoCloud Automation for Unattended CML 2.8.1 Install

This folder now supports fully automated CML 2.8.1 installation using cloud-init NoCloud seed ISO.

### Steps:
1. Edit `user-data` to set hostname, admin user, and inject your CML license (see placeholder).
2. Edit `meta-data` if you want to change the instance-id or hostname.
3. Run `build_nocloud_iso.sh` to generate `seed.iso`.
4. During Packer build, ensure `seed.iso` is attached as a secondary CD-ROM (NoCloud data source).
5. The CML ISO must be booted as the primary CD-ROM.
6. The installation and initial configuration will be performed automatically by cloud-init.

**Note:** The provisioning script no longer mounts or runs `install.sh` from the CML ISO. All configuration is handled by cloud-init.

See Cisco's official [CML Installation Guide](https://developer.cisco.com/docs/modeling-labs/2-8/cml-installation-guide/) for more details.

## File Staging for Packer Build
- Place the following files in `cml.2.8.1/CISCO_DOWNLOADS/` before running the build:
  - `cml2_p_2.8.1-14_amd64-35-iso.zip` (CML 2.8.1 ISO)
  - `refplat_p-20241223-fcs-iso.zip` (Reference platform ISO)
  - (Optional) `refplat_p-20241016-supplemental-iso.zip` (for SD-WAN/FirePower nodes)

## S3 Bucket Cleanup (2025-04-26)

As of April 26, 2025, all unused ZIP files have been removed from the S3 bucket (`s3://cml-ova-import/cml-2.8.1/`).

- Only `.iso`, `.signature`, and `.README` files are retained for the CML 2.8.1 build.
- This reduces S3 storage costs and avoids confusion during automated builds.
- The build process now references only the ISO files directly; ZIP extraction is no longer required or supported.

**Best Practice:**
Keep your S3 bucket clean and only retain files needed for the current automated build workflow.

## Automated Terraform Integration & AMI Updates

After a successful Packer build, the script automatically parses the new AMI ID from `packer-manifest.json` and writes it to `../network_validated_ami.auto.tfvars` in the correct format for Terraform. This ensures that Terraform deployments always use the latest validated CML AMI with no manual intervention required.

- This automation pattern mirrors the proven workflow used for CML 2.7.0.
- The script uses `jq` to extract the AMI ID and updates the tfvars file for seamless infrastructure-as-code deployments.

**SSM Agent Installation:**
- The provisioning script installs the AWS SSM agent using the official AWS GitHub .deb package, which is compatible with Ubuntu 24.04+ and all future releases. This method is region-agnostic and follows AWS best practices:

  ```sh
  curl -Lo /tmp/amazon-ssm-agent.deb https://github.com/aws/amazon-ssm-agent/releases/latest/download/amazon-ssm-agent.deb
  sudo dpkg -i /tmp/amazon-ssm-agent.deb
  sudo systemctl enable --now amazon-ssm-agent
  sudo systemctl status amazon-ssm-agent || echo "Warning: SSM Agent status check failed immediately after start."
  ```

- This ensures Systems Manager support in all new AMIs and resolves errors related to invalid or outdated SSM agent download URLs.

## AWS Snapshot and Volume Cleanup Workflow

### Identifying and Deleting Unused Snapshots

1. **Get all snapshot IDs referenced by active AMIs:**
   ```sh
   aws ec2 describe-images --owners self \
     --query "Images[*].BlockDeviceMappings[*].Ebs.SnapshotId" \
     --output text | tr '\t' '\n' | sort | uniq > used_snapshots.txt
   ```

2. **Get all snapshot IDs in your account:**
   ```sh
   aws ec2 describe-snapshots --owner-ids self \
     --query "Snapshots[*].SnapshotId" \
     --output text | tr '\t' '\n' | sort | uniq > all_snapshots.txt
   ```

3. **Find unused snapshots:**
   ```sh
   comm -23 all_snapshots.txt used_snapshots.txt > unused_snapshots.txt
   ```

4. **Delete unused snapshots:**
   ```sh
   for snap in $(cat unused_snapshots.txt); do
     echo "Deleting $snap"
     aws ec2 delete-snapshot --snapshot-id $snap
   done
   ```

### Cleaning Up 50 GiB Snapshots Only

1. **Get all 50 GiB snapshot IDs:**
   ```sh
   aws ec2 describe-snapshots --owner-ids self --filters Name=volume-size,Values=50 \
     --query "Snapshots[*].SnapshotId" --output text | tr '\t' '\n' | sort | uniq > all_50gib_snapshots.txt
   ```

2. **Find 50 GiB snapshots NOT in use:**
   ```sh
   comm -23 all_50gib_snapshots.txt used_snapshots.txt > unused_50gib_snapshots.txt
   ```

3. **Delete unused 50 GiB snapshots:**
   ```sh
   for snap in $(cat unused_50gib_snapshots.txt); do
     echo "Deleting $snap"
     aws ec2 delete-snapshot --snapshot-id $snap
   done
   ```

### Notes
- Only delete snapshots that are not referenced by any AMI you wish to keep.
- Review the list of unused snapshots before deletion for safety.
- Snapshots in use by AMIs (CML, DevNet, etc.) will not be deleted by these scripts.
- Regular cleanup helps prevent hitting AWS resource limits and reduces storage costs.

## Build Script
- The Packer build will reference these files for installation and node image staging.
- See `provision_cml2.8.1.sh` for detailed installation steps.
- Ensure the files are not committed to version control.

---

**Note:** See MIGRATION_PLAN.md and RELEASE_NOTES_SUMMARY.md for requirements and migration implications.
