# CML Deployment (Using Packer AMI)

This document outlines the configuration and steps for deploying Cisco Modeling Labs (CML) in AWS using a pre-built Packer AMI, alongside the standard DevNet workstation.

## Overview

This deployment utilizes:
1. A CML instance launched from a custom AMI created using Packer (`packer/cml-2.7.0.pkr.hcl`).
2. A standard DevNet workstation (details in `DEVNET_WORKSTATION.md`).

The deployment uses Terraform to provision the necessary AWS resources (VPC, subnets, security groups, instances).

## Current Stable Build Information (CML 2.7.0)

*   **Packer Template:** `packer/cml-2.7.0.pkr.hcl`
*   **Latest AMI (us-east-2):** `ami-0aef6f8637c4c6500` (Built 2025-04-06)
*   **Terraform Variables File:** `packer/network_validated_ami.auto.tfvars` (defines AMI ID, region, instance types etc.)

## Configuration Details

*   **CML Instance:** Launched from the AMI specified in `packer/network_validated_ami.auto.tfvars`.
    *   Instance type is also defined in the `.auto.tfvars` file (e.g., `cml_instance_type`).
    *   Accessible via HTTPS and SSH (port 22, user `ubuntu`). The CML application itself uses `admin` with the password set during the Packer build.
*   **DevNet Workstation:** Configuration detailed in `DEVNET_WORKSTATION.md`.
*   **Security:** Resources are deployed within security groups defined in the Terraform configuration (`modules/deploy/aws/main.tf`). Ensure rules allow necessary traffic (HTTPS to CML, SSH/RDP to workstations, etc.).

## Deployment Steps

1.  **Prerequisites:**
    *   Terraform installed.
    *   AWS CLI configured with appropriate credentials.
    *   Ensure the AMI ID specified in `packer/network_validated_ami.auto.tfvars` is correct and exists in the target `aws_region` defined in the same file.
2.  **Initialize Terraform:** Navigate to the root project directory (`my-cloud-cml`) and run:
    ```bash
    terraform init
    ```
3.  **Apply Configuration:**
    ```bash
    terraform apply -var-file=packer/network_validated_ami.auto.tfvars -auto-approve
    ```
    *(The `-auto-approve` flag skips the confirmation prompt)*
4.  **Output:** After deployment, Terraform will output the public IP addresses and other relevant details for the CML instance and DevNet workstation.

## Connectivity Verification

Standard network troubleshooting applies. Verify:
*   Security group rules allow traffic between the workstation and CML (HTTPS/443, SSH/22 for the instance, potentially other CML-specific ports if needed).
*   Instance status in the AWS console.
*   Basic ping tests.
*   Ability to access the CML Web UI via HTTPS using the public IP from the Terraform output.
*   Ability to log in to the CML UI using `admin` and the password set during the Packer build.

## Troubleshooting

*   **Terraform Errors:** Check Terraform output for specific errors. Ensure variables in the `.auto.tfvars` file are correct.
*   **CML Issues:** Refer to `documentation/TROUBLESHOOTING.md` and `documentation/CML_INSTALLATION.md`.
*   **Packer Build Issues:** Refer to `documentation/PACKER_BUILD.md`.

## References

- Original CML Cloud repository: https://github.com/CiscoDevNet/cloud-cml
- This fork: https://github.com/davisma20/my-cloud-cml
