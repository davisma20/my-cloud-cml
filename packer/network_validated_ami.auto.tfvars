# Configuration file for using the network-validated CML AMI
# This file will be automatically loaded by Terraform when present in the working directory

// This file contains the validated AMI ID from the latest successful Packer build.
// It should be used with the -var-file flag when running terraform apply.

cml_ami = "ami-0a8303fee58aa8f54"

# Specify AWS region (should match the region where Packer built the AMI)
aws_region = "us-east-2"

# Use recommended instance type for CML
cml_instance_type = "c5.2xlarge"

# Enable enhanced monitoring and network validation
enable_enhanced_monitoring = true
validate_network_on_boot = true

// Note: This file is automatically updated by the Packer build process.
// Do not edit manually unless you know what you are doing.
