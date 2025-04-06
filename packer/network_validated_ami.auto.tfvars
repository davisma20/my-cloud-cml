# Configuration file for using the network-validated CML AMI
# This file will be automatically loaded by Terraform when present in the working directory

# This AMI ID will need to be updated after the Packer build completes
# Replace "ami-placeholder" with the actual AMI ID from your Packer build
cml_ami = "ami-0aef6f8637c4c6500"

# Specify AWS region (should match the region where Packer built the AMI)
aws_region = "us-east-2"

# Use recommended instance type for CML
cml_instance_type = "c5.2xlarge"

# Enable enhanced monitoring and network validation
enable_enhanced_monitoring = true
validate_network_on_boot = true
