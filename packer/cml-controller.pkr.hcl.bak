packer {
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

// Use variables defined in variables.pkr.hcl
locals {
  timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
  ami_name  = "${var.ami_name_prefix}-${var.cml_version}-${local.timestamp}"
}

// Define the Amazon EBS builder
source "amazon-ebs" "cml_controller" {
  ami_name        = local.ami_name
  ami_description = "${var.ami_description} v${var.cml_version}"
  instance_type   = var.instance_type
  region          = var.aws_region
  source_ami      = var.source_ami
  ssh_username    = var.ssh_username
  
  ami_virtualization_type = "hvm"
  encrypt_boot            = var.encrypt_boot
  force_deregister        = true
  force_delete_snapshot   = true
  
  // Use IMDSv2 for enhanced security
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  
  // Configure the root volume
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = var.volume_size
    volume_type           = var.volume_type
    delete_on_termination = true
    encrypted             = var.encrypt_boot
  }
  
  // Add tags to the resulting AMI and snapshot
  tags = merge({
    Name        = local.ami_name
    Builder     = "Packer"
    BuildDate   = formatdate("YYYY-MM-DD hh:mm:ss", timestamp())
    CML_Version = var.cml_version
  }, var.ami_tags)
}

// Define the build process
build {
  name    = "cml-controller"
  sources = ["source.amazon-ebs.cml_controller"]
  
  // Copy installation files to the instance
  provisioner "file" {
    source      = "${path.root}/files/"
    destination = "/tmp/"
  }
  
  // Copy the installation scripts
  provisioner "file" {
    source      = "${path.root}/scripts/"
    destination = "/tmp/"
  }
  
  // Copy the existing CML installation scripts from the repository
  provisioner "file" {
    source      = "../modules/deploy/data/cml_install_reliable.sh"
    destination = "/tmp/cml_repo_install_reliable.sh"
  }
  
  provisioner "file" {
    source      = "../modules/deploy/data/cml_install_fix.sh"
    destination = "/tmp/cml_repo_install_fix.sh"
  }
  
  // Run the setup script
  provisioner "shell" {
    inline = [
      "chmod +x /tmp/*.sh",
      "echo 'Running pre-installation setup...'",
      "sudo /tmp/setup.sh"
    ]
  }
  
  // Run the CML installation script
  provisioner "shell" {
    inline = [
      "echo 'Installing CML...'",
      "sudo /tmp/install_cml.sh '${var.cml_version}' '${var.cml_s3_bucket}' '${var.cml_s3_key}' '${var.cml_package_url}'"
    ]
    timeout = "3600s" // CML installation may take up to an hour
  }
  
  // Perform cleanup and prepare for AMI creation
  provisioner "shell" {
    inline = [
      "echo 'Cleaning up...'",
      "sudo /tmp/cleanup.sh"
    ]
  }
  
  // Store the AMI ID in a manifest file
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
    custom_data = {
      cml_version = var.cml_version
    }
  }
}
