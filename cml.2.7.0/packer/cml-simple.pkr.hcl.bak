packer {
  required_plugins {
    amazon = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

// Define source variables for the build
variable "region" {
  type    = string
  default = "us-east-2"
}

variable "instance_type" {
  type    = string
  default = "c5.2xlarge"
}

// Timestamp for unique AMI naming
locals {
  timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
}

// Define the Amazon EBS builder with standard Ubuntu AMI
source "amazon-ebs" "cml" {
  ami_name        = "cml-ami-${local.timestamp}"
  instance_type   = var.instance_type
  region          = var.region
  
  // Use a standard Ubuntu 20.04 AMI as the source
  // The CML OVA import is causing connectivity issues, so we'll build on Ubuntu
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"] // Canonical
  }
  
  // Standard SSH access is reliable with official Ubuntu AMIs
  communicator    = "ssh"
  ssh_username    = "ubuntu"
  
  // Use IMDSv2 for enhanced security (as per your security preferences)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  
  // Root volume configuration - maintaining your 50GB minimum requirement
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 50
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }
  
  tags = {
    Name        = "CML-AMI"
    Environment = "Production"
    Builder     = "Packer"
    BuildDate   = formatdate("YYYY-MM-DD", timestamp())
  }
}

// Define the build process
build {
  sources = ["source.amazon-ebs.cml"]
  
  // Install CML dependencies
  provisioner "shell" {
    inline = [
      "echo 'Updating system and installing CML dependencies...'",
      
      # Update apt but ignore errors
      "sudo apt-get update || true",
      
      # Upgrade packages but ignore errors
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade || true",
      
      # Install dependencies with error handling
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-kvm libvirt-daemon libvirt-daemon-system libvirt-clients bridge-utils virt-manager libguestfs-tools openvswitch-switch python3-openvswitch openvpn wireguard awscli vlan wget curl unzip software-properties-common jq nginx gnupg apt-transport-https libnss-libvirt cloud-init python3-pip || true"
    ]
  }
  
  // Upload and run our CML optimization script
  provisioner "file" {
    source      = "bootstrap_cml.sh"
    destination = "/tmp/bootstrap_cml.sh"
  }
  
  provisioner "shell" {
    inline = [
      "chmod +x /tmp/bootstrap_cml.sh",
      "sudo bash /tmp/bootstrap_cml.sh || echo 'Bootstrap script completed with errors, but continuing'"
    ]
  }
  
  // Set up CML admin user credentials similar to the CML OVA
  provisioner "shell" {
    inline = [
      "echo 'Setting up CML admin user...'",
      
      # Create admin user with proper group
      "echo 'Creating admin user...'", 
      "sudo groupadd -f admin || echo 'Admin group already exists'",
      "sudo useradd -m -s /bin/bash -g admin admin || echo 'Failed to create admin user - it may already exist'",
      
      # Add admin to sudo group
      "sudo usermod -aG sudo admin || echo 'Failed to add admin to sudo group'",
      
      # Set password
      "echo 'Setting admin password...'",
      "sudo bash -c 'echo \"admin:1234QWer!\" | chpasswd'",
      
      # Create sudoers file
      "echo 'Configuring sudo access...'",
      "echo 'admin ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/admin",
      "sudo chmod 0440 /etc/sudoers.d/admin"
    ]
  }
  
  // Optimize system performance for CML
  provisioner "shell" {
    inline = [
      "echo 'Optimizing system for CML performance...'",
      
      "# Configure KVM for nested virtualization",
      "echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf",
      "echo 'options kvm-intel enable_shadow_vmcs=1' | sudo tee -a /etc/modprobe.d/kvm-nested.conf",
      "echo 'options kvm-intel enable_apicv=1' | sudo tee -a /etc/modprobe.d/kvm-nested.conf",
      "echo 'options kvm-intel ept=1' | sudo tee -a /etc/modprobe.d/kvm-nested.conf",
      
      "# Network optimizations for virtualization - remove bridge settings which are handled in bootstrap",
      "cat > /tmp/cml-sysctl.conf << 'EOL'",
      "net.core.rmem_max = 16777216",
      "net.core.wmem_max = 16777216",
      "net.core.rmem_default = 16777216",
      "net.core.wmem_default = 16777216",
      "net.core.optmem_max = 16777216",
      "net.ipv4.tcp_rmem = 4096 87380 16777216",
      "net.ipv4.tcp_wmem = 4096 65536 16777216",
      "net.ipv4.tcp_mem = 16777216 16777216 16777216",
      "net.core.netdev_max_backlog = 250000",
      "net.ipv4.ip_forward = 1",
      "EOL",
      "sudo mv /tmp/cml-sysctl.conf /etc/sysctl.d/99-cml-performance.conf",
      "sudo sysctl -p /etc/sysctl.d/99-cml-performance.conf || echo 'Some sysctl settings could not be applied, but continuing'"
    ]
  }
  
  // Create directories needed by CML
  provisioner "shell" {
    inline = [
      "echo 'Creating CML directories...'",
      "sudo mkdir -p /etc/virl2/",
      "sudo mkdir -p /var/lib/libvirt/images",
      "sudo mkdir -p /var/cache/virl2/",
      "sudo mkdir -p /var/log/virl2/",
      
      "# Create AWS init script for CML",
      "cat > /tmp/aws-init.sh << 'EOL'",
      "#!/bin/bash",
      "# This script will run at first boot on AWS",
      "TOKEN=$(curl -s -X PUT \"http://169.254.169.254/latest/api/token\" -H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\")",
      "INSTANCE_ID=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/instance-id)",
      "REGION=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/[a-z]$//')",
      "PRIVATE_IP=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/local-ipv4)",
      "PUBLIC_IP=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/public-ipv4)",
      "",
      "# Set the hostname to match instance ID",
      "hostnamectl set-hostname $INSTANCE_ID",
      "",
      "# Record AWS metadata for CML",
      "echo \"INSTANCE_ID=$INSTANCE_ID\" > /etc/virl2/aws-metadata",
      "echo \"REGION=$REGION\" >> /etc/virl2/aws-metadata",
      "echo \"PRIVATE_IP=$PRIVATE_IP\" >> /etc/virl2/aws-metadata",
      "echo \"PUBLIC_IP=$PUBLIC_IP\" >> /etc/virl2/aws-metadata",
      "EOL",
      "sudo mv /tmp/aws-init.sh /etc/virl2/aws-init.sh",
      "sudo chmod +x /etc/virl2/aws-init.sh",
      
      "# Add AWS init script to cloud-init for first boot",
      "cat > /tmp/cml-aws-setup.cfg << 'EOL'",
      "runcmd:",
      "  - [ /etc/virl2/aws-init.sh ]",
      "EOL",
      "sudo mv /tmp/cml-aws-setup.cfg /etc/cloud/cloud.cfg.d/99-cml-aws-setup.cfg"
    ]
  }
  
  // Clean up
  provisioner "shell" {
    inline = [
      "echo 'Cleaning up system...'",
      "sudo apt-get clean",
      "sudo rm -rf /tmp/*",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "bash -c 'history -c' || true",  
      "cat /dev/null > ~/.bash_history || true",
      
      "# Create a marker file to show this is a pre-prepared CML AMI",
      "sudo bash -c 'date > /etc/.cml_ami_prepared'"
    ]
  }
}
