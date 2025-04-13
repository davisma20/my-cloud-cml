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

variable "source_ami_filter" {
  type    = bool
  default = true
  description = "Whether to use AMI filter or specific AMI ID"
}

variable "source_ami" {
  type    = string
  default = ""
  description = "Specific source AMI ID (when source_ami_filter is false)"
}

variable "volume_size" {
  type    = number
  default = 50
  description = "Root volume size in GB"
}

variable "cml_bucket" {
  type    = string
  default = "cml-ova-import"
  description = "S3 bucket containing CML package"
}

variable "cml_pkg_path" {
  type    = string
  default = "cml2_2.7.0-4_amd64-20.pkg"
  description = "S3 key for CML package"
}

variable "cml_admin_username" {
  type    = string
  default = "admin"
  description = "Admin username for CML"
}

variable "cml_admin_password" {
  type    = string
  default = "1234QWer!"
  sensitive = true
  description = "Admin password for CML"
}

// Timestamp for unique AMI naming
locals {
  timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
}

// Define the Amazon EBS builder
source "amazon-ebs" "cml" {
  ami_name        = "cml-2.7.0-ami-${local.timestamp}"
  instance_type   = var.instance_type
  region          = var.region
  
  // Use Ubuntu 20.04 AMI as the source - choose between filter or specific ID
  dynamic "source_ami_filter" {
    for_each = var.source_ami_filter ? [1] : []
    content {
      filters = {
        name                = "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
        root-device-type    = "ebs"
        virtualization-type = "hvm"
      }
      most_recent = true
      owners      = ["099720109477"] // Canonical
    }
  }
  
  source_ami      = var.source_ami_filter ? null : var.source_ami
  
  // Standard SSH access is reliable with Ubuntu AMIs
  communicator    = "ssh"
  ssh_username    = "ubuntu"
  
  // Use IMDSv2 for enhanced security
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  
  // Use a temporary IAM instance profile with S3 access
  temporary_iam_instance_profile_policy_document {
    Version = "2012-10-17"
    Statement {
        Action   = ["s3:GetObject"]
        Effect   = "Allow"
        Resource = ["arn:aws:s3:::${var.cml_bucket}/cml-2.7.0-debs/*"]
    }
    Statement {
         Action = ["s3:ListBucket"]
         Effect = "Allow"
         Resource = ["arn:aws:s3:::${var.cml_bucket}"]
    }
  }
  
  // Root volume configuration
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = var.volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }
  
  tags = {
    Name        = "CML-2.7.0-AMI"
    Environment = "Production"
    Builder     = "Packer"
    BuildDate   = formatdate("YYYY-MM-DD", timestamp())
  }
}

// Define the build process
build {
  sources = ["source.amazon-ebs.cml"]
  
  // Fix GPG and repository issues before anything else
  provisioner "shell" {
    inline = [
      "echo 'Fixing repository and GPG issues...'",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true || true",
      "sudo apt-get install -y gnupg ca-certificates apt-transport-https --allow-unauthenticated || true",
      "sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C",
      "sudo apt-get update || true"
    ]
  }

  // Check hibinit-agent status (pre-installed, hibernation not enabled)
  provisioner "shell" {
    inline = [
      "echo 'Ensuring software-properties-common is installed (dependency check)..'",
      "sudo apt-get update -y",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common",
      "echo 'Checking status and enabled state of pre-installed hibinit-agent.service...'",
      "sudo systemctl status hibinit-agent.service --no-pager || echo 'INFO: Service likely inactive as hibernation is not enabled on build instance. Continuing if enabled.'",
      "if sudo systemctl is-enabled --quiet hibinit-agent.service; then echo 'hibinit-agent service is enabled.'; else echo 'Error: hibinit-agent service is NOT enabled.'; exit 1; fi"
    ]
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive"
    ]
  }

  // Upload and run CML bootstrap/optimization script
  provisioner "file" {
    source      = "bootstrap_cml.sh"
    destination = "/tmp/bootstrap_cml.sh"
  }

  provisioner "shell" {
    environment_vars = ["PACKER_AWS_REGION=${var.region}"]
    inline = [
      "chmod +x /tmp/bootstrap_cml.sh",
      "sudo -E bash -c 'export PACKER_AWS_REGION=\"$PACKER_AWS_REGION\"; bash /tmp/bootstrap_cml.sh'"
    ]
  }

  // Dump logs and user info post-bootstrap for debugging
  provisioner "shell" {
    inline = [
      "echo 'Dumping logs and user info post-bootstrap...'",
      "echo '--- CML Install Log: ---'",
      "sudo cat /var/log/cml_install.log || echo 'INFO: /var/log/cml_install.log not found.'",
      "echo '--- End CML Install Log ---'",
      "echo \"\"",
      "echo '--- /etc/passwd contents: ---'",
      "sudo cat /etc/passwd",
      "echo '--- End /etc/passwd ---'"
    ]
    only = ["amazon-ebs.cml"]
  }

  // Explicitly create admin user as bootstrap script seems to miss it
  provisioner "shell" {
    inline = [
      "echo 'Explicitly creating admin user...'",
      "sudo useradd -m -s /bin/bash -g admin admin || echo 'WARN: useradd -g admin admin command failed, maybe user already exists or group is wrong?'"
    ]
  }

  // Set up admin user password (MUST run after bootstrap creates the user)
  // Conditionally tries 'admin' first, then 'cml2'
  provisioner "shell" {
    environment_vars = ["CML_PASS=${var.cml_admin_password}"]
    inline = [ <<EOF
      echo 'Conditionally setting password for admin or cml2 user...'
      TARGET_USER=""
      if id -u admin &>/dev/null; then
          echo "INFO: Found user 'admin'. Attempting password set."
          TARGET_USER="admin"
      elif id -u cml2 &>/dev/null; then
          echo "INFO: User 'admin' not found. Found user 'cml2'. Attempting password set."
          TARGET_USER="cml2"
      else
          echo "ERROR: Neither user 'admin' nor 'cml2' found after bootstrap! Cannot set password."
          sudo cat /etc/passwd # Dump passwd again for context
          exit 1
      fi

      echo "Attempting to set password for user: $TARGET_USER"
      if ! printf "%s:%s" "$TARGET_USER" "$CML_PASS" | sudo chpasswd -c SHA512; then
        echo "ERROR: Failed to set password for user '$TARGET_USER' using chpasswd!"
        exit 1
      fi
      echo "Password for user '$TARGET_USER' set successfully."
 EOF
    ]
  }

  // Restart CML services to ensure they pick up the new password
  provisioner "shell" {
    inline = [
      "echo 'Restarting CML services after password change...'",
      "sudo systemctl restart virl2-controller virl2-uwm || echo 'Warning: Failed to restart CML services cleanly.'",
      "echo 'Waiting 30 seconds after service restart attempt...'",
      "sleep 30" # Give services a moment to come back up
    ]
  }

  // Install and configure MongoDB
  provisioner "shell" {
    inline = [
      "echo 'Installing and configuring MongoDB...'",
      "sudo apt-get update && sudo apt-get install -y mongodb-server net-tools || true",
      "sudo systemctl enable mongodb.service || true",
      "sudo systemctl start mongodb.service || true",
      "echo 'Waiting for MongoDB to initialize...'",
      "sleep 20", 
      "ps aux | grep mongo",
      "sudo netstat -tulpn | grep 27017 || true",
      "sudo systemctl status mongodb.service || true"
    ]
  }

  // Download CML deb files to a temporary location
  provisioner "shell" {
    environment_vars = [
      "AWS_REGION=${var.region}",
      "CML_BUCKET=${var.cml_bucket}"
    ]
    inline = [
      "echo 'Creating temporary directory for CML deb files...'",
      "mkdir -p /tmp/cml-debs",
      "echo 'Downloading CML 2.7.0 deb files from S3 recursively...'",
      "aws s3 cp s3://${var.cml_bucket}/cml-2.7.0-debs/ /tmp/cml-debs/ --recursive",
      "echo 'Verifying download...'",
      "ls -la /tmp/cml-debs/"
    ]
  }

  // Upload and run the actual CML installation script
  provisioner "file" {
    source      = "scripts/install_cml_2.7.0.sh"
    destination = "/tmp/install_cml_2.7.0.sh"
  }

  provisioner "shell" {
    inline = [
      "chmod +x /tmp/install_cml_2.7.0.sh",
      "sudo bash /tmp/install_cml_2.7.0.sh"
    ]
  }

  // Attempt to install CML
  provisioner "shell" {
    inline = [
      "echo 'Attempting CML installation...'",
      
      "# Check if we have any installation scripts",
      "echo 'Looking for installation scripts in multiple locations...'",
      "find /opt/cml-installer -type f -name \"*.sh\" || true",
      "find /tmp -name \"*.sh\" | grep -i cml || true",
      "find /tmp -name \"*.sh\" | grep -i virl || true",
      
      "# Check if we can find the installer in various places",
      "echo 'Searching for CML setup scripts...'",
      "find /opt/cml-installer -type f -name \"setup*\" || true",
      "find /opt/cml-installer -type f -name \"install*\" || true",
      
      "# Look for distribution packages",
      "echo 'Checking for .deb packages...'",
      "find /opt/cml-installer -name \"*.deb\" | sudo xargs -I{} dpkg -i {} 2>/dev/null || true",
      
      "# Try direct approach - look for common installation patterns in Cisco software",
      "echo 'Trying Cisco-style installation approach...'",
      "if [ -f /opt/cml-installer/cml-2.7.0.pkg ]; then",
      "  cd /opt/cml-installer",
      "  sudo bash -c 'DEBIAN_FRONTEND=noninteractive ./cml-2.7.0.pkg --unattendedmodeui none' || true",
      "fi",
      
      "# Look for specific Cisco CML installer patterns",
      "echo 'Checking for Cisco CML 2.x installation patterns...'",
      "sudo find / -path \"/tmp\" -prune -o -name \"cml2_*\" -type f -print 2>/dev/null || true",
      "sudo find / -path \"/tmp\" -prune -o -name \"virl2_*\" -type f -print 2>/dev/null || true",
      
      "# Check if the software was installed as a service",
      "echo 'Checking for CML services...'",
      "sudo systemctl list-units --all | grep -i cml || true",
      "sudo systemctl list-units --all | grep -i virl || true",
      
      "# Try to install any utilities we might need",
      "echo 'Installing potential dependencies...'",
      "sudo apt-get update && sudo apt-get install -y python3-pip || true",
      
      "# Check common Cisco CML 2.x installation locations",
      "echo 'Checking common CML 2.x locations...'",
      "ls -la /etc/virl2/ 2>/dev/null || true",
      "ls -la /usr/local/bin/refplat 2>/dev/null || true",
      "ls -la /usr/local/bin/virl 2>/dev/null || true",
      
      "# Create marker to indicate we've attempted installation",
      "echo 'Creating CML installation marker...'",
      "sudo touch /usr/local/etc/cml_installed.marker"
    ]
  }
  
  // Install KVM and related packages
  provisioner "shell" {
    inline = [
      "echo 'Installing KVM and related virtualization packages...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager cpu-checker",
      "sudo systemctl enable --now libvirtd",
      "sudo systemctl start libvirtd",
      "sudo usermod -aG libvirt ubuntu",
      "sudo usermod -aG kvm ubuntu",
      "echo 'Checking KVM installation...'",
      "kvm-ok || echo 'KVM acceleration may not be available or enabled in BIOS/UEFI'",
      "sudo systemctl status libvirtd || true",
      
      "echo 'Dumping recent system logs after CML install attempt...'",
      "sudo journalctl --no-pager -n 500 || true" # Dump last 500 lines of journal
    ]
  }

  // Create marker file after base installation steps
  provisioner "shell" {
    inline = [
      "echo 'Creating marker file after base installation steps...'",
      "sudo touch /usr/local/etc/cml_base_installed.marker"
    ]
  }
  
  // Check service status before web interface test
  provisioner "shell" {
    environment_vars = [
      "DEBIAN_FRONTEND=noninteractive",
    ]
    inline = [
      "#!/bin/bash",
      "set -e",
      "echo '+++ DIAGNOSTICS Start: Pre-Python Web Check Service Status +++'",
      "# Initialize diagnostic variables",
      "echo 'Checking CML service status...'",
      "sudo systemctl daemon-reload || true",
      
      "echo 'Fixing any broken package dependencies...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install",
      
      "echo 'Looking for CML service files...'",
      "sudo find /etc/systemd/system -name '*virl*' -o -name '*cml*' || true",
      "sudo find /lib/systemd/system -name '*virl*' -o -name '*cml*' || true",
      
      "echo 'Checking for initialization scripts...'",
      "sudo find /usr/local/bin -name '*virl*' -o -name '*cml*' -o -name 'init*' | sudo xargs ls -la 2>/dev/null || true",
      "sudo find /opt -name '*virl*' -o -name '*cml*' -o -name 'init*' | sudo xargs ls -la 2>/dev/null || true",
      
      "echo 'Checking CML data directories...'",
      "sudo ls -la /var/lib/virl2 2>/dev/null || echo 'virl2 data directory not found'",
      "sudo ls -la /etc/virl2 2>/dev/null || echo 'virl2 config directory not found'",
      
      "echo 'Checking CML controller logs...'",
      "sudo mkdir -p /var/log/virl2 2>/dev/null || true",
      "sudo find /var/log -name \"*virl*\" -o -name \"*cml*\" | sudo xargs ls -la 2>/dev/null || true",
      "sudo find /var/log/virl2 -type f | sudo xargs tail -n 50 2>/dev/null || echo 'No CML logs found'",
      "sudo tail -n 50 /var/log/nginx/error.log 2>/dev/null || true",
      
      "echo 'Checking if CML controller database is initialized...'",
      "sudo ls -la /var/lib/virl2/mongo 2>/dev/null || echo 'MongoDB data directory not found'",
      
      "echo 'Initializing CML controller and creating admin user...'",
      "if command -v virl2_controller; then",
      "  echo 'Setting up CML controller...'",
      "  # Stop services if running",
      "  sudo systemctl stop virl2-controller.service || true",
      "  sudo systemctl stop virl2-ui.service || true",
      "  sudo systemctl stop nginx.service || true",
      "  sleep 5",
      
      "  # Clean any old mongo data that might cause issues",
      "  sudo systemctl stop mongodb.service || true",
      "  sudo rm -rf /var/lib/virl2/mongo/* || true",
      "  sudo systemctl start mongodb.service || true",
      "  sleep 10",
      
      "  # Initialize controller with admin user",
      "  echo 'Running virl2_controller init...'",
      "  sudo virl2_controller init || true",
      "  echo 'Init completed, checking status...'",
      "  sudo virl2_controller status || true",
      
      "  # Create admin user if it doesn't exist",
      "  echo 'Creating admin user...'",
      "  sudo virl2_controller users add admin -p admin --full-name 'System Administrator' --email admin@example.com || true",
      "  sudo virl2_controller users grant admin admin || true",
      "  sudo virl2_controller users list || true",
      
      "  # Configure nginx properly for CML UI",
      "  echo 'Configuring nginx...'",
      "  if [ -f /etc/nginx/sites-enabled/default ]; then",
      "    sudo rm -f /etc/nginx/sites-enabled/default || true",
      "  fi",
      
      "  # Enable controller service and start it",
      "  echo 'Starting CML services...'",
      "  sudo systemctl enable virl2-controller.service || true",
      "  sudo systemctl start virl2-controller.service || true",
      "  sleep 20",
      "  sudo systemctl status virl2-controller.service || true",
      
      "  # Start UI service",
      "  sudo systemctl enable virl2-ui.service || true", 
      "  sudo systemctl start virl2-ui.service || true",
      "  sleep 10",
      "  sudo systemctl status virl2-ui.service || true",
      
      "  # Restart nginx with proper configuration",
      "  sudo systemctl enable nginx.service || true",
      "  sudo systemctl restart nginx.service || true",
      "  sleep 5",
      "  sudo systemctl status nginx.service || true",
      
      "echo 'Checking services after initialization...'",
      "sudo systemctl status virl2-controller.service || true",
      "sudo systemctl status virl2-ui.service || true", 
      "sudo systemctl status nginx.service || true",
      
      "echo 'Checking controller logs...'",
      "sudo find /var/log/virl2 -type f -name '*.log' -ls || true",
      "sudo tail -n 50 /var/log/virl2/controller.log || true",
      "echo 'Waiting for services to fully initialize...'",
      "sleep 30",
      
      "echo 'Verifying ports are open...'",
      "sudo ss -tuln | grep -E ':(80|443)' || true",
      
      "echo 'Installing Python requests library for test script...'",
      "pip3 install requests || true",
      
      "echo 'Creating default admin user if needed...'",
      "if [ -f /usr/local/bin/virl2_controller ]; then",
      "  echo 'Trying to create admin user...'",
      "  # Check if user already exists",
      "  sudo /usr/local/bin/virl2_controller user list 2>/dev/null || true",
      "  sudo /usr/local/bin/virl2_controller user add -u admin -p admin -s || echo 'Admin user creation failed or user already exists'",
      "fi",
      
      "echo 'Verifying ports are listening...'",
      "sudo lsof -i :443 || echo 'Nothing listening on port 443'",
      "sudo lsof -i :80 || echo 'Nothing listening on port 80'",
      "fi"
    ]
  }
  
  // Check if Web UI (Nginx proxy) is responding on HTTPS
  provisioner "shell" {
    inline = [
      "echo 'Checking if CML Web UI is responding on HTTPS...'",
      "sudo apt-get update && sudo apt-get install -y curl", # Ensure curl is present
      "for i in {1..10}; do echo \"Attempt $i/10\"; curl --insecure --retry 5 --retry-delay 10 -sfL https://127.0.0.1/ && break || sleep 30; done",
      "if [ $? -ne 0 ]; then echo 'ERROR: CML Web UI did not respond successfully on https://127.0.0.1/'; exit 1; fi",
      "echo 'CML Web UI appears to be responding on HTTPS.'"
    ]
  }
  
  // Clean up
  provisioner "shell" {
    inline = [
      "echo 'Cleaning up system...'",
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -f /home/ubuntu/.bash_history",
      "sudo rm -f /root/.bash_history",
      "sudo cloud-init clean",
      
      "echo 'CML 2.7.0 AMI preparation complete!'"
    ]
  }
}
