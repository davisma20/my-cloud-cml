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
  type        = string
  default     = "c5.2xlarge"
  description = "EC2 instance type for the Packer build instance."
}

variable "source_ami" {
  type        = string
  default     = "ami-014d2a8190b1bdeb4" // Ubuntu 20.04 LTS (Focal) for us-east-2 (fetched via SSM)
  description = "Base AMI ID for the build."
}

variable "volume_size" {
  type        = number
  default     = 100
  description = "Size of the root EBS volume in GB."
}

variable "source_ami_filter" {
  type    = bool
  default = false
  description = "Whether to use AMI filter or specific AMI ID"
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
  source_ami      = var.source_ami
  communicator    = "ssh"
  ssh_username    = "ubuntu"
  
  // Use IMDSv2 for enhanced security, but allow IMDSv1 fallback for SSM compatibility
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  // Changed from "required" to "optional" for SSM compatibility
    http_put_response_hop_limit = 2
  }
  
  // Use a temporary IAM instance profile with S3 and SSM access
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
    Statement { // Add SSM Core Permissions
         Action = [
              "ssm:UpdateInstanceInformation",
              "ssmmessages:CreateControlChannel",
              "ssmmessages:CreateDataChannel",
              "ssmmessages:OpenControlChannel",
              "ssmmessages:OpenDataChannel",
              "ec2messages:AcknowledgeMessage",
              "ec2messages:DeleteMessage",
              "ec2messages:FailMessage",
              "ec2messages:GetEndpoint",
              "ec2messages:GetMessages",
              "ec2messages:SendReply"
          ]
         Effect   = "Allow"
         Resource = ["*"] // These actions typically require '*' resource
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
      "echo '==== DEBUG: Running log dump provisioner ===='",
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
      "echo '==== DEBUG: Running explicit user create provisioner ===='",
      "echo 'Explicitly creating admin user...'",
      "sudo useradd -m -s /bin/bash -g admin admin || echo 'WARN: useradd -g admin admin command failed, maybe user already exists or group is wrong?'"
    ]
  }

  // Set up admin user password (MUST run after bootstrap creates the user)
  // Conditionally tries 'admin' first, then 'cml2'
  provisioner "shell" {
    environment_vars = ["CML_PASS=${var.cml_admin_password}"]
    inline = [ <<EOF
      echo '==== DEBUG: Running password set provisioner ===='
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

  // Install and configure MongoDB
  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Running MongoDB install provisioner ===='",
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
      "echo '==== DEBUG: Running S3 download provisioner ===='",
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
    source      = "install_cml_2.7.0.sh"
    destination = "/tmp/install_cml_2.7.0.sh"
  }

  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Running CML install script execution provisioner ===='",
      "chmod +x /tmp/install_cml_2.7.0.sh",
      "sudo bash /tmp/install_cml_2.7.0.sh"
    ]
  }

  // Create marker file after base installation steps
  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Running marker file provisioner ===='",
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
      "echo '==== DEBUG: Running final diagnostic provisioner ===='",
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
      
      "# echo 'Initializing CML controller and creating admin user...'",
      "# if command -v virl2_controller; then",
      "#   echo 'Setting up CML controller...'",
      "#   # Stop services if running",
      "#   sudo systemctl stop virl2-controller.service || true",
      "#   sudo systemctl stop virl2-ui.service || true",
      "#   sudo systemctl stop nginx.service || true",
      "#   sleep 5",
      "#",
      "#   # Clean any old mongo data that might cause issues",
      "#   sudo systemctl stop mongodb.service || true",
      "#   sudo rm -rf /var/lib/virl2/mongo/* || true",
      "#   sudo systemctl start mongodb.service || true",
      "#   sleep 10",
      "#",
      "#   # Initialize controller with admin user",
      "#   echo 'Running virl2_controller init...'",
      "#   sudo virl2_controller init || true",
      "#   echo 'Init completed, checking status...'",
      "#   sudo virl2_controller status || true",
      "#",
      "#   # Create admin user if it doesn't exist",
      "#   echo 'Creating admin user...'",
      "#   sudo virl2_controller users add admin -p admin --full-name 'System Administrator' --email admin@example.com || true",
      "# fi",
      
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
  
  // Create temporary directory for validator scripts before copying
  provisioner "shell" {
    inline = [
      "echo 'Creating temporary directory for validator scripts...'",
      "mkdir -p /tmp/validators"
    ]
  }
  
  // Copy internal validator scripts and directory to a temporary location
  provisioner "file" {
    source      = "../validators/"
    destination = "/tmp/validators"
  }
  provisioner "file" {
    source      = "../run_validation.py"
    destination = "/tmp/run_validation.py"
  }

  // Move validator scripts/directory to final location and make executable
  provisioner "shell" {
    inline = [
      "echo 'Moving internal validator scripts/directory to /usr/local/bin and making executable...'",
      "sudo mv /tmp/validators /usr/local/bin/",
      "sudo mv /tmp/run_validation.py /usr/local/bin/",
      "sudo chmod +x /usr/local/bin/run_validation.py"
    ]
  }

  // Ensure Cloud-Init Final waits for NetworkManager
  provisioner "shell" {
    inline = [
      "echo '[INFO] Modifying cloud-final.service to wait for NetworkManager...'",
      "sudo mkdir -p /etc/systemd/system/cloud-final.service.d",
      "echo -e '[Unit]\nAfter=NetworkManager-wait-online.service\nRequires=NetworkManager-wait-online.service' | sudo tee /etc/systemd/system/cloud-final.service.d/wait-for-network.conf > /dev/null",
      "sudo systemctl daemon-reload"
    ]
  }

  // Explicitly install and enable SSM Agent before cleanup
  provisioner "shell" {
    inline = [
      "echo 'Ensuring amazon-ssm-agent is installed and running...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y amazon-ssm-agent",
      "sudo systemctl enable --now amazon-ssm-agent",
      "sleep 5 # Give service a moment to start",
      "sudo systemctl status amazon-ssm-agent || echo 'Warning: SSM Agent status check failed immediately after start.'",
      "echo 'SSM Agent installation/activation attempted.'"
    ]
  }

  // === BEGIN: Cloud-init and SSH Diagnostics Provisioner ===
  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Dumping cloud-init and SSH diagnostics ===='",
      "which cloud-init || (echo 'cloud-init not installed!' && exit 1)",
      "sudo systemctl status cloud-init || (echo 'cloud-init service not running!' && exit 1)",
      "sudo systemctl status ssh || (echo 'ssh service not running!' && exit 1)",
      "sudo cat /etc/passwd",
      "sudo ls -l /home/ubuntu/.ssh/ || echo '/home/ubuntu/.ssh/ missing'",
      "sudo cat /home/ubuntu/.ssh/authorized_keys || echo 'No authorized_keys found'",
      "sudo cat /var/log/cloud-init.log | tail -n 50",
      "sudo cat /var/log/cloud-init-output.log | tail -n 50"
    ]
  }
  // === END: Cloud-init and SSH Diagnostics Provisioner ===

  // === BEGIN: Network Diagnostics Provisioner ===
  provisioner "shell" {
    inline = [
      "echo '==== DEBUG: Network diagnostics before AMI creation ===='",
      "ip addr show",
      "ip route",
      "ping -c 3 8.8.8.8 || echo 'Ping to 8.8.8.8 failed'",
      "curl -s http://169.254.169.254/latest/meta-data/ || echo 'Metadata service unavailable'"
    ]
  }
  // === END: Network Diagnostics Provisioner ===

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

  // Post-processor to record the AMI ID
  post-processor "manifest" {
    output     = "packer-manifest.json"
    strip_path = true // Optional: Remove paths from artifact file list
  }
}
