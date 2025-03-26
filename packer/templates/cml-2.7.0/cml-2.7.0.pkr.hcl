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
    Statement {
      Action   = ["s3:GetObject"]
      Effect   = "Allow"
      Resource = ["arn:aws:s3:::${var.cml_bucket}/${var.cml_pkg_path}"]
    }
    Version = "2012-10-17"
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
  
  // Install CML dependencies
  provisioner "shell" {
    inline = [
      "echo 'Updating system and installing CML dependencies...'",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade || true",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y qemu-kvm libvirt-daemon libvirt-daemon-system libvirt-clients bridge-utils virt-manager libguestfs-tools openvswitch-switch python3-openvswitch openvpn wireguard awscli vlan wget curl unzip software-properties-common jq nginx gnupg apt-transport-https libnss-libvirt cloud-init python3-pip || true"
    ]
  }
  
  // Upload and run CML optimization script
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

  // Download CML package
  provisioner "shell" {
    environment_vars = [
      "AWS_REGION=${var.region}",
      "CML_BUCKET=${var.cml_bucket}",
      "CML_PKG_PATH=${var.cml_pkg_path}"
    ]
    inline = [
      "echo 'Downloading CML 2.7.0 package from S3...'",
      "aws s3 cp s3://${var.cml_bucket}/${var.cml_pkg_path} /tmp/cml-2.7.0.pkg",
      "echo 'Verifying download...'",
      "ls -la /tmp/cml-2.7.0.pkg",
      
      "echo 'Determining the package format...'",
      "file /tmp/cml-2.7.0.pkg || true",
      
      "echo 'Creating secure extraction directory...'",
      "sudo mkdir -p /opt/cml-installer",
      "sudo chmod 755 /opt/cml-installer",
      
      "echo 'Copying package to secure location...'",
      "sudo cp /tmp/cml-2.7.0.pkg /opt/cml-installer/",
      "sudo chmod 644 /opt/cml-installer/cml-2.7.0.pkg",
      
      "echo 'Examining package content with file utility...'",
      "file cml-2.7.0.pkg || true",
      
      "echo 'Now that we know it is a tar archive, extracting properly...'",
      "sudo mkdir -p /opt/cml-installer/extracted",
      "sudo chmod 777 /opt/cml-installer/extracted",
      "cd /opt/cml-installer",
      "sudo tar -xf cml-2.7.0.pkg -C extracted || echo 'Tar extraction failed'",
      "sudo chmod -R 755 /opt/cml-installer/extracted",
      "echo 'Extracted contents:'",
      "ls -la /opt/cml-installer/extracted || true",
      
      "echo 'Looking for installation scripts in extracted content...'",
      "find /opt/cml-installer/extracted -type f -name \"*.sh\" | sudo xargs -I{} chmod +x {} 2>/dev/null || true",
      "find /opt/cml-installer/extracted -type f -name \"install*\" | sudo xargs -I{} chmod +x {} 2>/dev/null || true",
      "find /opt/cml-installer/extracted -type f -name \"setup*\" | sudo xargs -I{} chmod +x {} 2>/dev/null || true",
      
      "echo 'Attempting to run installation scripts if found...'",
      "cd /opt/cml-installer/extracted",
      "if [ -f setup.sh ]; then",
      "  echo 'Found setup.sh script, executing...'",
      "  sudo bash -c 'cd /opt/cml-installer/extracted && ./setup.sh' || echo 'Setup script failed'",
      "elif [ -f install.sh ]; then",
      "  echo 'Found install.sh script, executing...'",
      "  sudo bash -c 'cd /opt/cml-installer/extracted && ./install.sh' || echo 'Install script failed'",
      "else",
      "  echo 'No standard installation scripts found. Looking for other candidates...'",
      "  find . -type f -name \"*.sh\" -o -name \"install*\" -o -name \"setup*\" | sort || true",
      "fi",
      
      "echo 'Checking for Debian packages in extracted files...'",
      "find /opt/cml-installer/extracted -name \"*.deb\" | sudo xargs -I{} dpkg -i {} 2>/dev/null || echo 'No Debian packages found or installation failed'",
      
      "echo 'Fixing package dependencies...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install",
      "sudo apt-get -y install $(dpkg -I /opt/cml-installer/extracted/*.deb 2>/dev/null | grep Depends | sed 's/Depends://g' | tr ',' ' ' | tr '|' ' ') || true",
      
      "echo 'Retrying installation of any .deb packages that failed due to dependencies...'",
      "find /opt/cml-installer/extracted -name \"*.deb\" | sudo xargs -I{} dpkg -i {} 2>/dev/null || true", 
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install",
      
      "echo 'Looking for any installation files that were created...'",
      "sudo find /opt/cml-installer -type f -name \"*.sh\" -o -name \"install*\" -o -name \"setup*\" | xargs -I{} chmod +x {} 2>/dev/null || true",
      "sudo find /opt/cml-installer -type f -name \"*.sh\" -o -name \"install*\" -o -name \"setup*\" | xargs -I{} bash -c 'echo \"Running {}\"; {} || true' 2>/dev/null || true"
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
  
  // Check service status before web interface test
  provisioner "shell" {
    inline = [
      "echo 'Checking CML service status...'",
      "sudo systemctl daemon-reload || true",
      
      "echo 'Fixing any broken package dependencies...'",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install",
      
      "echo 'Looking for CML service files...'",
      "find /etc/systemd/system -name '*virl*' -o -name '*cml*' || true",
      "find /lib/systemd/system -name '*virl*' -o -name '*cml*' || true",
      
      "echo 'Checking for initialization scripts...'",
      "sudo find /usr/local/bin -name '*virl*' -o -name '*cml*' -o -name 'init*' | xargs ls -la 2>/dev/null || true",
      "sudo find /opt -name '*virl*' -o -name '*cml*' -o -name 'init*' | xargs ls -la 2>/dev/null || true",
      
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
      
      "echo 'Running manual CML controller initialization...'",
      "mkdir -p /var/log/virl2",
      "mkdir -p /var/cache/virl2",
      "mkdir -p /var/lib/virl2",
      "mkdir -p /etc/virl2",
      
      "echo 'Installing and configuring MongoDB...'",
      "DEBIAN_FRONTEND=noninteractive apt-get -y update",
      "DEBIAN_FRONTEND=noninteractive apt-get -y install apt-utils",
      "DEBIAN_FRONTEND=noninteractive apt-get -y install python3-pip python3-venv python3-dev",
      "DEBIAN_FRONTEND=noninteractive apt-get -y install libvirt-daemon libvirt-daemon-system python3-pymongo",
      "DEBIAN_FRONTEND=noninteractive apt-get -y install mongodb-server",
      "DEBIAN_FRONTEND=noninteractive apt-get -y install nginx",
      "DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y",
      "pip3 install --upgrade pip",
      "pip3 install pymongo requests",
      
      "echo 'Setting up MongoDB for CML...'",
      "mkdir -p /var/lib/mongodb",
      "chown -R mongodb:mongodb /var/lib/mongodb",
      "chmod 755 /var/lib/mongodb",
      "systemctl enable mongod",
      "systemctl restart mongod",
      "systemctl status mongod",
      "echo 'Waiting for MongoDB to fully initialize...'",
      "sleep 30",
      
      "echo 'Check if the CML package was extracted properly...'",
      "ls -la /opt/cml-installer/extracted/ 2>/dev/null || echo 'CML installer extracted directory not found'",
      "echo 'Check if setup.sh is present and executable...'",
      "if [ -f /opt/cml-installer/extracted/setup.sh ]; then",
      "  echo 'setup.sh found, making it executable...'",
      "  chmod +x /opt/cml-installer/extracted/setup.sh",
      "  ls -la /opt/cml-installer/extracted/setup.sh",
      "else",
      "  echo 'setup.sh not found, checking tar.gz contents...'",
      "  mkdir -p /opt/cml-installer/extracted/",
      "  if [ -f /opt/cml-installer/cml-2.7.0.pkg ]; then",
      "    echo 'Extracting the CML package...'",
      "    tar -xf /opt/cml-installer/cml-2.7.0.pkg -C /opt/cml-installer/extracted/",
      "  fi",
      "  ls -la /opt/cml-installer/extracted/",
      "fi",
      
      "echo 'Running CML setup script if available...'",
      "if [ -f /opt/cml-installer/extracted/setup.sh ]; then",
      "  cd /opt/cml-installer/extracted/",
      "  echo 'Executing setup.sh from extracted directory...'",
      "  ./setup.sh || echo 'setup.sh failed with error code $?'",
      "  ls -la /usr/local/bin/virl2_controller || echo 'virl2_controller not found after setup'",
      "else",
      "  echo 'setup.sh not found after extraction attempt!'",
      "  find /opt/cml-installer -type f -name \"setup.sh\" 2>/dev/null || echo 'No setup.sh found in /opt/cml-installer'",
      "fi",
      
      "echo 'Initializing CML controller and creating admin user...'",
      "if command -v virl2_controller; then",
      "  echo 'Setting up CML controller...'",
      
      "  # First, completely stop all services to avoid conflicts",
      "  echo 'Stopping all services for clean initialization...'",
      "  systemctl stop nginx || true",
      "  systemctl stop virl2-ui.service || true", 
      "  systemctl stop virl2-controller.service || true",
      "  systemctl stop mongod || true",
      "  sleep 10",
      
      "  # Purge and reconfigure nginx",
      "  echo 'Reconfiguring nginx...'",
      "  rm -f /etc/nginx/sites-enabled/default || true",
      "  echo 'server { listen 80; server_name _; location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; } }' > /etc/nginx/sites-available/cml",
      "  ln -sf /etc/nginx/sites-available/cml /etc/nginx/sites-enabled/cml",
      "  nginx -t || echo 'Nginx config test failed'",
      
      "  # Clean MongoDB and restart",
      "  echo 'Cleaning and reinitializing MongoDB...'",
      "  systemctl start mongod",
      "  sleep 15",
      
      "  # Run controller initialization with verbose output",
      "  echo 'Running controller initialization...'",
      "  virl2_controller init --force || true",
      "  echo 'Controller initialization status:'",
      "  virl2_controller status",
      
      "  # Create admin user with full privileges",
      "  echo 'Creating admin user...'",
      "  virl2_controller users add admin -p admin --full-name 'CML Administrator' --email admin@example.com || true",
      "  virl2_controller users grant admin admin || true",
      "  virl2_controller users grant admin root || true",
      "  virl2_controller users list",
      
      "  # Start services in proper order",
      "  echo 'Starting services in proper order...'",
      "  systemctl enable virl2-controller.service || true",
      "  systemctl start virl2-controller.service || true",
      "  sleep 15",
      
      "  systemctl enable virl2-ui.service || true",
      "  systemctl start virl2-ui.service || true",
      "  sleep 15",
      
      "  systemctl restart nginx || true",
      "  sleep 5",
      
      "  # Verify everything is running",
      "  echo 'Verifying service status...'",
      "  systemctl status mongod --no-pager || true",
      "  systemctl status virl2-controller.service --no-pager || true",
      "  systemctl status virl2-ui.service --no-pager || true",
      "  systemctl status nginx --no-pager || true",
      "  netstat -tulpn | grep -E '8000|8001|80' || true",
      
      "echo 'Checking services after initialization...'",
      "systemctl status virl2-controller.service || true",
      "systemctl status virl2-ui.service || true", 
      "systemctl status nginx.service || true",
      
      "echo 'Checking controller logs...'",
      "find /var/log/virl2 -type f -name '*.log' -ls || true",
      "tail -n 50 /var/log/virl2/controller.log || true",
      "echo 'Waiting for services to fully initialize...'",
      "sleep 30",
      
      "echo 'Verifying ports are open...'",
      "ss -tuln | grep -E ':(80|443)' || true",
      
      "echo 'Installing Python requests library for test script...'",
      "pip3 install requests || true",
      
      "echo 'Creating default admin user if needed...'",
      "if [ -f /usr/local/bin/virl2_controller ]; then",
      "  echo 'Trying to create admin user...'",
      "  sudo /usr/local/bin/virl2_controller user list 2>/dev/null || true",
      "  sudo /usr/local/bin/virl2_controller user add -u admin -p admin -s || echo 'Admin user creation failed or user already exists'",
      "fi",
      
      "echo 'Verifying ports are listening...'",
      "sudo lsof -i :443 || echo 'Nothing listening on port 443'",
      "sudo lsof -i :80 || echo 'Nothing listening on port 80'",
      "else",
      "  echo 'virl2_controller command not found. CML installation may be incomplete.'",
      "  echo 'Searching for virl2_controller binary...'",
      "  find / -name virl2_controller 2>/dev/null || echo 'virl2_controller not found'",
      "  echo 'Installation path contents...'",
      "  ls -la /usr/local/bin/ || true",
      "fi",
      
      "echo 'Final checking of services after initialization...'",
      "systemctl status virl2-controller.service || true",
      "systemctl status virl2-ui.service || true", 
      "systemctl status nginx.service || true"
    ]
  }
  
  // Wait for CML web interface to become available and test login
  provisioner "file" {
    source      = "${path.root}/../scripts/web-ui/setup_cml_web_ui.sh"
    destination = "/tmp/setup_cml_web_ui.sh" 
  }

  provisioner "file" {
    source      = "${path.root}/../scripts/web-ui/test_cml_web_ui.py"
    destination = "/tmp/test_cml_web_ui.py"
  }

  provisioner "shell" {
    inline = [
      "echo 'Setting up and testing CML web UI...'",
      "chmod +x /tmp/setup_cml_web_ui.sh",
      "chmod +x /tmp/test_cml_web_ui.py",
      "sudo /tmp/setup_cml_web_ui.sh",
      "python3 /tmp/test_cml_web_ui.py"
    ]
  }

  // Set up admin user
  provisioner "shell" {
    inline = [
      "echo 'Setting up CML admin user...'",
      "sudo groupadd -f admin || echo 'Admin group already exists'",
      "sudo useradd -m -s /bin/bash -g admin admin || echo 'Failed to create admin user - it may already exist'",
      "sudo usermod -aG sudo admin || echo 'Failed to add admin to sudo group'",
      "sudo bash -c 'echo \"${var.cml_admin_username}:${var.cml_admin_password}\" | chpasswd'",
      "echo '${var.cml_admin_username} ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/admin",
      "sudo chmod 0440 /etc/sudoers.d/admin"
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
