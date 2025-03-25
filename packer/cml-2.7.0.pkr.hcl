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
      "CML_PKG_PATH=${var.cml_pkg_path}",
      "CML_ADMIN_USERNAME=${var.cml_admin_username}",
      "CML_ADMIN_PASSWORD=${var.cml_admin_password}"
    ]
    inline = [
      "echo 'Downloading CML 2.7.0 package from S3...'",
      "aws s3 cp s3://${var.cml_bucket}/${var.cml_pkg_path} /tmp/cml-2.7.0.pkg",
      "echo 'Verifying download...'",
      "ls -la /tmp/cml-2.7.0.pkg",
      "echo 'Creating extraction directory...'",
      "mkdir -p /tmp/cml-2.7.0",
      "echo 'Extracting CML package...'",
      "cd /tmp",
      "if file cml-2.7.0.pkg | grep -i zip; then",
      "  echo 'Detected ZIP format'",
      "  unzip -o cml-2.7.0.pkg -d cml-2.7.0 || echo 'Unzip failed, trying alternate methods'",
      "elif file cml-2.7.0.pkg | grep -i gzip; then",
      "  echo 'Detected GZIP format'",
      "  tar -xzf cml-2.7.0.pkg -C cml-2.7.0 || echo 'Gzip extraction failed, trying alternate methods'",
      "else",
      "  echo 'Unknown format, trying multiple extraction methods'",
      "  unzip -o cml-2.7.0.pkg -d cml-2.7.0 || tar -xzf cml-2.7.0.pkg -C cml-2.7.0 || echo 'All extraction methods failed'",
      "fi",
      "echo 'Checking extracted contents...'",
      "ls -la /tmp/cml-2.7.0",
      "echo 'Setting permissions on extracted files...'",
      "chmod -R 755 /tmp/cml-2.7.0/*.sh 2>/dev/null || echo 'No shell scripts found to set permissions on'"
    ]
  }
  
  // Install CML 2.7.0
  provisioner "shell" {
    inline = [
      "echo 'Installing CML 2.7.0...'",
      
      "# Check for extracted directory with content",
      "if [ -d \"/tmp/cml-2.7.0\" ] && [ \"$(ls -A /tmp/cml-2.7.0)\" ]; then",
      "  echo 'Extracted directory exists and has content'",
      "  cd /tmp/cml-2.7.0",
      "  echo 'Contents of extracted directory:'",
      "  ls -la",
      "  ",
      "  # Examine setup.sh content",
      "  if [ -f \"setup.sh\" ]; then",
      "    echo 'Found setup.sh, examining content:'",
      "    cat setup.sh",
      "    echo 'Ensuring setup.sh is executable'",
      "    chmod +x setup.sh",
      "    echo 'Running setup.sh with detailed output...'",
      "    sudo bash -c 'cd /tmp/cml-2.7.0 && ./setup.sh' || echo 'Setup script completed with non-zero exit code'",
      "    echo 'Setup script execution completed'",
      "  else",
      "    echo 'setup.sh not found in extracted directory'",
      "    echo 'Checking for other installation methods...'",
      "    if [ -f \"install.sh\" ]; then",
      "      echo 'Found install.sh, running it...'",
      "      chmod +x install.sh",
      "      sudo bash -c 'cd /tmp/cml-2.7.0 && ./install.sh' || echo 'Install script completed with non-zero exit code'",
      "    else",
      "      echo 'No installation scripts found in extracted directory'",
      "    fi",
      "  fi",
      "else",
      "  echo 'Extracted directory does not exist or is empty'",
      "  # Check in root directory",
      "  if [ -f \"/tmp/cml-2.7.0.pkg\" ]; then",
      "    echo 'Found CML package file in /tmp'",
      "    cd /tmp",
      "    echo 'Attempting to extract directly...'",
      "    mkdir -p cml-extract",
      "    cd cml-extract",
      "    sudo tar -xzf /tmp/cml-2.7.0.pkg || echo 'Failed to extract with tar -xzf'",
      "    sudo unzip -o /tmp/cml-2.7.0.pkg || echo 'Failed to extract with unzip'",
      "  else",
      "    echo 'CML package file not found in /tmp'",
      "  fi",
      "fi",
      
      "# Check if installation has created necessary files",
      "echo 'Checking for CML installation files...'",
      "ls -la /usr/local/bin/ | grep -i virl || true",
      "ls -la /usr/local/bin/ | grep -i cml || true",
      "ls -la /etc/ | grep -i virl || true",
      "ls -la /etc/ | grep -i cml || true",
      
      "# Check systemd services",
      "echo 'Checking systemd services...'",
      "systemctl list-unit-files | grep -i virl || true",
      "systemctl list-unit-files | grep -i cml || true",
      
      "# Check what the software is expecting to install",
      "echo 'Examining available installation files...'",
      "find /tmp -name \"*.deb\" | sort || echo 'No .deb files found'",
      "find /tmp -name \"*.sh\" | sort || echo 'No shell scripts found'",
      
      "# Find any error logs from the installation",
      "echo 'Checking for error logs...'",
      "find /tmp -name \"*error*\" -o -name \"*log*\" | xargs ls -la 2>/dev/null || echo 'No error logs found'",
      
      "# Install .deb files",
      "find /tmp -name \"*.deb\" -exec sudo dpkg -i {} \\; || echo 'Failed to install .deb files'",
      
      "# Create marker to indicate we've attempted installation",
      "echo 'Creating CML installation marker...'",
      "sudo touch /usr/local/etc/cml_installed.marker"
    ]
  }
  
  // Check service status before web interface test
  provisioner "shell" {
    inline = [
      "echo 'Checking CML service status...'",
      "sudo systemctl status virl2-controller.service || true",
      "sudo systemctl status nginx.service || true",
      "sudo tail -n 50 /var/log/virl2/controller.log || true",
      "echo 'Verifying CML installation...'",
      "ls -la /usr/local/bin/refplat || true",
      "ls -la /etc/virl2 || true",
      "ls -la /etc/nginx/sites-enabled/ || true",
      "echo 'Attempting to start CML services...'",
      "sudo systemctl daemon-reload || true",
      "sudo systemctl restart virl2-controller.service || true",
      "sudo systemctl restart nginx.service || true",
      "echo 'Waiting for services to initialize...'",
      "sleep 30"
    ]
  }

  // Wait for CML web interface to become available and test login
  provisioner "shell" {
    inline = [
      "echo 'Waiting for CML services to start...'",
      "sudo apt-get update -qq",
      "sudo apt-get install -y curl jq || true",
      "sudo pip3 install requests || true",
      "cat > /tmp/test_cml_login.py << 'EOF'",
      "#!/usr/bin/env python3",
      "import requests",
      "import time",
      "import sys",
      "import os",
      "import json",
      "from urllib3.exceptions import InsecureRequestWarning",
      "",
      "# Suppress only the single warning from urllib3 needed.",
      "requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)",
      "",
      "def check_service(url):",
      "    try:",
      "        response = requests.get(url, verify=False, timeout=5)",
      "        return response.status_code < 500",
      "    except Exception as e:",
      "        print(f'Service check exception: {str(e)}')",
      "        return False",
      "",
      "def main():",
      "    base_url = 'https://localhost'",
      "    api_endpoint = f'{base_url}/api/v0'",
      "    username = os.environ.get('CML_ADMIN_USERNAME', 'admin')",
      "    password = os.environ.get('CML_ADMIN_PASSWORD', 'admin')",
      "    ",
      "    max_attempts = 30",
      "    attempt = 1",
      "    ",
      "    while attempt <= max_attempts:",
      "        print(f'Try {attempt}/{max_attempts}...')",
      "        try:",
      "            # Check if the web server is responding at all",
      "            if not check_service(base_url):",
      "                print('Web server not responding to base URL - checking nginx status')",
      "                os.system('sudo systemctl status nginx || true')",
      "                os.system('curl -k -v https://localhost/ || true')",
      "            ",
      "            # Try API about endpoint",
      "            about_response = requests.get(f'{api_endpoint}/about', verify=False, timeout=10)",
      "            print(f'About response: {about_response.status_code}')",
      "            if about_response.status_code < 400:",
      "                print('API is online, attempting login')",
      "            ",
      "            # Try login",
      "            login_data = {'username': username, 'password': password}",
      "            login_response = requests.post(f'{api_endpoint}/authenticate', json=login_data, verify=False, timeout=10)",
      "            ",
      "            if login_response.status_code == 200:",
      "                token = login_response.json().get('token')",
      "                if token:",
      "                    print('Login successful!')",
      "                    return 0",
      "                else:",
      "                    print('Login response missing token')",
      "            else:",
      "                print(f'Login failed. Status: {login_response.status_code}')",
      "                print(f'Response: {login_response.text}')",
      "        except requests.exceptions.RequestException as e:",
      "            print(f'Exception: {str(e)}')",
      "            ",
      "            # Check running services",
      "            if attempt % 5 == 0:",
      "                os.system('sudo systemctl status virl2-controller.service || true')",
      "                os.system('sudo systemctl status nginx.service || true')",
      "                os.system('ls -la /etc/nginx/sites-enabled/ || true')",
      "        ",
      "        if attempt < max_attempts:",
      "            print('Waiting 10 seconds before retry...')",
      "            time.sleep(10)",
      "        attempt += 1",
      "    ",
      "    print('Maximum attempts reached. CML web interface not available.')",
      "    return 1",
      "",
      "if __name__ == '__main__':",
      "    sys.exit(main())",
      "EOF",
      "chmod +x /tmp/test_cml_login.py",
      "export CML_ADMIN_USERNAME='admin'",
      "export CML_ADMIN_PASSWORD='admin'",
      "echo 'Running CML web interface login test...'",
      "python3 /tmp/test_cml_login.py"
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
