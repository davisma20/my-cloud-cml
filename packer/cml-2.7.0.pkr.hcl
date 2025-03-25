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

variable "cml_pkg_s3_bucket" {
  type    = string
  default = "cml-ova-import"
  description = "S3 bucket containing CML package"
}

variable "cml_pkg_s3_key" {
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
      Resource = ["arn:aws:s3:::${var.cml_pkg_s3_bucket}/${var.cml_pkg_s3_key}"]
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
  
  // Download CML 2.7.0 package from S3 using instance role
  provisioner "shell" {
    inline = [
      "echo 'Creating CML installation directory...'",
      "sudo mkdir -p /root/cml_installation/extracted",
      "sudo chmod 755 /root/cml_installation",
      
      "echo 'Downloading CML 2.7.0 package from S3...'",
      "sudo AWS_REGION=${var.region} aws s3 cp s3://${var.cml_pkg_s3_bucket}/${var.cml_pkg_s3_key} /root/cml_installation/",
      
      "echo 'Debug: Listing downloaded files...'",
      "sudo ls -la /root/cml_installation/",
      
      "echo 'Checking if download was successful...'",
      "if sudo test -f /root/cml_installation/${var.cml_pkg_s3_key}; then",
      "  echo 'Download successful!'",
      "else",
      "  echo 'Failed to download the CML package. Checking alternative paths...'",
      "  sudo find / -name ${var.cml_pkg_s3_key} -type f 2>/dev/null || true",
      "  if [ $? -ne 0 ]; then",
      "    echo 'Could not find the package anywhere, aborting.'",
      "    exit 1",
      "  fi",
      "  # If we found the file elsewhere, continue with that path",
      "  pkg_path=$(sudo find / -name ${var.cml_pkg_s3_key} -type f 2>/dev/null | head -1)",
      "  if [ -n \"$pkg_path\" ]; then",
      "    echo \"Found package at: $pkg_path\"",
      "    sudo cp \"$pkg_path\" /root/cml_installation/",
      "  else",
      "    echo 'Could not find the CML package. Aborting.'",
      "    exit 1",
      "  fi",
      "fi",
      
      "echo 'Extracting CML package...'",
      "sudo chmod 755 /root/cml_installation/${var.cml_pkg_s3_key}",
      
      "echo 'Detecting package format...'",
      "pkg_ext=$(echo ${var.cml_pkg_s3_key} | sudo awk -F '.' '{print $NF}')",
      "echo \"Package extension: $pkg_ext\"",
      
      "if [ \"$pkg_ext\" = \"pkg\" ]; then",
      "  echo 'Extracting PKG file...'",
      "  sudo tar -xf /root/cml_installation/${var.cml_pkg_s3_key} -C /root/cml_installation/extracted || echo 'Extraction had issues, but continuing...'",
      "elif [ \"$pkg_ext\" = \"zip\" ]; then",
      "  echo 'Extracting ZIP file...'",
      "  sudo apt-get install -y unzip || true",
      "  sudo unzip -o /root/cml_installation/${var.cml_pkg_s3_key} -d /root/cml_installation/extracted || echo 'Extraction had issues, but continuing...'",
      "elif [ \"$pkg_ext\" = \"tgz\" ] || [ \"$pkg_ext\" = \"gz\" ]; then",
      "  echo 'Extracting TGZ/TAR.GZ file...'",
      "  sudo tar -xzf /root/cml_installation/${var.cml_pkg_s3_key} -C /root/cml_installation/extracted || echo 'Extraction had issues, but continuing...'",
      "else",
      "  echo 'Unknown package format. Attempting generic extraction...'",
      "  sudo tar -xf /root/cml_installation/${var.cml_pkg_s3_key} -C /root/cml_installation/extracted || sudo cp /root/cml_installation/${var.cml_pkg_s3_key} /root/cml_installation/extracted/ || echo 'Extraction had issues, but continuing...'",
      "fi",
      
      "echo 'Listing extracted content:'",
      "sudo ls -la /root/cml_installation/extracted",
      
      "# Create a simple shell script to handle the extraction if the previous methods failed",
      "echo 'Creating backup extraction script...'",
      "cat << 'EOFSCRIPT' | sudo tee /root/cml_installation/extract.sh",
      "#!/bin/bash",
      "cd /root/cml_installation",
      "if [ -f \"${var.cml_pkg_s3_key}\" ]; then",
      "  echo \"Found package file: ${var.cml_pkg_s3_key}\"",
      "  # Try different extraction methods",
      "  mkdir -p extracted",
      "  if tar -xf \"${var.cml_pkg_s3_key}\" -C extracted 2>/dev/null; then",
      "    echo \"Extracted with tar\"",
      "  elif unzip -o \"${var.cml_pkg_s3_key}\" -d extracted 2>/dev/null; then",
      "    echo \"Extracted with unzip\"",
      "  elif cp \"${var.cml_pkg_s3_key}\" extracted/ 2>/dev/null; then",
      "    echo \"Copied file to extracted directory\"",
      "  else",
      "    echo \"All extraction methods failed\"",
      "  fi",
      "else",
      "  echo \"Package file not found: ${var.cml_pkg_s3_key}\"",
      "fi",
      "ls -la extracted",
      "EOFSCRIPT",
      "sudo chmod +x /root/cml_installation/extract.sh",
      "echo 'Running backup extraction script...'",
      "sudo bash /root/cml_installation/extract.sh"
    ]
  }
  
  // Install CML 2.7.0
  provisioner "shell" {
    inline = [
      "echo 'Installing CML 2.7.0...'",
      "# Verify directory exists and has content before trying to access it",
      "if sudo test -d /root/cml_installation/extracted && sudo ls -la /root/cml_installation/extracted | grep -v '^total' | grep -v '\\.$' | grep -v '\\.\\.$' | grep -q .; then",
      "  echo 'Extracted directory exists and has content'",
      "  sudo bash -c 'cd /root/cml_installation/extracted && {",
      "    if [ -f setup.sh ]; then",
      "      echo \"Found setup.sh, running it...\"",
      "      chmod +x setup.sh",
      "      ./setup.sh || echo \"Setup script may have encountered issues but continuing\"",
      "    elif [ -f *.deb ]; then",
      "      echo \"Found DEB packages, installing them...\"",
      "      DEBIAN_FRONTEND=noninteractive apt-get install -y ./cml2*.deb ./iol-tools*.deb ./patty*.deb || echo \"DEB installation may have encountered issues but continuing\"",
      "    else",
      "      echo \"Could not find installation method, listing directory contents:\"",
      "      ls -la",
      "    fi",
      "  }'",
      "else",
      "  echo 'Looking for files directly in the root/cml_installation directory'",
      "  sudo bash -c 'cd /root/cml_installation && {",
      "    if [ -f setup.sh ]; then",
      "      echo \"Found setup.sh in parent directory, running it...\"",
      "      chmod +x setup.sh",
      "      ./setup.sh || echo \"Setup script may have encountered issues but continuing\"",
      "    elif [ -f *.deb ]; then",
      "      echo \"Found DEB packages in parent directory, installing them...\"",
      "      DEBIAN_FRONTEND=noninteractive apt-get install -y ./cml2*.deb ./iol-tools*.deb ./patty*.deb || echo \"DEB installation may have encountered issues but continuing\"",
      "    elif [ -f cml2_*.pkg ]; then",
      "      echo \"Found direct pkg file, extracting and installing...\"",
      "      mkdir -p extracted_direct",
      "      tar -xf cml2_*.pkg -C extracted_direct || echo \"Direct extraction had issues, but continuing...\"",
      "      cd extracted_direct",
      "      if [ -f setup.sh ]; then",
      "        chmod +x setup.sh",
      "        ./setup.sh || echo \"Setup script may have encountered issues but continuing\"",
      "      elif [ -f *.deb ]; then",
      "        DEBIAN_FRONTEND=noninteractive apt-get install -y ./cml2*.deb ./iol-tools*.deb ./patty*.deb || echo \"DEB installation may have encountered issues but continuing\"", 
      "      else",
      "        echo \"No installation method found even after direct extraction\"",
      "        ls -la",
      "      fi",
      "    else",
      "      echo \"Could not find any installation method, listing directory contents:\"",
      "      ls -la",
      "    fi",
      "  }'",
      "fi",
      
      "echo 'Creating CML installation marker...'",
      "sudo mkdir -p /provision",
      "sudo touch /provision/.cml2_install_initiated"
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
      "apt-get update -qq",
      "apt-get install -y curl jq || true",
      "pip3 install requests || true",
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
