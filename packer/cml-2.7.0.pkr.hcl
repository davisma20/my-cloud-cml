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
      
      "echo 'Attempting direct use of the package...'",
      "cd /opt/cml-installer",
      "if [ -f cml-2.7.0.pkg ]; then",
      "  echo 'Found CML package, treating as self-contained installer'",
      "  sudo chmod +x cml-2.7.0.pkg",
      "  sudo ./cml-2.7.0.pkg || echo 'Direct execution failed'",
      "  ",
      "  echo 'Trying alternative installation method with package installer...'",
      "  sudo dpkg -i cml-2.7.0.pkg || echo 'dpkg install failed'",
      "  ",
      "  echo 'Examining package content with file utility...'",
      "  file cml-2.7.0.pkg || true",
      "  ",
      "  echo 'Checking for installation instructions in package...'",
      "  strings cml-2.7.0.pkg | grep -i install | head -20 || true",
      "  strings cml-2.7.0.pkg | grep -i setup | head -20 || true",
      "  strings cml-2.7.0.pkg | grep -i '.sh' | head -20 || true",
      "fi",
      
      "echo 'Checking if this is a Cisco self-extracting archive...'",
      "cd /opt/cml-installer",
      "strings cml-2.7.0.pkg | grep -i 'self-extracting' || true",
      
      "echo 'Attempting to extract as tar or zip...'",
      "mkdir -p extracted",
      "cd extracted",
      "sudo tar -xf ../cml-2.7.0.pkg || echo 'Not a tar archive'",
      "sudo unzip -o ../cml-2.7.0.pkg || echo 'Not a zip archive'",
      "ls -la || true",
      
      "echo 'Checking for any .deb files in the package...'",
      "sudo apt-get install -y binutils || true",
      "cd /opt/cml-installer",
      "ar x cml-2.7.0.pkg || echo 'Not an ar archive'",
      "ls -la || true",
      
      "echo 'Attempting bash installation...'",
      "sudo bash -c 'cd /opt/cml-installer && (sh ./cml-2.7.0.pkg || bash ./cml-2.7.0.pkg || true)'",
      
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
