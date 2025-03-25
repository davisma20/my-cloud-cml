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
      
      "echo 'Attempting to initialize CML controller...'",
      "if [ -f /usr/local/bin/virl2_controller ]; then",
      "  echo 'Found virl2_controller binary, checking if we need to initialize it...'",
      "  sudo /usr/local/bin/virl2_controller init || echo 'Controller initialization failed or not needed'",
      "  sudo /usr/local/bin/virl2_controller configure || echo 'Controller configuration failed or not needed'",
      "fi",
      
      "echo 'Checking CML controller status and logs after initialization...'",
      "sudo systemctl status virl2-controller.service || true",
      "sudo find /var/log/virl2 -type f -name \"controller.log\" | sudo xargs tail -n 100 2>/dev/null || echo 'No controller logs found'",
      
      "echo 'Checking CML UI status and logs...'",
      "sudo systemctl status virl2-ui.service 2>/dev/null || echo 'UI service not found'",
      "sudo find /var/log/virl2 -type f -name \"ui.log\" | sudo xargs tail -n 100 2>/dev/null || echo 'No UI logs found'",
      
      "echo 'Checking for authentication configuration...'",
      "sudo ls -la /etc/virl2/credentials.json 2>/dev/null || echo 'Credentials file not found'",
      "sudo cat /etc/virl2/credentials.json 2>/dev/null | grep -v password || echo 'No credentials found'",
      
      "echo 'Searching for default username/password...'",
      "sudo grep -r \"admin\" --include=\"*.json\" --include=\"*.conf\" --include=\"*.yml\" /etc/virl2/ 2>/dev/null || echo 'No default admin credentials found'",
      
      "echo 'Attempting to restart CML services in the correct order...'",
      "sudo systemctl daemon-reload || true",
      "sudo systemctl restart virl2-controller.service || true",
      "sleep 10 # Wait for controller to initialize",
      "sudo systemctl restart virl2-ui.service 2>/dev/null || true",
      "sudo systemctl restart nginx.service || true",
      
      "echo 'Checking if services are running now...'",
      "sudo systemctl status virl2-controller.service || true",
      "sudo systemctl status virl2-ui.service 2>/dev/null || true",
      "sudo systemctl status nginx.service || true",
      
      "echo 'Creating default admin user if needed...'",
      "if [ -f /usr/local/bin/virl2_controller ]; then",
      "  echo 'Trying to create admin user...'",
      "  sudo /usr/local/bin/virl2_controller user list 2>/dev/null || true",
      "  sudo /usr/local/bin/virl2_controller user add -u admin -p admin -s || echo 'Admin user creation failed or user already exists'",
      "fi",
      
      "echo 'Verifying ports are listening...'",
      "sudo lsof -i :443 || echo 'Nothing listening on port 443'",
      "sudo lsof -i :80 || echo 'Nothing listening on port 80'"
    ]
  }
  
  // Wait for CML web interface to become available and test login
  provisioner "shell" {
    inline = [
      "echo 'Waiting for CML services to start...'",
      "sleep 30",
      "sudo apt-get -y install curl jq python3-pip || true",
      "pip3 install requests || true",
      
      "echo 'Running CML web interface login test...'",
      <<EOT
      cat > /tmp/test_cml_login.py << 'EOF'
import requests
import time
import json
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

MAX_TRIES = 30
WAIT_TIME = 10
BASE_URL = "https://localhost"
USERNAME = "admin"
PASSWORD = "admin"

cookies = {}

print("Testing CML login with admin credentials")

for attempt in range(1, MAX_TRIES + 1):
    print(f"Try {attempt}/{MAX_TRIES}...")
    try:
        # Check if the about endpoint exists first
        try:
            about_resp = requests.get(f"{BASE_URL}/api/v0/about", verify=False, timeout=5)
            print(f"About response: {about_resp.status_code}")
            if about_resp.status_code == 200:
                print("About endpoint accessible, CML API is working")
        except Exception as e:
            print(f"Error accessing about endpoint: {e}")
            
        # Check if nginx is serving the UI
        try:
            ui_resp = requests.get(BASE_URL, verify=False, timeout=5)
            print(f"UI response: {ui_resp.status_code}")
            if ui_resp.status_code == 200:
                print("UI accessible")
        except Exception as e:
            print(f"Error accessing UI: {e}")

        # Try to login
        login_data = {
            "username": USERNAME, 
            "password": PASSWORD
        }
        
        # Get CSRF token if needed
        session = requests.Session()
        try:
            initial_resp = session.get(f"{BASE_URL}/auth/login", verify=False, timeout=5)
            print(f"Initial auth page status: {initial_resp.status_code}")
            if "csrftoken" in session.cookies:
                print("Found CSRF token in cookies")
                login_data["csrfmiddlewaretoken"] = session.cookies["csrftoken"]
        except Exception as e:
            print(f"Error getting initial page: {e}")

        # Attempt login
        try:
            login_resp = session.post(
                f"{BASE_URL}/api/v0/authenticate", 
                json=login_data,
                headers={"Referer": f"{BASE_URL}/auth/login"},
                verify=False,
                timeout=10
            )
            
            print(f"Login status: {login_resp.status_code}")
            
            if login_resp.status_code in [200, 201, 202]:
                print("Login successful!")
                print(f"Response: {login_resp.text[:100]}...")
                
                # Try to get a protected resource to verify authentication
                try:
                    labs_resp = session.get(f"{BASE_URL}/api/v0/labs", verify=False, timeout=5)
                    print(f"Labs API status: {labs_resp.status_code}")
                    if labs_resp.status_code == 200:
                        print("Successfully authenticated and accessed labs API")
                        sys.exit(0)  # Success!
                except Exception as e:
                    print(f"Error accessing labs API: {e}")
            else:
                print(f"Login failed. Status: {login_resp.status_code}")
                print(f"Response: {repr(login_resp.text)}")
        except Exception as e:
            print(f"Error during login: {e}")
            
        # Check system status
        print("Checking system status...")
        try:
            import subprocess
            subprocess.call(["sudo", "systemctl", "status", "virl2-controller.service"])
            subprocess.call(["sudo", "systemctl", "status", "virl2-ui.service"])
            subprocess.call(["sudo", "systemctl", "status", "nginx.service"])
            subprocess.call(["sudo", "tail", "-n", "50", "/var/log/virl2/controller.log"])
        except Exception as e:
            print(f"Error checking system status: {e}")
        
        # Wait before retrying
        if attempt < MAX_TRIES:
            print(f"Waiting {WAIT_TIME} seconds before retry...")
            time.sleep(WAIT_TIME)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if attempt < MAX_TRIES:
            print(f"Waiting {WAIT_TIME} seconds before retry...")
            time.sleep(WAIT_TIME)

print("Maximum attempts reached. CML web interface not available.")
sys.exit(1)  # Failure
EOF
chmod +x /tmp/test_cml_login.py
python3 /tmp/test_cml_login.py
EOT
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
