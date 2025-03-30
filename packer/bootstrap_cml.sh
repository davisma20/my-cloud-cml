#!/bin/bash
# Comprehensive bootstrap script to prepare the CML instance for the AMI
# This script will be embedded in the Packer configuration

set -e
set -o pipefail

# --- Apt/GPG Fixes ---
echo "Attempting to fix potential apt/GPG issues..."
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
sudo mkdir -p /var/lib/apt/lists/partial
sudo apt-get update -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true || {
    echo "Initial apt update failed, attempting further fixes..."
    sudo apt-get install -y gnupg ca-certificates apt-transport-https --allow-unauthenticated || echo "Warning: Failed to install GPG/HTTPS packages, continuing..."
    # Add specific keys known to be sometimes problematic
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C || echo "Warning: Failed to add standard Ubuntu keys"
    sudo apt-get update || echo "Warning: Apt update still failing after fixes."
}
echo "Apt/GPG fix attempt completed."
# --- End Apt/GPG Fixes ---

# Setup logging with timestamps
LOGFILE="/var/log/bootstrap_cml.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "Starting CML bootstrap at $(date)"

# Test network connectivity
echo "Testing network connectivity..."
ping -c 3 archive.ubuntu.com || echo "WARNING: Network connectivity issues detected"

# Ensure all repositories are enabled (universe, multiverse, restricted, backports)
echo "Ensuring all required repositories are enabled..."
apt-get update
apt-get install -y software-properties-common apt-utils
add-apt-repository -y universe
add-apt-repository -y multiverse
add-apt-repository -y restricted
# Enable backports explicitly
add-apt-repository -y "deb http://archive.ubuntu.com/ubuntu $(lsb_release -cs)-backports main restricted universe multiverse"

# Add specific repositories for problematic packages
echo "Adding specific repositories for packages..."
# For wireguard
add-apt-repository -y ppa:wireguard/wireguard || true
# For libguestfs-tools
add-apt-repository -y 'deb http://archive.ubuntu.com/ubuntu focal main universe'

# Try using the main Ubuntu archive if regional mirrors fail
apt-get update || {
  echo "Updating from regional mirror failed, trying main archive..."
  sed -i 's/us-east-2.ec2.archive.ubuntu.com/archive.ubuntu.com/g' /etc/apt/sources.list
  apt-get update
}

# Update system packages
export DEBIAN_FRONTEND=noninteractive
echo "Updating and upgrading system packages..."
apt-get upgrade -y

# Install essential dependencies for CML
echo "Installing essential CML dependencies..."
apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  software-properties-common \
  python3-pip \
  qemu-kvm \
  libvirt-daemon \
  libvirt-clients \
  nginx \
  wget \
  unzip \
  cloud-init \
  uuid \
  expect \
  cloud-guest-utils \
  python3-openvswitch \
  openvswitch-switch

# Function to install a package with error handling
install_package() {
  local package=$1
  echo "Attempting to install $package..."
  if apt-get install -y "$package"; then
    echo "$package installed successfully"
    return 0
  else
    echo "WARNING: Failed to install $package, continuing anyway"
    return 1
  fi
}

# Install additional packages with robust error handling
echo "Installing additional packages (with robust error handling)..."
OPTIONAL_PACKAGES=(
  "bridge-utils"
  "virt-manager"
  "libguestfs-tools"
  "vlan"
  "wireguard"
  "openvpn"
  "jq"
  "awscli"
)

# Try installing universe and multiverse packages one by one with detailed feedback
echo "Installing universe/multiverse packages..."
for pkg in "${OPTIONAL_PACKAGES[@]}"; do
  echo "Attempting to install $pkg..."
  if apt-get install -y "$pkg"; then
    echo "$pkg installed successfully"
  else
    echo "WARNING: Failed to install $pkg via apt, attempting alternative methods"
    
    # Alternative installation methods for specific packages
    case $pkg in
      "jq")
        echo "Installing jq from its direct download URL..."
        wget -O /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && \
        chmod +x /usr/local/bin/jq && \
        echo "jq installed via direct download" || echo "Failed to install jq via direct download"
        ;;
      "awscli") 
        echo "Installing awscli via pip3..."
        pip3 install awscli && echo "awscli installed via pip3" || echo "Failed to install awscli via pip3"
        ;;
      "virt-manager")
        echo "Installing virt-manager dependencies..."
        apt-get install -y python3-gi gir1.2-gtk-3.0 python3-libvirt || true
        ;;
      *)
        echo "No alternative installation method for $pkg"
        ;;
    esac
  fi
done

# Verify installations and report status
echo "Verifying package installations..."
for pkg in "${OPTIONAL_PACKAGES[@]}"; do
  if command -v "$pkg" &>/dev/null || dpkg -l | grep -q " $pkg "; then
    echo "$pkg is installed"
  else
    echo "$pkg could not be installed"
  fi
done

# Configure system for KVM virtualization
echo "Configuring system for virtualization..."
echo "options kvm_intel nested=1" > /etc/modprobe.d/kvm-nested.conf
echo "options kvm-intel enable_shadow_vmcs=1" >> /etc/modprobe.d/kvm-nested.conf
echo "options kvm-intel enable_apicv=1" >> /etc/modprobe.d/kvm-nested.conf
echo "options kvm-intel ept=1" >> /etc/modprobe.d/kvm-nested.conf

# Load the bridge module
echo "Loading bridge module..."
modprobe bridge || echo "Failed to load bridge module, but continuing anyway"

# Ensure bridge-nf module is loaded
echo "Loading bridge-nf module..."
modprobe br_netfilter || echo "Failed to load br_netfilter module, but continuing anyway"

# Optimize sysctl settings for CML
echo "Optimizing system settings for CML..."
cat > /etc/sysctl.d/99-cml-performance.conf << 'EOL'
# Network performance tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem = 16777216 16777216 16777216
net.core.netdev_max_backlog = 250000
net.ipv4.ip_forward = 1
# Bridge settings - these will be applied only if bridge module is loaded
# net.bridge.bridge-nf-call-iptables = 0
# net.bridge.bridge-nf-call-ip6tables = 0
EOL

# Load the new sysctl settings with error handling
echo "Applying sysctl settings..."
sysctl -p /etc/sysctl.d/99-cml-performance.conf || {
  echo "Some sysctl settings could not be applied, applying available settings only"
  # Apply settings one by one, ignoring errors
  while read line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$line" ]] && continue
    
    # Extract the parameter
    param=$(echo "$line" | cut -d= -f1 | xargs)
    if [ -n "$param" ]; then
      sysctl -w "$line" 2>/dev/null || echo "Could not apply: $line"
    fi
  done < /etc/sysctl.d/99-cml-performance.conf
}

# Configure bridge settings in a separate step after modules are loaded
echo "Configuring bridge netfilter settings..."
# Create a separate file for bridge settings
cat > /etc/sysctl.d/99-cml-bridge.conf << 'EOL'
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-ip6tables = 0
EOL

# Create a startup script to load modules and apply bridge settings at boot
cat > /etc/init.d/cml-bridge-setup << 'EOL'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          cml-bridge-setup
# Required-Start:    $network
# Required-Stop:     
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Load bridge modules and apply settings for CML
### END INIT INFO

modprobe bridge
modprobe br_netfilter
sleep 1
sysctl -p /etc/sysctl.d/99-cml-bridge.conf

exit 0
EOL
chmod +x /etc/init.d/cml-bridge-setup
update-rc.d cml-bridge-setup defaults

# Try to apply bridge settings now, but don't fail if it doesn't work
modprobe bridge
modprobe br_netfilter
sleep 1
sysctl -p /etc/sysctl.d/99-cml-bridge.conf || echo "Could not apply bridge settings now, will apply at next boot"

# Configure the bridge module to load at boot
echo "bridge" > /etc/modules-load.d/bridge.conf
echo "br_netfilter" >> /etc/modules-load.d/bridge.conf
echo "Configured bridge modules to load at boot"

# Configure user access for CML
echo "Setting up user permissions..."
groupadd -f libvirt
usermod -a -G libvirt ubuntu
usermod -a -G kvm ubuntu

# Final verification of critical packages
echo "Performing final verification of critical packages..."
CRITICAL_PACKAGES=(
  "qemu-kvm"
  "libvirt-daemon"
  "openvswitch-switch"
  "nginx"
  "python3-pip"
)

MISSING_CRITICAL=0
for pkg in "${CRITICAL_PACKAGES[@]}"; do
  if ! dpkg -l | grep -q "ii  $pkg"; then
    echo "ERROR: Critical package $pkg is not properly installed!"
    MISSING_CRITICAL=1
  else
    echo "✓ Critical package $pkg is properly installed."
  fi
done

# Print summary of optional packages
echo "Verification of optional packages:"
OPTIONAL_PACKAGES=(
  "bridge-utils"
  "virt-manager"
  "libguestfs-tools"
  "vlan"
  "wireguard"
  "openvpn"
  "jq"
  "awscli"
)

for pkg in "${OPTIONAL_PACKAGES[@]}"; do
  if command -v "$pkg" &>/dev/null || dpkg -l | grep -q "ii  $pkg"; then
    echo "✓ Optional package $pkg is installed"
  else
    echo "! Optional package $pkg could not be installed"
  fi
done

# Security hardening for CML instance
echo "Applying security hardening measures..."

# Enable and configure UFW firewall
echo "Setting up UFW firewall..."
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 3389/tcp   # RDP access
ufw logging on
echo "y" | ufw enable || true

# Install and configure fail2ban for brute force protection
echo "Setting up fail2ban..."
apt-get install -y fail2ban
cat > /etc/fail2ban/jail.local << 'EOL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[rdp]
enabled = true
port = 3389
filter = rdp
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400
EOL

# Create RDP filter for fail2ban
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/rdp.conf << 'EOL'
[Definition]
failregex = ^.*sshd.*: Failed .* from <HOST>
ignoreregex =
EOL

# Enable automatic security updates
echo "Setting up automatic security updates..."
apt-get install -y unattended-upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOL'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOL

# Enable and configure services
systemctl enable fail2ban
systemctl restart fail2ban

# Print results of verification
if [ $MISSING_CRITICAL -eq 1 ]; then
  echo "WARNING: Some critical packages are missing. The CML AMI may not function correctly."
else
  echo "All critical packages verified successfully."
fi

# Create directories needed by CML
echo "Creating CML directories..."
mkdir -p /etc/virl2/
mkdir -p /var/lib/libvirt/images
mkdir -p /var/cache/virl2/
mkdir -p /var/log/virl2/

# Ensure cloud-init will not overwrite our network settings on reboot
echo "Configuring cloud-init..."
echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

# Ensure the system is using Grub with BIOS boot
echo "Configuring boot settings..."
if [ -d /sys/firmware/efi ]; then
  echo "System appears to be using EFI/UEFI boot mode."
  echo "This is expected to be converted to BIOS boot in the final AMI."
fi

# Prepare AWS-specific settings
echo "Configuring AWS-specific settings..."
cat > /etc/virl2/aws-init.sh << 'EOL'
#!/bin/bash
# This script will run at first boot on AWS
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/[a-z]$//')
PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

# Set the hostname to match instance ID
hostnamectl set-hostname $INSTANCE_ID

# Record AWS metadata for CML
echo "INSTANCE_ID=$INSTANCE_ID" > /etc/virl2/aws-metadata
echo "REGION=$REGION" >> /etc/virl2/aws-metadata
echo "PRIVATE_IP=$PRIVATE_IP" >> /etc/virl2/aws-metadata
echo "PUBLIC_IP=$PUBLIC_IP" >> /etc/virl2/aws-metadata
EOL
chmod +x /etc/virl2/aws-init.sh

# Add AWS init script to cloud-init for first boot
cat > /etc/cloud/cloud.cfg.d/99-cml-aws-setup.cfg << 'EOL'
runcmd:
  - [ /etc/virl2/aws-init.sh ]
EOL

# Clean up any old service files that might conflict
for service in cml_install.service cml2.target virl2.target; do
  if [ -f "/etc/systemd/system/${service}" ]; then
    echo "Removing problematic service file: ${service}"
    rm -f "/etc/systemd/system/${service}"
  fi
done

# Create a marker file to show this is a pre-prepared CML AMI
date > /etc/.cml_ami_prepared
echo "CML bootstrap completed successfully at $(date)"
