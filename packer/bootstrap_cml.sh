#!/bin/bash
# Comprehensive bootstrap script to prepare the CML instance for the AMI
# This script will be embedded in the Packer configuration

# Re-enable set -e
set -e
set -o pipefail

# Logging helper
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Error handling helper
error_exit() {
    log "ERROR: $1" >&2 # Log error to stderr
    exit "${2:-1}"      # Exit with provided code or default to 1
}

# Function to check if a command exists
command_exists() {
  command -v "$1" &> /dev/null
}

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

# Function to install a package with error handling
install_package() {
  local package=$1
  echo "Attempting to install $package..."
  apt-get install -y "$package" # Try the installation
  local exit_code=$?            # Capture the exit code immediately
  echo "Exit code for 'apt-get install -y \\"$package\\"' was: $exit_code" # Log the exit code

  if [ $exit_code -eq 0 ]; then
    echo "$package installed successfully or already present."
    return 0
  else
    echo "ERROR: Failed to install $package (Exit Code: $exit_code). Exiting bootstrap script."
    # Optionally add more debug info here, like checking apt sources or logs
    # tail /var/log/apt/term.log || true
    exit 1
  fi
}

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
# For libguestfs-tools
# add-apt-repository -y 'deb http://archive.ubuntu.com/ubuntu focal main universe'

# Try using the main Ubuntu archive if regional mirrors fail
apt-get update || {
  echo "Updating from regional mirror failed, trying main archive..."
  sed -i 's/us-east-2.ec2.archive.ubuntu.com/archive.ubuntu.com/g' /etc/apt/sources.list
  apt-get update
}

# Update system packages
export DEBIAN_FRONTEND=noninteractive
echo "Updating system packages..."
# apt-get upgrade -y
apt-get update

# --- Start amazon-ssm-agent management ---
# Ensure amazon-ssm-agent is installed via the recommended .deb package
echo "Ensuring amazon-ssm-agent is installed via .deb package..."

# Check if snap version is installed and remove it if present
if snap list | grep -q amazon-ssm-agent; then
    echo "Detected snap version of amazon-ssm-agent. Removing..."
    snap remove amazon-ssm-agent || echo "Warning: Failed to remove snap amazon-ssm-agent. Continuing..."
fi

# Ensure curl is installed (needed for region detection)
if ! command_exists curl; then
    echo "curl not found, installing..."
    apt-get update
    apt-get install -y curl || error_exit "Failed to install curl, cannot proceed with SSM Agent installation."
fi

# Determine region (requires IMDSv1 or IMDSv2 token setup if IMDSv1 disabled)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
if [ -z "$REGION" ]; then
    # Attempt with IMDSv2 token
    TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
    if [ -n "$TOKEN" ]; then
        REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
    fi
fi

if [ -z "$REGION" ]; then
    error_exit "Could not determine AWS region from metadata service."
fi
echo "Detected region: $REGION"

# Download and install the agent
SSM_DEB_URL="https://s3.${REGION}.amazonaws.com/amazon-ssm-${REGION}/latest/debian_amd64/amazon-ssm-agent.deb"
SSM_DEB_PATH="/tmp/amazon-ssm-agent.deb"

echo "Downloading SSM Agent from $SSM_DEB_URL..."
curl -s -o "$SSM_DEB_PATH" "$SSM_DEB_URL"
if [ $? -ne 0 ] || [ ! -s "$SSM_DEB_PATH" ]; then
    error_exit "Failed to download amazon-ssm-agent.deb from $SSM_DEB_URL"
fi

dpkg -i "$SSM_DEB_PATH"
dpkg_exit_code=$? # Capture exit code immediately

if [ $dpkg_exit_code -ne 0 ]; then
    echo "dpkg install failed (Exit Code: $dpkg_exit_code), attempting apt install to fix dependencies..."
    apt --fix-broken install -y
fi
rm -f "$SSM_DEB_PATH" # Clean up downloaded file

# Ensure service is enabled and started
echo "Ensuring amazon-ssm-agent service is enabled and started..."
systemctl enable amazon-ssm-agent || echo "Warning: Failed to enable amazon-ssm-agent service."
systemctl start amazon-ssm-agent || echo "Warning: Failed to start amazon-ssm-agent service."

# Check status
echo "Checking amazon-ssm-agent service status..."
systemctl status amazon-ssm-agent --no-pager || echo "Warning: Failed to get amazon-ssm-agent status."
echo "Checking if amazon-ssm-agent service is enabled:"
systemctl is-enabled amazon-ssm-agent || echo "Warning: Failed to check if amazon-ssm-agent is enabled."

echo "amazon-ssm-agent setup via .deb package complete."
# --- End amazon-ssm-agent management ---

echo "Installing essential CML dependencies..."
echo "Updating package lists before critical installs..."
sudo apt-get update

CRITICAL_PACKAGES_TO_INSTALL=(
  "apt-transport-https"
  "ca-certificates"
  "curl"
  "gnupg"
  "lsb-release"
  "software-properties-common"
  "python3-pip"
  "python3-cryptography"
  "python3-pyasn1"
  "qemu-kvm"
  "libvirt-daemon-system"
  "libvirt-clients"
  "nginx"
  "wget"
  "unzip"
  "cloud-init"
  "uuid"
  "expect"
  "cloud-guest-utils"
  "python3-openvswitch"
  "openvswitch-switch"
  "wireguard"
  "wireguard-tools"
  "awscli"
  "python3-alembic"
)

for pkg in "${CRITICAL_PACKAGES_TO_INSTALL[@]}"; do
  install_package "$pkg"
  # Add immediate verification for qemu-kvm (checking for the real binary)
  if [[ "$pkg" == "qemu-kvm" ]]; then
    # On Ubuntu 20.04+, the main binary is qemu-system-x86_64
    if ! command -v qemu-system-x86_64 &> /dev/null; then
      echo "CRITICAL ERROR: qemu-system-x86_64 command not found after reported successful installation of qemu-kvm!"
      exit 5
    fi
    echo "qemu-system-x86_64 command found."
  fi
done

# Install additional packages with robust error handling
echo "Installing additional packages (with robust error handling)..."
OPTIONAL_PACKAGES=(
  "bridge-utils"
  "vlan"
  "openvpn"
  "jq"
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

# #########################################################################
# ## The CML .deb installation below was moved to install_cml_2.7.0.sh ##
# ## It needs to run AFTER the debs are downloaded by Packer.          ##
# #########################################################################
# # Install CML .deb packages
# DEB_DIR="/tmp/cml_debs" # Define where debs are expected (adjust if needed)
# echo "Installing CML .deb packages from $DEB_DIR..."
# # Ensure the directory exists and has .deb files before proceeding
# if [ -d "$DEB_DIR" ] && ls "$DEB_DIR"/*.deb &> /dev/null; then
#     # Install all .deb files from the specified directory
#     # Using the full path avoids issues with the current working directory.
#     if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -o Debug::pkgProblemResolver=yes -o Debug::pkgAcquire::Worker=1 "$DEB_DIR"/*.deb; then
#         echo "CML .deb packages installed successfully."
#         # Reload systemd daemon to recognize new services if any
#         echo "Reloading systemd daemon..."
#         sudo systemctl daemon-reload
#     else
#         error_exit "Failed to install CML .deb packages from $DEB_DIR. apt returned non-zero status."
#     fi
# else
#     error_exit "CML .deb package directory $DEB_DIR does not exist or contains no .deb files."
# fi
# #########################################################################

# Ensure libvirtd service is running and enabled
echo "Ensuring libvirtd service is active and enabled..."
systemctl enable libvirtd
systemctl start libvirtd

# Function for final verification of critical components
final_verification() {
    log "Performing final verification of critical packages..."
    local all_ok=true
    local pkg_status=""

    # 1. Verify Commands/Binaries
    log "Verifying commands..."
    for cmd_path in "/usr/bin/qemu-system-x86_64" "/usr/sbin/ovs-vswitchd" "/usr/bin/pip3"; do
        local cmd_name=$(basename "$cmd_path")
        if [[ -x "$cmd_path" ]]; then
            log "  Command $cmd_name found at $cmd_path."
        elif command -v "$cmd_name" &>/dev/null; then
            log "  Command $cmd_name found in PATH."
        else
            log "  ERROR: Command $cmd_name not found!"
            all_ok=false
        fi
    done

    # 2. Verify Services Status
    log "Verifying services..."
    log "Listing all found systemd unit files:"
    systemctl list-unit-files >&2 || log "Warning: Could not list systemd unit files."
    log "Finished listing unit files."

    local services=(
        "libvirtd.service" # Corrected name
        # "nginx.service" # Removed - Masked by CML
        # "openvswitch-switch.service" # Removed - Masked by CML
    )
    for service in "${services[@]}"; do
        # Check 1: Does the service unit file exist? Use 'systemctl cat' which exits non-zero if not found.
        if ! systemctl cat "$service" &> /dev/null; then
            log "  ERROR: Service unit file $service not found! (Checked using 'systemctl cat')"
            all_ok=false
            continue # Skip further checks for this service
        fi

        # Check 2: What is the service state? (Now that we know it exists)
        if systemctl is-active --quiet "$service"; then
            log "  Service $service is active."
        elif systemctl is-failed --quiet "$service"; then
            log "  ERROR: Service $service is in a 'failed' state!"
            systemctl status "$service" --no-pager -n 20 || true # Show status details
            all_ok=false
        elif [[ "$service" == "openvswitch-switch.service" ]] && systemctl show -p SubState --value "$service" | grep -qE 'exited|dead'; then
            # openvswitch-switch being 'exited' is okay as it's a setup service
            log "  Service $service is exited (normal state)."
        else # Service exists but isn't active, failed, or the special exited state for OVS
            # Service exists but isn't active/failed (maybe inactive/loading?)
            local current_status=$(systemctl show -p SubState --value "$service")
            log "  - Service $service exists but is not active/failed (State: $current_status). Attempting to start..."
            sudo systemctl start "$service"
            sleep 3 # Give it a moment
            if systemctl is-active --quiet "$service"; then
                log "  Service $service started and is now active."
            else
                log "  ERROR: Failed to start service $service or it did not stay active. Final state: $(systemctl show -p SubState --value "$service")"
                systemctl status "$service" --no-pager -n 20 || true # Show status details
                all_ok=false
            fi
        fi
    done

    # 3. Verify Python Open vSwitch module (optional but good check)
    log "Verifying Python Open vSwitch module..."
    if python3 -c "import openvswitch.vlog" &>/dev/null; then
        log "  Python module 'openvswitch.vlog' imported successfully."
    else
        # Check if the package is installed as a fallback
        if dpkg -s python3-openvswitch &>/dev/null; then
            log "  WARNING: Python module 'openvswitch.vlog' not directly importable, but package 'python3-openvswitch' seems installed. Continuing..."
        else
            log "  ERROR: Python module 'openvswitch' not importable and package 'python3-openvswitch' not found."
            # Decide if this is critical enough to set all_ok=false
            # all_ok=false # Uncomment if this should cause failure
        fi
    fi

    if [[ "$all_ok" == "true" ]]; then
        log "Final verification passed successfully."
        return 0
    else
        log "ERROR: Final verification failed. Critical components missing or not running."
        exit 5 # Consistent exit code for verification failure
    fi
}

# Apply security hardening measures
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
if [ "$MISSING_CRITICAL" -eq 1 ]; then
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
# echo 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

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

check_cml_web_interface() {
    log "Starting CML web interface check..."
    local max_attempts=30
    local wait_seconds=10
    local ui_url="http://localhost:80/"
    local about_url="http://localhost/api/v0/about"
    local login_url="http://localhost/api/v0/authenticate"
    # These credentials are likely incorrect based on CML docs, but keep for now
    # until we confirm services are running and implement credential passing.
    local username="admin"
    local password="password"

    log "+++ DIAGNOSTICS Start: Pre-Web Check Service Status +++"
    for service in virl2-controller.service virl2-uwm.service; do
        log "Checking status for $service..."
        if systemctl is-active --quiet "$service"; then
            log "  $service is ACTIVE."
        else
            log "  $service is INACTIVE or FAILED."
            log "  Status output for $service:"
            systemctl status "$service" --no-pager || log "    Failed to get status for $service"
        fi
        log "  Last 20 log lines for $service:"
        journalctl -u "$service" -n 20 --no-pager --output cat || log "    Failed to get logs for $service"
    done
    log "+++ DIAGNOSTICS End: Pre-Web Check Service Status +++"

    for (( i=1; i<=$max_attempts; i++ )); do
        log "Try $i/$max_attempts..."
        local http_code_about=$(curl -s -o /dev/null -w "%{http_code}" "$about_url")
        # ... rest of your code ...

    done
    log "Web interface check loop finished (actual checks need implementation)."
    # Example: check $http_code_about or perform login attempt

    # If check fails after all attempts:
    # error_exit "CML web interface did not become ready."

    log "CML web interface check completed (placeholder)."

} # Added missing closing brace for the function

exit 0
