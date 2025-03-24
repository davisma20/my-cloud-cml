#!/bin/bash
# CML Installation Script for Packer AMI Build
# This script installs Cisco Modeling Labs on an Ubuntu system

set -e
set -o pipefail

# Arguments
CML_VERSION="$1"
S3_BUCKET="$2"
S3_KEY="$3"
PACKAGE_URL="$4"

# Setup logging with timestamps
LOG_FILE="/var/log/cml_packer_install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_step() {
  log "================================================================="
  log "STEP: $1"
  log "================================================================="
}

log_step "Starting CML installation process for version $CML_VERSION"
log "S3 Bucket: $S3_BUCKET"
log "S3 Key: $S3_KEY"
log "Package URL: $PACKAGE_URL"

# Define package name
CML_PACKAGE="cml2_${CML_VERSION}_amd64.deb"
DOWNLOAD_PATH="/tmp/${CML_PACKAGE}"

# Function to download the CML package
download_cml_package() {
  log_step "Downloading CML package"
  
  if [ -n "$PACKAGE_URL" ]; then
    log "Downloading from provided URL: $PACKAGE_URL"
    wget -O "$DOWNLOAD_PATH" "$PACKAGE_URL"
  elif [ -n "$S3_BUCKET" ] && [ -n "$S3_KEY" ]; then
    log "Downloading from S3: s3://$S3_BUCKET/$S3_KEY"
    aws s3 cp "s3://$S3_BUCKET/$S3_KEY" "$DOWNLOAD_PATH"
  else
    # Check if the package is already in the /tmp directory (may have been uploaded separately)
    if [ -f "$DOWNLOAD_PATH" ]; then
      log "Using existing package at $DOWNLOAD_PATH"
    else
      log "ERROR: No package source specified and package not found locally"
      return 1
    fi
  fi
  
  # Verify file exists and has content
  if [ -f "$DOWNLOAD_PATH" ] && [ -s "$DOWNLOAD_PATH" ]; then
    log "CML package downloaded successfully"
    return 0
  else
    log "ERROR: Failed to download CML package"
    return 1
  fi
}

# Function to remove problematic service files
remove_problem_services() {
  log_step "Checking for and removing problematic service files"
  
  # List of problematic service files
  SERVICES=("cml_install.service" "cml2.target" "virl2.target")
  
  for service in "${SERVICES[@]}"; do
    if [ -f "/etc/systemd/system/${service}" ]; then
      log "Removing problematic service file: ${service}"
      rm -f "/etc/systemd/system/${service}"
    else
      log "Service file not found: ${service}"
    fi
  done
  
  log "Reloading systemd daemon"
  systemctl daemon-reload
}

# Function to install dependencies
install_dependencies() {
  log_step "Installing CML dependencies"
  
  export DEBIAN_FRONTEND=noninteractive
  
  log "Updating package lists"
  apt-get update
  
  log "Installing required packages"
  apt-get install -y \
    libvirt-daemon \
    libvirt-clients \
    qemu-kvm \
    bridge-utils \
    virt-manager \
    libnss-libvirt \
    nginx \
    python3-pip \
    chromium-browser \
    wireguard \
    openvpn \
    libvirt-dev
    
  log "Dependencies installation completed"
}

# Function to install the CML package
install_cml_package() {
  log_step "Installing CML package"
  
  log "Removing any existing CML package"
  dpkg -r cml2 || log "No existing CML package to remove"
  
  log "Installing CML package: $DOWNLOAD_PATH"
  export DEBIAN_FRONTEND=noninteractive
  dpkg -i "$DOWNLOAD_PATH" || {
    log "Error installing CML package, attempting to fix dependencies"
    apt-get install -f -y
    dpkg -i "$DOWNLOAD_PATH" || {
      log "ERROR: Failed to install CML package even after fixing dependencies"
      return 1
    }
  }
  
  log "CML package installation completed"
  return 0
}

# Function to configure CML
configure_cml() {
  log_step "Configuring CML"
  
  # Ensure logging directory exists
  mkdir -p /var/log/cml
  
  # Set log level to WARNING for better performance
  if [ -f "/etc/default/virl2" ]; then
    log "Setting log level to WARNING"
    sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=WARNING/' /etc/default/virl2
    sed -i 's/^SMART_LOG_LEVEL=.*/SMART_LOG_LEVEL=WARNING/' /etc/default/virl2
  else
    log "Warning: /etc/default/virl2 not found, cannot set log level"
  fi
  
  # Ensure CML services are enabled but not started (will be configured on first boot)
  log "Enabling CML services"
  systemctl enable virl2-controller.service || log "Warning: Failed to enable virl2-controller.service"
  
  log "CML configuration completed"
}

# Function to verify installation
verify_installation() {
  log_step "Verifying CML installation"
  
  log "Checking for installed packages"
  dpkg -l | grep -E 'cml2|iol-tools|patty'
  
  log "Checking CML files"
  ls -la /etc/virl2/ || log "Warning: /etc/virl2/ not found"
  
  log "Verification completed"
}

# Main installation process
main() {
  log "Starting CML installation process"
  
  # Create directories
  mkdir -p /var/log/cml
  mkdir -p /etc/virl2
  
  # Download CML package
  download_cml_package || {
    log "ERROR: Failed to download CML package. Exiting."
    exit 1
  }
  
  # Remove problematic service files
  remove_problem_services
  
  # Install dependencies
  install_dependencies
  
  # Install CML package
  install_cml_package || {
    log "ERROR: Failed to install CML package. Exiting."
    exit 1
  }
  
  # Configure CML
  configure_cml
  
  # Verify installation
  verify_installation
  
  log "CML installation process completed successfully"
}

# Execute main function
main
