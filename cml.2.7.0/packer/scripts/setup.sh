#!/bin/bash
# CML AMI Setup Script
# This script prepares the system for CML installation

set -e
set -o pipefail

# Setup logging
LOG_FILE="/var/log/cml_packer_setup.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "======================================================================="
echo "Starting CML AMI setup at $(date)"
echo "======================================================================="

# Update system and install dependencies
echo "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

echo "Installing required packages..."
apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  software-properties-common \
  jq \
  awscli \
  python3-pip \
  wget \
  unzip \
  apache2-utils \
  libvirt-daemon \
  libvirt-clients

# Install AWS CLI v2 if needed
if ! aws --version | grep -q "aws-cli/2"; then
  echo "Installing AWS CLI version 2..."
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  ./aws/install
  rm -rf aws awscliv2.zip
fi

# Configure system settings for CML
echo "Configuring system settings for CML..."

# Increase file descriptors
cat > /etc/security/limits.d/99-cml-limits.conf << EOF
*               soft    nofile          65535
*               hard    nofile          65535
root            soft    nofile          65535
root            hard    nofile          65535
EOF

# Check for problematic service files and remove them
for service in cml_install.service cml2.target virl2.target; do
  if [ -f "/etc/systemd/system/${service}" ]; then
    echo "Removing problematic service file: ${service}"
    rm -f "/etc/systemd/system/${service}"
  fi
done

# Reload systemd to recognize changes
systemctl daemon-reload

# Create required directories
echo "Creating required directories..."
mkdir -p /var/log/cml
mkdir -p /etc/cml
mkdir -p /var/lib/cml

# Setup pre-req for AWS SSM agent (already installed in the AMI)
echo "Ensuring AWS SSM agent is functioning properly..."
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent

# Set hostname
echo "Setting hostname to cml-controller..."
hostnamectl set-hostname cml-controller

echo "System preparation completed successfully at $(date)"
