#!/bin/bash
set -e

echo "Installing CML prerequisites..."

# Update repositories
apt-get update

# Install essential packages
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  qemu-kvm \
  libvirt-daemon-system \
  libvirt-clients \
  bridge-utils \
  cpu-checker \
  cloud-init \
  cloud-guest-utils \
  jq \
  python3-pip \
  amazon-ssm-agent

# Verify virtualization support
if ! kvm-ok; then
  echo "WARNING: KVM virtualization may not be supported on this machine!"
fi

# Configure libvirt
systemctl enable libvirtd
systemctl start libvirtd

# Configure SSM agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Verify network configuration
echo "Testing network connectivity..."
if ping -c 3 8.8.8.8 > /dev/null; then
  echo "Network connectivity test passed"
else
  echo "Network connectivity test failed!"
  exit 1
fi

echo "CML prerequisites installation completed successfully"
