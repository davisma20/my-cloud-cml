#!/bin/bash
# Script to build CML 2.7.0 AMI using Packer

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR"

echo "Building CML 2.7.0 AMI using Packer..."

# Ensure that AWS CLI is configured correctly
echo "Checking AWS CLI configuration..."
region=$(aws configure get region)
if [ -z "$region" ]; then
  echo "AWS region not configured. Please run 'aws configure' first."
  exit 1
fi

# Make installation script executable
chmod +x install_cml_2.7.0.sh
chmod +x bootstrap_cml.sh

# Clean Packer cache more thoroughly
echo "Cleaning Packer cache..."
rm -rf ~/.packer.d/tmp/* 2>/dev/null || true
rm -rf ~/.packer.d/plugins/* 2>/dev/null || true
rm -rf ~/.cache/packer/* 2>/dev/null || true

# Set environment variable to help with Ubuntu GPG issues
export DEBIAN_FRONTEND=noninteractive

# Add more debugging options
export PACKER_LOG=1
export PACKER_LOG_PATH="packer_build.log"

# Run Packer build with appropriate variables
echo "Starting Packer build..."
packer build \
  -var "region=$region" \
  -var "instance_type=c5.2xlarge" \
  -var "volume_size=50" \
  -var "cml_bucket=cml-ova-import" \
  -var "cml_pkg_path=cml2_2.7.0-4_amd64-20.pkg" \
  cml-2.7.0.pkr.hcl

echo "Packer build completed. Check the output above for the AMI ID."
echo "Full build log available at: $PACKER_LOG_PATH"
