#!/bin/bash
# Custom installation script for CML 2.7.0
# This script handles the installation of CML 2.7.0 packages

set -e
set -o pipefail

# Setup logging
LOGFILE="/var/log/cml_install.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "Starting CML 2.7.0 installation at $(date)"

# Working directory
CML_DIR="/root/cml_installation/extracted"
cd $CML_DIR

# Check what files we have
echo "Listing available installation files:"
ls -la

# Install dependencies if needed
echo "Installing any prerequisite packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-coredump

# Look for and run setup.sh if it exists
if [ -f setup.sh ]; then
    echo "Found setup.sh script, executing..."
    sudo chmod +x setup.sh
    sudo ./setup.sh || {
        echo "Warning: setup.sh exited with non-zero status. Will attempt direct package installation."
    }
# Otherwise try to install DEB packages directly
elif ls cml2*.deb >/dev/null 2>&1; then
    echo "Found DEB packages, installing directly..."
    
    # Install IOL tools and patty first if they exist
    for pkg in iol-tools*.deb patty*.deb; do
        if [ -f "$pkg" ]; then
            echo "Installing $pkg..."
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./$pkg || echo "Warning: Failed to install $pkg, continuing..."
        fi
    done
    
    # Install CML package
    echo "Installing CML package..."
    for pkg in cml2*.deb; do
        if [ -f "$pkg" ]; then
            echo "Installing $pkg..."
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./$pkg || echo "Warning: Failed to install CML package, installation may be incomplete"
        fi
    done
else
    echo "ERROR: No recognizable installation method found!"
    exit 1
fi

# Create necessary directories and files
echo "Creating required directories and configuration files..."
sudo mkdir -p /provision
sudo touch /provision/.cml2_install_initiated

# Check if CML services exist
if systemctl list-unit-files | grep -q "cml"; then
    echo "CML services found, installation appears successful"
else
    echo "Warning: CML services not found, installation may have issues"
fi

echo "CML 2.7.0 installation completed at $(date)"
