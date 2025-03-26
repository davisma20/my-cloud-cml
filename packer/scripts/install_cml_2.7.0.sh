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
mkdir -p "$CML_DIR"
sudo chown -R $(whoami) "$CML_DIR"
cd "$CML_DIR"

# Check what files we have
echo "Listing available installation files:"
ls -la

# Fix broken packages first
echo "Fixing any broken package dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

# Install dependencies if needed
echo "Installing any prerequisite packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-coredump libc6-dev libnss-libvirt

# Create required directories with proper permissions
echo "Creating required directories..."
sudo mkdir -p /var/lib/virl2
sudo chown -R $(whoami) /var/lib/virl2

# Look for and install the CML package
if [ -f cml-2.7.0.pkg ]; then
    echo "Found cml-2.7.0.pkg, making it executable and installing..."
    sudo chmod +x cml-2.7.0.pkg
    sudo ./cml-2.7.0.pkg || {
        echo "Warning: cml-2.7.0.pkg installation failed. Will try alternative methods."
    }
fi

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
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./$pkg || {
                echo "Warning: Failed to install CML package directly, trying with --fix-broken..."
                sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-broken ./$pkg
            }
        fi
    done
fi

# Check Cisco-style installation directory
echo "Checking for Cisco-style installation directory..."
if [ -d /opt/cisco/anyconnect/bin ]; then
    echo "Found Cisco-style installation directory, checking for CML..."
    if [ -f /opt/cisco/anyconnect/bin/cml-setup ]; then
        echo "Found cml-setup script, executing..."
        sudo chmod +x /opt/cisco/anyconnect/bin/cml-setup
        sudo /opt/cisco/anyconnect/bin/cml-setup
    fi
fi

# Fix any broken dependencies after installation
echo "Fixing any broken dependencies after installation..."
sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

# Verify installation
echo "Verifying CML installation..."
if command -v virl2_controller &> /dev/null; then
    echo "✓ CML controller command found"
else
    echo "✗ CML controller command not found, installation may have failed"
fi

echo "CML 2.7.0 installation completed at $(date)"
