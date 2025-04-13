#!/bin/bash
# Custom installation script for CML 2.7.0
# This script handles the installation of CML 2.7.0 packages

set -e
set -o pipefail
set -x # Enable verbose command execution logging

# Setup logging
LOGFILE="/var/log/cml_install.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "Starting CML 2.7.0 installation at $(date)"

# Directory containing the extracted CML .deb files
DEB_DIR="/tmp/cml-debs"

# Log file for installation process
LOG_FILE="/var/log/cml_install.log"

# Check for the downloaded DEB directory
DEB_DIR="/tmp/cml-debs"
if [ ! -d "$DEB_DIR" ]; then
    echo "Error: CML deb directory $DEB_DIR not found!" | tee -a $LOGFILE
    exit 1
fi
cd "$DEB_DIR"

echo "Listing available installation files in $DEB_DIR:" | tee -a $LOGFILE
ls -lha | tee -a $LOGFILE

# Try running setup.sh first if it exists
if [ -f setup.sh ]; then
    echo "Found setup.sh script, executing..." | tee -a $LOGFILE
    sudo chmod +x setup.sh
    # Inject set -x into setup.sh for verbose logging within it
    echo "Injecting set -x into setup.sh..."
    sudo sed -i '1a set -x' setup.sh || echo "Warning: Failed to inject set -x into setup.sh"
    sudo ./setup.sh || true # Force continuation even if setup.sh fails
    echo "setup.sh execution completed (errors ignored)." | tee -a $LOGFILE
# If setup.sh didn't exist or failed, try installing DEB packages directly
elif ls cml2*.deb >/dev/null 2>&1; then
    echo "Found DEB packages in $DEB_DIR, installing directly..." | tee -a $LOGFILE
    # Install supporting packages first
    if ls iol-tools*.deb >/dev/null 2>&1; then
        echo "Installing iol-tools*.deb..." | tee -a $LOGFILE
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./iol-tools*.deb | tee -a $LOGFILE
    fi
    if ls patty*.deb >/dev/null 2>&1; then
        echo "Installing patty*.deb..." | tee -a $LOGFILE
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./patty*.deb | tee -a $LOGFILE
    fi

    # Install the main CML package last
    echo "Installing CML package..." | tee -a $LOGFILE
    if ls cml2*.deb >/dev/null 2>&1; then
        echo "Installing cml2*.deb..." | tee -a $LOGFILE
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./cml2*.deb
    else
        echo "Warning: Main cml2*.deb package not found in $DEB_DIR." | tee -a $LOGFILE
    fi
else
    echo "Error: No setup.sh found and no cml2*.deb package found in $DEB_DIR. Cannot proceed with CML installation." | tee -a $LOGFILE
    exit 1
fi

# Create necessary directories and files
echo "Creating required directories and configuration files..." | tee -a $LOGFILE
sudo mkdir -p /provision
sudo touch /provision/.cml2_install_initiated

# Check if CML services exist
if systemctl list-unit-files | grep -q "cml"; then
    echo "CML services found, installation appears successful" | tee -a $LOGFILE
else
    echo "Warning: CML services not found, installation may have issues" | tee -a $LOGFILE
fi

echo "CML 2.7.0 installation completed at $(date)" | tee -a $LOGFILE
