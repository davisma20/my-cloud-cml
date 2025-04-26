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
#if [ -f setup.sh ]; then
#    echo "Found setup.sh script, executing..." | tee -a $LOGFILE
#    sudo chmod +x setup.sh
#    # Inject set -x into setup.sh for verbose logging within it
#    echo "Injecting set -x into setup.sh..."
#    sudo sed -i '1a set -x' setup.sh || echo "Warning: Failed to inject set -x into setup.sh"
#    sudo ./setup.sh || true # Force continuation even if setup.sh fails
#    echo "setup.sh execution completed (errors ignored)." | tee -a $LOG_FILE
# Check if the main CML deb file exists
if ls cml2*.deb >/dev/null 2>&1; then
    echo "Found DEB packages in $DEB_DIR, installing directly..." | tee -a $LOGFILE
    echo "Updating package lists..." | tee -a $LOGFILE
    sudo apt-get update -y || echo "Warning: apt-get update failed" | tee -a $LOGFILE

    echo "Upgrading existing packages (can take a while)..." | tee -a $LOGFILE
    # sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || echo "Warning: apt-get upgrade failed" | tee -a $LOGFILE
    echo "Skipping full apt-get upgrade to save time and avoid potential conflicts." | tee -a $LOGFILE

    echo "Installing known CML dependencies first..." | tee -a $LOGFILE
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3 tshark tuned python3-libvirt libvirt-daemon-system
    echo "Attempting to fix broken dependencies after initial deps install..." | tee -a $LOGFILE
    sudo apt-get install -f -y

    # Install supporting packages first
    if ls iol-tools*.deb >/dev/null 2>&1; then
        echo "Installing iol-tools*.deb..." | tee -a $LOGFILE
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./iol-tools*.deb | tee -a $LOGFILE
        echo "Attempting to fix broken dependencies after iol-tools install..." | tee -a $LOGFILE
        sudo apt-get install -f -y
    fi
    if ls patty*.deb >/dev/null 2>&1; then
        echo "Installing patty*.deb..." | tee -a $LOGFILE
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./patty*.deb | tee -a $LOGFILE
        echo "Attempting to fix broken dependencies after patty install..." | tee -a $LOGFILE
        sudo apt-get install -f -y
    fi

    # Install the main CML package last
    echo "Installing CML package..." | tee -a $LOGFILE
    if ls cml2*.deb >/dev/null 2>&1; then
        echo "Installing cml2*.deb..." | tee -a $LOGFILE
        # Capture detailed output of this specific install command
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ./cml2*.deb 2>&1 | tee -a /var/log/cml_deb_install_detail.log
    else
        echo "Warning: Main cml2*.deb package not found in $DEB_DIR." | tee -a $LOGFILE
    fi
else
    echo "Error: Main cml2*.deb package not found in $DEB_DIR. Cannot proceed with CML installation." | tee -a $LOGFILE
    exit 1
fi

# Create necessary directories and files
echo "Creating required directories and configuration files..." | tee -a $LOGFILE
sudo mkdir -p /provision
sudo touch /provision/.cml2_install_initiated

# Ensure systemd is aware of new services
echo "Reloading systemd daemon..." | tee -a $LOGFILE
sudo systemctl daemon-reload

# Attempt to enable CML services (DO NOT START THEM DURING BUILD)
echo "Attempting to enable CML services (virl2-controller, virl2-uwm)..." | tee -a $LOGFILE
sudo systemctl enable virl2-controller virl2-uwm || echo "Warning: Failed to enable virl2-controller or virl2-uwm. They might not exist." | tee -a $LOGFILE

# --- DETAILED STATUS CHECKS --- 
echo "--- Performing Detailed Service Status Checks ---" | tee -a $LOGFILE

# Check virl2-controller status
echo "Checking virl2-controller status:" | tee -a $LOGFILE
sudo systemctl status virl2-controller --no-pager | tee -a $LOGFILE || echo "Warning: Failed to get virl2-controller status." | tee -a $LOGFILE
echo "Checking if virl2-controller is enabled:" | tee -a $LOGFILE
sudo systemctl is-enabled virl2-controller | tee -a $LOGFILE || echo "Warning: Failed to check if virl2-controller is enabled." | tee -a $LOGFILE

# Check virl2-uwm status
echo "Checking virl2-uwm status:" | tee -a $LOGFILE
sudo systemctl status virl2-uwm --no-pager | tee -a $LOGFILE || echo "Warning: Failed to get virl2-uwm status." | tee -a $LOGFILE
echo "Checking if virl2-uwm is enabled:" | tee -a $LOGFILE
sudo systemctl is-enabled virl2-uwm | tee -a $LOGFILE || echo "Warning: Failed to check if virl2-uwm is enabled." | tee -a $LOGFILE

# Check SSM Agent status (.deb version)
echo "Checking DEB SSM Agent status:" | tee -a $LOGFILE
sudo systemctl status amazon-ssm-agent --no-pager | tee -a $LOGFILE || echo "Warning: Failed to get DEB SSM Agent status." | tee -a $LOGFILE
echo "Checking if DEB SSM Agent is enabled:" | tee -a $LOGFILE
sudo systemctl is-enabled amazon-ssm-agent | tee -a $LOGFILE || echo "Warning: Failed to check if DEB SSM Agent is enabled." | tee -a $LOGFILE

echo "--- End of Detailed Service Status Checks ---" | tee -a $LOGFILE

# DO NOT Restart CML services during the build process
# echo "Restarting CML services (virl2-controller, virl2-uwm)..." | tee -a $LOGFILE
# sudo systemctl restart virl2-controller || echo "Warning: Failed to restart virl2-controller. Check status manually." | tee -a $LOGFILE
# sudo systemctl restart virl2-uwm || echo "Warning: Failed to restart virl2-uwm. Check status manually." | tee -a $LOGFILE
# echo "Waiting a few seconds after CML service restart attempt..." | tee -a $LOGFILE
# sleep 15

# Check if CML services exist
if systemctl list-unit-files | grep -q "cml"; then
    echo "CML services found, installation appears successful" | tee -a $LOGFILE
else
    echo "Warning: CML services not found, installation may have issues" | tee -a $LOGFILE
fi

echo "CML 2.7.0 installation completed at $(date)" | tee -a $LOGFILE
