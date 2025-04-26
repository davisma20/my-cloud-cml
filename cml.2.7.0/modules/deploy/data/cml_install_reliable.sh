#!/bin/bash

# cml_install_reliable.sh
# Purpose: A more reliable CML2 installation script
# This script handles the installation of CML2 with safeguards
# to prevent common issues with cloud-init service configurations.

set -e
LOGFILE="/var/log/cml_reliable_install.log"

echo "CML2 Installation - Starting reliable installation at $(date)" | tee $LOGFILE

# CRITICAL FIX: Remove problematic service file if it exists 
# This prevents systemd errors due to invalid escape sequences
echo "Checking for problematic service files..." | tee -a $LOGFILE
if [ -f /etc/systemd/system/cml_install.service ]; then
    echo "Found problematic service file, removing it..." | tee -a $LOGFILE
    systemctl stop cml_install.service 2>/dev/null || true
    systemctl disable cml_install.service 2>/dev/null || true
    rm -f /etc/systemd/system/cml_install.service
    systemctl daemon-reload
    echo "Problematic service file removed" | tee -a $LOGFILE
else
    echo "No problematic service files found" | tee -a $LOGFILE
fi

# Find the CML2 package
echo "Checking for CML package..." | tee -a $LOGFILE
CML_PKG=$(find /root -name "cml2*.deb" | head -1)

if [ -n "$CML_PKG" ]; then
    echo "Found CML package: $CML_PKG" | tee -a $LOGFILE
    
    # Set up wireshark non-interactively
    echo "Setting up wireshark..." | tee -a $LOGFILE
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
    
    # Install the CML package
    echo "Installing CML package..." | tee -a $LOGFILE
    apt-get update -y || echo "Warning: apt-get update failed, proceeding anyway" | tee -a $LOGFILE
    DEBIAN_FRONTEND=noninteractive apt-get -y install $CML_PKG 2>&1 | tee -a $LOGFILE
    
    # Verify if CML was installed successfully
    if dpkg -l | grep -q cml2; then
        echo "CML2 is successfully installed!" | tee -a $LOGFILE
        
        # Set log levels
        if [ -f /etc/default/virl2 ]; then
            echo "Setting log levels..." | tee -a $LOGFILE
            sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=WARNING/' /etc/default/virl2
            sed -i 's/^SMART_LOG_LEVEL=.*/SMART_LOG_LEVEL=WARNING/' /etc/default/virl2
        fi
        
        # Create the unconfigured flag file
        echo "Creating unconfigured flag file..." | tee -a $LOGFILE
        touch /etc/.virl2_unconfigured
        
        # Start and enable CML services
        echo "Starting and enabling CML services..." | tee -a $LOGFILE
        systemctl start virl2-controller.service
        systemctl enable virl2-controller.service
        
        # Verify that nginx is running (for web UI)
        echo "Verifying web UI service..." | tee -a $LOGFILE
        if systemctl is-active --quiet nginx; then
            echo "Nginx is running successfully" | tee -a $LOGFILE
        else
            echo "Warning: Nginx is not running, attempting to start it..." | tee -a $LOGFILE
            systemctl start nginx || echo "Failed to start Nginx" | tee -a $LOGFILE
        fi
        
        # Install additional packages if they're not already installed
        echo "Checking for additional required packages..." | tee -a $LOGFILE
        if ! dpkg -l | grep -q iol-tools; then
            echo "Installing iol-tools package..." | tee -a $LOGFILE
            DEBIAN_FRONTEND=noninteractive apt-get -y install iol-tools || echo "Warning: Failed to install iol-tools" | tee -a $LOGFILE
        fi
        
        if ! dpkg -l | grep -q patty; then
            echo "Installing patty package..." | tee -a $LOGFILE
            DEBIAN_FRONTEND=noninteractive apt-get -y install patty || echo "Warning: Failed to install patty" | tee -a $LOGFILE
        fi
        
        echo "CML installation completed successfully at $(date)" | tee -a $LOGFILE
        exit 0
    else
        echo "ERROR: CML package installation failed!" | tee -a $LOGFILE
        exit 1
    fi
else
    echo "ERROR: CML package file not found in /root/" | tee -a $LOGFILE
    exit 1
fi
