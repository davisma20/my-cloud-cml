#!/bin/bash
#
# Fix script for CML installation issues
# To be run as part of cloud-init or manually via SSM if needed

# Create a log file for our activities
LOGFILE="/var/log/cml_fix_install.log"
echo "Starting CML installation fix at $(date)" | tee $LOGFILE

# Ensure any problematic service files are removed
function remove_problematic_services() {
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
}

# Ensure installation completes properly using direct package installation
function ensure_cml_install() {
    echo "Checking if CML2 is already installed..." | tee -a $LOGFILE
    if dpkg -l | grep -q cml2; then
        echo "CML2 is already installed, checking services..." | tee -a $LOGFILE
    else
        echo "CML2 is not installed, proceeding with installation..." | tee -a $LOGFILE
        
        # Check if the package file exists
        if ls /root/cml2*.deb 1> /dev/null 2>&1; then
            echo "Found CML package file, preparing for installation..." | tee -a $LOGFILE
            
            # Set up wireshark non-interactively
            echo "Setting up wireshark..." | tee -a $LOGFILE
            echo 'wireshark-common wireshark-common/install-setuid boolean true' | debconf-set-selections
            DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common
            
            # Install the CML package
            echo "Installing CML package..." | tee -a $LOGFILE
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get -y install /root/cml2*.deb
            
            # Set log levels
            if [ -f /etc/default/virl2 ]; then
                echo "Setting log levels..." | tee -a $LOGFILE
                sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=WARNING/' /etc/default/virl2
                sed -i 's/^SMART_LOG_LEVEL=.*/SMART_LOG_LEVEL=WARNING/' /etc/default/virl2
            fi
            
            # Create the unconfigured flag file
            echo "Creating unconfigured flag file..." | tee -a $LOGFILE
            touch /etc/.virl2_unconfigured
            
            echo "CML installation completed at $(date)" | tee -a $LOGFILE
        else
            echo "ERROR: CML package file not found in /root/" | tee -a $LOGFILE
            exit 1
        fi
    fi
}

# Start CML services and verify installation
function start_cml_services() {
    echo "Starting CML services..." | tee -a $LOGFILE
    systemctl start virl2-controller.service || true
    systemctl enable virl2-controller.service || true
    
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
    
    # Verify installation status
    echo "Verifying installation..." | tee -a $LOGFILE
    if dpkg -l | grep -q cml2; then
        echo "CML2 is successfully installed!" | tee -a $LOGFILE
        
        # Create success flag
        touch /etc/.virl2_installed
        echo "CML installation fix completed successfully at $(date)" | tee -a $LOGFILE
        return 0
    else
        echo "CML installation failed!" | tee -a $LOGFILE
        return 1
    fi
}

# Main execution path
remove_problematic_services
ensure_cml_install
start_cml_services

# Create a success flag to signal completion
touch /run/reboot
