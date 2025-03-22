#!/bin/bash
#
# Fix script for CML installation issues
# To be run as part of cloud-init

# Ensure installation completes properly even if service fails
function ensure_cml_install() {
    echo "Starting CML installation fix script at $(date)"
    
    # Create improved service file that doesn't have escape sequence issues
    if [ -f /etc/systemd/system/cml_install.service ]; then
        echo "Replacing problematic systemd service file with improved version..."
        # Copy our improved service file to the system location
        cp /provision/cml_install.service /etc/systemd/system/cml_install.service
        
        # Reload systemd to apply changes
        systemctl daemon-reload
        
        # Try installation via improved service
        echo "Attempting CML installation via improved systemd service..."
        systemctl start cml_install.service
        
        # Wait for service to complete (it's a oneshot service)
        echo "Waiting for installation service to complete..."
        timeout 30m systemctl start cml_install.service
        
        # Check installation status
        systemctl status cml_install.service || true
    else
        echo "CML installation service file not found, creating it..."
        # Copy our improved service file to the system location
        cp /provision/cml_install.service /etc/systemd/system/cml_install.service
        
        # Reload systemd and start the service
        systemctl daemon-reload
        systemctl start cml_install.service
        
        # Wait for service to complete (it's a oneshot service)
        echo "Waiting for installation service to complete..."
        timeout 30m systemctl start cml_install.service
    fi
    
    # Check if package is installed, if not install manually
    if ! dpkg -l | grep -q cml2; then
        echo "CML package not installed via service, installing manually..."
        
        # Check if package file exists
        if ls /root/cml2*.deb 1> /dev/null 2>&1; then
            echo "Found CML package file, installing..."
            apt-get update
            apt-get -y install /root/cml2*.deb
        else
            echo "ERROR: CML package file not found in /root/"
            return 1
        fi
    fi
    
    # Check again and report status
    if dpkg -l | grep -q cml2; then
        echo "CML package successfully installed!"
        
        # Set log level to WARNING directly (avoiding problematic sed command)
        if [ -f /etc/default/virl2 ]; then
            echo "Setting log levels to WARNING..."
            grep -q "^LOG_LEVEL=" /etc/default/virl2 && \
            sed -i 's/^LOG_LEVEL=.*/LOG_LEVEL=WARNING/' /etc/default/virl2
            
            grep -q "^SMART_LOG_LEVEL=" /etc/default/virl2 && \
            sed -i 's/^SMART_LOG_LEVEL=.*/SMART_LOG_LEVEL=WARNING/' /etc/default/virl2
        fi
        
        # Ensure the first-time configuration flag is set
        if [ ! -f /etc/.virl2_unconfigured ]; then
            echo "Creating unconfigured flag to ensure first-time setup runs..."
            touch /etc/.virl2_unconfigured
        fi
        
        # Ensure all CML services are running
        echo "Starting CML services..."
        systemctl start virl2-controller.service || true
        
        # Create flag file to indicate success
        touch /etc/.virl2_installed
        echo "CML installation fix completed successfully at $(date)"
        return 0
    else
        echo "CML installation failed at $(date)!"
        return 1
    fi
}

# Run the function
ensure_cml_install
