#!/bin/bash
# Custom installation script for CML 2.7.0
# This script handles the installation of CML 2.7.0 packages

set -e
set -o pipefail

# Setup logging
LOGFILE="/var/log/cml_install.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "Starting CML 2.7.0 installation at $(date)"

# Source helper functions from the bootstrap script uploaded by Packer
# This provides log, error_exit, final_verification etc.
if [ -f /tmp/bootstrap_cml.sh ]; then
    echo "Sourcing helper functions from /tmp/bootstrap_cml.sh..."
    source /tmp/bootstrap_cml.sh
else
    echo "CRITICAL ERROR: /tmp/bootstrap_cml.sh not found. Cannot source helper functions." >&2
    exit 1
fi

# Working directory
DEB_DIR=/tmp/cml-debs
CML_DIR="/root/cml_installation/extracted"
mkdir -p "$CML_DIR"
sudo chown -R $(whoami) "$CML_DIR"
cd "$CML_DIR"

echo "Listing available installation files in ${DEB_DIR}:"
ls -lha "${DEB_DIR}" || true

# Remove initial fix attempt - dependencies handled below
# echo "Fixing any broken package dependencies..."
# sudo DEBIAN_FRONTEND=noninteractive apt-get update
# sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

# Pre-seed debconf answer for wireshark-common to avoid interactive prompt
echo wireshark-common wireshark-common/install-setuid boolean false | sudo debconf-set-selections

# Update package lists before installing prerequisites
echo "Updating package lists..."
sudo apt-get update || echo "apt-get update failed, continuing..."

# Install minimal base dependencies ONLY
# Let 'apt install ./*.deb' handle core component dependencies like libvirt
echo "Installing minimal prerequisite packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated \
    systemd-coredump libc6-dev libnss-libvirt
#   libvirt-daemon-system libvirt-clients qemu-kvm virtinst bridge-utils cpu-checker

# Install DEB packages directly from the main DEB_DIR using apt
echo "Installing all CML DEB packages from ${DEB_DIR} using dpkg -i and apt --fix-broken..."
if ls "${DEB_DIR}"/*.deb 1> /dev/null 2>&1; then
    # --- BEGIN Libvirt CA Path Fix ---
    LIBVIRT_CONF="/etc/libvirt/libvirtd.conf"
    if [ -f "$LIBVIRT_CONF" ]; then
        log "Attempting to fix libvirt CA path in $LIBVIRT_CONF..."
        # Comment out the line specifying the incorrect CA file path if it exists
        # Pattern matches: optional leading whitespace, 'ca_file', optional whitespace, '=', optional whitespace, '"/etc/pki/CA/cacert.pem"'
        if sudo sed -i.bak 's|^\s*ca_file\s*=\s*"/etc/pki/CA/cacert.pem"|#&|' "$LIBVIRT_CONF"; then
            log "Successfully commented out problematic ca_file line in $LIBVIRT_CONF (if it existed). Backup created at ${LIBVIRT_CONF}.bak"
        else
            log "Warning: Failed to modify $LIBVIRT_CONF. Proceeding anyway..."
        fi
    else
        log "Warning: $LIBVIRT_CONF not found. Skipping libvirt CA path fix."
    fi
    # --- END Libvirt CA Path Fix ---

    log "Ensuring python3-pip is installed..."
    if ! dpkg -s python3-pip >/dev/null 2>&1; then
        log "python3-pip not found, installing..."
        sudo apt-get update && sudo apt-get install -y python3-pip || log "ERROR: Failed to install python3-pip"
    fi

    log "Attempting to install all DEB packages from ${DEB_DIR} using dpkg -i and apt --fix-broken..."
    pushd "${DEB_DIR}" > /dev/null
    log "Running dpkg -i on all .deb files (ignoring initial errors)..."
    if sudo dpkg -i ./*.deb; then
        log "dpkg -i completed without errors."
    else
        log "Warning: dpkg -i reported errors, attempting apt --fix-broken install..."
        log "--- Attempting manual trace of cml2-controller.postinst --- START ---"
        if [ -f /var/lib/dpkg/info/cml2-controller.postinst ]; then
            log "Executing: sudo bash -x /var/lib/dpkg/info/cml2-controller.postinst configure"
            sudo bash -x /var/lib/dpkg/info/cml2-controller.postinst configure || log "Warning: Manual postinst execution also failed."
        else
            log "Error: /var/lib/dpkg/info/cml2-controller.postinst not found for tracing."
        fi
        log "--- Manual trace of cml2-controller.postinst --- END ---"
    fi

    log "Running apt update and apt --fix-broken install..."
    if sudo apt-get update && sudo apt-get --fix-broken install -y; then
        log "CML package installation command finished (exit code 0)."

        log "--- Dumping APT logs --- START ---"
        log "--- /var/log/apt/history.log --- BEGIN ---"
        cat /var/log/apt/history.log || echo "Could not read /var/log/apt/history.log"
        log "--- /var/log/apt/history.log --- END ---"
        log "--- /var/log/apt/term.log --- BEGIN ---"
        cat /var/log/apt/term.log || echo "Could not read /var/log/apt/term.log"
        log "--- /var/log/apt/term.log --- END ---"
        log "--- Dumping APT logs --- END ---"

        log "Attempting to configure any unpacked packages..."
        sudo dpkg --configure -a || log "Warning: dpkg --configure -a encountered issues."

        log "Listing installed files for CML packages (if installed)..."
        # Assuming package names are cml2-controller and cml2-uwm, adjust if needed
        log "--- Files for cml2-controller ---"
        sudo dpkg -L cml2-controller || log "Warning: Could not list files for cml2-controller (might not be installed or name is different)."
        log "--- Files for cml2-uwm ---"
        sudo dpkg -L cml2-uwm || log "Warning: Could not list files for cml2-uwm (might not be installed or name is different)."

        log "Python sys.path:"
        sudo python3 -c "import sys, json; print(json.dumps(sys.path, indent=2))" || log "Error getting Python sys.path"
        log "Listing contents of /usr/local/lib/python3.8/dist-packages/..."
        sudo ls -la /usr/local/lib/python3.8/dist-packages/ || log "Error listing /usr/local/lib/python3.8/dist-packages/"

        # Force reinstall libvirt-daemon-system to ensure service file is present
        log "Forcing reinstall of libvirt-daemon-system..."
        if sudo apt-get install --reinstall -y libvirt-daemon-system; then
            log "Successfully reinstalled libvirt-daemon-system."
            log "+++ DIAGNOSTICS Start: Post libvirt reinstall +++"
            log "Checking for service file existence: /lib/systemd/system/libvirt.service"
            ls -l /lib/systemd/system/libvirt.service || log "Service file NOT FOUND at /lib/systemd/system/libvirt.service"
            log "Checking package manifest for service file: dpkg -L libvirt-daemon-system | grep service"
            dpkg -L libvirt-daemon-system | grep service || log "Service file NOT FOUND in package manifest"
            log "Checking systemd view of service file: systemctl cat libvirt.service"
            sudo systemctl cat libvirt.service || log "systemctl cat FAILED for libvirt.service"
            log "+++ DIAGNOSTICS End: Post libvirt reinstall +++"
        else
            log "Warning: Failed to reinstall libvirt-daemon-system. Continuing verification..."
        fi

        # --- BEGIN Post-CML Install Verification ---
        log "--- Verifying CML service files existence ---"
        sudo ls -l /lib/systemd/system/virl2-*.service || log "Warning: Could not list virl2 service files."

        log "--- Attempting to enable and start CML services ---"
        sudo systemctl daemon-reload
        # Try enabling first, ignore errors if already enabled
        sudo systemctl enable virl2-controller.service || log "Warning: Failed to enable virl2-controller.service (maybe already enabled?)"
        sudo systemctl enable virl2-uwm.service || log "Warning: Failed to enable virl2-uwm.service (maybe already enabled?)"
        # Try starting
        sudo systemctl start virl2-controller.service || log "Warning: Failed to start virl2-controller.service"
        sudo systemctl start virl2-uwm.service || log "Warning: Failed to start virl2-uwm.service"
        sleep 5 # Give services a moment

        log "--- Checking CML service status immediately after start attempt ---"
        sudo systemctl status virl2-controller.service --no-pager || log "Error getting virl2-controller status"
        sudo systemctl status virl2-uwm.service --no-pager || log "Error getting virl2-uwm status"

        log "--- Dumping last 50 journal entries for virl2-controller ---"
        sudo journalctl -u virl2-controller.service --no-pager -n 50 || log "Error getting virl2-controller journal logs"
        log "--- Dumping last 50 journal entries for virl2-uwm ---"
        sudo journalctl -u virl2-uwm.service --no-pager -n 50 || log "Error getting virl2-uwm journal logs"

        log "--- Checking CML install log ---"
        sudo cat /var/log/cml-install.log || log "Info: /var/log/cml-install.log not found or could not be read."
        # --- END Post-CML Install Verification ---
    else
        INSTALL_ERROR=$?
        log "ERROR: Failed to install CML DEB packages using dpkg -i and apt --fix-broken (Exit Code: $INSTALL_ERROR). Capturing diagnostic info..."
        # Capture diagnostics on failure
        sudo systemctl status libvirtd.service --no-pager || true
        sudo journalctl -u libvirtd --no-pager || true
        sudo journalctl -n 100 --no-pager || true
        popd > /dev/null # Ensure popd runs even on error
        exit ${INSTALL_ERROR}
    fi
    popd > /dev/null

    # Reload systemd daemon to recognize new services if any
    log "Reloading systemd daemon..."
    sudo systemctl daemon-reload
else
    echo "ERROR: CML .deb package directory $DEB_DIR does not exist or contains no .deb files."
    exit 1 # Exit script on failure
fi

# Remove final fix attempt - apt install should handle it
# echo "Attempting to fix any broken dependencies post-install..."
# sudo apt --fix-broken install -y

# Check for CML services again after direct installation
echo "Verifying CML services after direct installation..."
if ! systemctl list-unit-files | grep -q cml; then
    echo "Warning: CML services still not found after direct installation attempt."
fi

# Log completion
echo "CML 2.7.0 installation script finished at $(date)." | tee -a "$LOGFILE"

echo "--- APT History Log --- $(date) ---"
cat /var/log/apt/history.log || echo "Could not read /var/log/apt/history.log"
echo "--- End APT History Log ---"

echo "--- APT Term Log --- $(date) ---"
cat /var/log/apt/term.log || echo "Could not read /var/log/apt/term.log"
echo "--- End APT Term Log ---"

# Call final verification from bootstrap_cml.sh AFTER CML install completes
# Ensure systemd has re-read all unit files just before verification
echo "Reloading systemd daemon again before final verification..."
sudo systemctl daemon-reload

echo "Running final verification..."
final_verification

echo "CML Installation and Final Verification Completed at $(date)."

exit 0 # Ensure the script exits cleanly for Packer
