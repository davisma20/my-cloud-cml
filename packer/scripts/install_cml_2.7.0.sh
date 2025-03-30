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

# Fix broken packages first
echo "Fixing any broken package dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

# Install dependencies if needed
echo "Installing any prerequisite packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated systemd-coredump libc6-dev libnss-libvirt

# Install DEB packages directly from the main DEB_DIR
echo "Installing all DEB packages from ${DEB_DIR}..."
if ls "${DEB_DIR}"/*.deb 1> /dev/null 2>&1; then
    # Refresh package lists right before installing local debs to avoid hash mismatches
    echo "Running apt-get update before installing local DEB packages..."
    if ! sudo apt-get update -y; then
        echo "Warning: apt-get update failed before DEB install. Proceeding anyway..."
    fi

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

    log "Attempting to install all DEB packages from ${DEB_DIR} using dpkg --force-depends..."
    if ls "${DEB_DIR}"/*.deb 1> /dev/null 2>&1; then
        # Use dpkg --force-depends to install packages despite dependency issues
        # Follow up immediately with apt -f install to try and fix broken dependencies
        pushd "${DEB_DIR}" > /dev/null
        if sudo dpkg -i --force-depends *.deb; then
            log "dpkg installation phase completed (may have dependency errors)."
        else
            log "dpkg installation phase failed."
            # Even if dpkg fails, attempt apt --fix-broken
        fi
        popd > /dev/null

        log "Attempting to fix any broken dependencies with apt --fix-broken install..."
        if sudo apt-get install -f -y; then
            log "Successfully fixed dependencies."
        else
            INSTALL_ERROR=$?
            log "ERROR: Failed to fix dependencies after dpkg install (Exit Code: $INSTALL_ERROR). Capturing diagnostic info..."
            # Attempt to capture diagnostics immediately on failure
            log "Attempting to capture libvirtd/journald logs after install failure..."
            sudo systemctl status libvirtd.service --no-pager || true
            sudo journalctl -u libvirtd --no-pager || true
            sudo journalctl -n 100 --no-pager || true # Last 100 lines of journal
            exit ${INSTALL_ERROR}
        fi

        # Diagnostics after successful install (might still catch issues from post-install scripts)
        log "Capturing libvirtd/journald logs after successful install command..."
        sudo systemctl status libvirtd.service --no-pager || true
        sudo journalctl -u libvirtd --no-pager || true
        sudo journalctl -n 50 --no-pager || true # Last 50 lines of journal
    else
        echo "ERROR: CML .deb package directory $DEB_DIR does not exist or contains no .deb files."
        exit 1 # Exit script on failure
    fi

    # Reload systemd daemon to recognize new services if any
    log "Reloading systemd daemon..."
    sudo systemctl daemon-reload
else
    echo "ERROR: CML .deb package directory $DEB_DIR does not exist or contains no .deb files."
    exit 1 # Exit script on failure
fi

# Attempt to fix broken dependencies just in case
echo "Attempting to fix any broken dependencies post-install..."
sudo apt --fix-broken install -y

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
