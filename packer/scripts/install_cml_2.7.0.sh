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
DEB_DIR=/tmp/cml-debs
CML_DIR="/root/cml_installation/extracted"
mkdir -p "$CML_DIR"
sudo chown -R $(whoami) "$CML_DIR"
cd "$CML_DIR"

# Define subdirectories within DEB_DIR
KERNEL_DEBS=${DEB_DIR}/kernel_debs
DEPEND_DEBS=${DEB_DIR}/dependencies_debs
CML_DEBS=${DEB_DIR}/cml_deps

echo "Listing available installation files in ${DEB_DIR}:"
ls -lha "${DEB_DIR}" || true

# Fix broken packages first
echo "Fixing any broken package dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y

# Install dependencies if needed
echo "Installing any prerequisite packages..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-unauthenticated systemd-coredump libc6-dev libnss-libvirt

echo "Creating required subdirectories inside ${DEB_DIR}..."
mkdir -p "${KERNEL_DEBS}" "${DEPEND_DEBS}" "${CML_DEBS}"

echo "Organizing DEB files into expected subdirectories in ${DEB_DIR}..."

# Move Kernel DEBs (ignore errors if none found)
echo "Moving kernel DEBs..."
mv "${DEB_DIR}"/linux-image-*.deb "${DEB_DIR}"/linux-headers-*.deb "${DEB_DIR}"/linux-modules-*.deb "${KERNEL_DEBS}/" 2>/dev/null || echo "Info: No kernel DEBs found or error moving."

# Move CML and related DEBs (ignore errors if none found)
echo "Moving CML and related DEBs..."
mv "${DEB_DIR}"/cml*.deb "${DEB_DIR}"/patty*.deb "${CML_DEBS}/" 2>/dev/null || echo "Info: No CML/Patty DEBs found or error moving."

# Move remaining dependency DEBs (ignore errors if some files don't exist or can't be moved)
echo "Moving remaining dependency DEBs..."
# Use find to move only .deb files, avoiding trying to move setup.sh etc.
find "${DEB_DIR}" -maxdepth 1 -name '*.deb' -exec mv -t "${DEPEND_DEBS}/" {} + 2>/dev/null || echo "Info: Error moving some dependency DEBs (already moved or non-DEB files present?)."

# Add a verification step to show the structure
echo "DEB file organization complete. Current structure in ${DEB_DIR}:"
tree "${DEB_DIR}" || ls -lR "${DEB_DIR}"

# Install DEB packages directly from the organized subdirectories
echo "Installing DEB packages directly..."
if ls "${KERNEL_DEBS}"/*.deb 1> /dev/null 2>&1; then
    echo "Installing kernel DEBs..."
    sudo apt-get install -y "${KERNEL_DEBS}"/*.deb || echo "Failed to install kernel DEBs"
else
    echo "No kernel DEBs found to install."
fi

if ls "${DEPEND_DEBS}"/*.deb 1> /dev/null 2>&1; then
    echo "Installing dependency DEBs..."
    sudo apt-get install -y "${DEPEND_DEBS}"/*.deb || echo "Failed to install dependency DEBs"
else
    echo "No dependency DEBs found to install."
fi

if ls "${CML_DEBS}"/*.deb 1> /dev/null 2>&1; then
    echo "Installing CML DEBs..."
    sudo apt-get install -y "${CML_DEBS}"/*.deb || echo "Failed to install CML DEBs"
else
    echo "No CML DEBs found to install."
fi

# Attempt to fix broken dependencies just in case
echo "Attempting to fix any broken dependencies..."
sudo apt --fix-broken install -y

# Check for CML services again after direct installation
echo "Verifying CML services after direct installation..."
if ! systemctl list-unit-files | grep -q cml; then
    echo "Warning: CML services still not found after direct installation attempt."
fi

# Log completion
echo "CML 2.7.0 installation script finished at $(date)." | tee -a "$LOGFILE"

exit 0 # Ensure the script exits cleanly for Packer
