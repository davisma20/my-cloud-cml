#!/bin/bash
# Automated forensic script: Download CML .deb package(s) from S3 and inspect for service files
# Usage: ./forensic_cml_deb_s3_download.sh

set -euo pipefail

# Configurable S3 bucket and path (update as needed)
S3_BUCKET="s3://cml-ova-import/cml-2.7.0-debs/"
LOCAL_DIR="/tmp/cml-deb-forensics"

mkdir -p "$LOCAL_DIR"
echo "Downloading all CML .deb packages from $S3_BUCKET to $LOCAL_DIR..."
aws s3 cp --recursive "$S3_BUCKET" "$LOCAL_DIR"

cd "$LOCAL_DIR"
echo "Listing downloaded .deb files:"
ls -lh *.deb || { echo "No .deb files found in $LOCAL_DIR."; exit 1; }

echo "--- Inspecting contents of each .deb for systemd service files (virl2-uwm.service, virl2-controller.service, etc) ---"
for deb in *.deb; do
    echo "\nInspecting $deb:"
    dpkg -c "$deb" | grep 'systemd' || echo "No systemd service files found in $deb."
    dpkg -c "$deb" | grep 'virl2-uwm.service' && echo "Found virl2-uwm.service in $deb!" || echo "virl2-uwm.service NOT found in $deb."
    dpkg -c "$deb" | grep 'virl2-controller.service' && echo "Found virl2-controller.service in $deb!" || echo "virl2-controller.service NOT found in $deb."
    # Optionally inspect postinst scripts
    dpkg-deb -e "$deb" "$deb-extract" && cat "$deb-extract/postinst" || echo "No postinst script in $deb."
    rm -rf "$deb-extract"
done

echo "--- Forensic inspection complete. Review output above for missing or present service files. ---"
