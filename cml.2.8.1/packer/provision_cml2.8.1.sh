#!/bin/bash
set -e

# Variables
DOWNLOADS="/home/ubuntu/my-cloud-cml/cml.2.8.1/CISCO_DOWNLOADS"
CML_ISO="$DOWNLOADS/cml2_2.8.1-14_amd64-35.iso"
REFPLAT_ISO="$DOWNLOADS/refplat-20241223-fcs.iso"

# Install unzip if needed
sudo apt-get update && sudo apt-get install -y unzip

# Always use S3 as the source of truth for ISOs
aws s3 cp s3://cml-ova-import/cml-2.8.1/cml2_2.8.1-14_amd64-35.iso "$CML_ISO"
aws s3 cp s3://cml-ova-import/cml-2.8.1/refplat-20241223-fcs.iso "$REFPLAT_ISO"

# Validate ISO files before mounting
if ! file "$CML_ISO" | grep -q 'ISO 9660'; then
  echo "ERROR: $CML_ISO is not a valid ISO. Aborting."
  exit 1
fi
if ! file "$REFPLAT_ISO" | grep -q 'ISO 9660'; then
  echo "ERROR: $REFPLAT_ISO is not a valid ISO. Aborting."
  exit 1
fi

echo "[INFO] CML and Reference Platform ISOs downloaded and validated."

echo "[INFO] CML 2.8.1 installation is now handled via cloud-init NoCloud seed ISO."
echo "[INFO] Please ensure the NoCloud seed.iso is attached as a secondary CD-ROM during the AMI build."
# No further installation steps are needed here. The instance will auto-install CML using cloud-init user-data from the NoCloud ISO.

# [CML-dependent logic removed]
# All CML installation validation and image copying is now handled by cloud-init user-data.

# System configuration (hostname, SSH, etc.) is handled by cloud-init user-data

# Robust, Ubuntu 24.04+ compatible SSM Agent installation (Snap-aware, region-aware, no apt-get)
echo "[INFO] Checking for Amazon SSM Agent installation..."
if snap list | grep -q amazon-ssm-agent; then
  echo "[INFO] SSM Agent is already installed via Snap. Enabling and starting..."
  sudo snap start amazon-ssm-agent
  echo "[INFO] Snap SSM Agent status:"
  sudo snap services amazon-ssm-agent || echo "Warning: Failed to get Snap SSM Agent status."
else
  REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | awk -F\" '{print $4}')
  SSM_DEB_URL=https://s3.${REGION}.amazonaws.com/amazon-ssm-${REGION}/latest/debian_amd64/amazon-ssm-agent.deb
  echo "[INFO] Installing Amazon SSM Agent via AWS S3 regional .deb package from $SSM_DEB_URL..."
  curl -Lo /tmp/amazon-ssm-agent.deb $SSM_DEB_URL
  sudo dpkg -i /tmp/amazon-ssm-agent.deb
  sudo systemctl enable --now amazon-ssm-agent
  echo "[INFO] DEB SSM Agent status:"
  sudo systemctl status amazon-ssm-agent --no-pager || echo "Warning: Failed to get DEB SSM Agent status."
  echo "[INFO] Checking if DEB SSM Agent is enabled:"
  sudo systemctl is-enabled amazon-ssm-agent || echo "Warning: Failed to check if DEB SSM Agent is enabled."
fi
echo "[INFO] Final SSM Agent process check (Snap or DEB):"
if pgrep -f amazon-ssm-agent >/dev/null; then
  echo "[SUCCESS] SSM Agent process is running."
else
  echo "[ERROR] SSM Agent process is NOT running! Manual intervention required."
fi
echo "SSM Agent validation/installation complete."

# Security hardening and cleanup
sudo apt-get clean
sudo rm -rf $DOWNLOADS/*.zip
