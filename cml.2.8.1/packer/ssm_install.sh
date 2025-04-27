#!/bin/bash
set -e

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
