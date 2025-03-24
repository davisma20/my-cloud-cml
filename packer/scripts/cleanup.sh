#!/bin/bash
# Comprehensive cleanup script for CML AMI
# This script prepares the system for AMI creation by removing unnecessary files
# and securing the system.

set -e
set -o pipefail

# Setup logging
LOGFILE="/var/log/cleanup.log"
exec > >(tee -a ${LOGFILE}) 2>&1
echo "Starting cleanup at $(date)"

# Remove apt cache and lists to reduce image size
echo "Cleaning apt cache..."
apt-get clean -y || true
apt-get autoclean -y || true
rm -rf /var/lib/apt/lists/* || true

# Remove temporary files
echo "Removing temporary files..."
rm -rf /tmp/* || true
rm -rf /var/tmp/* || true

# Remove SSH host keys (will be regenerated on first boot)
echo "Removing SSH host keys..."
rm -f /etc/ssh/ssh_host_* || true

# Secure SSH configuration
echo "Securing SSH configuration..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config || true
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config || true

# Ensure SSH is properly configured for security
echo "Configuring additional SSH security settings..."
grep -q "^Protocol 2" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
grep -q "^PermitEmptyPasswords no" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
grep -q "^X11Forwarding no" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
grep -q "^IgnoreRhosts yes" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

# Clear command history
echo "Clearing command history..."
# Use bash explicitly to ensure history command works in non-interactive shells
if [ -f ~/.bash_history ]; then
  bash -c "history -c" || true
fi
cat /dev/null > ~/.bash_history || true
rm -f /root/.bash_history || true
rm -f /home/ubuntu/.bash_history || true
rm -f /home/admin/.bash_history || true

# Set up the first-boot script that will complete CML configuration
echo "Setting up first-boot configuration script..."
cat > /usr/local/bin/cml-first-boot.sh << 'EOF'
#!/bin/bash
# CML First Boot Configuration
# This script runs on the first boot of the instance to complete CML configuration

# Log all output
exec > >(tee -a /var/log/cml-first-boot.log) 2>&1
echo "Starting CML first boot configuration at $(date)"

# Generate new SSH host keys
echo "Generating new SSH host keys..."
ssh-keygen -A

# Apply system-specific configuration
echo "Applying system-specific configuration..."
# Set hostname based on instance ID
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
hostname "cml-${INSTANCE_ID}"
echo "cml-${INSTANCE_ID}" > /etc/hostname

# Ensure proper file permissions
echo "Setting file permissions..."
chmod 700 /root
chmod 700 /home/*

# Mark first boot as complete
touch /etc/.cml_first_boot_complete
echo "CML first boot configuration completed successfully at $(date)"
EOF

# Make the script executable
chmod +x /usr/local/bin/cml-first-boot.sh

# Set up a service to run the script on first boot
cat > /etc/systemd/system/cml-first-boot.service << 'EOF'
[Unit]
Description=CML First Boot Configuration
After=network.target
ConditionPathExists=!/etc/.cml_first_boot_complete

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cml-first-boot.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
systemctl enable cml-first-boot.service

# Disable services that should not run during AMI creation
echo "Disabling unnecessary services for AMI creation..."
systemctl disable virl2-controller.service

# Add a marker file to indicate this is a Packer-built AMI
touch /etc/.packer_ami_build_complete || true

echo "Cleanup completed successfully at $(date)"
echo "System is ready for AMI creation"
