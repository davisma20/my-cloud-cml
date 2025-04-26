#!/bin/bash
set -e

echo "Applying security hardening measures..."

# Install security packages
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  unattended-upgrades \
  apt-listchanges \
  ufw \
  fail2ban \
  libpam-pwquality

# Configure automatic updates
echo "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# Configure firewall
echo "Configuring UFW firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 1122/tcp
ufw allow 9090/tcp
ufw allow 2000:7999/tcp
ufw allow 2000:7999/udp

# Enable UFW but don't start it yet (can interrupt Packer SSH session)
systemctl enable ufw

# Configure fail2ban
echo "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true

[sshd-ddos]
enabled = true
EOF

systemctl enable fail2ban

# Configure password policies
echo "Configuring password policies..."
cat > /etc/security/pwquality.conf << EOF
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

# Secure SSH configuration
echo "Securing SSH configuration..."
cat > /etc/ssh/sshd_config.d/hardening.conf << EOF
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
EOF

echo "Security hardening completed successfully"
