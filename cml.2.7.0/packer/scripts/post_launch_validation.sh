#!/bin/bash
set -e

# This script is designed to be run on a newly launched CML instance
# to validate its networking and web interface accessibility

echo "Starting CML post-launch validation..."
INSTANCE_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Log validation start
echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting CML validation on $INSTANCE_IP" > /var/log/cml_validation.log

# Basic network connectivity
echo "Testing basic network connectivity..."
if ping -c 3 8.8.8.8 > /dev/null; then
  echo "✅ External network connectivity successful" | tee -a /var/log/cml_validation.log
else
  echo "❌ CRITICAL: External network connectivity failed" | tee -a /var/log/cml_validation.log
  exit 1
fi

# Test HTTP connectivity
echo "Testing HTTP connectivity..."
if curl -s https://www.cisco.com -o /dev/null; then
  echo "✅ External HTTP connectivity successful" | tee -a /var/log/cml_validation.log
else
  echo "❌ CRITICAL: External HTTP connectivity failed" | tee -a /var/log/cml_validation.log
  exit 1
fi

# Wait for CML to initialize (can take some time)
echo "Waiting for CML services to initialize..."
for i in {1..30}; do
  if systemctl is-active --quiet nginx && systemctl is-active --quiet virl2; then
    echo "✅ CML services are active" | tee -a /var/log/cml_validation.log
    break
  fi
  if [ $i -eq 30 ]; then
    echo "❌ CRITICAL: CML services did not become active within timeout period" | tee -a /var/log/cml_validation.log
    exit 1
  fi
  echo "Waiting for CML services to initialize... (attempt $i/30)" | tee -a /var/log/cml_validation.log
  sleep 10
done

# Test CML GUI accessibility
echo "Testing CML GUI accessibility..."
if curl -s -k https://localhost/login -o /dev/null; then
  echo "✅ CML GUI is accessible (HTTPS)" | tee -a /var/log/cml_validation.log
else
  echo "❌ CRITICAL: CML GUI is not accessible via HTTPS" | tee -a /var/log/cml_validation.log
  # Try HTTP as fallback
  if curl -s http://localhost/login -o /dev/null; then
    echo "⚠️ CML GUI is accessible via HTTP (not HTTPS)" | tee -a /var/log/cml_validation.log
  else
    echo "❌ CRITICAL: CML GUI is not accessible via either HTTP or HTTPS" | tee -a /var/log/cml_validation.log
    exit 1
  fi
fi

# Test external GUI accessibility
echo "Testing external CML GUI accessibility..."
if curl -s -k https://$INSTANCE_IP/login -o /dev/null; then
  echo "✅ CML GUI is externally accessible at https://$INSTANCE_IP/login" | tee -a /var/log/cml_validation.log
else
  echo "❌ WARNING: CML GUI is not externally accessible" | tee -a /var/log/cml_validation.log
  # This might not be critical as it could be due to security groups
  echo "  - Please verify security group settings allow port 443" | tee -a /var/log/cml_validation.log
fi

# Test API accessibility
echo "Testing CML API accessibility..."
if curl -s -k https://localhost/api/v0/status | grep -q "version\|api_running"; then
  echo "✅ CML API is accessible and returning status" | tee -a /var/log/cml_validation.log
else
  echo "❌ CRITICAL: CML API is not accessible" | tee -a /var/log/cml_validation.log
  exit 1
fi

# Final verification
echo "CML validation completed successfully!" | tee -a /var/log/cml_validation.log
echo "Instance IP: $INSTANCE_IP" | tee -a /var/log/cml_validation.log
echo "CML GUI should be accessible at: https://$INSTANCE_IP/login" | tee -a /var/log/cml_validation.log
echo "Validation log saved to /var/log/cml_validation.log"
