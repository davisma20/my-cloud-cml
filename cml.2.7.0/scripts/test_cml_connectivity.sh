#!/bin/bash
# CML Controller Connectivity Test Script
# For the Cisco DevNet Expert Workstation
# https://github.com/davisma20/my-cloud-cml

CML_IP="$1"

if [ -z "$CML_IP" ]; then
  echo "Usage: $0 <CML_IP_ADDRESS>"
  echo "Example: $0 3.148.166.186"
  exit 1
fi

echo "===================================================="
echo "Testing connectivity to CML Controller at $CML_IP"
echo "===================================================="

# Basic network connectivity tests
echo -e "\n1. Testing basic network connectivity..."
ping -c 4 $CML_IP
PING_RESULT=$?

if [ $PING_RESULT -eq 0 ]; then
  echo "✅ Ping successful - Network path is reachable"
else
  echo "❌ Ping failed - Network path may be blocked"
fi

# Check key ports
echo -e "\n2. Testing key CML service ports..."

# HTTP (80)
echo -n "HTTP (80): "
nc -z -w 2 $CML_IP 80
if [ $? -eq 0 ]; then echo "✅ Open"; else echo "❌ Closed"; fi

# HTTPS (443)
echo -n "HTTPS (443): "
nc -z -w 2 $CML_IP 443
if [ $? -eq 0 ]; then echo "✅ Open"; else echo "❌ Closed"; fi

# SSH (22)
echo -n "SSH (22): "
nc -z -w 2 $CML_IP 22
if [ $? -eq 0 ]; then echo "✅ Open"; else echo "❌ Closed"; fi

# Custom SSH (1122)
echo -n "Custom SSH (1122): "
nc -z -w 2 $CML_IP 1122
if [ $? -eq 0 ]; then echo "✅ Open"; else echo "❌ Closed"; fi

# Cockpit Web UI (9090)
echo -n "Cockpit (9090): "
nc -z -w 2 $CML_IP 9090
if [ $? -eq 0 ]; then echo "✅ Open"; else echo "❌ Closed"; fi

# Test HTTPS connection
echo -e "\n3. Testing HTTPS connectivity (CML Web UI)..."
curl -k -I https://$CML_IP --connect-timeout 5
if [ $? -eq 0 ]; then
  echo "✅ HTTPS connection successful"
else
  echo "❌ HTTPS connection failed"
fi

# Security Group Verification
echo -e "\n4. Verifying AWS Security Group Configuration..."
echo "This test requires the AWS CLI to be configured on this machine."
echo "If you see errors below, you may need to run this script from your local machine."

if command -v aws &> /dev/null; then
  echo "Checking CML Controller (i-0ba610b6850d2b0fc) security group..."
  aws ec2 describe-instance-attribute --instance-id i-0ba610b6850d2b0fc --attribute groupSet 2>/dev/null
  
  echo "Checking DevNet Workstation security group..."
  aws ec2 describe-instance-attribute --instance-id i-0d3f97caed3696ef0 --attribute groupSet 2>/dev/null
else
  echo "AWS CLI not found or not configured."
fi

# Summary
echo -e "\n===================================================="
echo "CONNECTIVITY TEST SUMMARY"
echo "===================================================="
echo "CML Controller IP: $CML_IP"
echo ""
echo "If you're having connectivity issues:"
echo "1. Verify both security groups allow traffic between instances"
echo "2. Check if the CML services are fully initialized"
echo "3. Try stopping and starting the CML controller instance"
echo "4. Verify your browser security settings allow access"
echo ""
echo "To access the CML web interface, use: https://$CML_IP"
echo "Username: admin"
echo "===================================================="
