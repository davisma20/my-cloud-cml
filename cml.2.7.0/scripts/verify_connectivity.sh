#!/bin/bash
#
# Verify connectivity between DevNet workstation and CML
# For use with CAD-7 ticket verification
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if CML IP is provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <cml_ip_address>${NC}"
    echo -e "Example: $0 10.0.0.10"
    exit 1
fi

CML_IP=$1
PING_COUNT=4
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
CML_SSH_PORT=1122
REQUIRED_PORTS=($HTTP_PORT $HTTPS_PORT $SSH_PORT $CML_SSH_PORT)

echo -e "${YELLOW}==================================================================${NC}"
echo -e "${YELLOW}DEVNET WORKSTATION TO CML CONNECTIVITY VERIFICATION${NC}"
echo -e "${YELLOW}==================================================================${NC}"
echo ""
echo -e "Testing connectivity to CML at ${YELLOW}$CML_IP${NC}"
echo ""

# 1. Ping Test
echo -e "${YELLOW}[1/4] Running ICMP ping test...${NC}"
if ping -c $PING_COUNT $CML_IP > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Ping successful${NC}"
    PING_OUTPUT=$(ping -c 1 $CML_IP | grep "time=")
    echo -e "  $PING_OUTPUT"
else
    echo -e "  ${RED}✗ Ping failed${NC}"
    echo -e "  ${YELLOW}This may indicate network connectivity issues or ICMP blocking${NC}"
fi
echo ""

# 2. TCP Port Test
echo -e "${YELLOW}[2/4] Testing TCP port connectivity...${NC}"
for PORT in "${REQUIRED_PORTS[@]}"; do
    if nc -z -w 2 $CML_IP $PORT > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Port $PORT is open${NC}"
    else
        echo -e "  ${RED}✗ Port $PORT is closed${NC}"
        if [ $PORT -eq $HTTP_PORT ]; then
            echo -e "  ${YELLOW}HTTP port is not accessible, web interface may not be available${NC}"
        elif [ $PORT -eq $HTTPS_PORT ]; then
            echo -e "  ${YELLOW}HTTPS port is not accessible, secure web interface may not be available${NC}"
        elif [ $PORT -eq $SSH_PORT ]; then
            echo -e "  ${YELLOW}SSH port is not accessible, standard SSH may not be available${NC}"
        elif [ $PORT -eq $CML_SSH_PORT ]; then
            echo -e "  ${YELLOW}CML SSH port is not accessible, CML SSH may not be available${NC}"
        fi
    fi
done
echo ""

# 3. HTTPS Certificate Test
echo -e "${YELLOW}[3/4] Testing HTTPS certificate...${NC}"
if curl -s -k -m 5 https://$CML_IP > /dev/null 2>&1; then
    CERT_INFO=$(echo | openssl s_client -connect $CML_IP:443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
    if [ -n "$CERT_INFO" ]; then
        echo -e "  ${GREEN}✓ HTTPS certificate found${NC}"
        echo -e "  Certificate details:"
        echo -e "  $CERT_INFO" | sed 's/^/  /'
    else
        echo -e "  ${YELLOW}⚠ HTTPS accessible but couldn't retrieve certificate information${NC}"
    fi
else
    echo -e "  ${RED}✗ Could not connect to HTTPS service${NC}"
fi
echo ""

# 4. Web UI Test
echo -e "${YELLOW}[4/4] Testing CML Web UI accessibility...${NC}"
HTTP_STATUS=$(curl -s -k -o /dev/null -w "%{http_code}" https://$CML_IP 2>/dev/null)
if [[ $HTTP_STATUS -ge 200 && $HTTP_STATUS -lt 400 ]]; then
    echo -e "  ${GREEN}✓ CML Web UI is accessible (HTTP Status: $HTTP_STATUS)${NC}"
else
    echo -e "  ${RED}✗ CML Web UI returned HTTP Status: $HTTP_STATUS${NC}"
    if [[ $HTTP_STATUS -eq 000 ]]; then
        echo -e "  ${YELLOW}Connection failed or timed out${NC}"
    elif [[ $HTTP_STATUS -eq 301 || $HTTP_STATUS -eq 302 ]]; then
        echo -e "  ${YELLOW}Redirect detected - this may be normal for initial access${NC}"
    elif [[ $HTTP_STATUS -ge 400 && $HTTP_STATUS -lt 500 ]]; then
        echo -e "  ${YELLOW}Client error - authentication may be required${NC}"
    else
        echo -e "  ${YELLOW}Server error - the CML service may be starting up or experiencing issues${NC}"
    fi
fi
echo ""

# Summary
echo -e "${YELLOW}==================================================================${NC}"
echo -e "${YELLOW}CONNECTIVITY VERIFICATION SUMMARY${NC}"
echo -e "${YELLOW}==================================================================${NC}"
echo ""
echo -e "DevNet Workstation can access the CML instance with the following results:"
echo ""
echo -e "  ICMP Ping: ${PING_SUCCESS:-FAILED}"
echo -e "  Required TCP Ports: ${TCP_SUCCESS:-PARTIAL or FAILED}"
echo -e "  HTTPS Certificate: ${CERT_SUCCESS:-NOT VALIDATED}"
echo -e "  Web UI Access: ${WEB_SUCCESS:-FAILED}"
echo ""
echo -e "For complete CML functionality, ensure all tests pass successfully."
echo -e "If any tests failed, check the security groups, network ACLs, and"
echo -e "firewall settings on both the DevNet workstation and CML instance."
echo ""
echo -e "${YELLOW}==================================================================${NC}"
