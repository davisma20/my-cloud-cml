#!/bin/bash
# Script to install dependencies, run diagnostics, and execute the CML Python login test.

set -e

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - TEST_LOGIN: $1"
}

log "Starting CML Login Test Script..."

log "Checking environment variables..."
if [ -z "${CML_ADMIN_PASSWORD}" ]; then
  log "WARN: CML_ADMIN_PASSWORD environment variable is NOT set. Using default 'PASSWORD'."
else
  log "INFO: CML_ADMIN_PASSWORD environment variable is SET."
fi

log "Installing prerequisites: curl, jq, python3-pip, requests..."
sudo apt-get update
sudo apt-get -y install curl jq python3-pip || { log "ERROR: Failed to install prerequisites."; exit 1; }
pip3 install requests || { log "ERROR: Failed to install requests library."; exit 1; }
log "Prerequisites installed."

# Diagnostic: Create and run a temporary script to check CML service status
log "Running pre-check diagnostics..."
sudo tee /tmp/check_cml_services.sh > /dev/null << 'EOF_DIAG'
#!/bin/bash
echo '+++ DIAGNOSTICS Start: Pre-Python Web Check Service Status +++'
for service in virl2-controller.service virl2-uwm.service nginx.service; do
  echo "--- Status for $service ---"
  if sudo systemctl is-active --quiet "$service"; then
    echo "  $service is ACTIVE."
  else
    echo "  $service is INACTIVE or FAILED."
  fi
  sudo systemctl status "$service" --no-pager || echo "    Failed to get status for $service"
  echo "--- Last 20 logs for $service ---"
  sudo journalctl -u "$service" -n 20 --no-pager --output cat || echo "    Failed to get logs for $service"
done
echo '+++ DIAGNOSTICS End: Pre-Python Web Check Service Status +++'
EOF_DIAG

sudo chmod +x /tmp/check_cml_services.sh
sudo /tmp/check_cml_services.sh
log "Pre-check diagnostics finished."

# Create the Python login test script
log "Creating Python test script (/tmp/test_cml_login.py)..."
cat <<EOF > /tmp/test_cml_login.py
import requests
import time
import os
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

CML_HOST = "127.0.0.1"
CML_USER = "admin"
# Default password is 'PASSWORD', ensure this matches CML defaults or Packer vars
CML_PASS = os.getenv('CML_ADMIN_PASSWORD', 'PASSWORD')
TIMEOUT = 30 # seconds for requests

LOGIN_URL = f"https://{CML_HOST}/api/v0/authenticate" # Correct endpoint for CML 2.x authentication, using HTTPS
SYSTEM_INFO_URL = f"https://{CML_HOST}/api/v0/system_information" # Using HTTPS

print(f"+++ Python: Attempting to log in to CML at {CML_HOST} as user {CML_USER}...")
print(f"+++ Python: Using CML_PASS: {CML_PASS[:1]}...{CML_PASS[-1:] if len(CML_PASS) > 1 else ''}") # Log masked password

s = requests.Session()
# CML often uses self-signed certs, disable verification for local checks
s.verify = False 

try:
    # Login
    print(f"+++ Python: Posting to {LOGIN_URL}")
    response = s.post(LOGIN_URL, json={"username": CML_USER, "password": CML_PASS}, timeout=TIMEOUT)
    
    if response.status_code == 200:
        print(f"+++ Python: Login successful (Status Code: {response.status_code})")
        try:
            token = response.json()
            if isinstance(token, str): # Check if the response is just the token string
                 s.headers.update({"Authorization": f"Bearer {token}"})
            else:
                print(f"--- Python: Login response was not a token string: {token}", file=sys.stderr)
                sys.exit(1)
        except requests.exceptions.JSONDecodeError:
             print(f"--- Python: Login response was not valid JSON: {response.text[:100]}", file=sys.stderr)
             sys.exit(1)

    else:
        print(f"--- Python: Login FAILED (Status Code: {response.status_code})", file=sys.stderr)
        print(f"--- Python: Response Body (first 500 chars):\n{response.text[:500]}", file=sys.stderr)
        sys.exit(1)

    # Get System Info (as validation that the token works)
    print(f"+++ Python: Getting system info from {SYSTEM_INFO_URL}")
    response = s.get(SYSTEM_INFO_URL, timeout=TIMEOUT) # Session already has headers and verify=False
    
    if response.status_code == 200:
        print(f"+++ Python: System info retrieved successfully (Status Code: {response.status_code})")
        print(f"+++ Python: System Info: {response.json()}")
    else:
        print(f"--- Python: Failed to get system info (Status Code: {response.status_code})", file=sys.stderr)
        print(f"--- Python: Response Body (first 500 chars):\n{response.text[:500]}", file=sys.stderr)
        sys.exit(1)

    print("+++ Python: CML web interface check PASSED.")
    sys.exit(0)

except requests.exceptions.Timeout:
    print(f"--- Python: Request timed out after {TIMEOUT} seconds.", file=sys.stderr)
    sys.exit(1)
except requests.exceptions.ConnectionError as e:
    print(f"--- Python: Connection error: {e}", file=sys.stderr)
    sys.exit(1)
except requests.exceptions.RequestException as e:
    print(f"--- Python: An unexpected error occurred during the web check: {e}", file=sys.stderr)
    sys.exit(1)

EOF
log "Python test script created."

# Execute the Python script
log "Running Python login test script..."
python3 /tmp/test_cml_login.py
EXIT_CODE=$?
log "Python script finished with exit code $EXIT_CODE."

if [ $EXIT_CODE -ne 0 ]; then
    log "ERROR: Python login test script failed. Dumping relevant logs..."
    log "--- Nginx Access Log (last 50 lines) ---"
    sudo tail -n 50 /var/log/nginx/access.log || log "WARN: Failed to read Nginx access log."
    log "--- Nginx Error Log (last 50 lines) ---"
    sudo tail -n 50 /var/log/nginx/error.log || log "WARN: Failed to read Nginx error log."
    log "--- CML Controller Log (last 100 lines) ---"
    sudo tail -n 100 /var/log/virl2/controller.log || log "WARN: Failed to read CML controller log."
    log "--- CML UWM Log (last 100 lines) ---"
    sudo tail -n 100 /var/log/virl2/uwm.log || log "WARN: Failed to read CML UWM log."
    log "--- End of Log Dump ---"
    exit $EXIT_CODE
fi

log "CML Login Test Script finished successfully."
exit 0
