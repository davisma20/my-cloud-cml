#!/usr/bin/env python3
"""
CML Web Interface Test Script
This script tests if the CML web interface is properly initialized,
verifies SSL/TLS configuration, and validates successful authentication.
"""

import requests
import time
import json
import sys
import subprocess
import ssl
import socket
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Configuration
MAX_TRIES = 30
WAIT_TIME = 10
BASE_URL = "https://localhost"
USERNAME = "admin"
PASSWORD = "admin"
CHECK_SSL = True

# Suppress warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def check_port_open(host, port, timeout=5):
    """Check if a port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def check_ssl_certificate(hostname, port=443):
    """Verify SSL certificate properties."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    print("✓ SSL certificate found")
                    return True
                else:
                    print("✗ No SSL certificate found")
                    return False
    except Exception as e:
        print(f"SSL certificate check error: {e}")
        return False

def check_service_status(service_name):
    """Check the status of a systemd service."""
    try:
        result = subprocess.run(
            ["systemctl", "status", service_name], 
            capture_output=True, 
            text=True
        )
        if "active (running)" in result.stdout:
            print(f"✓ {service_name} is running")
            return True
        else:
            print(f"✗ {service_name} is not running")
            print(f"Status: {result.stdout}")
            return False
    except Exception as e:
        print(f"Error checking {service_name}: {e}")
        return False

def main():
    """Main test function for CML web GUI."""
    print("\n=========================================")
    print("CML Web Interface Authentication Test")
    print("=========================================\n")
    
    # Check if essential services are running
    services_ok = True
    for service in ["mongod", "virl2-controller.service", "virl2-ui.service", "nginx.service"]:
        if not check_service_status(service):
            services_ok = False
    
    if not services_ok:
        print("WARNING: Some required services are not running")
    
    # Check if ports are open
    if not check_port_open("localhost", 443):
        print("✗ HTTPS port (443) is not open")
        print("Checking if HTTP port (80) is open...")
        if check_port_open("localhost", 80):
            print("✓ HTTP port (80) is open, continuing with tests")
            global BASE_URL
            BASE_URL = "http://localhost"
        else:
            print("✗ Neither HTTP (80) nor HTTPS (443) ports are open")
    else:
        print("✓ HTTPS port (443) is open")
        if CHECK_SSL:
            check_ssl_certificate("localhost")

    # Create a session for consistent cookies
    session = requests.Session()
    
    for attempt in range(1, MAX_TRIES + 1):
        print(f"\nAttempt {attempt}/{MAX_TRIES}...")
        try:
            # Check system API endpoint
            try:
                about_resp = session.get(f"{BASE_URL}/api/v0/about", verify=False, timeout=5)
                print(f"About API response: {about_resp.status_code}")
                if about_resp.status_code == 200:
                    print("✓ About endpoint accessible, CML API is working")
                    print(f"CML Version: {about_resp.json().get('version', 'Unknown')}")
                else:
                    print("✗ About endpoint returned error")
            except Exception as e:
                print(f"✗ Error accessing about endpoint: {e}")
            
            # Try to access the UI
            try:
                ui_resp = session.get(BASE_URL, verify=False, timeout=5)
                print(f"UI response: {ui_resp.status_code}")
                if ui_resp.status_code == 200:
                    print("✓ UI accessible")
                else:
                    print("✗ UI returned error")
            except Exception as e:
                print(f"✗ Error accessing UI: {e}")

            # Prepare login data
            login_data = {
                "username": USERNAME, 
                "password": PASSWORD
            }
            
            # Check if we need CSRF token
            try:
                initial_resp = session.get(f"{BASE_URL}/auth/login", verify=False, timeout=5)
                if "csrftoken" in session.cookies:
                    print("Found CSRF token in cookies")
                    login_data["csrfmiddlewaretoken"] = session.cookies["csrftoken"]
            except Exception as e:
                print(f"Error getting initial page: {e}")

            # Attempt login
            try:
                login_resp = session.post(
                    f"{BASE_URL}/api/v0/authenticate", 
                    json=login_data,
                    headers={"Referer": f"{BASE_URL}/auth/login"},
                    verify=False,
                    timeout=10
                )
                
                print(f"Login status: {login_resp.status_code}")
                
                if login_resp.status_code in [200, 201, 202]:
                    print("✓ Login successful!")
                    
                    # Try to access a protected resource
                    labs_resp = session.get(f"{BASE_URL}/api/v0/labs", verify=False, timeout=5)
                    print(f"Labs API status: {labs_resp.status_code}")
                    if labs_resp.status_code == 200:
                        print("✓ Successfully authenticated and accessed labs API")
                        print("\n=========================================")
                        print("CML WEB INTERFACE TEST: SUCCESS")
                        print("=========================================\n")
                        sys.exit(0)  # Success!
                    else:
                        print("✗ Labs API access failed after login")
                else:
                    print(f"✗ Login failed. Status: {login_resp.status_code}")
                    try:
                        error_msg = login_resp.json().get("description", login_resp.text)
                        print(f"Error: {error_msg}")
                    except:
                        print(f"Response: {login_resp.text[:100]}")
            except Exception as e:
                print(f"✗ Error during login: {e}")
            
            # Wait before retrying
            if attempt < MAX_TRIES:
                print(f"Waiting {WAIT_TIME} seconds before retry...")
                time.sleep(WAIT_TIME)
        except Exception as e:
            print(f"Unexpected error: {e}")
            if attempt < MAX_TRIES:
                print(f"Waiting {WAIT_TIME} seconds before retry...")
                time.sleep(WAIT_TIME)

    print("\n=========================================")
    print("CML WEB INTERFACE TEST: FAILED")
    print("Maximum attempts reached. CML web interface not available.")
    print("=========================================\n")
    
    # Print diagnostic information
    print("Diagnostic Information:")
    try:
        # Show service logs
        print("\n--- Controller Log (last 30 lines) ---")
        subprocess.call(["sudo", "tail", "-n", "30", "/var/log/virl2/controller.log"])
        
        print("\n--- UI Log (last 30 lines) ---")
        subprocess.call(["sudo", "tail", "-n", "30", "/var/log/virl2/ui.log"])
        
        print("\n--- Nginx Error Log (last 30 lines) ---")
        subprocess.call(["sudo", "tail", "-n", "30", "/var/log/nginx/error.log"])
        
        print("\n--- Network Connections ---")
        subprocess.call(["netstat", "-tulpn"])
    except Exception as e:
        print(f"Error gathering diagnostic information: {e}")
    
    sys.exit(1)  # Failure

if __name__ == "__main__":
    main()
