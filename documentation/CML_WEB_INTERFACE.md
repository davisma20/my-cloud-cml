# CML Web Interface Setup and Validation

This document describes the improved process for setting up and validating the CML web interface during the Packer build process.

## Overview

The CML web interface is a critical component of the CML deployment. It provides access to the CML controller via a web browser, allowing users to create and manage labs, devices, and topologies. Our improved setup ensures:

1. **Secure HTTPS Access**: Properly configured with TLS/SSL
2. **Robust Service Initialization**: Correct order and verification
3. **Authentication Testing**: Validates login process
4. **Comprehensive Error Diagnostics**: Detailed logging for troubleshooting

## Web Interface Configuration

### nginx Configuration

The web interface uses nginx as a reverse proxy to the CML UI services. Our enhanced configuration:

- Redirects HTTP to HTTPS for security
- Properly configures SSL with modern cipher suites
- Adds security headers to prevent common web vulnerabilities
- Includes proper WebSocket support for terminal access
- Sets appropriate timeouts for lab operations

### Service Sequence

For proper initialization, services must be started in the correct order:

1. **MongoDB**: Database must be running first
2. **CML Controller**: Core API and backend services
3. **CML UI**: Frontend UI components
4. **nginx**: Web server for proxying requests

## Validation Process

Our enhanced testing script performs comprehensive validation:

1. **Service Status Checking**: Confirms all required services are running
2. **Port Verification**: Ensures web ports (80/443) are listening
3. **API Endpoint Testing**: Validates the CML API is accessible
4. **Authentication**: Tests login process and session management
5. **Authorization**: Verifies access to protected resources

## Troubleshooting

Common issues and solutions:

### Web Interface Not Accessible

1. Check if nginx is running: `systemctl status nginx`
2. Verify nginx configuration: `nginx -t`
3. Check if required ports are open: `netstat -tulpn | grep -E ':(80|443|8000|8001)'`
4. Review nginx logs: `tail -n 50 /var/log/nginx/error.log`

### Authentication Failures

1. Verify CML controller is running: `systemctl status virl2-controller.service`
2. Check if admin user exists: `virl2_controller users list`
3. Reset admin password if needed: `virl2_controller users passwd admin -p admin`
4. Review controller logs: `tail -n 50 /var/log/virl2/controller.log`

### SSL/TLS Issues

1. Verify certificate exists: `ls -la /etc/ssl/certs/ssl-cert-snakeoil.pem`
2. Generate new certificate if needed: `make-ssl-cert generate-default-snakeoil`
3. Check nginx SSL configuration in `/etc/nginx/sites-available/cml`

## Automated Setup and Testing

Our Packer build process now includes:

1. A dedicated setup script: `setup_cml_web_ui.sh`
2. A comprehensive test script: `test_cml_web_ui.py`

These scripts ensure the web interface is properly configured and validated during the AMI build process, resulting in a more reliable CML deployment.
