#!/bin/bash
set -e

echo "============================"
echo "CML Web UI Setup and Testing"
echo "============================"

# Initial system check
echo "Checking system status before configuration..."
systemctl status mongod || true
systemctl status virl2-controller.service || true
systemctl status virl2-ui.service || true
systemctl status nginx.service || true

echo "Checking current network configuration..."
netstat -tulpn | grep -E ':(80|443|8000|8001)' || true

# Stop all services to avoid conflicts
echo "Stopping all services for clean configuration..."
systemctl stop nginx || true
systemctl stop virl2-ui.service || true 
systemctl stop virl2-controller.service || true
sleep 5

# Configure nginx properly with a secure setup
echo "Configuring nginx for CML web interface..."
cat > /etc/nginx/sites-available/cml << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name _;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    
    # Proxy configuration
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
}
EOF

# Create symlink and remove default site
rm -f /etc/nginx/sites-enabled/default || true
ln -sf /etc/nginx/sites-available/cml /etc/nginx/sites-enabled/
mkdir -p /etc/nginx/ssl

# Generate self-signed certificate if not present
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
    echo "Generating self-signed SSL certificate..."
    apt-get update -y
    apt-get install -y ssl-cert
    make-ssl-cert generate-default-snakeoil
fi

# Test nginx configuration
echo "Testing nginx configuration..."
nginx -t || echo "Nginx config test failed"

# Start services in correct order
echo "Starting MongoDB..."
systemctl restart mongod
sleep 5

echo "Starting CML Controller..."
systemctl restart virl2-controller.service
sleep 10

echo "Starting CML UI..."
systemctl restart virl2-ui.service
sleep 5

echo "Starting Nginx..."
systemctl restart nginx
sleep 5

# Verify services are running
echo "Verifying service status..."
systemctl status mongod --no-pager || true
systemctl status virl2-controller.service --no-pager || true
systemctl status virl2-ui.service --no-pager || true
systemctl status nginx.service --no-pager || true

# Check for listening ports
echo "Checking listening ports..."
netstat -tulpn | grep -E ':(80|443|8000|8001)' || true

# Create admin user if needed
echo "Ensuring admin user exists..."
if command -v virl2_controller; then
    virl2_controller users list | grep -q "admin" || virl2_controller users add admin -p admin --full-name "System Administrator" --email admin@example.com
    virl2_controller users grant admin admin || true
    virl2_controller users grant admin root || true
    virl2_controller users list
else
    echo "virl2_controller command not found, skipping user creation"
fi

echo "Web UI setup complete. You should now be able to access the CML interface via HTTPS."
