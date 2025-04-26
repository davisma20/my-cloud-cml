#!/bin/bash
set -e

echo "============================"
echo "CML Web UI Setup and Testing"
echo "============================"

# Setup proper error handling
handle_error() {
    echo "Error occurred at line $1"
    exit 1
}
trap 'handle_error $LINENO' ERR

# Initial system check
echo "Checking system status before configuration..."
sudo systemctl status mongod || true
sudo systemctl status virl2-controller.service || true
sudo systemctl status virl2-ui.service || true
sudo systemctl status nginx.service || true

echo "Checking current network configuration..."
sudo netstat -tulpn | grep -E ':(80|443|8000|8001)' || true

# Stop all services to avoid conflicts
echo "Stopping all services for clean configuration..."
sudo systemctl stop nginx || true
sudo systemctl stop virl2-ui.service || true 
sudo systemctl stop virl2-controller.service || true
sleep 5

# Generate self-signed SSL certificate if needed
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ] || [ ! -f /etc/ssl/private/ssl-cert-snakeoil.key ]; then
    echo "Generating self-signed SSL certificate..."
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/ssl-cert-snakeoil.key \
        -out /etc/ssl/certs/ssl-cert-snakeoil.pem \
        -subj "/C=US/ST=California/L=San Francisco/O=CML/CN=localhost"
    sudo chmod 600 /etc/ssl/private/ssl-cert-snakeoil.key
fi

# Configure nginx properly with a secure setup
echo "Configuring nginx for CML web interface..."
sudo mkdir -p /etc/nginx/sites-available
sudo mkdir -p /etc/nginx/sites-enabled

sudo tee /etc/nginx/sites-available/cml > /dev/null << 'EOF'
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
    
    # Proxy settings for CML UI
    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Proxy settings for CML API
    location /api {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable the site and disable default
echo "Enabling CML nginx site..."
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/cml /etc/nginx/sites-enabled/

# Test nginx config
echo "Testing nginx configuration..."
sudo nginx -t

# Ensure all required services are running in the correct order
echo "Starting services in proper order..."
sudo systemctl daemon-reload

# Start MongoDB first
echo "Starting MongoDB..."
sudo systemctl start mongod
sleep 5

# Start CML controller
echo "Starting CML controller..."
sudo systemctl start virl2-controller.service
sleep 10

# Start CML UI
echo "Starting CML UI..."
sudo systemctl start virl2-ui.service
sleep 5

# Start nginx last
echo "Starting nginx..."
sudo systemctl start nginx

# Verify everything is running
echo "Verifying all services are running..."
sudo systemctl status mongod || true
sudo systemctl status virl2-controller.service || true
sudo systemctl status virl2-ui.service || true
sudo systemctl status nginx.service || true

# Configure UFW firewall with required ports
echo "Configuring UFW firewall rules..."
sudo ufw allow 22/tcp comment "SSH"
sudo ufw allow 80/tcp comment "HTTP"
sudo ufw allow 443/tcp comment "HTTPS"
sudo ufw --force enable

echo "CML Web UI setup completed successfully"
