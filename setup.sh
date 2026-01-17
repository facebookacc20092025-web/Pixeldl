#!/bin/bash
# setup.sh

echo "Setting up VPS Proxy Server..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Verify installation
node --version
npm --version

# Create app directory
mkdir -p ~/vps-proxy
cd ~/vps-proxy

# Copy your files (assuming they're in current directory)
# npm init -y
# Copy package.json and index.js here

# Install dependencies
npm install

# Create .env file if not exists
if [ ! -f .env ]; then
  cat > .env << EOF
PORT=3000
NODE_ENV=production
LOG_LEVEL=info
API_KEY=$(openssl rand -base64 32)
ALLOWED_DOMAINS=pixeldrain.com,pixeldrain.eu
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
REQUEST_TIMEOUT=60000
RATE_LIMIT_MAX=100
EOF
  echo ".env file created with random API key"
fi

# Install PM2 for process management
sudo npm install -g pm2

# Start the application with PM2
pm2 start index.js --name "vps-proxy"

# Save PM2 process list
pm2 save

# Setup PM2 to start on boot
pm2 startup
# Follow the instructions shown

echo "Setup complete!"
echo "Your server is running on port 3000"
echo "API Key: $(grep API_KEY .env | cut -d '=' -f2)"
echo ""
echo "To check logs: pm2 logs vps-proxy"
echo "To restart: pm2 restart vps-proxy"
echo "To stop: pm2 stop vps-proxy"
