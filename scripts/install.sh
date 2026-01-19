#!/bin/bash

# Configuration
APP_NAME="caddy-control"
INSTALL_DIR="/opt/$APP_NAME"
SERVICE_NAME="$APP_NAME.service"
CURRENT_USER=$(whoami)

echo "-----------------------------------------------------"
echo "  🚀 Installing Caddy Control Plane"
echo "-----------------------------------------------------"

# 1. Check for Go
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed. Please install Go (golang) first."
    exit 1
fi

# 2. Build the Application
echo "📦 Building application..."
cd app
go mod tidy
go build -o $APP_NAME main.go
if [ $? -ne 0 ]; then
    echo "❌ Build failed."
    exit 1
fi
cd ..

# 3. Create Installation Directory
echo "📂 Setting up directories at $INSTALL_DIR..."
sudo mkdir -p $INSTALL_DIR
sudo mkdir -p $INSTALL_DIR/templates
sudo chown -R $CURRENT_USER:$CURRENT_USER $INSTALL_DIR

# 4. Copy Files
echo "Tx Copying files..."
cp app/$APP_NAME $INSTALL_DIR/
cp app/templates/*.html $INSTALL_DIR/templates/

# 5. Configure .env
if [ ! -f "$INSTALL_DIR/.env" ]; then
    echo "⚙️ Creating .env file..."
    cp .env.example $INSTALL_DIR/.env
    echo "⚠️  IMPORTANT: You must edit $INSTALL_DIR/.env with your Google Client ID!"
else
    echo "ℹ️  Existing .env found, skipping creation."
fi

# 6. Install Systemd Service
echo "🔧 Installing systemd service..."
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
sudo cp scripts/caddy-control.service $SERVICE_PATH

# Replace Placeholders in Service File
sudo sed -i "s|PLACEHOLDER_USER|$CURRENT_USER|g" $SERVICE_PATH
sudo sed -i "s|PLACEHOLDER_DIR|$INSTALL_DIR|g" $SERVICE_PATH

# 7. Enable and Start
echo "🚀 Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

echo "-----------------------------------------------------"
echo "✅ Installation Complete!"
echo "-----------------------------------------------------"
echo "1. Edit configuration: nano $INSTALL_DIR/.env"
echo "2. Restart service:    sudo systemctl restart $SERVICE_NAME"
echo "3. View logs:          sudo journalctl -u $SERVICE_NAME -f"
echo "-----------------------------------------------------"
