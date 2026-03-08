#!/bin/bash

set -e

APP_DIR="/opt/fiber-monitor"

echo "Installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

echo "Cloning repository..."
sudo rm -rf $APP_DIR
sudo git clone https://github.com/abodcr/fiber.git $APP_DIR

cd $APP_DIR

echo "Creating python environment..."
python3 -m venv venv

source venv/bin/activate

echo "Installing python packages..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Creating systemd services..."

sudo bash -c 'cat > /etc/systemd/system/fiber-web.service <<EOF
[Unit]
Description=Fiber Monitor Web
After=network.target

[Service]
WorkingDirectory=/opt/fiber-monitor
ExecStart=/opt/fiber-monitor/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

sudo bash -c 'cat > /etc/systemd/system/fiber-collector.service <<EOF
[Unit]
Description=Fiber Monitor Collector
After=network.target

[Service]
WorkingDirectory=/opt/fiber-monitor
ExecStart=/opt/fiber-monitor/venv/bin/python collector.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF'

sudo systemctl daemon-reload
sudo systemctl enable fiber-web
sudo systemctl enable fiber-collector

sudo systemctl restart fiber-web
sudo systemctl restart fiber-collector

echo "Installation finished"
echo "Web UI: http://SERVER_IP:8050"
