#!/bin/bash

# FOFF Milter Installation Script

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc"
SERVICE_DIR="/etc/systemd/system"
USER="milter"
GROUP="milter"

echo "Installing FOFF Milter..."

# Build the project
echo "Building project..."
cargo build --release

# Create milter user if it doesn't exist
if ! id "$USER" &>/dev/null; then
    echo "Creating milter user..."
    sudo useradd -r -s /bin/false -d /var/lib/milter "$USER"
fi

# Install binary
echo "Installing binary to $INSTALL_DIR..."
sudo cp target/release/foff-milter "$INSTALL_DIR/"
sudo chown root:root "$INSTALL_DIR/foff-milter"
sudo chmod 755 "$INSTALL_DIR/foff-milter"

# Generate default configuration if it doesn't exist
if [ ! -f "$CONFIG_DIR/foff-milter.yaml" ]; then
    echo "Generating default configuration..."
    sudo "$INSTALL_DIR/foff-milter" --generate-config "$CONFIG_DIR/foff-milter.yaml"
    sudo chown root:root "$CONFIG_DIR/foff-milter.yaml"
    sudo chmod 644 "$CONFIG_DIR/foff-milter.yaml"
fi

# Create systemd service file
echo "Creating systemd service..."
sudo tee "$SERVICE_DIR/foff-milter.service" > /dev/null <<EOF
[Unit]
Description=FOFF Email Milter
After=network.target

[Service]
Type=simple
User=$USER
Group=$GROUP
ExecStart=$INSTALL_DIR/foff-milter -c $CONFIG_DIR/foff-milter.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create socket directory
sudo mkdir -p /var/run/milter
sudo chown "$USER:$GROUP" /var/run/milter
sudo chmod 755 /var/run/milter

echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Edit the configuration file: sudo nano $CONFIG_DIR/foff-milter.yaml"
echo "2. Test the configuration: sudo $INSTALL_DIR/foff-milter --test-config"
echo "3. Enable the service: sudo systemctl enable foff-milter"
echo "4. Start the service: sudo systemctl start foff-milter"
echo "5. Configure sendmail/postfix to use the milter"
echo ""
echo "For sendmail, add to sendmail.mc:"
echo "INPUT_MAIL_FILTER(\`foff-milter', \`S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')"
echo ""
echo "For postfix, add to main.cf:"
echo "smtpd_milters = unix:/var/run/foff-milter.sock"
echo "non_smtpd_milters = unix:/var/run/foff-milter.sock"
echo "milter_default_action = accept"
