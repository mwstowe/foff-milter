#!/bin/bash

# FOFF Milter Installation Script

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/foff-milter"
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

# Create config directory structure
echo "Creating configuration directories..."
sudo mkdir -p "$CONFIG_DIR"
sudo mkdir -p "$CONFIG_DIR/legacy-configs"
sudo mkdir -p "$CONFIG_DIR/configs"

# Generate default configuration if it doesn't exist
if [ ! -f "$CONFIG_DIR/foff-milter.yaml" ]; then
    echo "Generating default configuration..."
    sudo "$INSTALL_DIR/foff-milter" --generate-config "$CONFIG_DIR/foff-milter.yaml"
    sudo chown root:root "$CONFIG_DIR/foff-milter.yaml"
    sudo chmod 644 "$CONFIG_DIR/foff-milter.yaml"
fi

# Install legacy configurations
if [ -d "legacy-configs" ]; then
    echo "Installing legacy configurations..."
    sudo cp -r legacy-configs/* "$CONFIG_DIR/legacy-configs/"
    sudo chown -R root:root "$CONFIG_DIR/legacy-configs"
    sudo chmod -R 644 "$CONFIG_DIR/legacy-configs"/*.yaml
fi

# Generate modular configurations
echo "Generating modular configurations..."
sudo "$INSTALL_DIR/foff-milter" --generate-modules "$CONFIG_DIR/configs"
sudo chown -R root:root "$CONFIG_DIR/configs"
sudo chmod -R 644 "$CONFIG_DIR/configs"/*.yaml

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
echo "Configuration files installed:"
echo "  Main config: $CONFIG_DIR/foff-milter.yaml"
echo "  Legacy rules: $CONFIG_DIR/legacy-configs/"
echo "  Modular configs: $CONFIG_DIR/configs/"
echo ""
echo "Next steps:"
echo "1. Edit the configuration file: sudo nano $CONFIG_DIR/foff-milter.yaml"
echo "2. Choose configuration system:"
echo "   - Legacy: Use rules from $CONFIG_DIR/legacy-configs/hotel.yaml"
echo "   - Modular: Set module_config_dir: \"$CONFIG_DIR/configs\""
echo "3. Test the configuration: sudo $INSTALL_DIR/foff-milter --test-config -c $CONFIG_DIR/foff-milter.yaml"
echo "4. Enable the service: sudo systemctl enable foff-milter"
echo "5. Start the service: sudo systemctl start foff-milter"
echo "6. Configure sendmail/postfix to use the milter"
echo ""
echo "For sendmail, add to sendmail.mc:"
echo "INPUT_MAIL_FILTER(\`foff-milter', \`S=unix:/var/run/foff-milter.sock, T=S:30s;R:30s')"
echo ""
echo "For postfix, add to main.cf:"
echo "smtpd_milters = unix:/var/run/foff-milter.sock"
echo "non_smtpd_milters = unix:/var/run/foff-milter.sock"
echo "milter_default_action = accept"
