#!/bin/bash
# Install ClawTower tray autostart for current user
mkdir -p ~/.config/autostart
cp assets/clawtower-tray.desktop ~/.config/autostart/
echo "Autostart installed for $(whoami)"
