#!/bin/bash
set -euo pipefail

RULES_FILE="/etc/audit/rules.d/clawtower.rules"

cat > "$RULES_FILE" << 'EOF'
# ClawTower tamper detection rules
# Watch for attribute changes on ClawTower binary (chattr -i attempts)
-w /usr/local/bin/clawtower -p a -k clawtower-tamper

# Watch for writes/attribute changes to ClawTower config
-w /etc/clawtower/ -p wa -k clawtower-config

# Watch for changes to the service file
-w /etc/systemd/system/clawtower.service -p wa -k clawtower-tamper

# Watch for changes to the sudoers deny file
-w /etc/sudoers.d/clawtower-deny -p wa -k clawtower-tamper

# Watch for changes to AppArmor profile
-w /etc/apparmor.d/clawtower.deny-agent -p wa -k clawtower-tamper
EOF

# Reload audit rules
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE"

echo "Audit rules installed and loaded"
