#!/bin/bash
# Block the openclaw user from running sudo commands that could disable ClawTower
set -euo pipefail

DENY_FILE="/etc/sudoers.d/clawtower-deny"
AGENT_USER="openclaw"

cat > "$DENY_FILE" << 'EOF'
# ClawTower: Deny agent user from disabling the watchdog
# This file is immutable (chattr +i) — requires admin key to modify

# Block stopping/disabling ClawTower service
openclaw ALL=(ALL) !/usr/bin/systemctl stop clawtower, \
                    !/usr/bin/systemctl stop clawtower.service, \
                    !/usr/bin/systemctl disable clawtower, \
                    !/usr/bin/systemctl disable clawtower.service, \
                    !/usr/bin/systemctl mask clawtower, \
                    !/usr/bin/systemctl mask clawtower.service

# Block modifying ClawTower binary and config
openclaw ALL=(ALL) !/usr/bin/chattr * /usr/local/bin/clawtower, \
                    !/usr/bin/chattr * /etc/clawtower/*, \
                    !/usr/bin/chattr * /etc/systemd/system/clawtower.service

# Block removing/replacing ClawTower files
openclaw ALL=(ALL) !/usr/bin/rm /usr/local/bin/clawtower, \
                    !/usr/bin/rm -f /usr/local/bin/clawtower, \
                    !/usr/bin/rm -rf /etc/clawtower, \
                    !/usr/bin/rm -rf /etc/clawtower/*, \
                    !/usr/bin/mv /usr/local/bin/clawtower *, \
                    !/usr/bin/cp * /usr/local/bin/clawtower, \
                    !/usr/bin/install * /usr/local/bin/clawtower

# Block killing ClawTower process directly
openclaw ALL=(ALL) !/usr/bin/kill, \
                    !/usr/bin/killall clawtower, \
                    !/usr/bin/pkill clawtower

# Block getting a root shell (prevents sudo su / sudo -i / sudo bash escape)
openclaw ALL=(ALL) !/usr/bin/su, \
                    !/usr/bin/su -, \
                    !/usr/bin/su root, \
                    !/usr/bin/su - root, \
                    !/usr/sbin/su, \
                    !/usr/bin/bash, \
                    !/usr/bin/sh, \
                    !/usr/bin/zsh, \
                    !/usr/bin/dash, \
                    !/usr/bin/fish, \
                    !/usr/bin/env bash, \
                    !/usr/bin/env sh

# Block sudo flags that give interactive root shells
openclaw ALL=(ALL) !/usr/bin/sudo -i, \
                    !/usr/bin/sudo -s, \
                    !/usr/bin/sudo su, \
                    !/usr/bin/sudo su -, \
                    !/usr/bin/sudo -u root /usr/bin/bash, \
                    !/usr/bin/sudo -u root /usr/bin/sh

# Block editing sudoers (prevent removing these rules)
openclaw ALL=(ALL) !/usr/sbin/visudo, \
                    !/usr/bin/sudoedit

# Block user/account manipulation (prevent compromising admin account)
openclaw ALL=(ALL) !/usr/bin/passwd, \
                    !/usr/sbin/useradd, \
                    !/usr/sbin/usermod, \
                    !/usr/sbin/userdel, \
                    !/usr/sbin/groupmod, \
                    !/usr/sbin/deluser, \
                    !/usr/sbin/adduser, \
                    !/usr/bin/chage, \
                    !/usr/bin/gpasswd, \
                    !/usr/bin/chsh, \
                    !/usr/bin/chfn
EOF

chmod 440 "$DENY_FILE"
chown root:root "$DENY_FILE"

# Validate syntax
if ! visudo -cf "$DENY_FILE"; then
    echo "ERROR: Invalid sudoers syntax, removing file"
    rm -f "$DENY_FILE"
    exit 1
fi

# Make immutable
chattr +i "$DENY_FILE"

echo "Created and locked $DENY_FILE"
