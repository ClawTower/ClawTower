#!/bin/bash
# Install ClawTower polkit policy
sudo cp assets/com.clawtower.policy /usr/share/polkit-1/actions/
echo "Polkit policy installed"
