#!/bin/bash

set -e  # Exit on error

# Function to check if a package is installed
check_package() {
    dpkg -s "$1" &> /dev/null
}

# Install python3.12-venv if missing
if ! check_package python3.12-venv; then
    echo "[INFO] Installing python3.12-venv..."
    sudo apt update && sudo apt install -y python3.12-venv
fi

# Create virtual environment if it doesn't exist
[ ! -d "venv" ] && echo "[INFO] Creating Python virtual environment..." && python3.12 -m venv venv

# Activate the virtual environment
echo "[INFO] Activating virtual environment..."
source venv/bin/activate

# Install splunk-packaging-toolkit if 'slim' is missing
if ! command -v slim &> /dev/null; then
    echo "[INFO] Installing splunk-packaging-toolkit..."
    pip install splunk-packaging-toolkit
fi

# Create 'releases' directory if it doesn't exist
mkdir -p releases

# Update version in app.conf file
echo "[INFO] Updating version in app.conf..."
rm -rf ./IDMEFv2-Splunk/app.manifest
version="s/^version = .*/version = 1.0.$(date +"%s")/g"
sed -i "$version" IDMEFv2-Splunk/default/app.conf

# Package the app with slim
echo "[INFO] Packaging the app..."
cd releases && slim package ../IDMEFv2-Splunk

echo "[OK] Setup complete and app packaged successfully."
