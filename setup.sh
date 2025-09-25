#!/bin/bash

# Function to check if a tool is installed
check_tool_installed() {
    if ! command -v "$1" &> /dev/null; then
        echo "Installing $1..."
        apt-get install -y "$1"
    else
        echo "$1 is already installed"
    fi
}

echo "Starting Vulfy setup..."

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install base dependencies
echo "Installing base dependencies..."
sudo apt-get install -y python3 python3-pip git

# Install security tools
echo "Installing security tools..."
check_tool_installed nmap
check_tool_installed nikto
check_tool_installed sqlmap
check_tool_installed sslyze
check_tool_installed dirb
check_tool_installed dnsrecon

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Check if all tools were installed successfully
echo "\nVerifying installation..."
for tool in nmap nikto sqlmap sslyze dirb dnsrecon; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool is installed"
    else
        echo "✗ $tool installation failed"
    fi
done

echo "\nSetup complete! You can now run Vulfy using:"
echo "python3 vulfy.py"
