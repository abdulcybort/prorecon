#!/bin/bash

# ProRecon Installation Script for Kali Linux
# Author: Abdulbasid Yakubu | cy30rt
# Version: 2.0.0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            ProRecon Installation Script                  ║"
echo "║            For Kali Linux & Debian-based Systems          ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Running without root. Some features may require sudo.${NC}"
fi

echo -e "${CYAN}[*] Starting installation...${NC}\n"

# Update package lists
echo -e "${CYAN}[*] Updating package lists...${NC}"
sudo apt-get update -qq

# Install Python3 and pip
echo -e "${CYAN}[*] Checking Python3 installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}[!] Python3 not found. Installing...${NC}"
    sudo apt-get install -y python3 python3-pip
else
    echo -e "${GREEN}[+] Python3 already installed: $(python3 --version)${NC}"
fi

# Install pip if not present
echo -e "${CYAN}[*] Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}[!] pip3 not found. Installing...${NC}"
    sudo apt-get install -y python3-pip
else
    echo -e "${GREEN}[+] pip3 already installed${NC}"
fi

# Install system dependencies
echo -e "\n${CYAN}[*] Installing system dependencies...${NC}"
sudo apt-get install -y \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    dnsutils \
    net-tools

# Upgrade pip
echo -e "\n${CYAN}[*] Upgrading pip...${NC}"
python3 -m pip install --upgrade pip

# Install Python dependencies
echo -e "\n${CYAN}[*] Installing Python packages...${NC}"
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    echo -e "${GREEN}[+] Python packages installed successfully${NC}"
else
    echo -e "${YELLOW}[!] requirements.txt not found. Installing packages manually...${NC}"
    pip3 install requests urllib3 dnspython
fi

# Make script executable
echo -e "\n${CYAN}[*] Setting permissions...${NC}"
chmod +x prorecon.py

# Create symlink for easy access (optional)
echo -e "\n${CYAN}[*] Creating command alias...${NC}"
INSTALL_DIR=$(pwd)
if [ -f "$INSTALL_DIR/prorecon.py" ]; then
    # Add alias to bashrc if not already present
    if ! grep -q "alias prorecon" ~/.bashrc; then
        echo "alias prorecon='python3 $INSTALL_DIR/prorecon.py'" >> ~/.bashrc
        echo -e "${GREEN}[+] Added 'prorecon' alias to ~/.bashrc${NC}"
        echo -e "${YELLOW}[!] Run 'source ~/.bashrc' or restart terminal to use 'prorecon' command${NC}"
    fi
    
    # Also add to zshrc if zsh is installed
    if [ -f ~/.zshrc ] && ! grep -q "alias prorecon" ~/.zshrc; then
        echo "alias prorecon='python3 $INSTALL_DIR/prorecon.py'" >> ~/.zshrc
        echo -e "${GREEN}[+] Added 'prorecon' alias to ~/.zshrc${NC}"
    fi
fi

# Test installation
echo -e "\n${CYAN}[*] Testing installation...${NC}"
if python3 prorecon.py --version &> /dev/null; then
    echo -e "${GREEN}[+] Installation successful!${NC}"
else
    echo -e "${RED}[!] Installation test failed. Please check for errors above.${NC}"
    exit 1
fi

# Success message
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         ProRecon Installed Successfully!                  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo -e "\n${CYAN}Usage Examples:${NC}"
echo -e "  ${YELLOW}python3 prorecon.py -t example.com${NC}"
echo -e "  ${YELLOW}python3 prorecon.py -t example.com --tcp --udp --subs${NC}"
echo -e "  ${YELLOW}python3 prorecon.py -t 8.8.8.8 --tcp${NC}"
echo -e "\n${CYAN}For more information, run:${NC}"
echo -e "  ${YELLOW}python3 prorecon.py --help${NC}"
echo -e "\n${GREEN}Happy Hacking!${NC}\n"
