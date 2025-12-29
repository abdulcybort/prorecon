#!/data/data/com.termux/files/usr/bin/bash

# ProRecon Installation Script for Termux
# Author: Abdulbasid Yakubu | cy30rt
# Version: 2.0.0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║            ProRecon Installation Script                  ║"
echo "║                   For Termux Android                      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${CYAN}[*] Starting Termux installation...${NC}\n"

# Update and upgrade Termux packages
echo -e "${CYAN}[*] Updating Termux packages...${NC}"
pkg update -y
pkg upgrade -y

# Install Python
echo -e "\n${CYAN}[*] Installing Python...${NC}"
pkg install -y python

# Install additional dependencies
echo -e "\n${CYAN}[*] Installing dependencies...${NC}"
pkg install -y \
    python-pip \
    openssl \
    libffi \
    dnsutils \
    net-tools \
    git

# Upgrade pip
echo -e "\n${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip

# Install Python packages
echo -e "\n${CYAN}[*] Installing Python packages...${NC}"
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install requests urllib3 dnspython
fi

# Make script executable
echo -e "\n${CYAN}[*] Setting permissions...${NC}"
chmod +x prorecon.py

# Create shortcut command
echo -e "\n${CYAN}[*] Creating command shortcut...${NC}"
INSTALL_DIR=$(pwd)
mkdir -p ~/.shortcuts

# Create shortcut script
cat > ~/.shortcuts/prorecon << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
python "$HOME/prorecon/prorecon.py" "$@"
EOF

chmod +x ~/.shortcuts/prorecon

# Add to PATH if not already there
if ! grep -q "~/.shortcuts" ~/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.shortcuts:$PATH"' >> ~/.bashrc
    echo -e "${GREEN}[+] Added shortcuts to PATH${NC}"
fi

# Test installation
echo -e "\n${CYAN}[*] Testing installation...${NC}"
if python prorecon.py --version &> /dev/null; then
    echo -e "${GREEN}[+] Installation successful!${NC}"
else
    echo -e "${YELLOW}[!] Installation completed with warnings${NC}"
fi

# Grant storage permissions reminder
echo -e "\n${YELLOW}[!] Important: Grant storage permissions for file saving${NC}"
echo -e "${YELLOW}[!] Run: termux-setup-storage${NC}"

# Success message
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         ProRecon Installed Successfully!                  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo -e "\n${CYAN}Usage:${NC}"
echo -e "  ${YELLOW}python prorecon.py -t example.com${NC}"
echo -e "  ${YELLOW}python prorecon.py -t example.com --tcp --subs${NC}"
echo -e "\n${CYAN}Termux Tips:${NC}"
echo -e "  • Run ${YELLOW}termux-setup-storage${NC} for SD card access"
echo -e "  • Use ${YELLOW}termux-wake-lock${NC} to prevent sleep during scans"
echo -e "  • Results saved in current directory"
echo -e "\n${GREEN}Happy Hacking on Android!${NC}\n"
