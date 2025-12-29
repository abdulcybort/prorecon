#!/bin/bash

# ReconMaster Installation Script for Kali Linux
# Author: Abdulbasid Yakubu | cy30rt

echo -e "\e[1;34m"
echo "    ╔══════════════════════════════════════════════════════════════╗"
echo "    ║                    RECONMASTER INSTALLER                     ║"
echo "    ║                 Professional Reconnaissance Tool             ║"
echo "    ╚══════════════════════════════════════════════════════════════╝"
echo -e "\e[0m"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "\e[1;33m[!] Running as non-root user. Some features may require sudo.\e[0m"
fi

echo -e "\e[1;32m[+] Starting ReconMaster installation...\e[0m"

# Update system
echo -e "\e[1;36m[*] Updating package list...\e[0m"
sudo apt update -y

# Install Python and pip
echo -e "\e[1;36m[*] Installing Python and pip...\e[0m"
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Install system dependencies
echo -e "\e[1;36m[*] Installing system dependencies...\e[0m"
sudo apt install -y \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev \
    nmap \
    dnsutils \
    whois \
    net-tools

# Create virtual environment
echo -e "\e[1;36m[*] Creating Python virtual environment...\e[0m"
python3 -m venv recon-env
source recon-env/bin/activate

# Install Python packages
echo -e "\e[1;36m[*] Installing Python dependencies...\e[0m"
pip install --upgrade pip
pip install -r requirements.txt

# Install additional security tools (optional)
echo -e "\e[1;36m[*] Installing additional security tools...\e[0m"
sudo apt install -y \
    whatweb \
    dnsrecon \
    amass \
    sublist3r \
    eyewitness \
    gobuster \
    ffuf \
    sqlmap \
    nikto \
    wpscan

# Install dnspython if not already installed
echo -e "\e[1;36m[*] Installing dnspython for DNS resolution...\e[0m"
pip install dnspython

# Make recon_master.py executable
echo -e "\e[1;36m[*] Setting up executable permissions...\e[0m"
chmod +x recon_master.py

# Create default config file if it doesn't exist
if [ ! -f config.json ]; then
    echo -e "\e[1;36m[*] Creating default configuration file...\e[0m"
    cat > config.json << 'EOF'
{
    "shodan": "YOUR_SHODAN_API_KEY_HERE",
    "securitytrails": "YOUR_SECURITYTRAILS_API_KEY_HERE",
    "ipinfo": "YOUR_IPINFO_API_KEY_HERE",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
    "abuseipdb": "YOUR_ABUSEIPDB_API_KEY_HERE",
    "greynoise": "YOUR_GREYNOISE_API_KEY_HERE",
    "builtwith": "YOUR_BUILTWITH_API_KEY_HERE",
    "wappalyzer": "YOUR_WAPPALYZER_API_KEY_HERE"
}
EOF
fi

# Create desktop shortcut (GUI only)
if [ -d "/usr/share/applications" ]; then
    echo -e "\e[1;36m[*] Creating desktop shortcut...\e[0m"
    cat > ~/Desktop/ReconMaster.desktop << EOF
[Desktop Entry]
Name=ReconMaster
Comment=Professional Bug Bounty Reconnaissance Tool
Exec=bash -c 'cd "$(dirname "$0")" && ./recon_master.py'
Icon=utilities-terminal
Terminal=true
Type=Application
Categories=Utility;Security;
EOF
    chmod +x ~/Desktop/ReconMaster.desktop
fi

# Setup complete
echo -e "\e[1;32m[+] Installation complete!\e[0m"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo -e "\e[1;36mQUICK START GUIDE:\e[0m"
echo ""
echo -e "\e[1;32m1. Activate virtual environment:\e[0m"
echo -e "   \e[1;37msource recon-env/bin/activate\e[0m"
echo ""
echo -e "\e[1;32m2. Configure API keys:\e[0m"
echo -e "   \e[1;37mnano config.json\e[0m"
echo -e "   or"
echo -e "   \e[1;37mpython3 recon_master.py --setup\e[0m"
echo ""
echo -e "\e[1;32m3. Basic usage:\e[0m"
echo -e "   \e[1;37mpython3 recon_master.py -t example.com --enum-subs\e[0m"
echo -e "   \e[1;37mpython3 recon_master.py -t example.com --advanced --full-scan\e[0m"
echo ""
echo -e "\e[1;32m4. Advanced setup:\e[0m"
echo -e "   \e[1;37mpython3 recon_master.py --advanced-setup\e[0m"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo ""
echo -e "\e[1;35mAvailable API Services:\e[0m"
echo -e "• Shodan (Essential) - https://account.shodan.io/"
echo -e "• SecurityTrails - https://securitytrails.com/"
echo -e "• VirusTotal - https://www.virustotal.com/"
echo -e "• AbuseIPDB - https://www.abuseipdb.com/"
echo -e "• GreyNoise - https://www.greynoise.io/"
echo -e "• BuiltWith - https://builtwith.com/"
echo -e "• Wappalyzer - https://www.wappalyzer.com/"
echo -e "• IPInfo - https://ipinfo.io/"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo -e "\e[1;32mHappy Hacking! - Abdulbasid Yakubu | cy30rt\e[0m"
