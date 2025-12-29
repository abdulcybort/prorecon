#!/data/data/com.termux/files/usr/bin/bash

# ReconMaster Installation Script for Termux (Android)
# Author: Abdulbasid Yakubu | cy30rt

echo -e "\e[1;34m"
echo "    ╔══════════════════════════════════════════════════════════════╗"
echo "    ║                  RECONMASTER - TERMUX INSTALLER              ║"
echo "    ║        Professional Reconnaissance Tool for Android         ║"
echo "    ╚══════════════════════════════════════════════════════════════╝"
echo -e "\e[0m"

echo -e "\e[1;32m[+] Starting ReconMaster installation for Termux...\e[0m"

# Check if running in Termux
if [ ! -d "/data/data/com.termux/files/usr" ]; then
    echo -e "\e[1;31m[!] Error: This script must be run in Termux!\e[0m"
    echo -e "\e[1;33m[!] Install Termux from: https://f-droid.org/en/packages/com.termux/\e[0m"
    exit 1
fi

# Update Termux packages
echo -e "\e[1;36m[*] Updating Termux packages...\e[0m"
pkg update -y && pkg upgrade -y

# Install essential packages
echo -e "\e[1;36m[*] Installing essential packages...\e[0m"
pkg install -y \
    python \
    python-pip \
    git \
    curl \
    wget \
    dnsutils \
    net-tools \
    nano \
    vim

# Clone ReconMaster repository
echo -e "\e[1;36m[*] Cloning ReconMaster repository...\e[0m"
if [ -d "ReconMaster" ]; then
    echo -e "\e[1;33m[!] ReconMaster directory exists, updating...\e[0m"
    cd ReconMaster
    git pull origin main
else
    git clone https://github.com/abdulcybort/ReconMaster.git
    cd ReconMaster
fi

# Install Python dependencies
echo -e "\e[1;36m[*] Installing Python dependencies...\e[0m"
pip install --upgrade pip
pip install \
    requests \
    urllib3 \
    dnspython \
    colorama

# Optional: Install lightweight async support
echo -e "\e[1;36m[*] Installing optional packages for better performance...\e[0m"
pip install \
    aiohttp \
    tqdm

# Make recon_master.py executable
echo -e "\e[1;36m[*] Setting up executable permissions...\e[0m"
chmod +x recon_master.py

# Create default config file if it doesn't exist
if [ ! -f "config.json" ]; then
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
    echo -e "\e[1;33m[!] Please edit config.json to add your API keys\e[0m"
fi

# Create Termux shortcuts
echo -e "\e[1;36m[*] Creating Termux shortcuts...\e[0m"

# Create alias in bashrc
if ! grep -q "reconmaster" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# ReconMaster Aliases" >> ~/.bashrc
    echo "alias recon='cd ~/ReconMaster && python recon_master.py'" >> ~/.bashrc
    echo "alias recon-quick='cd ~/ReconMaster && python recon_master.py --quick'" >> ~/.bashrc
    echo "alias recon-setup='cd ~/ReconMaster && python recon_master.py --setup'" >> ~/.bashrc
fi

# Create help script
cat > recon-help.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   RECONMASTER - TERMUX HELP                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Available Commands:                                         ║"
echo "║    recon                    - Go to ReconMaster and start    ║"
echo "║    recon-quick              - Quick scan mode                ║"
echo "║    recon-setup              - API setup wizard               ║"
echo "║    cd ~/ReconMaster         - Navigate to ReconMaster        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Example Usage:                                              ║"
echo "║    recon -t example.com --quick                              ║"
echo "║    recon -t example.com --enum-subs                          ║"
echo "║    recon -t 8.8.8.8 --risk-assessment                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
EOF
chmod +x recon-help.sh

# Ask for storage permission (optional)
echo -e "\e[1;36m[*] Setting up storage permissions...\e[0m"
echo -e "\e[1;33m[?] Do you want to grant storage permissions? (y/n): \e[0m"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    termux-setup-storage
    echo -e "\e[1;32m[+] Storage permission granted!\e[0m"
else
    echo -e "\e[1;33m[!] Storage permission skipped. Results saved in ~/ReconMaster/\e[0m"
fi

# Installation complete
echo -e "\e[1;32m[+] Installation complete!\e[0m"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo -e "\e[1;36mQUICK START GUIDE FOR TERMUX:\e[0m"
echo ""
echo -e "\e[1;32m1. Restart Termux or run:\e[0m"
echo -e "   \e[1;37msource ~/.bashrc\e[0m"
echo ""
echo -e "\e[1;32m2. Quick commands now available:\e[0m"
echo -e "   \e[1;37mrecon           - Launch ReconMaster\e[0m"
echo -e "   \e[1;37mrecon-quick     - Quick scan mode\e[0m"
echo -e "   \e[1;37mrecon-setup     - Configure API keys\e[0m"
echo ""
echo -e "\e[1;32m3. Basic usage:\e[0m"
echo -e "   \e[1;37mrecon -t example.com --quick\e[0m"
echo -e "   \e[1;37mrecon -t example.com --enum-subs\e[0m"
echo -e "   \e[1;37mrecon -t 8.8.8.8 --risk-assessment\e[0m"
echo ""
echo -e "\e[1;32m4. For Termux optimization:\e[0m"
echo -e "   • Use \e[1;37m--quick\e[0m mode for faster scans"
echo -e "   • Save output with \e[1;37m-o results.json\e[0m"
echo -e "   • Avoid heavy scans on mobile data"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo ""
echo -e "\e[1;35mRecommended API Services for Mobile:\e[0m"
echo -e "• Shodan (Essential) - https://account.shodan.io/"
echo -e "• IPInfo - https://ipinfo.io/ (Fast, good for mobile)"
echo -e "• VirusTotal - https://www.virustotal.com/"
echo ""
echo -e "\e[1;33m════════════════════════════════════════════════════════════════\e[0m"
echo -e "\e[1;32mHappy Hacking from your Android device! - Abdulbasid Yakubu | cy30rt\e[0m"
echo ""
echo -e "\e[1;33m[!] Note: Some features may be limited on mobile. Use --quick for best results.\e[0m"
