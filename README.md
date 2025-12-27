# 🔍 ReconMaster

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Termux-red.svg)

**Professional Bug Bounty Reconnaissance Tool**

Multi-API intelligence gathering for security researchers and bug bounty hunters

</div>

---

## 🎯 Overview

**ReconMaster** is a powerful reconnaissance tool that combines data from Shodan, SecurityTrails, IPInfo, and VirusTotal to provide comprehensive target intelligence.

## ✨ Features

- 🔍 **Shodan Integration** - Port scanning, service detection, vulnerabilities
- 🌐 **SecurityTrails Integration** - Subdomain enumeration, DNS history
- 📍 **IPInfo Integration** - Geolocation, ASN information
- 🛡️ **VirusTotal Integration** - Malware analysis, reputation checks
- 🎨 **Beautiful CLI** - Color-coded, professional interface
- 💾 **JSON Export** - Save results for further analysis
- 🖥️ **Cross-Platform** - Works on Kali Linux and Termux

## 📦 Installation

### Quick Install
```bash
git clone https://github.com/yourusername/ReconMaster.git
cd ReconMaster
chmod +x install.sh
./install.sh
```

### Manual Install
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip -y
pip3 install -r requirements.txt

# Make executable
chmod +x recon_master.py
```

## ⚙️ Configuration

Run the setup wizard:
```bash
python3 recon_master.py --setup
```

Or manually edit `config.json` with your API keys.

## 📖 Usage

### Basic Scan
```bash
python3 recon_master.py -t example.com
```

### IP Address Scan
```bash
python3 recon_master.py -t 8.8.8.8
```

### Get Help
```bash
python3 recon_master.py -h
```

## 🔑 API Keys

You'll need free API keys from:

1. **Shodan** - https://account.shodan.io/
2. **SecurityTrails** - https://securitytrails.com/
3. **IPInfo** - https://ipinfo.io/
4. **VirusTotal** - https://www.virustotal.com/

## 📊 Output

Results are saved as JSON files:
- Filename: `recon_TARGET_TIMESTAMP.json`
- Contains all gathered intelligence
- Easy to parse and analyze

## ⚖️ Legal Disclaimer

**This tool is for authorized security testing only.**

- Only scan targets you have permission to test
- Unauthorized access is illegal
- Respect API terms of service
- Follow responsible disclosure practices

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please open an issue or pull request.

---

**Made with ❤️ for Bug Bounty Hunters**
