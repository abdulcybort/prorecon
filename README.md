🎯 ReconMaster IP - IP & Subdomain Reconnaissance Tool
<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Termux-red.svg)

Focused IP & Subdomain Intelligence Gathering

Created by Abdulbasid Yakubu | cy30rt

Fast, focused reconnaissance for IP addresses and subdomains - perfect for network reconnaissance and asset discovery

Features • Quick Start • IP Scanning • Subdomain Enumeration • Examples

</div>
📋 Table of Contents
Overview

✨ Features

🚀 Quick Start

📦 Installation

🎯 IP Scanning

🌐 Subdomain Enumeration

⚙️ Configuration

📊 Output & Reports

💡 Examples

🔧 Troubleshooting

🤝 Contributing

⚖️ Legal Disclaimer

👤 Author

📄 License

🎯 Overview
ReconMaster IP v2.0.0 is a streamlined, focused reconnaissance tool designed specifically for IP address intelligence and subdomain enumeration. Unlike generic reconnaissance tools, ReconMaster IP specializes in two critical areas of security reconnaissance:

Why ReconMaster IP?
🎯 Focused Expertise: Specialized in IP and subdomain reconnaissance only

⚡ Lightning Fast: Optimized for speed with parallel processing

🎨 Clean Interface: Professional, color-coded output with actionable insights

🔧 Simple to Use: Intuitive command-line interface with minimal configuration

📊 Actionable Intelligence: Focuses on practical, useful information for security assessments

🚀 Production Ready: Battle-tested for real-world security operations

✨ Features
🎯 IP Address Intelligence
🔍 Multi-Source IP Analysis:

Shodan integration for ports, services, and vulnerabilities

IPInfo for geolocation and organization data

VirusTotal for security reputation and threat analysis

Basic port scanning for common services

Reverse DNS lookup to find associated domains

📊 Risk Assessment:

Automated risk scoring based on multiple factors

Malicious IP detection via VirusTotal

Risky port identification (FTP, Telnet, RDP, etc.)

Hosting provider detection

Private IP (RFC1918) identification

⚡ Performance:

Parallel port scanning (50 threads by default)

Batch IP scanning support

CIDR notation and IP range scanning

Smart rate limiting to avoid bans

🌐 Subdomain Enumeration
🔍 Multi-Source Discovery:

Certificate Transparency logs (crt.sh)

HackerTarget API integration

ThreatCrowd threat intelligence

Active DNS brute force with 150+ common subdomains

Parallel DNS resolution for speed

📊 Comprehensive Results:

IP resolution for all discovered subdomains

Source attribution (know where each subdomain was found)

Statistics and summary reports

Clean, organized output

⚡ Speed Optimized:

50-thread DNS brute force

Parallel API queries

Intelligent caching and rate limiting

Progress indicators for large scans

🎨 User Experience
Professional ASCII banner with version info

Color-coded terminal output for easy reading

Real-time progress indicators

Interactive setup wizard for API keys

Auto-generated timestamped reports

Clear, actionable summaries

JSON export for automation

🔧 Technical Excellence
Cross-Platform: Works on Kali Linux, Ubuntu, Termux (Android)

Minimal Dependencies: Only requests and dnspython required

Error Resilient: Graceful degradation on API failures

Configurable: Adjustable threads, timeouts, and verbosity

Modular Design: Easy to extend with new features

Clean Code: Well-documented, PEP-8 compliant Python

🚀 Quick Start
Install in 60 Seconds
bash
# Clone the repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install dependencies
pip3 install requests dnspython

# Run setup (optional but recommended)
python3 recon_master.py --setup

# Start scanning!
python3 recon_master.py --ip 8.8.8.8
Most Common Commands
bash
# Single IP scan
python3 recon_master.py --ip 8.8.8.8

# IP scan with port scanning
python3 recon_master.py --ip 8.8.8.8 --port-scan

# Subdomain enumeration
python3 recon_master.py --domain example.com

# Scan IP range
python3 recon_master.py --ip-range 192.168.1.1-192.168.1.10

# Scan CIDR block
python3 recon_master.py --cidr 192.168.1.0/24
📦 Installation
Standard Installation (Linux/Termux)
bash
# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install Python dependencies
pip3 install requests dnspython

# Make executable
chmod +x recon_master.py
Termux (Android) Installation
bash
# Update packages
pkg update && pkg upgrade

# Install Python and git
pkg install python git

# Clone repository
git clone https://github.com/cy30rt/ReconMaster.git
cd ReconMaster

# Install dependencies
pip install requests dnspython

# Make executable
chmod +x recon_master.py

# Optional: Add to PATH
cp recon_master.py $PREFIX/bin/reconmaster
Dependencies
Required:

requests >= 2.25.1

dnspython >= 2.1.0

Optional (for API features):

Shodan API key

IPInfo API key

VirusTotal API key

🎯 IP Scanning
Single IP Scan
bash
python3 recon_master.py --ip 8.8.8.8
What it checks:

Shodan intelligence (ports, services, vulnerabilities)

IPInfo geolocation and organization data

VirusTotal security reputation

Reverse DNS lookup

Private IP detection

IP Scan with Port Scanning
bash
python3 recon_master.py --ip 8.8.8.8 --port-scan
Ports scanned (21 common ports):

Web: 80 (HTTP), 443 (HTTPS), 8080, 8443

Remote Access: 22 (SSH), 3389 (RDP), 5900 (VNC)

File Services: 21 (FTP), 139 (NetBIOS), 445 (SMB)

Email: 25 (SMTP), 110 (POP3), 143 (IMAP), 993, 995

Database: 3306 (MySQL)

DNS: 53

Other: 23 (Telnet), 111 (RPC), 135 (MSRPC), 1723 (PPTP)

Batch IP Scanning
bash
# IP Range
python3 recon_master.py --ip-range 192.168.1.1-192.168.1.10

# CIDR Notation
python3 recon_master.py --cidr 192.168.1.0/24

# Multiple IPs (comma-separated)
# Note: Modify the script or use shell expansion
for ip in 8.8.8.8 1.1.1.1 9.9.9.9; do
    python3 recon_master.py --ip $ip
done
Risk Assessment
ReconMaster IP calculates risk scores based on:

+50 points: Malicious detection by VirusTotal

+30 points: Suspicious detection by VirusTotal

+10 points per risky port: FTP, Telnet, RDP, etc.

Private IP detection: Warning for RFC1918 addresses

Hosting provider detection: Alerts for cloud/VPS IPs

Risk Levels:

🔴 HIGH (50+): Malicious IP or multiple risky ports

🟠 MEDIUM (30-49): Suspicious detection or some risky ports

🟡 LOW (1-29): Minor issues or information only

🟢 LOW (0): No significant issues detected

🌐 Subdomain Enumeration
Basic Subdomain Discovery
bash
python3 recon_master.py --domain example.com
Sources used:

crt.sh: Certificate Transparency logs

HackerTarget: Public API for subdomains

ThreatCrowd: Threat intelligence feed

DNS Brute Force: 150+ common subdomains

Process Flow
text
Phase 1: Passive Discovery
  → crt.sh certificate search
  → HackerTarget API query
  → ThreatCrowd intelligence

Phase 2: Active DNS Brute Force
  → 150+ common subdomains
  → 50-thread parallel resolution
  → Active host detection

Phase 3: IP Resolution
  → Resolve all subdomains to IPs
  → Map subdomain → IP relationships
  → Identify unique IP addresses
Sample Output
text
═══════════════════════════════════════════════
  SUBDOMAIN ENUMERATION
═══════════════════════════════════════════════
  Target: example.com
═══════════════════════════════════════════════

[*] Phase 1: Passive Discovery
[+] crt.sh: Found 15 subdomains
[+] HackerTarget: Found 8 subdomains
[+] ThreatCrowd: Found 5 subdomains

[*] Phase 2: DNS Brute Force
[+] DNS Brute Force: Found 12 active subdomains

[*] Phase 3: IP Resolution
  www.example.com -> 93.184.216.34
  mail.example.com -> 93.184.216.35
  api.example.com -> 93.184.216.36

═══════════════════════════════════════════════
  ENUMERATION COMPLETE
═══════════════════════════════════════════════

📊 Statistics:
  Total Subdomains: 40
  Unique IP Addresses: 12
  Subdomains with IPs: 35
⚙️ Configuration
API Setup Wizard
bash
python3 recon_master.py --setup
The interactive wizard will guide you through configuring:

Shodan API (network intelligence)

IPInfo API (geolocation data)

VirusTotal API (security reputation)

All APIs are optional - the tool works without them, but with enhanced capabilities when configured.

Manual Configuration
Edit config.json:

json
{
    "shodan": "YOUR_SHODAN_API_KEY",
    "ipinfo": "YOUR_IPINFO_API_KEY",
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY"
}
Getting Free API Keys
API	Free Tier	Use Case	Sign-up URL
Shodan	Limited queries	Port scanning, vulnerabilities	shodan.io
IPInfo	50k/month	Geolocation, organization	ipinfo.io
VirusTotal	4/minute	Security reputation	virustotal.com
📊 Output & Reports
Console Output
text
═══════════════════════════════════════════════
  IP RECONNAISSANCE REPORT
═══════════════════════════════════════════════
  Target: 8.8.8.8
  Scan Time: 2024-01-15 14:30:22
═══════════════════════════════════════════════

[*] Querying Shodan database...
[+] Shodan: Data retrieved successfully
    IP: 8.8.8.8
    Organization: Google LLC
    Country: United States
    Open Ports: 53

[*] Querying IPInfo database...
[+] IPInfo: Geolocation data retrieved
    Hostname: dns.google
    City: Mountain View
    Region: California
    Country: US

📊 Risk Assessment:
  Risk Level: 🟢 LOW RISK
  Risk Score: 0

[+] Results saved to: ip_scan_8_8_8_8_20240115_143022.json
JSON Report Structure
json
{
  "target": "8.8.8.8",
  "timestamp": "2024-01-15T14:30:22.123456",
  "is_valid": true,
  "is_private": false,
  "shodan": {
    "ip_str": "8.8.8.8",
    "org": "Google LLC",
    "country_name": "United States",
    "ports": [53]
  },
  "ipinfo": {
    "ip": "8.8.8.8",
    "hostname": "dns.google",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "loc": "37.4056,-122.0775",
    "org": "AS15169 Google LLC"
  },
  "virustotal": {
    "data": {
      "attributes": {
        "last_analysis_stats": {
          "malicious": 0,
          "suspicious": 0,
          "harmless": 72
        }
      }
    }
  },
  "port_scan": {
    "open_ports": [53],
    "port_services": {
      "53": "DNS"
    }
  },
  "reverse_dns": {
    "ptr_records": ["dns.google"],
    "domains_found": ["dns.google"]
  }
}
File Naming Convention
IP Scans: ip_scan_8_8_8_8_20240115_143022.json

Subdomain Scans: subdomains_example_com_20240115_143022.json

Batch Scans: ip_scan_batch_20240115_143022.json

Location: Current working directory

💡 Examples
Example 1: Basic IP Intelligence
bash
python3 recon_master.py --ip 1.1.1.1
Use case: Quick IP lookup for threat intelligence or network reconnaissance.

Example 2: Full IP Assessment
bash
python3 recon_master.py --ip 192.168.1.1 --port-scan
Use case: Internal network assessment or penetration testing.

Example 3: Subdomain Discovery
bash
python3 recon_master.py --domain example.com
Use case: Bug bounty reconnaissance or asset inventory.

Example 4: Network Range Scan
bash
python3 recon_master.py --cidr 192.168.1.0/24
Use case: Internal network mapping or security audit.

Example 5: Custom Output File
bash
python3 recon_master.py --ip 8.8.8.8 -o my_scan_results.json
Use case: Integration with other tools or reporting.

Command Reference
bash
# Basic usage
python3 recon_master.py --ip TARGET_IP
python3 recon_master.py --domain TARGET_DOMAIN

# Advanced options
python3 recon_master.py --ip 8.8.8.8 --port-scan --threads 100
python3 recon_master.py --ip-range 192.168.1.1-192.168.1.20
python3 recon_master.py --cidr 10.0.0.0/16

# Setup and help
python3 recon_master.py --setup
python3 recon_master.py --help
🔧 Troubleshooting
Common Issues & Solutions
"Module not found" errors
bash
# Install missing dependencies
pip3 install requests dnspython

# On Termux
pip install requests dnspython
API key errors
bash
# Run setup wizard
python3 recon_master.py --setup

# Or edit config.json manually
nano config.json
Permission denied
bash
chmod +x recon_master.py
Slow DNS resolution
bash
# Check your DNS server
cat /etc/resolv.conf

# Try using Google DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
Rate limiting issues
Wait between scans

Consider API plan upgrades

Use fewer concurrent threads

Termux-Specific Issues
bash
# SSL errors
pkg install openssl-tool

# Storage permissions
termux-setup-storage

# Python path
python recon_master.py --ip 8.8.8.8  # Use python, not python3
Debug Mode
For detailed troubleshooting:

bash
# Check Python version
python3 --version

# Verify dependencies
pip3 list | grep -E "requests|dnspython"

# Test basic connectivity
ping -c 1 8.8.8.8
🤝 Contributing
How to Contribute
Fork the repository

Create a feature branch: git checkout -b feature/AmazingFeature

Commit your changes: git commit -m 'Add AmazingFeature'

Push to the branch: git push origin feature/AmazingFeature

Open a Pull Request

Development Guidelines
Follow PEP 8 Python style guidelines

Add comprehensive comments for complex logic

Update documentation for new features

Test on both Kali Linux and Termux

Ensure backward compatibility

Add error handling for new features

Areas for Contribution
Additional IP intelligence sources

Enhanced port scanning capabilities

More subdomain enumeration sources

Performance optimizations

New output formats (CSV, HTML, PDF)

GUI interface

Docker containerization

⚖️ Legal Disclaimer
IMPORTANT: READ BEFORE USE
This tool is for educational and authorized security testing purposes only.

✅ Permitted Uses
Testing systems you own or manage

Authorized penetration testing

Bug bounty programs with explicit permission

Educational and research purposes

Security awareness training

Internal security assessments with proper authorization

❌ Prohibited Uses
Unauthorized access to computer systems

Violating laws or regulations

Disrupting services or networks

Malicious activities

Privacy violations

Scanning without explicit permission

Legal Compliance
By using this tool, you agree to:

Obtain proper authorization before scanning

Comply with all applicable laws

Respect API terms of service

Follow responsible disclosure practices

Accept full responsibility for your actions

No Warranty
This software is provided "as is" without warranty of any kind. The author assumes no liability for damages resulting from use of this tool.

Responsible Disclosure
If you discover vulnerabilities using this tool:

Do not exploit or share them publicly

Report them to the appropriate security team

Follow the organization's disclosure policy

Allow reasonable time for remediation

Respect bug bounty program rules

👤 Author
Abdulbasid Yakubu | cy30rt

Professional Bug Bounty Hunter & Security Researcher

ReconMaster IP was created to provide a focused, efficient tool for IP and subdomain reconnaissance - two of the most critical aspects of security assessment.

Connect
GitHub: @cy30rt

Twitter: @cy30rt

Professional: Active on major bug bounty platforms

Acknowledgments
Special thanks to:

The security community for feedback and testing

API providers for their excellent services

Open source contributors and maintainers

Everyone who supports ethical security research

📄 License
This project is licensed under the MIT License.

text
MIT License

Copyright (c) 2024 Abdulbasid Yakubu | cy30rt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
📈 Roadmap
v2.1.0 (Next Release)
Additional IP intelligence sources

Enhanced port scanning with service detection

More subdomain enumeration sources

Performance improvements

v2.2.0
HTTP/HTTPS service detection

Banner grabbing for open ports

Technology stack fingerprinting

Basic vulnerability checks

v3.0.0 (Future)
Web interface

API endpoint for automation

Scheduled scanning

Advanced reporting features

<div align="center">
Made with ❤️ by Abdulbasid Yakubu | cy30rt

Focused Reconnaissance for Security Professionals

Version 2.0.0 - IP & Subdomain Focused

⭐ If you find this tool useful, please give it a star on GitHub! ⭐

Stay Curious, Stay Secure! 🔍🔒

</div>
