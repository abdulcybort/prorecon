#!/usr/bin/env python3

"""
ReconMaster - Professional Bug Bounty Reconnaissance Tool
Author: Abdulbasid Yakubu | cy30rt
Version: 3.0.0 - Advanced Edition
"""

import os
import sys
import json
import time
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import urllib3
import concurrent.futures
from urllib.parse import urlparse
import socket
import ssl
import warnings
import asyncio

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Config:
    """Configuration manager for API keys"""
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), 'config.json')
        self.apis = self.load_config()
    
    def load_config(self) -> Dict:
        """Load API keys from config file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"{Colors.RED}[!] Error loading config: {e}{Colors.END}")
                return {}
        return {}
    
    def save_config(self, apis: Dict):
        """Save API keys to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(apis, f, indent=4)
            print(f"{Colors.GREEN}[+] Configuration saved successfully!{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving config: {e}{Colors.END}")

class PortScanner:
    """Simple port scanner for discovered hosts"""
    
    def __init__(self, timeout=1):
        self.timeout = timeout
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                           993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 27017, 5432]
    
    def scan_port(self, host: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_host(self, host: str, ports: List[int] = None) -> Dict:
        """Scan common ports on a host"""
        if ports is None:
            ports = self.common_ports
        
        print(f"{Colors.BLUE}[*] Scanning ports on {host}...{Colors.END}")
        
        open_ports = []
        for port in ports:
            if self.scan_port(host, port):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append({'port': port, 'service': service})
                print(f"{Colors.GREEN}[+] Port {port}/tcp OPEN - {service}{Colors.END}")
        
        if not open_ports:
            print(f"{Colors.YELLOW}[!] No open ports found on common port list{Colors.END}")
        
        return {
            'host': host,
            'open_ports': open_ports,
            'total_scanned': len(ports),
            'timestamp': datetime.now().isoformat()
        }

class SubdomainEnumerator:
    """Advanced subdomain enumeration engine"""
    
    def __init__(self, domain: str, config: Config = None):
        self.domain = domain
        self.config = config or Config()
        self.subdomains = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Rate limiting tracking
        self.rate_limits = {}
        self.failed_apis = set()
        
        # Create SSL context that doesn't verify certificates for problematic APIs
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Common subdomain wordlist
        self.common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
            'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta',
            'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
            'images', 'img', 'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns4', 'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat',
            'wap', 'my', 'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums', 'store',
            'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office',
            'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2', 'ntp', 'monitor', 'login',
            'service', 'correo', 'www4', 'moodle', 'it', 'gateway', 'gw', 'i', 'stat', 'stage',
            'ldap', 'tv', 'ssl', 'web1', 'tracker', 'web2', 'finance', 'upload', 'billing',
            'video1', 'registration', 'jobs', 'jenkins', 'jira', 'confluence', 'gitlab', 'github'
        ]
    
    def resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to IP address"""
        try:
            ip = socket.gethostbyname(subdomain)
            return ip
        except:
            return None
    
    def fetch_with_retry(self, url: str, max_retries: int = 3, 
                         use_ssl: bool = True, headers: dict = None) -> Optional[requests.Response]:
        """Fetch URL with retry logic and SSL handling"""
        for attempt in range(max_retries):
            try:
                if not use_ssl:
                    # Use HTTP instead of HTTPS
                    url = url.replace('https://', 'http://')
                
                if headers:
                    response = self.session.get(url, timeout=20, headers=headers, 
                                               verify=use_ssl)
                else:
                    response = self.session.get(url, timeout=20, verify=use_ssl)
                
                if response.status_code == 429:  # Rate limited
                    wait_time = (2 ** attempt) * 5  # Exponential backoff
                    print(f"{Colors.YELLOW}[!] Rate limited, waiting {wait_time}s...{Colors.END}")
                    time.sleep(wait_time)
                    continue
                
                return response
                
            except requests.exceptions.SSLError:
                if attempt == max_retries - 1:
                    raise
                # Try without SSL on next attempt
                use_ssl = False
                print(f"{Colors.YELLOW}[!] SSL error, trying HTTP...{Colors.END}")
                
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return None
    
    def crtsh_search(self) -> List[Dict]:
        """Search crt.sh certificate transparency logs"""
        print(f"{Colors.BLUE}[*] Searching Certificate Transparency logs (crt.sh)...{Colors.END}")
        found = []
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                data = response.json()
                unique_subs = set()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().lower()
                            if n.endswith(self.domain) and n != self.domain:
                                n = n.replace('*.', '')
                                unique_subs.add(n)
                
                # Resolve IPs
                for sub in unique_subs:
                    ip = self.resolve_subdomain(sub)
                    found.append({
                        'subdomain': sub,
                        'ip': ip if ip else 'Not resolved',
                        'source': 'crt.sh'
                    })
                
                print(f"{Colors.GREEN}[+] crt.sh: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] crt.sh: No data returned{Colors.END}")
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] crt.sh error: {str(e)}{Colors.END}")
            self.failed_apis.add('crt.sh')
            return []
    
    def hackertarget_search(self) -> List[Dict]:
        """Search HackerTarget API"""
        print(f"{Colors.BLUE}[*] Querying HackerTarget API...{Colors.END}")
        found = []
        
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200 and 'error' not in response.text.lower():
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        parts = line.split(',')
                        subdomain = parts[0].strip()
                        ip = parts[1].strip() if len(parts) > 1 else None
                        
                        if subdomain and subdomain.endswith(self.domain):
                            found.append({
                                'subdomain': subdomain,
                                'ip': ip if ip else 'Not resolved',
                                'source': 'hackertarget'
                            })
                
                print(f"{Colors.GREEN}[+] HackerTarget: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] HackerTarget: Rate limited or no data{Colors.END}")
                self.failed_apis.add('hackertarget')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] HackerTarget error: {str(e)}{Colors.END}")
            self.failed_apis.add('hackertarget')
            return []
    
    def threatcrowd_search(self) -> List[Dict]:
        """Search ThreatCrowd API with SSL fix"""
        print(f"{Colors.BLUE}[*] Querying ThreatCrowd API...{Colors.END}")
        found = []
        
        try:
            # Try HTTPS first, fall back to HTTP
            urls = [
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
                f"http://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            ]
            
            response = None
            for url in urls:
                try:
                    response = self.session.get(url, timeout=20, verify=False)
                    if response.status_code == 200:
                        break
                except:
                    continue
            
            if response and response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                
                for sub in subdomains:
                    if sub.endswith(self.domain):
                        ip = self.resolve_subdomain(sub)
                        found.append({
                            'subdomain': sub,
                            'ip': ip if ip else 'Not resolved',
                            'source': 'threatcrowd'
                        })
                
                print(f"{Colors.GREEN}[+] ThreatCrowd: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] ThreatCrowd: No data returned{Colors.END}")
                self.failed_apis.add('threatcrowd')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] ThreatCrowd error: {str(e)}{Colors.END}")
            self.failed_apis.add('threatcrowd')
            return []
    
    def alienvault_search(self) -> List[Dict]:
        """Search AlienVault OTX API with SSL fix"""
        print(f"{Colors.BLUE}[*] Querying AlienVault OTX...{Colors.END}")
        found = []
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = self.session.get(url, timeout=20, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(self.domain) and hostname != self.domain:
                        ip = entry.get('address', None)
                        found.append({
                            'subdomain': hostname,
                            'ip': ip if ip else 'Not resolved',
                            'source': 'alienvault'
                        })
                
                print(f"{Colors.GREEN}[+] AlienVault: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] AlienVault: No data returned{Colors.END}")
                self.failed_apis.add('alienvault')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] AlienVault error: {str(e)}{Colors.END}")
            self.failed_apis.add('alienvault')
            return []
    
    def urlscan_search(self) -> List[Dict]:
        """Search URLScan.io API"""
        print(f"{Colors.BLUE}[*] Querying URLScan.io...{Colors.END}")
        found = []
        
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                data = response.json()
                unique_subs = set()
                
                for result in data.get('results', []):
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain and page_domain.endswith(self.domain) and page_domain != self.domain:
                        unique_subs.add(page_domain)
                
                for sub in unique_subs:
                    ip = self.resolve_subdomain(sub)
                    found.append({
                        'subdomain': sub,
                        'ip': ip if ip else 'Not resolved',
                        'source': 'urlscan'
                    })
                
                print(f"{Colors.GREEN}[+] URLScan: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] URLScan: No data returned{Colors.END}")
                self.failed_apis.add('urlscan')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] URLScan error: {str(e)}{Colors.END}")
            self.failed_apis.add('urlscan')
            return []
    
    def anubis_search(self) -> List[Dict]:
        """Search AnubisDB API - Very reliable"""
        print(f"{Colors.BLUE}[*] Querying AnubisDB API...{Colors.END}")
        found = []
        
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                subdomains = response.json()
                for sub in subdomains:
                    if sub.endswith(self.domain):
                        ip = self.resolve_subdomain(sub)
                        found.append({
                            'subdomain': sub,
                            'ip': ip if ip else 'Not resolved',
                            'source': 'anubisdb'
                        })
                
                print(f"{Colors.GREEN}[+] AnubisDB: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] AnubisDB: No data returned{Colors.END}")
                self.failed_apis.add('anubisdb')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] AnubisDB error: {str(e)}{Colors.END}")
            self.failed_apis.add('anubisdb')
            return []
    
    def bufferover_search(self) -> List[Dict]:
        """Search BufferOver.run API"""
        print(f"{Colors.BLUE}[*] Querying BufferOver.run DNS...{Colors.END}")
        found = []
        
        try:
            # Disable SSL warnings for this request
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                
                url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
                response = self.session.get(url, timeout=30, verify=False)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parse FDNS_A and RDNS records
                    records = []
                    if data.get('FDNS_A'):
                        records.extend(data['FDNS_A'])
                    if data.get('RDNS'):
                        records.extend(data['RDNS'])
                    
                    seen = set()
                    for record in records:
                        if ',' in record:
                            parts = record.split(',')
                            if len(parts) >= 2:
                                subdomain = parts[1].strip()
                                if (subdomain.endswith(self.domain) and 
                                    subdomain not in seen and 
                                    subdomain != self.domain):
                                    seen.add(subdomain)
                                    ip = self.resolve_subdomain(subdomain)
                                    found.append({
                                        'subdomain': subdomain,
                                        'ip': ip if ip else parts[0].strip(),
                                        'source': 'bufferover'
                                    })
                    
                    print(f"{Colors.GREEN}[+] BufferOver.run: Found {len(found)} subdomains{Colors.END}")
                    return found
                else:
                    print(f"{Colors.YELLOW}[!] BufferOver.run: No data returned{Colors.END}")
                    self.failed_apis.add('bufferover')
                    return []
        except Exception as e:
            print(f"{Colors.RED}[!] BufferOver.run error: {str(e)}{Colors.END}")
            self.failed_apis.add('bufferover')
            return []
    
    def rapiddns_search(self) -> List[Dict]:
        """Search RapidDNS API"""
        print(f"{Colors.BLUE}[*] Querying RapidDNS...{Colors.END}")
        found = []
        
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                # Parse HTML response (RapidDNS returns HTML)
                import re
                pattern = r'<td>([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+)</td>'
                subdomains = re.findall(pattern, response.text)
                
                for sub in subdomains:
                    if sub.endswith(self.domain) and sub != self.domain:
                        ip = self.resolve_subdomain(sub)
                        found.append({
                            'subdomain': sub,
                            'ip': ip if ip else 'Not resolved',
                            'source': 'rapiddns'
                        })
                
                print(f"{Colors.GREEN}[+] RapidDNS: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] RapidDNS: No data returned{Colors.END}")
                self.failed_apis.add('rapiddns')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] RapidDNS error: {str(e)}{Colors.END}")
            self.failed_apis.add('rapiddns')
            return []
    
    def certspotter_search(self) -> List[Dict]:
        """Search CertSpotter API"""
        print(f"{Colors.BLUE}[*] Querying CertSpotter...{Colors.END}")
        found = []
        
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                data = response.json()
                seen = set()
                
                for entry in data:
                    for dns_name in entry.get('dns_names', []):
                        if (dns_name.endswith(self.domain) and 
                            dns_name != self.domain and 
                            dns_name not in seen):
                            seen.add(dns_name)
                            ip = self.resolve_subdomain(dns_name)
                            found.append({
                                'subdomain': dns_name,
                                'ip': ip if ip else 'Not resolved',
                                'source': 'certspotter'
                            })
                
                print(f"{Colors.GREEN}[+] CertSpotter: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] CertSpotter: No data returned{Colors.END}")
                self.failed_apis.add('certspotter')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] CertSpotter error: {str(e)}{Colors.END}")
            self.failed_apis.add('certspotter')
            return []
    
    def facebook_ct_search(self) -> List[Dict]:
        """Search Facebook Certificate Transparency logs"""
        print(f"{Colors.BLUE}[*] Querying Facebook CT logs...{Colors.END}")
        found = []
        
        try:
            url = f"https://api.facebook.com/certificate_transparency/search?domain={self.domain}"
            response = self.fetch_with_retry(url, use_ssl=True)
            
            if response and response.status_code == 200:
                data = response.json()
                seen = set()
                
                for entry in data.get('data', []):
                    domains = entry.get('domains', [])
                    for domain in domains:
                        if (domain.endswith(self.domain) and 
                            domain != self.domain and 
                            domain not in seen):
                            seen.add(domain)
                            ip = self.resolve_subdomain(domain)
                            found.append({
                                'subdomain': domain,
                                'ip': ip if ip else 'Not resolved',
                                'source': 'facebook_ct'
                            })
                
                print(f"{Colors.GREEN}[+] Facebook CT: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] Facebook CT: No data returned{Colors.END}")
                self.failed_apis.add('facebook_ct')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] Facebook CT error: {str(e)}{Colors.END}")
            self.failed_apis.add('facebook_ct')
            return []
    
    def virustotal_search(self) -> List[Dict]:
        """Search VirusTotal API (requires API key)"""
        print(f"{Colors.BLUE}[*] Querying VirusTotal...{Colors.END}")
        found = []
        
        api_key = self.config.apis.get('virustotal')
        if not api_key:
            print(f"{Colors.YELLOW}[!] VirusTotal API key not configured - skipping{Colors.END}")
            self.failed_apis.add('virustotal')
            return []
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {'x-apikey': api_key}
            response = self.fetch_with_retry(url, use_ssl=True, headers=headers)
            
            if response and response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain and subdomain.endswith(self.domain) and subdomain != self.domain:
                        ip = self.resolve_subdomain(subdomain)
                        found.append({
                            'subdomain': subdomain,
                            'ip': ip if ip else 'Not resolved',
                            'source': 'virustotal'
                        })
                
                print(f"{Colors.GREEN}[+] VirusTotal: Found {len(found)} subdomains{Colors.END}")
                return found
            elif response and response.status_code == 429:
                print(f"{Colors.YELLOW}[!] VirusTotal: Rate limited (free tier){Colors.END}")
                self.failed_apis.add('virustotal')
                return []
            else:
                print(f"{Colors.YELLOW}[!] VirusTotal: No data returned{Colors.END}")
                self.failed_apis.add('virustotal')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] VirusTotal error: {str(e)}{Colors.END}")
            self.failed_apis.add('virustotal')
            return []
    
    def securitytrails_subdomains(self) -> List[Dict]:
        """Get subdomains from SecurityTrails"""
        print(f"{Colors.BLUE}[*] Querying SecurityTrails for subdomains...{Colors.END}")
        found = []
        
        api_key = self.config.apis.get('securitytrails')
        if not api_key:
            print(f"{Colors.YELLOW}[!] SecurityTrails API key not configured - skipping{Colors.END}")
            self.failed_apis.add('securitytrails')
            return []
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = self.fetch_with_retry(url, use_ssl=True, headers=headers)
            
            if response and response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])
                
                for sub in subdomains:
                    full_domain = f"{sub}.{self.domain}"
                    ip = self.resolve_subdomain(full_domain)
                    found.append({
                        'subdomain': full_domain,
                        'ip': ip if ip else 'Not resolved',
                        'source': 'securitytrails'
                    })
                
                print(f"{Colors.GREEN}[+] SecurityTrails: Found {len(found)} subdomains{Colors.END}")
                return found
            else:
                print(f"{Colors.YELLOW}[!] SecurityTrails: No data returned{Colors.END}")
                self.failed_apis.add('securitytrails')
                return []
        except Exception as e:
            print(f"{Colors.RED}[!] SecurityTrails error: {str(e)}{Colors.END}")
            self.failed_apis.add('securitytrails')
            return []
    
    def brute_force(self, wordlist: List[str] = None, threads: int = 10) -> List[Dict]:
        """Brute force subdomain discovery using DNS resolution"""
        print(f"{Colors.BLUE}[*] Starting DNS brute force attack...{Colors.END}")
        
        if wordlist is None:
            wordlist = self.common_subs
        
        found = []
        
        def check_subdomain(sub):
            try:
                hostname = f"{sub}.{self.domain}"
                ip = socket.gethostbyname(hostname)
                return {'subdomain': hostname, 'ip': ip, 'source': 'dns_brute'}
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        print(f"{Colors.GREEN}[+] DNS Brute Force: Found {len(found)} active subdomains{Colors.END}")
        return found
    
    def enumerate_all_enhanced(self, brute_force: bool = True, scan_ports: bool = False) -> Dict:
        """Enhanced enumeration with multiple reliable sources"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}  ENHANCED SUBDOMAIN ENUMERATION ENGINE{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{self.domain}{Colors.END}")
        print(f"{Colors.CYAN}  Sources: 12+ APIs available{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}\n")
        
        results = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'subdomains': [],
            'port_scans': [],
            'failed_apis': []
        }
        
        all_findings = []
        
        # Phase 1: Passive enumeration (Free APIs)
        print(f"{Colors.YELLOW}[*] Phase 1: Passive Enumeration (Free APIs){Colors.END}\n")
        
        free_sources = [
            ('crtsh', self.crtsh_search),
            ('anubisdb', self.anubis_search),
            ('bufferover', self.bufferover_search),
            ('rapiddns', self.rapiddns_search),
            ('certspotter', self.certspotter_search),
            ('facebook_ct', self.facebook_ct_search),
            ('hackertarget', self.hackertarget_search),
            ('threatcrowd', self.threatcrowd_search),
            ('alienvault', self.alienvault_search),
            ('urlscan', self.urlscan_search)
        ]
        
        for source_name, source_func in free_sources:
            try:
                print(f"{Colors.BLUE}[*] Trying {source_name}...{Colors.END}")
                found = source_func()
                if found:
                    results['sources'][source_name] = len(found)
                    all_findings.extend(found)
                    print(f"{Colors.GREEN}[+] {source_name}: {len(found)} subdomains{Colors.END}")
                else:
                    results['sources'][source_name] = 0
                    print(f"{Colors.YELLOW}[!] {source_name}: No results{Colors.END}")
                
                # Small delay to avoid rate limits
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{Colors.RED}[!] {source_name} failed: {str(e)}{Colors.END}")
                results['sources'][source_name] = 0
                self.failed_apis.add(source_name)
        
        # Phase 2: API Key based enumeration
        print(f"\n{Colors.YELLOW}[*] Phase 2: API Key Based Enumeration{Colors.END}\n")
        
        api_sources = [
            ('virustotal', self.virustotal_search),
            ('securitytrails', self.securitytrails_subdomains)
        ]
        
        for source_name, source_func in api_sources:
            try:
                print(f"{Colors.BLUE}[*] Trying {source_name}...{Colors.END}")
                found = source_func()
                if found:
                    results['sources'][source_name] = len(found)
                    all_findings.extend(found)
                    print(f"{Colors.GREEN}[+] {source_name}: {len(found)} subdomains{Colors.END}")
                else:
                    results['sources'][source_name] = 0
                
                time.sleep(1)
                
            except Exception as e:
                print(f"{Colors.RED}[!] {source_name} failed: {str(e)}{Colors.END}")
                results['sources'][source_name] = 0
                self.failed_apis.add(source_name)
        
        # Phase 3: Active enumeration
        if brute_force:
            print(f"\n{Colors.YELLOW}[*] Phase 3: Active DNS Brute Force{Colors.END}\n")
            try:
                found = self.brute_force()
                results['sources']['dns_brute_force'] = len(found)
                all_findings.extend(found)
                print(f"{Colors.GREEN}[+] DNS Brute Force: {len(found)} active subdomains{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] DNS brute force failed: {str(e)}{Colors.END}")
                results['sources']['dns_brute_force'] = 0
                self.failed_apis.add('dns_brute_force')
        
        # Deduplicate and compile results
        unique_subdomains = {}
        for finding in all_findings:
            sub = finding['subdomain']
            if sub not in unique_subdomains:
                unique_subdomains[sub] = finding
            elif finding['ip'] != 'Not resolved' and unique_subdomains[sub]['ip'] == 'Not resolved':
                unique_subdomains[sub]['ip'] = finding['ip']
                # Also update source if we got a better one
                if finding['source'] not in unique_subdomains[sub].get('sources', []):
                    if 'sources' not in unique_subdomains[sub]:
                        unique_subdomains[sub]['sources'] = [unique_subdomains[sub]['source']]
                    unique_subdomains[sub]['sources'].append(finding['source'])
                    unique_subdomains[sub]['source'] = ', '.join(unique_subdomains[sub]['sources'])
        
        results['subdomains'] = list(unique_subdomains.values())
        results['total_found'] = len(unique_subdomains)
        results['failed_apis'] = list(self.failed_apis)
        
        # Port scanning
        if scan_ports and results['subdomains']:
            print(f"\n{Colors.YELLOW}[*] Phase 4: Port Scanning{Colors.END}\n")
            print(f"{Colors.CYAN}[*] Scanning {len(results['subdomains'])} hosts for open ports...{Colors.END}\n")
            
            scanner = PortScanner()
            max_to_scan = min(50, len(results['subdomains']))  # Limit to first 50
            
            for i, sub_info in enumerate(results['subdomains'][:max_to_scan], 1):
                subdomain = sub_info['subdomain']
                ip = sub_info['ip']
                
                if ip and ip != 'Not resolved':
                    print(f"{Colors.BLUE}[{i}/{max_to_scan}] {subdomain} ({ip}){Colors.END}")
                    scan_result = scanner.scan_host(ip)
                    scan_result['subdomain'] = subdomain
                    results['port_scans'].append(scan_result)
                    print()
                    time.sleep(0.2)  # Smaller delay for faster scanning
            
            if len(results['subdomains']) > max_to_scan:
                print(f"{Colors.YELLOW}[!] Limited port scanning to first {max_to_scan} subdomains{Colors.END}")
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  ENUMERATION COMPLETE{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}==============================================={Colors.END}\n")
        
        # Display statistics
        successful_sources = sum(1 for v in results['sources'].values() if v > 0)
        print(f"{Colors.CYAN}┌─────────────────────────────────────────────┐{Colors.END}")
        print(f"{Colors.CYAN}│           ENUMERATION STATISTICS           │{Colors.END}")
        print(f"{Colors.CYAN}├─────────────────────────────────────────────┤{Colors.END}")
        print(f"{Colors.CYAN}│ Total Subdomains Found: {results['total_found']:>19} │{Colors.END}")
        print(f"{Colors.CYAN}│ Successful Sources: {successful_sources:>23} │{Colors.END}")
        print(f"{Colors.CYAN}│ Failed Sources: {len(results['failed_apis']):>26} │{Colors.END}")
        
        if results['port_scans']:
            open_ports_total = sum(len(scan.get('open_ports', [])) for scan in results['port_scans'])
            print(f"{Colors.CYAN}│ Total Open Ports Found: {open_ports_total:>20} │{Colors.END}")
        
        print(f"{Colors.CYAN}└─────────────────────────────────────────────┘{Colors.END}\n")
        
        # Display top subdomains
        if results['subdomains']:
            print(f"{Colors.YELLOW}Top 30 Subdomains:{Colors.END}\n")
            sorted_subs = sorted(results['subdomains'], 
                               key=lambda x: (x['ip'] != 'Not resolved', x['subdomain']))
            
            for i, sub_info in enumerate(sorted_subs[:30], 1):
                subdomain = sub_info['subdomain']
                ip = sub_info['ip']
                source = sub_info['source']
                
                if ip != 'Not resolved':
                    print(f"  {i:2}. {Colors.GREEN}{subdomain:<40}{Colors.END}")
                    print(f"      IP: {Colors.CYAN}{ip:<15}{Colors.END} Source: {source}")
                else:
                    print(f"  {i:2}. {Colors.YELLOW}{subdomain:<40}{Colors.END}")
                    print(f"      IP: {Colors.RED}{ip:<15}{Colors.END} Source: {source}")
                print()
            
            if len(results['subdomains']) > 30:
                print(f"  ... and {len(results['subdomains']) - 30} more subdomains\n")
        
        # Display failed APIs
        if results['failed_apis']:
            print(f"{Colors.YELLOW}Failed APIs:{Colors.END}")
            for api in results['failed_apis']:
                print(f"  - {api}")
            print()
        
        return results

class ReconMaster:
    """Main reconnaissance tool class"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        self.results = {}
    
    def banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
    ╠╦╝║╣ ║  ║ ║║║║  ║║║╠═╣╚═╗ ║ ║╣ ╠╦╝
    ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╩ ╩╩ ╩╚═╝ ╩ ╚═╝╩╚═
{Colors.END}
{Colors.YELLOW}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Professional Bug Bounty Reconnaissance Tool
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
{Colors.GREEN}    Version: 3.0.0 (Advanced Edition)
    Author:  Abdulbasid Yakubu | cy30rt
{Colors.END}
{Colors.CYAN}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Subdomain Enumeration + IP Discovery + Port Scanning
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{Colors.END}
        """
        print(banner)
    
    def save_results(self, target: str):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"recon_{target.replace('.', '_')}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"\n{Colors.GREEN}[+] Results saved to: {filename}{Colors.END}")
            return filename
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}")
            return None
    
    def shodan_lookup(self, target: str) -> Dict:
        """Query Shodan API for host information"""
        print(f"\n{Colors.BLUE}[*] Querying Shodan database...{Colors.END}")
        
        api_key = self.config.apis.get('shodan')
        if not api_key or api_key == "YOUR_SHODAN_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] Shodan API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] Shodan: Data retrieved successfully{Colors.END}")
                print(f"    IP: {data.get('ip_str', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    Country: {data.get('country_name', 'N/A')}")
                print(f"    OS: {data.get('os', 'N/A')}")
                print(f"    Open Ports: {', '.join(map(str, data.get('ports', []))) if data.get('ports') else 'None'}")
                return data
            else:
                print(f"{Colors.YELLOW}[!] Shodan: No information available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] Shodan error: {str(e)}{Colors.END}")
            return {}
    
    def securitytrails_lookup(self, domain: str) -> Dict:
        """Query SecurityTrails API for domain information"""
        print(f"\n{Colors.BLUE}[*] Querying SecurityTrails database...{Colors.END}")
        
        api_key = self.config.apis.get('securitytrails')
        if not api_key or api_key == "YOUR_SECURITYTRAILS_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] SecurityTrails API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}"
            headers = {'APIKEY': api_key}
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] SecurityTrails: Domain data retrieved{Colors.END}")
                
                # Get subdomains
                subdomain_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                sub_response = self.session.get(subdomain_url, headers=headers, timeout=15)
                
                if sub_response.status_code == 200:
                    subdomains = sub_response.json().get('subdomains', [])
                    print(f"    Subdomains discovered: {len(subdomains)}")
                    if subdomains:
                        print(f"    Sample subdomains: {', '.join(subdomains[:5])}")
                    data['subdomains'] = subdomains[:50]
                
                return data
            else:
                print(f"{Colors.YELLOW}[!] SecurityTrails: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] SecurityTrails error: {str(e)}{Colors.END}")
            return {}
    
    def ipinfo_lookup(self, ip: str) -> Dict:
        """Query IPInfo API for IP geolocation"""
        print(f"\n{Colors.BLUE}[*] Querying IPInfo database...{Colors.END}")
        
        api_key = self.config.apis.get('ipinfo')
        if not api_key or api_key == "YOUR_IPINFO_API_KEY_HERE":
            print(f"{Colors.YELLOW}[!] IPInfo API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"https://ipinfo.io/{ip}?token={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print(f"{Colors.GREEN}[+] IPInfo: Geolocation data retrieved{Colors.END}")
                print(f"    Location: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}")
                print(f"    Organization: {data.get('org', 'N/A')}")
                print(f"    Timezone: {data.get('timezone', 'N/A')}")
                return data
            else:
                print(f"{Colors.YELLOW}[!] IPInfo: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] IPInfo error: {str(e)}{Colors.END}")
            return {}
    
    def full_recon(self, target: str, target_type: str = 'auto', enum_subdomains: bool = False, scan_ports: bool = False):
        """Perform full reconnaissance on target"""
        print(f"\n{Colors.YELLOW}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}  INITIATING RECONNAISSANCE{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.CYAN}  Target: {Colors.BOLD}{target}{Colors.END}")
        print(f"{Colors.CYAN}  Type: {target_type}{Colors.END}")
        print(f"{Colors.CYAN}  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.YELLOW}{Colors.BOLD}==============================================={Colors.END}")
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': target_type,
            'shodan': {},
            'securitytrails': {},
            'ipinfo': {},
            'subdomain_enum': {},
            'port_scan': {}
        }
        
        # Determine if target is IP or domain
        is_ip = all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.')) if target.count('.') == 3 else False
        
        if is_ip or target_type == 'ip':
            # IP-based reconnaissance
            print(f"\n{Colors.CYAN}[*] Detected IP address target - running IP-based reconnaissance{Colors.END}")
            
            self.results['shodan'] = self.shodan_lookup(target)
            time.sleep(2)
            
            self.results['ipinfo'] = self.ipinfo_lookup(target)
            time.sleep(2)
            
            # Port scan if enabled
            if scan_ports:
                scanner = PortScanner()
                self.results['port_scan'] = scanner.scan_host(target)
            
        else:
            # Domain-based reconnaissance
            print(f"\n{Colors.CYAN}[*] Detected domain target - running domain-based reconnaissance{Colors.END}")
            
            # Subdomain enumeration (if enabled)
            if enum_subdomains:
                enumerator = SubdomainEnumerator(target, self.config)
                self.results['subdomain_enum'] = enumerator.enumerate_all_enhanced(brute_force=True, scan_ports=scan_ports)
                time.sleep(2)
            
            self.results['securitytrails'] = self.securitytrails_lookup(target)
            time.sleep(2)
            
            # Try to resolve domain to IP
            try:
                print(f"\n{Colors.BLUE}[*] Resolving domain to IP address...{Colors.END}")
                ip = socket.gethostbyname(target)
                print(f"{Colors.GREEN}[+] Resolved IP: {ip}{Colors.END}")
                self.results['resolved_ip'] = ip
                
                # Run IP-based checks
                time.sleep(2)
                self.results['shodan'] = self.shodan_lookup(ip)
                time.sleep(2)
                self.results['ipinfo'] = self.ipinfo_lookup(ip)
                
                # Port scan if enabled
                if scan_ports:
                    scanner = PortScanner()
                    self.results['port_scan'] = scanner.scan_host(ip)
                
            except socket.gaierror:
                print(f"{Colors.RED}[!] Could not resolve domain to IP address{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[!] Error resolving domain: {str(e)}{Colors.END}")
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}==============================================={Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  RECONNAISSANCE COMPLETED{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}==============================================={Colors.END}")
        
        # Summary
        apis_used = sum(1 for v in [self.results['shodan'], self.results['securitytrails'], 
                                     self.results['ipinfo']] if v)
        print(f"{Colors.CYAN}  APIs queried: {apis_used}/3{Colors.END}")
        
        if enum_subdomains and self.results.get('subdomain_enum'):
            subdomain_count = self.results['subdomain_enum'].get('total_found', 0)
            print(f"{Colors.CYAN}  Subdomains discovered: {subdomain_count}{Colors.END}")
        
        if scan_ports:
            if self.results.get('port_scan'):
                open_ports = len(self.results['port_scan'].get('open_ports', []))
                print(f"{Colors.CYAN}  Open ports found: {open_ports}{Colors.END}")
            elif self.results.get('subdomain_enum', {}).get('port_scans'):
                total_scans = len(self.results['subdomain_enum']['port_scans'])
                print(f"{Colors.CYAN}  Port scans performed: {total_scans}{Colors.END}")
        
        filename = self.save_results(target)
        if filename:
            print(f"{Colors.GREEN}  Report: {filename}{Colors.END}")
        
        print(f"{Colors.GREEN}{Colors.BOLD}==============================================={Colors.END}\n")

class AdvancedReconMaster(ReconMaster):
    """Advanced ReconMaster with enhanced features"""
    
    def __init__(self, config: Config):
        super().__init__(config)
        
        # Extended API sources
        self.api_endpoints = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2',
            'greynoise': 'https://api.greynoise.io/v3',
            'censys': 'https://search.censys.io/api/v2',
            'builtwith': 'https://api.builtwith.com/v20',
            'wappalyzer': 'https://api.wappalyzer.com/v2'
        }
    
    def abuseipdb_check(self, ip: str) -> Dict:
        """Check IP reputation on AbuseIPDB"""
        print(f"{Colors.BLUE}[*] Checking AbuseIPDB reputation...{Colors.END}")
        
        api_key = self.config.apis.get('abuseipdb')
        if not api_key:
            print(f"{Colors.YELLOW}[!] AbuseIPDB API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"{self.api_endpoints['abuseipdb']}/check"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})
                
                print(f"{Colors.GREEN}[+] AbuseIPDB: Score {result.get('abuseConfidenceScore', 0)}%{Colors.END}")
                
                if result.get('abuseConfidenceScore', 0) > 50:
                    print(f"{Colors.RED}[!] WARNING: High abuse confidence score!{Colors.END}")
                    print(f"    Reports: {result.get('totalReports', 0)}")
                    print(f"    Country: {result.get('countryCode', 'Unknown')}")
                    if result.get('isp'):
                        print(f"    ISP: {result.get('isp')}")
                
                return result
            else:
                print(f"{Colors.YELLOW}[!] AbuseIPDB: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] AbuseIPDB error: {str(e)}{Colors.END}")
            return {}
    
    def greynoise_check(self, ip: str) -> Dict:
        """Check IP on GreyNoise"""
        print(f"{Colors.BLUE}[*] Checking GreyNoise...{Colors.END}")
        
        api_key = self.config.apis.get('greynoise')
        if not api_key:
            print(f"{Colors.YELLOW}[!] GreyNoise API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"{self.api_endpoints['greynoise']}/community/{ip}"
            headers = {
                'key': api_key,
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                print(f"{Colors.GREEN}[+] GreyNoise: Classification: {data.get('classification', 'unknown')}{Colors.END}")
                
                if data.get('classification') == 'malicious':
                    print(f"{Colors.RED}[!] WARNING: Malicious IP detected!{Colors.END}")
                    print(f"    Name: {data.get('name', 'Unknown')}")
                    print(f"    Last Seen: {data.get('last_seen', 'Unknown')}")
                elif data.get('classification') == 'benign':
                    print(f"{Colors.GREEN}[+] IP is benign (internet background noise){Colors.END}")
                
                return data
            else:
                print(f"{Colors.YELLOW}[!] GreyNoise: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] GreyNoise error: {str(e)}{Colors.END}")
            return {}
    
    def builtwith_scan(self, domain: str) -> Dict:
        """Detect technologies with BuiltWith"""
        print(f"{Colors.BLUE}[*] Detecting technologies with BuiltWith...{Colors.END}")
        
        api_key = self.config.apis.get('builtwith')
        if not api_key:
            print(f"{Colors.YELLOW}[!] BuiltWith API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"{self.api_endpoints['builtwith']}/api.json"
            params = {
                'key': api_key,
                'lookup': domain
            }
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                # Parse technologies
                technologies = {}
                for result in data.get('Results', []):
                    for tech in result.get('Result', {}).get('Paths', []):
                        for detail in tech.get('Technologies', []):
                            tech_name = detail.get('Name', '')
                            if tech_name:
                                if tech_name not in technologies:
                                    technologies[tech_name] = {
                                        'categories': set(),
                                        'versions': set()
                                    }
                                if detail.get('Categories'):
                                    for cat in detail.get('Categories', []):
                                        technologies[tech_name]['categories'].add(cat.get('Name', ''))
                                if detail.get('Version'):
                                    technologies[tech_name]['versions'].add(detail.get('Version'))
                
                # Format results
                formatted_techs = []
                for tech_name, info in technologies.items():
                    formatted_techs.append({
                        'name': tech_name,
                        'categories': list(info['categories']),
                        'versions': list(info['versions'])
                    })
                
                print(f"{Colors.GREEN}[+] BuiltWith: Found {len(formatted_techs)} technologies{Colors.END}")
                
                # Show top 10 technologies
                if formatted_techs:
                    print(f"{Colors.CYAN}Top Technologies:{Colors.END}")
                    for tech in formatted_techs[:10]:
                        print(f"  - {tech['name']}")
                        if tech['versions']:
                            print(f"    Version: {', '.join(tech['versions'])}")
                
                return {'technologies': formatted_techs}
            else:
                print(f"{Colors.YELLOW}[!] BuiltWith: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] BuiltWith error: {str(e)}{Colors.END}")
            return {}
    
    def wappalyzer_scan(self, domain: str) -> Dict:
        """Detect technologies with Wappalyzer"""
        print(f"{Colors.BLUE}[*] Detecting technologies with Wappalyzer...{Colors.END}")
        
        api_key = self.config.apis.get('wappalyzer')
        if not api_key:
            print(f"{Colors.YELLOW}[!] Wappalyzer API key not configured - skipping{Colors.END}")
            return {}
        
        try:
            url = f"{self.api_endpoints['wappalyzer']}/lookup"
            params = {
                'urls': f"https://{domain}",
                'live': 'true',
                'recursive': 'false'
            }
            headers = {
                'x-api-key': api_key
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                technologies = data[0].get('technologies', []) if data else []
                
                print(f"{Colors.GREEN}[+] Wappalyzer: Found {len(technologies)} technologies{Colors.END}")
                
                # Categorize technologies
                categories = {}
                for tech in technologies:
                    for category in tech.get('categories', []):
                        cat_name = category.get('name', 'Other')
                        if cat_name not in categories:
                            categories[cat_name] = []
                        categories[cat_name].append(tech.get('name', 'Unknown'))
                
                # Display by category
                if categories:
                    print(f"{Colors.CYAN}Technology Categories:{Colors.END}")
                    for category, techs in categories.items():
                        print(f"  {category}:")
                        for tech in techs[:5]:  # Show first 5 per category
                            print(f"    - {tech}")
                        if len(techs) > 5:
                            print(f"    ... and {len(techs) - 5} more")
                
                return {'technologies': technologies, 'categories': categories}
            else:
                print(f"{Colors.YELLOW}[!] Wappalyzer: No data available{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}[!] Wappalyzer error: {str(e)}{Colors.END}")
            return {}
    
    def tech_detection_scan(self, domain: str) -> Dict:
        """Comprehensive technology detection using multiple sources"""
        print(f"\n{Colors.YELLOW}[*] Running Comprehensive Technology Detection{Colors.END}")
        
        results = {
            'builtwith': {},
            'wappalyzer': {},
            'manual': {}
        }
        
        # Try BuiltWith first
        results['builtwith'] = self.builtwith_scan(domain)
        time.sleep(2)
        
        # Try Wappalyzer
        results['wappalyzer'] = self.wappalyzer_scan(domain)
        time.sleep(2)
        
        # Try manual detection via headers
        try:
            print(f"{Colors.BLUE}[*] Analyzing HTTP headers...{Colors.END}")
            response = self.session.get(f"https://{domain}", timeout=10, verify=False)
            
            manual_techs = {}
            
            # Detect from headers
            headers = response.headers
            
            if 'server' in headers:
                manual_techs['web_server'] = headers['server']
                print(f"{Colors.GREEN}[+] Web Server: {headers['server']}{Colors.END}")
            
            if 'x-powered-by' in headers:
                manual_techs['powered_by'] = headers['x-powered-by']
                print(f"{Colors.GREEN}[+] Powered By: {headers['x-powered-by']}{Colors.END}")
            
            if 'x-aspnet-version' in headers:
                manual_techs['aspnet'] = headers['x-aspnet-version']
                print(f"{Colors.GREEN}[+] ASP.NET: {headers['x-aspnet-version']}{Colors.END}")
            
            results['manual'] = manual_techs
            
        except Exception as e:
            print(f"{Colors.RED}[!] Manual detection failed: {str(e)}{Colors.END}")
        
        return results
    
    def perform_risk_assessment(self) -> Dict:
        """Perform risk assessment based on gathered data"""
        print(f"{Colors.BLUE}[*] Performing risk assessment...{Colors.END}")
        
        risk_score = 0
        risk_factors = []
        recommendations = []
        
        # Check IP reputation
        if self.results['findings'].get('abuseipdb'):
            abuse_score = self.results['findings']['abuseipdb'].get('abuseConfidenceScore', 0)
            if abuse_score > 70:
                risk_score += 40
                risk_factors.append(f"High abuse confidence score ({abuse_score}%)")
                recommendations.append("Investigate IP for malicious activity")
            elif abuse_score > 30:
                risk_score += 20
                risk_factors.append(f"Moderate abuse confidence score ({abuse_score}%)")
        
        # Check GreyNoise
        if self.results['findings'].get('greynoise'):
            classification = self.results['findings']['greynoise'].get('classification')
            if classification == 'malicious':
                risk_score += 50
                risk_factors.append("Malicious classification on GreyNoise")
                recommendations.append("Block IP immediately")
            elif classification == 'benign':
                risk_score -= 10  # Reduce risk for benign
        
        # Check open ports
        if self.results['findings'].get('port_scan'):
            open_ports = self.results['findings']['port_scan'].get('open_ports', [])
            risky_ports = [21, 23, 139, 445, 3389, 5900]  # FTP, Telnet, SMB, RDP, VNC
            
            for port_info in open_ports:
                port = port_info.get('port')
                if port in risky_ports:
                    risk_score += 15
                    risk_factors.append(f"Risky port open: {port}/{port_info.get('service', 'unknown')}")
                    recommendations.append(f"Secure or close port {port}")
        
        # Check Shodan data
        if self.results['findings'].get('shodan'):
            shodan_data = self.results['findings']['shodan']
            if shodan_data.get('vulns'):
                risk_score += 30
                risk_factors.append(f"Vulnerabilities detected: {len(shodan_data['vulns'])}")
                recommendations.append("Patch vulnerabilities immediately")
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
            color = Colors.RED
        elif risk_score >= 50:
            risk_level = "HIGH"
            color = Colors.YELLOW
        elif risk_score >= 30:
            risk_level = "MEDIUM"
            color = Colors.YELLOW
        elif risk_score >= 10:
            risk_level = "LOW"
            color = Colors.GREEN
        else:
            risk_level = "VERY LOW"
            color = Colors.GREEN
        
        print(f"{color}[!] Risk Assessment: {risk_level} ({risk_score}/100){Colors.END}")
        
        if risk_factors:
            print(f"{Colors.CYAN}Risk Factors:{Colors.END}")
            for factor in risk_factors:
                print(f"  - {factor}")
        
        if recommendations:
            print(f"{Colors.CYAN}Recommendations:{Colors.END}")
            for rec in recommendations:
                print(f"  - {rec}")
        
        return {
            'score': risk_score,
            'level': risk_level,
            'factors': risk_factors,
            'recommendations': recommendations
        }
    
    def full_advanced_recon(self, target: str, target_type: str = 'auto', 
                          enum_subdomains: bool = False, scan_ports: bool = False,
                          tech_detect: bool = False, risk_assessment: bool = False):
        """Perform advanced reconnaissance with all features"""
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}║                ADVANCED RECONNAISSANCE                       ║{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}╠══════════════════════════════════════════════════════════════╣{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}║  Target: {target:<55} ║{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}║  Mode: {'Full Scan' if enum_subdomains else 'Quick Scan':<56} ║{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.END}\n")
        
        # Start timer
        start_time = time.time()
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'advanced',
            'modules': {
                'subdomain_enum': False,
                'port_scan': False,
                'tech_detect': False,
                'risk_assessment': False,
                'ip_intelligence': False
            },
            'findings': {}
        }
        
        # Determine target type
        is_ip = all(part.isdigit() and 0 <= int(part) <= 255 for part in target.split('.')) if target.count('.') == 3 else False
        
        resolved_ip = None
        
        if is_ip or target_type == 'ip':
            # IP-based reconnaissance
            print(f"{Colors.GREEN}[+] Target is IP address: {target}{Colors.END}")
            resolved_ip = target
            
            # IP Intelligence
            print(f"\n{Colors.YELLOW}[*] Phase 1: IP Intelligence Gathering{Colors.END}")
            
            self.results['findings']['abuseipdb'] = self.abuseipdb_check(target)
            time.sleep(1)
            
            self.results['findings']['greynoise'] = self.greynoise_check(target)
            time.sleep(1)
            
            self.results['findings']['shodan'] = self.shodan_lookup(target)
            time.sleep(1)
            
            self.results['findings']['ipinfo'] = self.ipinfo_lookup(target)
            time.sleep(1)
            
            self.results['modules']['ip_intelligence'] = True
            
            # Port scanning
            if scan_ports:
                print(f"\n{Colors.YELLOW}[*] Phase 2: Port Scanning{Colors.END}")
                scanner = PortScanner()
                self.results['findings']['port_scan'] = scanner.scan_host(target)
                self.results['modules']['port_scan'] = True
            
        else:
            # Domain-based reconnaissance
            print(f"{Colors.GREEN}[+] Target is domain: {target}{Colors.END}")
            
            # Subdomain enumeration
            if enum_subdomains:
                print(f"\n{Colors.YELLOW}[*] Phase 1: Subdomain Enumeration{Colors.END}")
                enumerator = SubdomainEnumerator(target, self.config)
                self.results['findings']['subdomain_enum'] = enumerator.enumerate_all_enhanced(
                    brute_force=True, scan_ports=scan_ports
                )
                self.results['modules']['subdomain_enum'] = True
                self.results['modules']['port_scan'] = scan_ports
                
                # Get resolved IPs from subdomains
                resolved_ips = set()
                for sub in self.results['findings']['subdomain_enum'].get('subdomains', []):
                    ip = sub.get('ip')
                    if ip and ip != 'Not resolved':
                        resolved_ips.add(ip)
                
                if resolved_ips:
                    print(f"\n{Colors.GREEN}[+] Found {len(resolved_ips)} unique IP addresses{Colors.END}")
                    
                    # Run IP intelligence on first few IPs
                    sample_ips = list(resolved_ips)[:3]
                    for ip in sample_ips:
                        print(f"\n{Colors.CYAN}[*] Analyzing IP: {ip}{Colors.END}")
                        self.abuseipdb_check(ip)
                        time.sleep(0.5)
            
            # Technology detection
            if tech_detect:
                print(f"\n{Colors.YELLOW}[*] Phase 2: Technology Detection{Colors.END}")
                self.results['findings']['tech_detection'] = self.tech_detection_scan(target)
                self.results['modules']['tech_detect'] = True
            
            # Try to resolve main domain
            try:
                print(f"\n{Colors.YELLOW}[*] Phase 3: Main Domain Analysis{Colors.END}")
                resolved_ip = socket.gethostbyname(target)
                print(f"{Colors.GREEN}[+] Resolved IP: {resolved_ip}{Colors.END}")
                
                # Run IP intelligence on main domain IP
                print(f"\n{Colors.CYAN}[*] Analyzing main domain IP...{Colors.END}")
                self.results['findings']['main_domain_ip'] = {
                    'ip': resolved_ip,
                    'shodan': self.shodan_lookup(resolved_ip),
                    'ipinfo': self.ipinfo_lookup(resolved_ip),
                    'abuseipdb': self.abuseipdb_check(resolved_ip)
                }
                
            except socket.gaierror:
                print(f"{Colors.RED}[!] Could not resolve domain to IP{Colors.END}")
                resolved_ip = None
        
        # Risk assessment
        if risk_assessment:
            print(f"\n{Colors.YELLOW}[*] Phase 4: Risk Assessment{Colors.END}")
            self.results['findings']['risk_assessment'] = self.perform_risk_assessment()
            self.results['modules']['risk_assessment'] = True
        
        # Calculate time
        elapsed_time = time.time() - start_time
        
        # Generate report
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════╗{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║                    SCAN COMPLETE                           ║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}╠══════════════════════════════════════════════════════════════╣{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Time Elapsed: {elapsed_time:.2f} seconds{' ' * (39 - len(f'{elapsed_time:.2f}'))}║{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}║  Modules Executed: {' ' * 39}║{Colors.END}")
        
        modules = self.results['modules']
        for module, enabled in modules.items():
            if enabled:
                status = f"{Colors.GREEN}✓{Colors.END}"
            else:
                status = f"{Colors.RED}✗{Colors.END}"
            print(f"{Colors.GREEN}{Colors.BOLD}║    {module.replace('_', ' ').title():<20} {status}{' ' * 32}║{Colors.END}")
        
        # Summary statistics
        if enum_subdomains and self.results['findings'].get('subdomain_enum'):
            sub_count = self.results['findings']['subdomain_enum'].get('total_found', 0)
            print(f"{Colors.GREEN}{Colors.BOLD}║  Subdomains Found: {sub_count:<40}║{Colors.END}")
        
        if scan_ports:
            open_ports = 0
            if self.results['findings'].get('port_scan'):
                open_ports = len(self.results['findings']['port_scan'].get('open_ports', []))
            elif self.results['findings'].get('subdomain_enum', {}).get('port_scans'):
                for scan in self.results['findings']['subdomain_enum']['port_scans']:
                    open_ports += len(scan.get('open_ports', []))
            print(f"{Colors.GREEN}{Colors.BOLD}║  Open Ports Found: {open_ports:<40}║{Colors.END}")
        
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════════════════════════════╝{Colors.END}")
        
        # Save results
        filename = self.save_results(target)
        if filename:
            print(f"\n{Colors.GREEN}[+] Full report saved to: {filename}{Colors.END}")
        
        # Quick findings summary
        print(f"\n{Colors.CYAN}{Colors.BOLD}QUICK FINDINGS SUMMARY:{Colors.END}")
        
        if resolved_ip:
            print(f"{Colors.CYAN}  Primary IP: {resolved_ip}{Colors.END}")
        
        if self.results['findings'].get('abuseipdb'):
            score = self.results['findings']['abuseipdb'].get('abuseConfidenceScore', 0)
            if score > 50:
                print(f"{Colors.RED}  WARNING: High abuse score detected ({score}%){Colors.END}")
        
        if self.results['findings'].get('greynoise'):
            classification = self.results['findings']['greynoise'].get('classification')
            if classification == 'malicious':
                print(f"{Colors.RED}  WARNING: Malicious IP detected on GreyNoise{Colors.END}")
        
        print()

def setup_wizard():
    """Interactive setup wizard for API keys"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  RECONMASTER SETUP WIZARD{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}\n")
    
    print(f"{Colors.YELLOW}Configure your API keys for enhanced reconnaissance.{Colors.END}")
    print(f"{Colors.YELLOW}Press Enter to skip any API you don't have.{Colors.END}\n")
    
    apis = {}
    
    print(f"{Colors.CYAN}[1/3] Shodan API Configuration{Colors.END}")
    print(f"      Get your key at: https://account.shodan.io/")
    apis['shodan'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[2/3] SecurityTrails API Configuration{Colors.END}")
    print(f"      Get your key at: https://securitytrails.com/")
    apis['securitytrails'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    print(f"{Colors.CYAN}[3/3] IPInfo API Configuration{Colors.END}")
    print(f"      Get your key at: https://ipinfo.io/")
    apis['ipinfo'] = input(f"{Colors.BLUE}      Enter API Key: {Colors.END}").strip()
    print()
    
    # Remove empty keys
    apis = {k: v for k, v in apis.items() if v}
    
    if apis:
        config = Config()
        config.save_config(apis)
        print(f"\n{Colors.GREEN}[+] Configuration saved! {len(apis)}/3 APIs configured.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[!] No API keys provided. You can run setup again anytime.{Colors.END}")
    
    print(f"{Colors.CYAN}\nYou're ready to start reconnaissance!{Colors.END}")
    print(f"{Colors.CYAN}Example: python3 recon_master.py -t example.com --enum-subs{Colors.END}")
    print(f"{Colors.CYAN}Example: python3 recon_master.py -t example.com --enum-subs --scan-ports{Colors.END}\n")

def enhanced_setup_wizard():
    """Enhanced setup wizard with more API options"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}  ADVANCED API CONFIGURATION WIZARD{Colors.END}")
    print(f"{Colors.CYAN}{Colors.BOLD}==============================================={Colors.END}\n")
    
    print(f"{Colors.YELLOW}Configure API keys for enhanced reconnaissance capabilities.{Colors.END}")
    print(f"{Colors.YELLOW}Press Enter to skip any API you don't have.{Colors.END}")
    print(f"{Colors.YELLOW}At minimum, configure Shodan for best results.{Colors.END}\n")
    
    apis = {}
    
    sections = [
        {
            'title': 'Essential APIs',
            'apis': [
                ('shodan', 'https://account.shodan.io/', 'Subdomain & port scanning'),
                ('securitytrails', 'https://securitytrails.com/', 'Historical DNS data'),
                ('ipinfo', 'https://ipinfo.io/', 'IP geolocation'),
            ]
        },
        {
            'title': 'Threat Intelligence',
            'apis': [
                ('virustotal', 'https://www.virustotal.com/', 'Malware detection'),
                ('abuseipdb', 'https://www.abuseipdb.com/', 'IP reputation'),
                ('greynoise', 'https://www.greynoise.io/', 'Background noise filtering'),
            ]
        },
        {
            'title': 'Technology Detection',
            'apis': [
                ('builtwith', 'https://builtwith.com/', 'Tech stack analysis'),
                ('wappalyzer', 'https://www.wappalyzer.com/', 'Technology fingerprinting'),
            ]
        }
    ]
    
    for section in sections:
        print(f"\n{Colors.CYAN}{Colors.BOLD}{section['title']}{Colors.END}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.END}")
        
        for api_name, api_url, description in section['apis']:
            print(f"\n{Colors.BLUE}[{api_name.upper()}]{Colors.END}")
            print(f"  {Colors.YELLOW}{description}{Colors.END}")
            print(f"  Get key at: {api_url}")
            
            key = input(f"{Colors.BLUE}  Enter API Key (press Enter to skip): {Colors.END}").strip()
            if key:
                apis[api_name] = key
                print(f"{Colors.GREEN}  ✓ Configured{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  ✗ Skipped{Colors.END}")
    
    if apis:
        config = Config()
        config.save_config(apis)
        print(f"\n{Colors.GREEN}[+] Configuration saved! {len(apis)} APIs configured.{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}[!] No API keys provided. Basic functionality only.{Colors.END}")
    
    print(f"\n{Colors.CYAN}You're ready to start advanced reconnaissance!{Colors.END}")
    print(f"{Colors.CYAN}Example commands:{Colors.END}")
    print(f"  python3 recon_master.py -t example.com --advanced --enum-subs")
    print(f"  python3 recon_master.py -t 8.8.8.8 --advanced --risk-assessment")
    print(f"  python3 recon_master.py -t example.com --advanced --tech-detect\n")

def main():
    parser = argparse.ArgumentParser(
        description='ReconMaster Advanced - Professional Bug Bounty Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}Usage Examples:{Colors.END}
  
  {Colors.GREEN}Basic Scans:{Colors.END}
  python3 recon_master.py -t example.com --enum-subs
  python3 recon_master.py -t 8.8.8.8 --scan-ports
  
  {Colors.GREEN}Advanced Scans:{Colors.END}
  python3 recon_master.py -t example.com --advanced --enum-subs --tech-detect
  python3 recon_master.py -t example.com --advanced --full-scan
  python3 recon_master.py -t 192.168.1.1 --advanced --risk-assessment
  
  {Colors.GREEN}Configuration:{Colors.END}
  python3 recon_master.py --setup          Basic API setup
  python3 recon_master.py --advanced-setup Advanced API setup

{Colors.YELLOW}Author: Abdulbasid Yakubu | cy30rt{Colors.END}
{Colors.YELLOW}Version: 3.0.0 - Advanced Edition{Colors.END}
        """
    )
    
    # Basic arguments
    parser.add_argument('-t', '--target', help='Target domain or IP address')
    parser.add_argument('--type', choices=['auto', 'ip', 'domain'], default='auto',
                       help='Target type (default: auto)')
    
    # Setup arguments
    parser.add_argument('--setup', action='store_true', help='Run basic setup wizard')
    parser.add_argument('--advanced-setup', action='store_true', help='Run advanced API setup wizard')
    
    # Basic scan options
    parser.add_argument('--enum-subs', action='store_true', help='Enable subdomain enumeration')
    parser.add_argument('--scan-ports', action='store_true', help='Enable port scanning')
    
    # Advanced scan options
    parser.add_argument('--advanced', action='store_true', help='Enable advanced scanning features')
    parser.add_argument('--full-scan', action='store_true', help='Run all available scans (implies --advanced)')
    parser.add_argument('--tech-detect', action='store_true', help='Enable technology detection')
    parser.add_argument('--risk-assessment', action='store_true', help='Generate risk assessment report')
    parser.add_argument('--quick', action='store_true', help='Quick scan only (skip intensive checks)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('--format', choices=['json', 'txt', 'csv'], default='json',
                       help='Output format (default: json)')
    
    # Performance options
    parser.add_argument('--threads', type=int, default=10,
                       help='Threads for parallel scanning (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout per request in seconds (default: 30)')
    
    parser.add_argument('-v', '--version', action='version', 
                       version='ReconMaster Advanced v3.0.0 by Abdulbasid Yakubu | cy30rt')
    
    args = parser.parse_args()
    
    # Handle setup
    if args.setup:
        setup_wizard()
        return
    
    if args.advanced_setup:
        enhanced_setup_wizard()
        return
    
    # Validate arguments
    if not args.target and not (args.setup or args.advanced_setup):
        print(f"{Colors.RED}[!] Error: Target required. Use -h for help.{Colors.END}\n")
        parser.print_help()
        return
    
    # Configure based on arguments
    if args.full_scan:
        args.advanced = True
        args.enum_subs = True
        args.scan_ports = True
        args.tech_detect = True
        args.risk_assessment = True
    
    if args.quick:
        args.enum_subs = False
        args.scan_ports = False
        args.tech_detect = False
        args.risk_assessment = False
    
    config = Config()
    
    # Show banner
    if args.advanced:
        print(f"""
{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                    RECONMASTER ADVANCED                      ║
    ║                 Professional Reconnaissance Tool             ║
    ╚══════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}    Target: {args.target}
    Mode: {'Full Scan' if args.full_scan else 'Advanced Scan' if args.advanced else 'Basic Scan'}
{Colors.END}
        """)
        recon = AdvancedReconMaster(config)
        
        # Run advanced scan
        recon.full_advanced_recon(
            target=args.target,
            target_type=args.type,
            enum_subdomains=args.enum_subs,
            scan_ports=args.scan_ports,
            tech_detect=args.tech_detect,
            risk_assessment=args.risk_assessment
        )
    else:
        # Run basic scan
        recon = ReconMaster(config)
        recon.banner()
        recon.full_recon(
            target=args.target,
            target_type=args.type,
            enum_subdomains=args.enum_subs,
            scan_ports=args.scan_ports
        )
    
    # Save to specified output file
    if args.output and hasattr(recon, 'results'):
        try:
            with open(args.output, 'w') as f:
                if args.format == 'json':
                    json.dump(recon.results, f, indent=2)
                elif args.format == 'txt':
                    # Simple text format
                    f.write(f"ReconMaster Scan Report\n")
                    f.write(f"Target: {args.target}\n")
                    f.write(f"Time: {datetime.now().isoformat()}\n")
                    f.write(f"{'='*50}\n\n")
                    
                    if recon.results.get('subdomain_enum'):
                        f.write("SUBDOMAINS:\n")
                        for sub in recon.results['subdomain_enum'].get('subdomains', []):
                            f.write(f"  {sub.get('subdomain')} - {sub.get('ip')}\n")
                        f.write("\n")
                
                print(f"{Colors.GREEN}[+] Results also saved to: {args.output}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving to {args.output}: {e}{Colors.END}")

if __name__ == "__main__":
    try:
        # Disable SSL warnings globally
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Check for required packages
        try:
            import dns.resolver
        except ImportError:
            print(f"{Colors.YELLOW}[!] Installing required package: dnspython{Colors.END}")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"])
            print(f"{Colors.GREEN}[+] dnspython installed successfully{Colors.END}")
        
        # Run main
        main()
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        print(f"{Colors.YELLOW}[!] Partial results may have been saved{Colors.END}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        import traceback
        traceback.print_exc()
        print(f"{Colors.RED}[!] Please report this issue{Colors.END}\n")
        sys.exit(1)
