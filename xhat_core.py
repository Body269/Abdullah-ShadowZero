"""
X-HAT Framework - Open Source Intelligence (OSINT) & Recon Module
Developed by: Abdullah (Shadow Zero) - Null_Sec Lead
Description: A multi-functional security automation script for sub-domain reconnaissance and network auditing.
Version: 1.0.0 (Alpha Beta Test)
"""

import socket
import sys
from datetime import datetime

class XHatRecon:
    def __init__(self, target_host):
        self.target = target_host
        self.target_ip = None

    def resolve_target(self):
        """Resolves target domain to IP address."""
        try:
            self.target_ip = socket.gethostbyname(self.target)
            print(f"[+] Target Resolved: {self.target} -> {self.target_ip}")
            return True
        except socket.gaierror:
            print(f"[-] Error: Could not resolve host {self.target}")
            return False

    def scan_ports(self, ports_list=[21, 22, 80, 443, 8080]):
        """Performs a basic TCP banner grabbing and port check."""
        if not self.target_ip:
            print("[-] Target IP not set. Run resolve_target() first.")
            return

        print(f"[*] Starting X-HAT Network Audit on {self.target_ip} at {datetime.now()}")
        print("-" * 50)
        
        for port in ports_list:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            result = s.connect_ex((self.target_ip, port))
            
            if result == 0:
                print(f"[+] Port {port}: OPEN")
                # Attempt basic banner grabbing for version detection
                try:
                    s.send(b'Head / HTTP/1.1\r\n\r\n')
                    banner = s.recv(1024).decode().strip()
                    if banner:
                        print(f"    [-->] Banner: {banner[:50]}")
                except:
                    pass
            s.close()
        print("-" * 50)

# =====================================================================
# 📖 X-HAT SCENARIO & USAGE EXPLANATION (How to Use this Module)
# =====================================================================
"""
SCENARIO USAGE:
This module is part of the X-HAT Framework used during the initial reconnaissance phase of a Red Team assessment.
By feeding a target domain into the framework, it automatically maps the infrastructure, checks critical entry points 
(like SSH on 22, HTTP on 80/443), and extracts software banners to check against known CVE databases.

Example of execution inside the core framework:
    >>> auditor = XHatRecon("example.com")
    >>> if auditor.resolve_target():
    >>>     auditor.scan_ports([22, 80, 443])
"""

if __name__ == "__main__":
    # Test case to ensure script structure is valid
    print("[!] X-HAT Framework Core Loaded Successfully.")
    print("[!] Developed by Abdullah (Shadow Zero). Ready for auditing deployment.")
                  
