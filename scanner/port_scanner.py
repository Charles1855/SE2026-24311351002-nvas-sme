"""
 port scanner
 Handles host discovery, port scanning, and service detection
 using python-nmap
"""
import nmap

class PortScanner:
    def __init__(self):
        self.scanner=nmap.PortScanner()

    def scan_target(self,target, port_range="1-10000"):
        