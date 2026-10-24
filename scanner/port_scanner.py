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
        """
         Scans a single target IP for open ports and detected services.
         Args:
            target (str): IP address or hostname (e.g. "192.168.0.5")
            port_rsnge (str): Port range to scan

        Returns:
            list[dict]: One dict per port - port, protocol, service,
                        products, version. This is what vuln_matcher 
                        will consume later to look up CVE's.
        """
        print(f"[*] Scanning {target} on ports {port_range}...")
        self.scanner.scan(hosts=target, ports=port_range, arguments="-sV -T4")

        results = []

        if target not in self.scanner.all_hosts():
            print(f"[!] Host {target} appears to be down or unreachable.")
            return results
        
        for proto in self.scanner[target].all_protocols():
            ports = self.scanner[target][proto].keys()

            for port in sorted(ports):
                port_info = self.scanner[target][proto][port]

                if port_info["state"] == "open":
                    results.append({
                        "port" : port,
                        "protocol" : proto,
                        "state" : port_info["state"],
                        "service" : port_info.get("name", "unknown"),
                        "product" : port_info.get("product", ""),
                        "version" : port_info.get("version", "")
                    })
        print(f"[+] Found {len(results)} open port(s) on {target}")
        return results


def scan_target(self, target, port_range="1-10000"):
    results = []

    for port in self.nm[target]['tcp']:
        service_info = self.nm[target]['tcp'][port]
        results.append({
            "port": port,
            "service": service_info.get('name', ''),
            "product": service_info.get('product', ''),
            "version": service_info.get('version', '')
        })
    return results

if __name__ == "__main__":
    target_ip = input("Enter target IP to scan: ").strip()
    scanner = PortScanner()
    open_ports = scanner.scan_target(target_ip)
    
    print("\n--- Scan Results ---")
    for entry in open_ports:
        print(f"Port {entry['port']}/{entry['protocol']} -{entry['service']} {entry['product']} {entry['version']}")