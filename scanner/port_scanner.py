"""
port_scanner.py
Handles port scanning and service detection using python-nmap.

The scanner cannot be used without a ScopeGuard: every target is checked
against the signed scope file before nmap is even started.
"""
import nmap

from scanner.scope_guard import ScopeError, ValidatedTarget, load_default_guard


class PortScanner:
    def __init__(self, guard):
        self.guard = guard

    def scan_target(self, target, port_range="1-10000", actor=""):
        """
        Scan one target for open ports and detected services.

        Args:
            target (str or ValidatedTarget): IP address, e.g. "192.168.56.102"
            port_range (str): Ports to scan, e.g. "1-10000"

        Raises:
            ScopeError: the target is outside the signed scope (nothing is sent).

        Returns:
            list[dict]: One dict per open port with port, protocol, state,
                        service, product, version and cpe.
        """
        # refuses BEFORE anything is sent (a target the guard already checked is not checked twice)
        validated = target if isinstance(target, ValidatedTarget) else self.guard.authorise(target, actor)
        if not validated.is_single_host:
            raise ValueError("Scanning a whole network arrives with the discovery "
                             "stage. Give a single IP address for now.")

        arguments = "-sV -T4" + (" -6" if validated.network.version == 6 else "")
        print(f"[*] Scanning {validated.address} on ports {port_range}...")
        engine = nmap.PortScanner()
        engine.scan(hosts=validated.address, ports=port_range, arguments=arguments)
        return self.collect_open_ports(engine, validated.address)

    def collect_open_ports(self, engine, address):
        results = []
        if address not in engine.all_hosts():
            print(f"[!] Host {address} appears to be down or unreachable.")
            return results

        for proto in engine[address].all_protocols():
            for port in sorted(engine[address][proto].keys()):
                port_info = engine[address][proto][port]
                if port_info["state"] == "open":
                    results.append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "cpe": port_info.get("cpe", ""),
                    })

        print(f"[+] Found {len(results)} open port(s) on {address}")
        return results


if __name__ == "__main__":  # pragma: no cover
    try:
        scanner = PortScanner(load_default_guard())
        target_ip = input("Enter target IP to scan: ").strip()
        open_ports = scanner.scan_target(target_ip)
    except ScopeError as error:
        raise SystemExit(f"REFUSED ({error.code}): {error}")

    print("\n--- Scan Results ---")
    for entry in open_ports:
        print(f"Port {entry['port']}/{entry['protocol']} - {entry['service']} "
              f"{entry['product']} {entry['version']}")