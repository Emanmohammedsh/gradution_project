"""
recon/host_discovery.py
-----------------------
Layer 1 — Ping-sweep / host discovery via nmap -sn.
"""

import nmap


class HostDiscovery:

    def __init__(self, target: str):
        self.target  = target
        self.scanner = nmap.PortScanner()

    def discover(self) -> list[str]:
        print(f"[Recon] Ping-sweep → {self.target}")
        self.scanner.scan(hosts=self.target, arguments="-sn")

        live = []
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                live.append(host)
                print(f"  [+] Live: {host}")

        if not live:
            print("  [-] No live hosts found.")
        return live
