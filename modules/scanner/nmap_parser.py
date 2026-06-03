"""
scanner/nmap_parser.py
----------------------
Runs nmap -sV -sC --open and returns raw structured data.
"""

import nmap


class NmapParser:

    SCAN_ARGS = "-sV -sC --open"

    def __init__(self, target: str):
        self.target  = target
        self.scanner = nmap.PortScanner()

    def run(self) -> dict:
        """Returns raw nmap scan dict keyed by host."""
        print(f"[Scanner] nmap {self.SCAN_ARGS} {self.target}")
        self.scanner.scan(hosts=self.target, arguments=self.SCAN_ARGS)
        return self.scanner
