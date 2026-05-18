import nmap

class ScannerModule:

    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan_target(self):
        print(f"\n[R3/R4/R5] Starting Scan on: {self.target}")

        self.scanner.scan(
            hosts=self.target,
            arguments='-sV -sC --open'
        )

        results = {}

        for host in self.scanner.all_hosts():
            print(f"\n[+] Host: {host}")
            results[host] = {
                "os": "unknown",
                "ports": []
            }

            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    service = self.scanner[host][proto][port]
                    port_info = {
                        "port": port,
                        "service": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", "")
                    }
                    results[host]["ports"].append(port_info)
                    print(f"  Port: {port} | Service: {service.get('name')} | Version: {service.get('product')} {service.get('version')}")

        return results
