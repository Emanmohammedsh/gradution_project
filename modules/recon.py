import nmap

class ReconModule:

    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def discover_hosts(self):
        print(f"[R0/R1] Starting Reconnaissance on: {self.target}")
        
        self.scanner.scan(
            hosts=self.target,
            arguments='-sn'
        )

        live_hosts = []

        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                live_hosts.append(host)
                print(f"[+] Live Host Found: {host}")

        if not live_hosts:
            print("[-] No live hosts found. Halting.")

        return live_hosts
