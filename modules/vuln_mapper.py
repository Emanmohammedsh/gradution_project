class VulnMapperModule:

    def __init__(self):
        # CVE Database - Service to Exploit Mapping
        self.vuln_db = {
            "vsftpd 2.3.4": {
                "cve": "CVE-2011-2523",
                "exploit": "exploit/unix/ftp/vsftpd_234_backdoor",
                "type": "metasploit",
                "priority": 1
            },
            "samba": {
                "cve": "CVE-2007-2447",
                "exploit": "exploit/multi/samba/usermap_script",
                "type": "metasploit",
                "priority": 2
            },
            "ssh": {
                "cve": "BRUTE-FORCE",
                "exploit": "ssh",
                "type": "hydra",
                "priority": 3
            },
            "ftp": {
                "cve": "BRUTE-FORCE",
                "exploit": "ftp",
                "type": "hydra",
                "priority": 4
            },
            "http": {
                "cve": "WEB-SCAN",
                "exploit": "web",
                "type": "web",
                "priority": 5
            }
        }

    def map_vulnerabilities(self, scan_results):
        print(f"\n[R6] Starting Vulnerability Mapping...")

        findings = []

        for host, data in scan_results.items():
            for port_info in data["ports"]:
                service = port_info.get("service", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                port = port_info.get("port")

                full_name = f"{product} {version}".strip().lower()

                for key, vuln in self.vuln_db.items():
                    if key.lower() in full_name or key.lower() == service.lower():
                        finding = {
                            "host": host,
                            "port": port,
                            "service": service,
                            "matched_key": key,
                            "cve": vuln["cve"],
                            "exploit": vuln["exploit"],
                            "type": vuln["type"],
                            "priority": vuln["priority"]
                        }
                        findings.append(finding)
                        print(f"  [!] Match Found: {host}:{port} | {key} | CVE: {vuln['cve']}")

        if not findings:
            print("  [-] No vulnerabilities matched.")

        findings.sort(key=lambda x: x["priority"])
        return findings
