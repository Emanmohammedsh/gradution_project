import datetime
import os

class ReporterModule:

    def __init__(self):
        self.report_dir = "reports"

    def generate_report(self, target, live_hosts, scan_results,
                        vuln_findings, exploit_results, post_data):

        print(f"\n[R10] Generating Report...")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.report_dir}/report_{timestamp}.txt"

        with open(filename, "w") as f:

            f.write("=" * 60 + "\n")
            f.write("   PENETRATION TESTING REPORT\n")
            f.write("   Rule-Based Adaptive Red Teaming System\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Date       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target     : {target}\n")
            f.write(f"Live Hosts : {len(live_hosts)}\n\n")

            f.write("=" * 60 + "\n")
            f.write("PHASE 1 - RECONNAISSANCE\n")
            f.write("=" * 60 + "\n")
            for host in live_hosts:
                f.write(f"  [+] Live Host: {host}\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("PHASE 2 - SCANNING AND ENUMERATION\n")
            f.write("=" * 60 + "\n")
            for host, data in scan_results.items():
                f.write(f"\n  Host: {host}\n")
                f.write(f"  OS  : {data.get('os', 'unknown')}\n")
                f.write(f"  Open Ports:\n")
                for port_info in data["ports"]:
                    f.write(f"    Port {port_info['port']} | ")
                    f.write(f"{port_info['service']} | ")
                    f.write(f"{port_info['product']} ")
                    f.write(f"{port_info['version']}\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("PHASE 3 - VULNERABILITY MAPPING\n")
            f.write("=" * 60 + "\n")
            for finding in vuln_findings:
                f.write(f"\n  Host    : {finding['host']}:{finding['port']}\n")
                f.write(f"  Service : {finding['service']}\n")
                f.write(f"  CVE     : {finding['cve']}\n")
                f.write(f"  Exploit : {finding['exploit']}\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("PHASE 4 - EXPLOITATION\n")
            f.write("=" * 60 + "\n")
            for result in exploit_results:
                status = "SUCCESS" if result["success"] else "FAILED"
                f.write(f"\n  Host    : {result['host']}:{result['port']}\n")
                f.write(f"  Exploit : {result['exploit']}\n")
                f.write(f"  Status  : {status}\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("PHASE 5 - POST-EXPLOITATION\n")
            f.write("=" * 60 + "\n")
            if post_data:
                f.write(f"  Host    : {post_data.get('host', 'N/A')}\n")
                f.write(f"  UID     : {post_data.get('uid', ['N/A'])}\n")
                f.write(f"  Hashes  : {post_data.get('hashes', ['N/A'])}\n")
            else:
                f.write("  No post-exploitation data collected.\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 60 + "\n")
            f.write("  1. Update all outdated services.\n")
            f.write("  2. Disable unnecessary open ports.\n")
            f.write("  3. Enforce strong password policies.\n")
            f.write("  4. Apply latest security patches.\n")
            f.write("  5. Enable IDS/IPS monitoring.\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 60 + "\n")

        print(f"  [+] Report saved: {filename}")
        return filename
