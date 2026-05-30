"""
reporter.py
-----------
Generates the final penetration testing report.
Includes: Recon → Scan → Vulns → Risk → Exploit → Post-Exploit
          → MITRE ATT&CK → Social Engineering → Recommendations
"""

import datetime
import os
import json


class ReporterModule:

    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, target, live_hosts, scan_results,
                        vuln_findings, exploit_results, post_data,
                        se_results=None, attack_chain=None):

        print(f"\n[R10] Generating Report...")

        timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file    = f"{self.report_dir}/report_{timestamp}.txt"
        chain_file  = f"{self.report_dir}/attack_chain_{timestamp}.json"

        with open(txt_file, "w", encoding="utf-8") as f:
            self._write_header(f, target, live_hosts)
            self._write_scan(f, scan_results)
            self._write_vulns(f, vuln_findings)
            self._write_exploits(f, exploit_results)
            self._write_post(f, post_data)
            self._write_mitre(f, exploit_results)
            if se_results:
                self._write_se(f, se_results)
            self._write_recommendations(f, vuln_findings)
            self._write_footer(f)

        print(f"  [+] Report saved     : {txt_file}")

        # Save attack chain JSON separately
        if attack_chain:
            with open(chain_file, "w", encoding="utf-8") as f:
                json.dump(attack_chain, f, indent=2)
            print(f"  [+] Attack chain     : {chain_file}")

        return txt_file

    # -----------------------------------------------------------------------

    def _write_header(self, f, target, live_hosts):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write("=" * 60 + "\n")
        f.write("   PENETRATION TESTING REPORT\n")
        f.write("   Hybrid AI Red Teaming Framework\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Date       : {now}\n")
        f.write(f"Target     : {target}\n")
        f.write(f"Live Hosts : {len(live_hosts)}\n\n")

        f.write("=" * 60 + "\n")
        f.write("PHASE 1 — RECONNAISSANCE\n")
        f.write("=" * 60 + "\n")
        for host in live_hosts:
            f.write(f"  [+] Live Host: {host}\n")
        f.write("\n")

    def _write_scan(self, f, scan_results):
        f.write("=" * 60 + "\n")
        f.write("PHASE 2 — SCANNING AND ENUMERATION\n")
        f.write("=" * 60 + "\n")
        for host, data in scan_results.items():
            f.write(f"\n  Host : {host}\n")
            f.write(f"  OS   : {data.get('os', 'unknown')}\n")
            f.write(f"  Open Ports:\n")
            for p in data["ports"]:
                f.write(
                    f"    Port {p['port']:>5} | "
                    f"{p['service']:<10} | "
                    f"{p['product']} {p['version']}\n"
                )
        f.write("\n")

    def _write_vulns(self, f, vuln_findings):
        f.write("=" * 60 + "\n")
        f.write("PHASE 3 — VULNERABILITY MAPPING\n")
        f.write("=" * 60 + "\n")
        for finding in vuln_findings:
            sev = finding.get("severity", "unknown").upper()
            f.write(f"\n  [{sev}] {finding['host']}:{finding['port']}\n")
            f.write(f"    Service  : {finding.get('service', 'N/A')}\n")
            f.write(f"    CVE      : {finding.get('cve', 'N/A')}\n")
            f.write(f"    CVSS     : {finding.get('cvss', 'N/A')}\n")
            f.write(f"    Exploit  : {finding.get('exploit', 'N/A')}\n")
            f.write(f"    Source   : {finding.get('source', 'N/A')}\n")
            if finding.get("edb_title"):
                f.write(f"    Title    : {finding['edb_title']}\n")
            # AI prioritizer output
            if finding.get("ai_priority"):
                pri_label = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(
                    finding["ai_priority"], "?"
                )
                f.write(
                    f"    AI Rank  : {pri_label} "
                    f"(source={finding.get('ai_source','?')}, "
                    f"conf={finding.get('ai_confidence','?')})\n"
                )
        f.write("\n")

    def _write_exploits(self, f, exploit_results):
        f.write("=" * 60 + "\n")
        f.write("PHASE 4 — EXPLOITATION\n")
        f.write("=" * 60 + "\n")
        for result in exploit_results:
            status = "SUCCESS" if result.get("success") else "FAILED"
            f.write(f"\n  [{status}] {result['host']}:{result['port']}\n")
            f.write(f"    Exploit  : {result.get('exploit', 'N/A')}\n")
        f.write("\n")

    def _write_post(self, f, post_data):
        f.write("=" * 60 + "\n")
        f.write("PHASE 5 — POST-EXPLOITATION\n")
        f.write("=" * 60 + "\n")
        if post_data:
            f.write(f"  Host       : {post_data.get('host', 'N/A')}\n")
            # Classic post_exploit.py output
            if post_data.get("uid"):
                f.write(f"  UID        : {post_data.get('uid', ['N/A'])}\n")
            if post_data.get("hashes"):
                f.write(f"  Hashes     : {post_data.get('hashes', ['N/A'])}\n")
            # AI post_exploit_ai.py output
            if post_data.get("os_type"):
                f.write(f"  OS Type    : {post_data.get('os_type', 'N/A')}\n")
                f.write(f"  Privilege  : {post_data.get('privilege_level', 'N/A')}\n")
                f.write(f"  AI Action  : {post_data.get('recommended_action', 'N/A')} "
                        f"(conf={post_data.get('ai_confidence', 'N/A')})\n")
            if post_data.get("credentials"):
                f.write(f"  Credentials: {len(post_data['credentials'])} found\n")
                for cred in post_data["credentials"]:
                    f.write(f"    - {cred}\n")
            if post_data.get("users"):
                f.write(f"  Users      : {', '.join(post_data['users'])}\n")
            if post_data.get("network_info"):
                ni = post_data["network_info"]
                f.write(f"  IPs Found  : {', '.join(ni.get('ips_found', []))}\n")
        else:
            f.write("  No post-exploitation data collected.\n")
        f.write("\n")

    def _write_mitre(self, f, exploit_results):
        f.write("=" * 60 + "\n")
        f.write("PHASE 6 — MITRE ATT&CK MAPPING\n")
        f.write("=" * 60 + "\n")
        for result in exploit_results:
            mitre = result.get("mitre")
            if not mitre:
                continue
            f.write(f"\n  Host       : {result['host']}:{result['port']}\n")
            f.write(f"  Tactic     : {mitre.get('tactic', 'unknown')}\n")
            f.write(f"  Phase      : {mitre.get('attack_phase', '?')}\n")
            f.write(f"  Confidence : {mitre.get('confidence', 0):.2f} "
                    f"[{mitre.get('source', '?')}]\n")
            f.write(f"  Techniques :\n")
            for tech in mitre.get("techniques", []):
                f.write(f"    [{tech['id']}] {tech.get('name', '')}\n")
            for tech in mitre.get("extra_techniques", []):
                f.write(f"    [{tech['id']}] {tech.get('name', '')} (post-exploit)\n")
        f.write("\n")

    def _write_se(self, f, se_results):
        f.write("=" * 60 + "\n")
        f.write("PHASE 7 — SOCIAL ENGINEERING CAMPAIGN\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Domain     : {se_results.get('domain', 'N/A')}\n")
        profile = se_results.get("osint_profile", {})
        f.write(f"  Surface    : {profile.get('attack_surface', 'N/A')}/10\n")
        f.write(f"  Emails Gen : {len(se_results.get('phishing_emails', []))}\n")
        for email in se_results.get("phishing_emails", []):
            f.write(f"\n    Pretext  : {email.get('pretext')}\n")
            f.write(f"    From     : {email.get('sender')}\n")
            f.write(f"    Subject  : {email.get('subject')}\n")
            mitre = email.get("mitre", {})
            f.write(f"    MITRE    : {mitre.get('id', 'N/A')} — {mitre.get('name', '')}\n")
            f.write(f"    Risk     : {email.get('risk')}\n")
        for t in se_results.get("mitre_tactics", []):
            f.write(f"  [{t['id']}] {t['name']}\n")
        f.write("\n")

    def _write_recommendations(self, f, vuln_findings):
        f.write("=" * 60 + "\n")
        f.write("RECOMMENDATIONS\n")
        f.write("=" * 60 + "\n")
        # Dynamic recommendations based on findings
        has_critical = any(v.get("severity") == "critical" for v in vuln_findings)
        has_brute    = any(v.get("type") == "hydra" for v in vuln_findings)
        has_web      = any(v.get("service") in ("http", "https") for v in vuln_findings)

        recs = [
            "Apply all available security patches and updates immediately.",
            "Disable or firewall unnecessary open ports and services.",
        ]
        if has_critical:
            recs.append("CRITICAL: Patch or isolate systems with critical CVEs immediately.")
        if has_brute:
            recs.append("Enforce account lockout policies and strong password requirements.")
            recs.append("Consider multi-factor authentication (MFA) on all remote services.")
        if has_web:
            recs.append("Deploy a Web Application Firewall (WAF) and harden web services.")
        recs += [
            "Enable IDS/IPS monitoring and centralized logging (SIEM).",
            "Conduct regular penetration testing and vulnerability assessments.",
            "Implement network segmentation to limit lateral movement.",
        ]
        for i, rec in enumerate(recs, 1):
            f.write(f"  {i}. {rec}\n")
        f.write("\n")

    def _write_footer(self, f):
        f.write("=" * 60 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 60 + "\n")
