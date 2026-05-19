from modules.recon import ReconModule
from modules.scanner import ScannerModule
from modules.vuln_mapper import VulnMapperModule
from modules.risk_engine import RiskEngine
from modules.exploiter import ExploiterModule
from modules.mitre_mapper import MitreMapper
from modules.post_exploit import PostExploitModule
from modules.reporter import ReporterModule
from modules.social_engineering import SocialEngineeringModule

def main():
    print("=" * 60)
    print("   Rule-Based Adaptive Red Teaming System")
    print("=" * 60)

    target = input("\nEnter Target IP or Network: ")
    lhost = input("Enter Your Kali IP (LHOST): ")

    # Phase 1 - Reconnaissance (R0, R1)
    recon = ReconModule(target)
    live_hosts = recon.discover_hosts()

    if not live_hosts:
        print("\n[-] No live hosts. Halting system.")
        return

    # Phase 2 - Scanning (R3, R4, R5)
    scanner = ScannerModule(live_hosts[0])
    scan_results = scanner.scan_target()

    if not scan_results or all(len(data["ports"]) == 0 for data in scan_results.values()):
        print("\n[-] No scan results. Halting system.")
        return

    # Phase 3 - Vulnerability Mapping (R6)
    vuln_mapper = VulnMapperModule()
    vuln_findings = vuln_mapper.map_vulnerabilities(scan_results)

    if not vuln_findings:
        print("\n[-] No vulnerabilities found. Halting system.")
        return

    # Phase 4 - Risk Engine
    risk_engine = RiskEngine()
    high_risk_findings = risk_engine.filter_by_risk(vuln_findings, threshold=30)

    if not high_risk_findings:
        print("\n[-] No high risk targets. Halting system.")
        return

    # Phase 5 - Exploitation (R7, R8)
    exploiter = ExploiterModule(lhost)
    exploit_results = exploiter.run_exploits(high_risk_findings)

    # Phase 6 - MITRE ATT&CK Mapping
    mitre_mapper = MitreMapper()
    mapped_results = mitre_mapper.map_techniques(exploit_results)

    # Phase 7 - Post-Exploitation (R9)
    post_data = {}
    for result in exploit_results:
        if result["success"]:
            post_exploit = PostExploitModule(lhost)
            post_data = post_exploit.run_post_exploitation(
                result["host"],
                result["port"],
                result["exploit"]
            )
            break

    # Phase 8 - Social Engineering Campaign
    target_domain = target.split("/")[0]
    open_services = []
    for host_data in scan_results.values():
        for p in host_data["ports"]:
            svc = p.get("service", "")
            if svc and svc not in open_services:
                open_services.append(svc)

    se_module = SocialEngineeringModule(target_domain, lhost)
    se_results = se_module.run_campaign({"open_services": open_services})

    # Phase 9 - Reporting (R10)
    reporter = ReporterModule()
    report_file = reporter.generate_report(
        target,
        live_hosts,
        scan_results,
        vuln_findings,
        mapped_results,
        post_data
    )

    print(f"\n[+] Pipeline Complete!")
    print(f"[+] Report: {report_file}")
    print("=" * 60)

if __name__ == "__main__":
    main()
