from modules.recon              import ReconModule
from modules.scanner            import ScannerModule
from modules.vuln_mapper        import VulnMapperModule
from modules.risk_engine        import RiskEngine
from modules.exploiter          import ExploiterModule
from modules.mitre              import MitreEngine          # ← new hybrid engine
from modules.post_exploit       import PostExploitModule
from modules.reporter           import ReporterModule
from modules.social_engineering import SocialEngineeringModule


def main():
    print("=" * 60)
    print("   Hybrid AI Red Team Simulation Framework")
    print("   UCAS Cyber Security Engineering 2026")
    print("=" * 60)

    target = input("\nEnter Target IP or Network: ")
    lhost  = input("Enter Your Kali IP (LHOST): ")

    # ── Phase 1: Reconnaissance ──────────────────────────────────────
    recon      = ReconModule(target)
    live_hosts = recon.discover_hosts()
    if not live_hosts:
        print("\n[-] No live hosts. Halting."); return

    # ── Phase 2: Scanning ─────────────────────────────────────────────
    scanner     = ScannerModule(live_hosts[0])
    scan_results = scanner.scan_target()
    if not scan_results or all(len(d["ports"]) == 0 for d in scan_results.values()):
        print("\n[-] No scan results. Halting."); return

    # ── Phase 3: Vulnerability Mapping ───────────────────────────────
    vuln_mapper   = VulnMapperModule()
    vuln_findings = vuln_mapper.map_vulnerabilities(scan_results)
    if not vuln_findings:
        print("\n[-] No vulnerabilities found. Halting."); return

    # ── Phase 4: Risk Engine ──────────────────────────────────────────
    risk_engine        = RiskEngine()
    high_risk_findings = risk_engine.filter_by_risk(vuln_findings, threshold=30)
    if not high_risk_findings:
        print("\n[-] No high-risk targets. Halting."); return

    # ── Phase 5: Exploitation ─────────────────────────────────────────
    exploiter      = ExploiterModule(lhost)
    exploit_results = exploiter.run_exploits(high_risk_findings)

    # ── Phase 6: Post-Exploitation ────────────────────────────────────
    post_data      = {}
    post_commands  = []
    for result in exploit_results:
        if result["success"]:
            pe = PostExploitModule(lhost)
            post_data     = pe.run_post_exploitation(result["host"], result["port"], result["exploit"])
            post_commands = ["sysinfo", "getuid", "hashdump", "arp", "ps", "getsystem"]
            break

    # ── Phase 7: Hybrid MITRE ATT&CK Engine ─────────────────────────
    mitre_engine  = MitreEngine()
    mapped_results = mitre_engine.map_all(exploit_results, post_commands=post_commands)

    attack_chain  = mitre_engine.build_chain(mapped_results)

    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    mitre_engine.save_heatmap(mapped_results, f"reports/attack_layer_{ts}.json")
    mitre_engine.save_chain(attack_chain,     f"reports/attack_chain_{ts}.json")

    # ── Phase 8: Social Engineering ───────────────────────────────────
    domain       = target.split("/")[0]
    open_services = list({p.get("service","") for d in scan_results.values()
                          for p in d["ports"] if p.get("service","")})
    se_module    = SocialEngineeringModule(domain, lhost)
    se_results   = se_module.run_campaign({"open_services": open_services})

    # ── Phase 9: Report ───────────────────────────────────────────────
    reporter    = ReporterModule()
    report_file = reporter.generate_report(
        target, live_hosts, scan_results,
        vuln_findings, mapped_results, post_data,
        attack_chain=attack_chain,
    )

    print(f"\n[+] Pipeline Complete!")
    print(f"[+] Report        : {report_file}")
    print(f"[+] ATT&CK Chain  : reports/attack_chain_{ts}.json")
    print(f"[+] ATT&CK Heatmap: reports/attack_layer_{ts}.json")
    print("=" * 60)


if __name__ == "__main__":
    main()
