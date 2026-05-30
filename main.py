"""
main.py
-------
Hybrid AI-Based Penetration Testing Framework
Pipeline:
  Recon → Scanner → VulnMapper → RiskEngine → ExploitPrioritizer (AI)
  → Exploiter → PostExploit + PostExploitAI → MitreEngine (Hybrid)
  → SocialEngineering → Reporter
"""

import datetime
import os

from modules.recon               import ReconModule
from modules.scanner             import ScannerModule
from modules.vuln_mapper         import VulnMapperModule
from modules.risk_engine         import RiskEngine
from modules.exploit_prioritizer import ExploitPrioritizer
from modules.exploiter           import ExploiterModule
from modules.post_exploit        import PostExploitModule
from modules.post_exploit_ai     import PostExploitAI
from modules.mitre               import MitreEngine, AttackChainBuilder, HeatmapGenerator
from modules.social_engineering  import SocialEngineeringModule
from modules.reporter            import ReporterModule


def main():
    print("=" * 60)
    print("   Hybrid AI-Based Penetration Testing Framework")
    print("=" * 60)

    target = input("\nEnter Target IP or Network: ")
    lhost  = input("Enter Your Kali IP (LHOST): ")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)

    # ------------------------------------------------------------------
    # Phase 1 — Reconnaissance
    # ------------------------------------------------------------------
    recon      = ReconModule(target)
    live_hosts = recon.discover_hosts()

    if not live_hosts:
        print("\n[-] No live hosts found. Halting.")
        return

    # ------------------------------------------------------------------
    # Phase 2 — Scanning
    # ------------------------------------------------------------------
    scanner      = ScannerModule(live_hosts[0])
    scan_results = scanner.scan_target()

    if not scan_results or all(len(d["ports"]) == 0 for d in scan_results.values()):
        print("\n[-] No scan results. Halting.")
        return

    # ------------------------------------------------------------------
    # Phase 3 — Vulnerability Mapping
    # ------------------------------------------------------------------
    vuln_mapper   = VulnMapperModule()
    vuln_findings = vuln_mapper.map_vulnerabilities(scan_results)

    if not vuln_findings:
        print("\n[-] No vulnerabilities found. Halting.")
        return

    # ------------------------------------------------------------------
    # Phase 4 — Risk Engine
    # ------------------------------------------------------------------
    risk_engine       = RiskEngine()
    high_risk_findings = risk_engine.filter_by_risk(vuln_findings, threshold=30)

    if not high_risk_findings:
        print("\n[-] No high-risk targets. Halting.")
        return

    # ------------------------------------------------------------------
    # Phase 4b — AI Exploit Prioritizer (NEW)
    # ------------------------------------------------------------------
    prioritizer        = ExploitPrioritizer()
    prioritized        = prioritizer.prioritize(high_risk_findings)

    # ------------------------------------------------------------------
    # Phase 5 — Exploitation
    # ------------------------------------------------------------------
    exploiter      = ExploiterModule(lhost)
    exploit_results = exploiter.run_exploits(prioritized)

    # ------------------------------------------------------------------
    # Phase 6 — Post-Exploitation (classic + AI)
    # ------------------------------------------------------------------
    post_data    = {}
    post_ai_data = {}

    for result in exploit_results:
        if result.get("success"):
            # Classic post-exploitation (Meterpreter commands)
            post_exploit = PostExploitModule(lhost)
            post_data    = post_exploit.run_post_exploitation(
                result["host"], result["port"], result["exploit"]
            )
            # AI post-exploitation analysis
            post_ai = PostExploitAI()
            post_ai_data = post_ai.analyze(
                result["host"],
                post_data.get("raw_output", "")
            )
            # Merge AI output into post_data for reporter
            post_data.update(post_ai_data)
            # Attach post output to result for MITRE engine
            result["post_data"] = post_data
            break

    # ------------------------------------------------------------------
    # Phase 7 — Hybrid MITRE ATT&CK Engine (NEW)
    # ------------------------------------------------------------------
    mitre_engine   = MitreEngine()
    mapped_results = mitre_engine.map_techniques(exploit_results)

    # Build Kill Chain
    chain_builder = AttackChainBuilder()
    attack_chain  = chain_builder.build(
        [r["mitre"] for r in mapped_results if r.get("mitre")]
    )
    chain_builder.print_chain(attack_chain)

    # Generate ATT&CK Navigator heatmap
    heatmap_gen  = HeatmapGenerator()
    heatmap_layer = heatmap_gen.generate(attack_chain, target=target)
    heatmap_file  = f"reports/attack_layer_{timestamp}.json"
    heatmap_gen.save(heatmap_layer, heatmap_file)

    # ------------------------------------------------------------------
    # Phase 8 — Social Engineering Campaign
    # ------------------------------------------------------------------
    target_domain = target.split("/")[0]
    open_services = []
    for host_data in scan_results.values():
        for p in host_data["ports"]:
            svc = p.get("service", "")
            if svc and svc not in open_services:
                open_services.append(svc)

    se_module  = SocialEngineeringModule(target_domain, lhost)
    se_results = se_module.run_campaign({"open_services": open_services})

    # ------------------------------------------------------------------
    # Phase 9 — Report
    # ------------------------------------------------------------------
    reporter    = ReporterModule()
    report_file = reporter.generate_report(
        target,
        live_hosts,
        scan_results,
        vuln_findings,
        mapped_results,
        post_data,
        se_results=se_results,
        attack_chain=attack_chain
    )

    print(f"\n{'=' * 60}")
    print(f"[+] Pipeline Complete!")
    print(f"[+] Report         : {report_file}")
    print(f"[+] ATT&CK Layer   : {heatmap_file}")
    print(f"    → Import at    : https://mitre-attack.github.io/attack-navigator/")
    print("=" * 60)


if __name__ == "__main__":
    main()
