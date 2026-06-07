"""
main.py — Hybrid AI Red Team Simulation Framework v2.1
=======================================================
Pipeline:
  1   Reconnaissance
  2   Scanning
  3   Vulnerability Mapping
  4   Threat Intelligence     (CVSS · EPSS · KEV · Vendor)
  5   Risk Engine
  6   Exploitation
  7   Post-Exploitation       (Credential · Discovery · Persistence · PrivEsc · Lateral)
  8   MITRE ATT&CK Engine     (Rule · STIX · ML · ConfidenceFusion)
  9   AI Enrichment           (MitrePredictor · RiskPredictor · XAI · Recommendations)
  10  Attack Graph            (GraphBuilder · GraphAnalyzer · Neo4j optional)
  11  Social Engineering
  12  Report + DB Persist
"""

import uuid
from datetime import datetime

# ── Core pipeline ─────────────────────────────────────────────────────
from modules.recon             import ReconModule
from modules.scanner           import ScannerModule
from modules.vulnerability     import VulnMapperModule
from modules.risk_engine       import RiskEngine
from modules.exploiter         import ExploiterModule
from modules.post_exploitation import PostExploitModule
from modules.mitre             import MitreEngine
from modules.ai                import AIPipeline           # Phase 9 ← was missing
from modules.reporting         import ReportGenerator
from modules.social_engineering import SocialEngineeringModule
from modules.ai.training_pipeline import TrainingPipeline

# ── Threat Intelligence ───────────────────────────────────────────────
from modules.threat_intelligence.threat_correlation import ThreatCorrelation
from modules.threat_intelligence.threat_score       import ThreatScore

# ── Attack Graph ──────────────────────────────────────────────────────
from modules.attack_graph.graph_builder   import GraphBuilder
from modules.attack_graph.graph_analyzer  import GraphAnalyzer
from modules.attack_graph.neo4j_connector import Neo4jConnector

# ── Post-Exploit attack chain integration ────────────────────────────
from modules.post_exploitation.attack_chain_integrator import AttackChainIntegrator

# ── MITRE technique merger ────────────────────────────────────────────
from modules.mitre.technique_merger import TechniqueMerger

# ── Database persistence ──────────────────────────────────────────────
from database.repository import (
    save_session, save_vulnerabilities,
    save_exploit_results, save_mitre_findings, save_report,
)

# ── Config ────────────────────────────────────────────────────────────
from config.settings       import NEO4J_ENABLED
from config.logging_config import setup_logging, get_logger
setup_logging()
log = get_logger(__name__)


def main():
    print("=" * 62)
    print("   Hybrid AI Red Team Simulation Framework v2.1")
    print("   UCAS Cyber Security Engineering 2026")
    print("=" * 62)

    target = input("\nEnter Target IP or Network (e.g. 192.168.1.100): ").strip()
    lhost  = input("Enter Your Kali IP (LHOST): ").strip()

    session_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
    log.info("Session %s started — target=%s lhost=%s", session_id, target, lhost)

    # ── Phase 1: Reconnaissance ───────────────────────────────────────
    print(f"\n{'─'*50}")
    print("[Phase 1] Reconnaissance")
    recon      = ReconModule(target)
    live_hosts = recon.discover_hosts()
    if not live_hosts:
        print("[-] No live hosts. Halting."); return

    # ── Phase 2: Scanning ─────────────────────────────────────────────
    print(f"\n[Phase 2] Scanning & Service Enumeration")
    scanner      = ScannerModule(live_hosts[0])
    scan_results = scanner.scan_target()
    if not scan_results or all(len(d["ports"]) == 0 for d in scan_results.values()):
        print("[-] No open ports found. Halting."); return

    # ── Phase 3: Vulnerability Mapping ────────────────────────────────
    print(f"\n[Phase 3] Vulnerability Mapping (ExploitDB + Fallback)")
    vuln_mapper   = VulnMapperModule()
    vuln_findings = vuln_mapper.map_vulnerabilities(scan_results)
    if not vuln_findings:
        print("[-] No vulnerabilities mapped. Halting."); return

    # ── Phase 4: Threat Intelligence Enrichment ───────────────────────
    print(f"\n[Phase 4] Threat Intelligence (CVSS · EPSS · KEV · Vendor)")
    ti            = ThreatCorrelation()
    ts_scorer     = ThreatScore()
    vuln_findings = ti.enrich_all(vuln_findings)
    for f in vuln_findings:
        f["threat_score"]       = ts_scorer.calculate(f)
        f["threat_score_label"] = ts_scorer.label(f["threat_score"])
        if f.get("in_kev"):
            f["severity"] = "critical"   # KEV → always critical
        print(f"  [TI] {f['host']}:{f['port']} | "
              f"CVSS={f.get('cvss_live',f.get('cvss',0))} "
              f"EPSS={f.get('epss',0):.3f} "
              f"KEV={'YES' if f.get('in_kev') else 'no'} "
              f"TScore={f['threat_score']}")

    # ── Phase 5: Risk Engine ──────────────────────────────────────────
    print(f"\n[Phase 5] Risk Scoring (CVSS+EPSS+KEV → composite score)")
    risk_engine        = RiskEngine()
    high_risk_findings = risk_engine.filter_by_risk(vuln_findings, threshold=30)
    if not high_risk_findings:
        print("[-] No high-risk targets. Halting."); return

    # ── Phase 6: Exploitation ─────────────────────────────────────────
    print(f"\n[Phase 6] Exploitation (Rank → Probability → Execute)")
    exploiter       = ExploiterModule(lhost)
    exploit_run     = exploiter.run_exploits(high_risk_findings)
    exploit_results = exploit_run        # list[dict] — per-exploit results
    log.info("Exploitation complete — %d attempts, success=%s",
             len(exploit_results), exploit_run["success"])

    # ── Phase 7: Post-Exploitation ────────────────────────────────────
    print(f"\n[Phase 7] Post-Exploitation")
    post_data     = {}
    post_commands = []
    attack_chain  = {}   # will be built in Phase 8, updated in Phase 7

    for result in exploit_results:
        if result.get("success"):
            pe            = PostExploitModule(lhost)
            post_data     = pe.run_post_exploitation(
                                result["host"], result["port"], result["exploit"])
            post_commands = ["sysinfo", "getuid", "hashdump",
                             "arp", "ps", "getsystem"]
            break

    # ── Phase 8: Hybrid MITRE ATT&CK Engine ──────────────────────────
    print(f"\n[Phase 8] MITRE ATT&CK (Rule · STIX · ML · ConfidenceFusion)")
    mitre_engine   = MitreEngine()
    mapped_results = mitre_engine.map_all(exploit_results,
                                          post_commands=post_commands)
    # TechniqueMerger — deduplicate across all hosts  ← Bug 4 fixed
    merger         = TechniqueMerger()
    merged_techs   = merger.merge(mapped_results)
    log.info("Merged techniques: %d unique", len(merged_techs))

    attack_chain   = mitre_engine.build_chain(mapped_results)

    # AttackChainIntegrator — enrich chain with post-exploit phases ← Bug 3 fixed
    if post_data:
        integrator   = AttackChainIntegrator()
        attack_chain = integrator.integrate(post_data, attack_chain)
        log.info("Attack chain extended with post-exploit phases: %d total",
                 len(attack_chain))

    mitre_engine.save_heatmap(mapped_results, f"reports/attack_layer_{ts}.json")
    mitre_engine.save_chain(attack_chain,     f"reports/attack_chain_{ts}.json")

    # ── Phase 9: AI Enrichment ────────────────────────────────────────
    print(f"\n[Phase 9] AI Enrichment (MitrePredictor · XAI · Adversary · Recommendations)")
    ai_pipeline = AIPipeline()                           # ← Bug 2 fixed
    ai_results  = ai_pipeline.enrich_findings(mapped_results, attack_chain)

    if ai_results.get("adversary_match"):
        top_match = max(ai_results["adversary_match"],
                        key=lambda x: x.get("similarity", 0), default={})
        if top_match:
            print(f"  [AI] Closest adversary: {top_match.get('name')} "
                  f"similarity={top_match.get('similarity', 0):.0%}")

    if ai_results.get("recommendations"):
        print(f"  [AI] {len(ai_results['recommendations'])} remediation recommendations generated")

    # ── Phase 10: Attack Graph ────────────────────────────────────────
    print(f"\n[Phase 10] Attack Graph (nodes · edges · centrality)")
    graph_data    = GraphBuilder().build(exploit_results, attack_chain)
    analyzer      = GraphAnalyzer()
    graph_analysis = analyzer.analyze(graph_data)
    print(f"  [Graph] Nodes={graph_analysis['total_nodes']} "
          f"Edges={graph_analysis['total_edges']} "
          f"Top={graph_analysis.get('top_nodes', [])[:3]}")

    # Neo4j — optional, controlled by env var
    if NEO4J_ENABLED:
        from config.settings import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
        neo = Neo4jConnector(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        neo.push_graph(graph_data)
        neo.close()
    else:
        print("  [Graph] Neo4j disabled (NEO4J_ENABLED=false) — using in-memory graph")

    # ── Phase 11: Social Engineering ─────────────────────────────────
    print(f"\n[Phase 11] Social Engineering")
    domain        = target.split("/")[0]
    open_services = list({p.get("service", "")
                          for d in scan_results.values()
                          for p in d["ports"] if p.get("service", "")})
    se_module  = SocialEngineeringModule(domain, lhost)
    se_results = se_module.run_campaign({"open_services": open_services})

    # ── Phase 12: Report + DB ─────────────────────────────────────────
    print(f"\n[Phase 12] Generating Reports & Saving to Database")
    generator   = ReportGenerator()
    report_file = generator.generate(
        target          = target,
        live_hosts      = live_hosts,
        scan_results    = scan_results,
        vuln_findings   = vuln_findings,
        exploit_results = mapped_results,
        post_data       = post_data,
        attack_chain    = attack_chain,
        graph_data      = graph_analysis,
        session_id      = session_id,
        ai_results      = ai_results,
        formats         = ["json", "pdf"],
    )

    # Database
    try:
        db_id = save_session(session_id, target, lhost, live_hosts)
        save_vulnerabilities(db_id, vuln_findings)
        save_exploit_results(db_id, exploit_results)
        save_mitre_findings(db_id, mapped_results)
        if report_file:
            save_report(db_id, report_file, "json")
        log.info("Session %s persisted — DB id=%s", session_id, db_id)
    except Exception as e:
        log.warning("DB save skipped: %s", e)

    # ── Final Summary ─────────────────────────────────────────────────
    print(f"\n{'=' * 62}")
    print(f"[+] Session ID    : {session_id}")
    print(f"[+] Pipeline      : COMPLETE (12 phases)")
    print(f"[+] Findings      : {len(vuln_findings)} vulnerabilities")
    print(f"[+] MITRE Techs   : {len(merged_techs)} unique techniques")
    print(f"[+] Chain Phases  : {len(attack_chain)}")
    print(f"[+] Graph Nodes   : {graph_analysis['total_nodes']}")
    print(f"[+] AI Recs       : {len(ai_results.get('recommendations', []))}")
    print(f"[+] Report        : {report_file}")
    print(f"[+] ATT&CK Heatmap: reports/attack_layer_{ts}.json")
    print(f"[+] ATT&CK Chain  : reports/attack_chain_{ts}.json")
    print(f"{'=' * 62}")


if __name__ == "__main__":
    main()
