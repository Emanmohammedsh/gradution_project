"""
main.py — Hybrid AI Red Team Simulation Framework v2.1
=======================================================
Pipeline:
  1   Reconnaissance
  2   Scanning + OWASP Web Security
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
from modules.recon              import ReconModule
from modules.scanner            import ScannerModule
from modules.vulnerability      import VulnMapperModule
from modules.risk_engine        import RiskEngine
from modules.exploiter          import ExploiterModule
from modules.post_exploitation  import PostExploitModule
from modules.mitre              import MitreEngine
from modules.mitre.coverage_analyzer  import CoverageAnalyzer
from modules.mitre.technique_merger   import TechniqueMerger
from modules.ai                 import AIPipeline
from modules.reporting          import ReportGenerator
from modules.social_engineering import SocialEngineeringModule

# ── OWASP Web Security Module ─────────────────────────────────────────
from modules.web_security import (
    OWASPEngine,
    TechnologyDetector,
    InjectionChecker,
    BrokenAccessControlChecker,
    AuthFailureChecker,
    SecurityMisconfigurationChecker,
    VulnerableComponentsChecker,
    CryptographicFailureChecker,
    SSRFChecker,
    OWASPReportBuilder,
)

# ── Threat Intelligence ───────────────────────────────────────────────
from modules.threat_intelligence.threat_correlation import ThreatCorrelation
from modules.threat_intelligence.threat_score       import ThreatScore

# ── Attack Graph ──────────────────────────────────────────────────────
from modules.attack_graph.graph_builder   import GraphBuilder
from modules.attack_graph.graph_analyzer  import GraphAnalyzer
from modules.attack_graph.neo4j_connector import Neo4jConnector

# ── Post-exploit chain integrator ────────────────────────────────────
from modules.post_exploitation.attack_chain_integrator import AttackChainIntegrator

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


def run_owasp_web_scan(target: str, ts: str) -> dict:
    """
    Run OWASP Top 10 checkers against a web target.
    Returns dict with owasp_findings, technologies, owasp_report, owasp_summary.
    If target is not an HTTP/HTTPS URL the scan is skipped gracefully.
    """
    print("\n[🔒 OWASP Web Security Scan]")
    print("─" * 40)

    # Only scan web targets
    if not target.startswith(("http://", "https://")):
        print("  [⚠️]  Target is not a web URL — skipping OWASP scan")
        return {
            "owasp_findings": [],
            "technologies":   [],
            "owasp_report":   {},
            "owasp_summary":  {},
        }

    # ── Technology fingerprinting ─────────────────────────────────────
    detector     = TechnologyDetector()
    fingerprint  = detector.detect(target)          # returns dict with tech_stack etc.
    technologies = fingerprint.get("tech_stack", []) if isinstance(fingerprint, dict) else list(fingerprint)

    if technologies:
        print(f"  📊 Technologies : {', '.join(technologies)}")

    # ── Build service_data stub for checkers ──────────────────────────
    from urllib.parse import urlparse
    parsed = urlparse(target)
    service_data = {
        "host":    parsed.hostname or target,
        "port":    parsed.port or (443 if parsed.scheme == "https" else 80),
        "service": parsed.scheme,
        "banner":  fingerprint.get("raw_banner", "") if isinstance(fingerprint, dict) else "",
    }

    # ── Run all 7 OWASP checkers ──────────────────────────────────────
    checkers = [
        InjectionChecker(),
        BrokenAccessControlChecker(),
        AuthFailureChecker(),
        SecurityMisconfigurationChecker(),
        VulnerableComponentsChecker(),
        CryptographicFailureChecker(),
        SSRFChecker(),
    ]

    all_findings = []
    for checker in checkers:
        try:
            findings = checker.check(service_data, fingerprint if isinstance(fingerprint, dict) else {})
            all_findings.extend(findings)
        except Exception as exc:
            log.warning("OWASP checker %s failed: %s", checker.__class__.__name__, exc)

    print(f"  [+] OWASP findings : {len(all_findings)}")

    # ── Build structured OWASP report ────────────────────────────────
    owasp_report = OWASPReportBuilder().build(all_findings, target=service_data["host"])

    # Save OWASP report to disk alongside other reports
    try:
        import json, os
        os.makedirs("reports", exist_ok=True)
        owasp_path = f"reports/owasp_report_{ts}.json"
        with open(owasp_path, "w") as fh:
            json.dump(owasp_report, fh, indent=2)
        print(f"  [+] OWASP report   : {owasp_path}")
    except Exception as exc:
        log.warning("Could not save OWASP report: %s", exc)

    return {
        "owasp_findings": all_findings,          # list[WebFinding]
        "technologies":   technologies,
        "owasp_report":   owasp_report,
        "owasp_summary":  owasp_report.get("risk_summary", {}),
    }


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

    # ── Phase 2: Scanning + OWASP Web Security ────────────────────────
    print("\n[Phase 2] Scanning & Service Enumeration")
    scanner      = ScannerModule(live_hosts[0])
    scan_results = scanner.scan_target()

    # OWASP scan runs in parallel with port scanning
    owasp_results = run_owasp_web_scan(target, ts)

    if not scan_results or all(len(d["ports"]) == 0 for d in scan_results.values()):
        print("[-] No open ports found. Halting."); return

    # ── Phase 3: Vulnerability Mapping ────────────────────────────────
    print("\n[Phase 3] Vulnerability Mapping (ExploitDB + Fallback + OWASP)")
    vuln_mapper   = VulnMapperModule()
    vuln_findings = vuln_mapper.map_vulnerabilities(scan_results)

    # Merge WebFinding objects from OWASP into the unified vuln list
    for wf in owasp_results["owasp_findings"]:
        wf_dict = wf.to_dict() if hasattr(wf, "to_dict") else wf
        vuln_findings.append({
            "host":          target,
            "port":          wf_dict.get("port") or (443 if "https" in target else 80),
            "service":       wf_dict.get("service", "web"),
            "vulnerability": wf_dict.get("title", "Unknown"),
            "description":   "; ".join(wf_dict.get("evidence", [])),
            "severity":      wf_dict.get("risk_level", "MEDIUM").lower(),
            "cve":           wf_dict.get("cwe_id", ""),
            "cvss":          wf_dict.get("cvss_base", 0.0),
            "mitre":         wf_dict.get("mitre_technique", ""),
            "owasp_id":      wf_dict.get("owasp_id", ""),
            "remediation":   wf_dict.get("remediation", ""),
            "source":        "OWASP Web Security",
        })

    if owasp_results["owasp_findings"]:
        print(f"  [+] Added {len(owasp_results['owasp_findings'])} OWASP findings")

    if not vuln_findings:
        print("[-] No vulnerabilities mapped. Halting."); return

    # ── Phase 4: Threat Intelligence Enrichment ───────────────────────
    print("\n[Phase 4] Threat Intelligence (CVSS · EPSS · KEV · Vendor)")
    ti            = ThreatCorrelation()
    ts_scorer     = ThreatScore()
    vuln_findings = ti.enrich_all(vuln_findings)
    for f in vuln_findings:
        f["threat_score"]       = ts_scorer.calculate(f)
        f["threat_score_label"] = ts_scorer.label(f["threat_score"])
        if f.get("in_kev"):
            f["severity"] = "critical"
        print(f"  [TI] {f['host']}:{f['port']} | "
              f"CVSS={f.get('cvss_live', f.get('cvss', 0))} "
              f"EPSS={f.get('epss', 0):.3f} "
              f"KEV={'YES' if f.get('in_kev') else 'no'} "
              f"TScore={f['threat_score']}")

    # ── Phase 5: Risk Engine ──────────────────────────────────────────
    print("\n[Phase 5] Risk Scoring (CVSS+EPSS+KEV → composite score)")
    risk_engine        = RiskEngine()
    high_risk_findings = risk_engine.filter_by_risk(vuln_findings, threshold=30)
    if not high_risk_findings:
        print("[-] No high-risk targets. Halting."); return

    # ── Phase 6: Exploitation ─────────────────────────────────────────
    print("\n[Phase 6] Exploitation")
    exploiter       = ExploiterModule(lhost)
    exploit_results = exploiter.run_exploits(high_risk_findings)
    log.info("Exploitation complete — %d attempts", len(exploit_results))

    # ── Phase 7: Post-Exploitation ────────────────────────────────────
    print("\n[Phase 7] Post-Exploitation")
    post_data     = {}
    post_commands = []

    for result in exploit_results:
        if result.get("success"):
            pe        = PostExploitModule(lhost)
            post_data = pe.run_post_exploitation(
                result["host"], result["port"],
                result.get("exploit", ""),
                attack_chain=None,
            )
            post_commands = ["sysinfo", "getuid", "hashdump",
                             "arp", "ps", "getsystem"]
            break

    # ── Phase 8: Hybrid MITRE ATT&CK Engine ──────────────────────────
    print("\n[Phase 8] MITRE ATT&CK (Rule · STIX · ML · ConfidenceFusion)")
    mitre_engine   = MitreEngine()
    mapped_results = mitre_engine.map_all(exploit_results,
                                          post_commands=post_commands)

    merged_techs = TechniqueMerger().merge(mapped_results)
    log.info("Merged unique techniques: %d", len(merged_techs))

    attack_chain = mitre_engine.build_chain(mapped_results)

    if post_data:
        attack_chain = AttackChainIntegrator().integrate(post_data, attack_chain)
        log.info("Attack chain extended: %d phases", len(attack_chain))

    mitre_engine.save_heatmap(mapped_results, f"reports/attack_layer_{ts}.json")
    mitre_engine.save_chain(attack_chain,     f"reports/attack_chain_{ts}.json")

    coverage = CoverageAnalyzer().analyze(mapped_results)
    print(f"  [Coverage] Tactics={len(coverage['covered_tactics'])} "
          f"Techniques={coverage['technique_count']} "
          f"Coverage={coverage['tactic_coverage_pct']}%")

    # ── Phase 9: AI Enrichment ────────────────────────────────────────
    print("\n[Phase 9] AI Enrichment (MitrePredictor · XAI · Adversary · Recommendations)")
    ai_pipeline = AIPipeline()
    ai_results  = ai_pipeline.enrich_findings(mapped_results, attack_chain)

    if ai_results.get("adversary_match"):
        top = ai_results["adversary_match"][0]
        print(f"  [AI] Closest adversary: {top.get('apt')} "
              f"similarity={top.get('similarity', 0):.0%} "
              f"matched={top.get('matched', [])}")

    if ai_results.get("recommendations"):
        print(f"  [AI] {len(ai_results['recommendations'])} remediation recommendations")

    # ── Phase 10: Attack Graph ────────────────────────────────────────
    print("\n[Phase 10] Attack Graph (nodes · edges · centrality)")
    graph_data     = GraphBuilder().build(exploit_results, attack_chain)
    graph_analysis = GraphAnalyzer().analyze(graph_data)
    print(f"  [Graph] Nodes={graph_analysis.get('total_nodes', 0)} "
          f"Edges={graph_analysis.get('total_edges', 0)} "
          f"Top={graph_analysis.get('top_nodes', [])[:3]}")

    if NEO4J_ENABLED:
        from config.settings import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
        neo = Neo4jConnector(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        neo.push_graph(graph_data)
        neo.close()
    else:
        print("  [Graph] Neo4j disabled — using in-memory graph")

    # ── Phase 11: Social Engineering ─────────────────────────────────
    print("\n[Phase 11] Social Engineering")
    domain        = target.split("/")[0]
    open_services = list({p.get("service", "")
                          for d in scan_results.values()
                          for p in d["ports"] if p.get("service", "")})
    se_module  = SocialEngineeringModule(domain, lhost)
    se_results = se_module.run_campaign({"open_services": open_services})

    # ── Phase 12: Report + DB ─────────────────────────────────────────
    print("\n[Phase 12] Generating Reports & Saving to Database")

    risk_summary = {
        "total_findings":   len(vuln_findings),
        "high_risk_count":  len(high_risk_findings),
        "kev_count":        sum(1 for f in vuln_findings if f.get("in_kev")),
        "exploit_success":  sum(1 for r in exploit_results if r.get("success")),
        "risk_score":       max((f.get("risk_score", 0) for f in vuln_findings), default=0),
        "attack_phases":    len(attack_chain),
        "post_credentials": len(post_data.get("hashes", [])),
        "lateral_targets":  len(post_data.get("lateral_opps", [])),
        "owasp_findings":   len(owasp_results["owasp_findings"]),
        "owasp_coverage":   owasp_results["owasp_report"].get("owasp_coverage", {}),
        "technologies":     owasp_results["technologies"],
    }

    generator = ReportGenerator()
    report    = generator.generate(
        scan_results   = scan_results,
        findings       = vuln_findings,
        mapped_results = mapped_results,
        attack_chain   = attack_chain,
        risk_summary   = risk_summary,
        coverage       = coverage,
        formats        = ["json"],
    )
    report_file = report.get("saved_files", {}).get("json", "")

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
    owasp_cov = owasp_results["owasp_report"].get("owasp_coverage", {})
    print(f"\n{'=' * 62}")
    print(f"[+] Session ID      : {session_id}")
    print(f"[+] Pipeline        : COMPLETE (12 phases + OWASP)")
    print(f"[+] Findings        : {len(vuln_findings)} vulnerabilities")
    print(f"[+] OWASP Findings  : {len(owasp_results['owasp_findings'])}")
    print(f"[+] OWASP Coverage  : {owasp_cov.get('coverage_pct', 0)}% "
          f"({len(owasp_cov.get('covered_categories', []))}/10 categories)")
    print(f"[+] Technologies    : {', '.join(owasp_results['technologies'])}")
    print(f"[+] MITRE Techs     : {len(merged_techs)} unique techniques")
    print(f"[+] Chain Phases    : {len(attack_chain)}")
    print(f"[+] MITRE Coverage  : {coverage['tactic_coverage_pct']}%")
    print(f"[+] Graph Nodes     : {graph_analysis.get('total_nodes', 0)}")
    print(f"[+] AI Recs         : {len(ai_results.get('recommendations', []))}")
    print(f"[+] Report          : {report_file}")
    print(f"[+] ATT&CK Heatmap  : reports/attack_layer_{ts}.json")
    print(f"[+] ATT&CK Chain    : reports/attack_chain_{ts}.json")
    print(f"{'=' * 62}")


if __name__ == "__main__":
    main()
