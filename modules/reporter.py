"""
reporter.py  —  Enhanced Report Generator
Produces:
  1. reports/report_<ts>.txt       — human-readable full report
  2. reports/attack_report_<ts>.json — structured JSON (for frontend/API)
"""

import datetime
import json
import os


class ReporterModule:

    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, target, live_hosts, scan_results,
                        vuln_findings, exploit_results, post_data,
                        attack_chain: dict | None = None) -> str:

        print(f"\n[R10] Generating Reports...")

        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_path  = f"{self.report_dir}/report_{ts}.txt"
        json_path = f"{self.report_dir}/attack_report_{ts}.json"

        self._write_txt(txt_path, target, live_hosts, scan_results,
                        vuln_findings, exploit_results, post_data, attack_chain)

        self._write_json(json_path, target, live_hosts, scan_results,
                         vuln_findings, exploit_results, post_data, attack_chain)

        print(f"  [+] TXT  report → {txt_path}")
        print(f"  [+] JSON report → {json_path}")
        return txt_path

    # ── TXT ───────────────────────────────────────────────────────────

    def _write_txt(self, path, target, live_hosts, scan_results,
                   vuln_findings, exploit_results, post_data, attack_chain):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "w", encoding="utf-8") as f:

            def ln(s=""): f.write(s + "\n")
            def sec(title):
                ln(); ln("=" * 60); ln(title); ln("=" * 60)

            ln("=" * 60)
            ln("   PENETRATION TESTING REPORT")
            ln("   Hybrid AI Red Team Simulation Framework")
            ln("   UCAS Cyber Security Engineering 2026")
            ln("=" * 60)
            ln(f"Date       : {now}")
            ln(f"Target     : {target}")
            ln(f"Live Hosts : {len(live_hosts)}")

            # ── Phase 1 ──
            sec("PHASE 1 — RECONNAISSANCE")
            for h in live_hosts:
                ln(f"  [+] {h}")

            # ── Phase 2 ──
            sec("PHASE 2 — SCANNING & ENUMERATION")
            for host, data in scan_results.items():
                ln(f"\n  Host: {host}  |  OS: {data.get('os','unknown')}")
                for p in data["ports"]:
                    ln(f"    {p['port']:>5}/tcp  {p['service']:<20} {p['product']} {p['version']}")

            # ── Phase 3 ──
            sec("PHASE 3 — VULNERABILITY MAPPING")
            for f_ in vuln_findings:
                ln(f"\n  {f_['host']}:{f_['port']}  |  {f_['service']}")
                ln(f"  CVE      : {f_['cve']}")
                ln(f"  Severity : {f_['severity'].upper()}  |  CVSS: {f_['cvss']}")
                ln(f"  Exploit  : {f_['exploit']}")
                if f_.get("edb_title"):
                    ln(f"  Title    : {f_['edb_title']}")

            # ── Phase 4 ──
            sec("PHASE 4 — EXPLOITATION")
            for r in exploit_results:
                if r.get("_is_post"):
                    continue
                status = "SUCCESS" if r.get("success") else "FAILED"
                ln(f"\n  {r['host']}:{r['port']}  |  {r['exploit']}")
                ln(f"  Status : {status}")

            # ── Phase 5 ──
            sec("PHASE 5 — POST-EXPLOITATION")
            if post_data:
                ln(f"  Host   : {post_data.get('host','N/A')}")
                ln(f"  UID    : {post_data.get('uid',['N/A'])}")
                ln(f"  Hashes : {post_data.get('hashes',['N/A'])}")
            else:
                ln("  No session established.")

            # ── Phase 6: MITRE ──
            sec("PHASE 6 — MITRE ATT&CK MAPPING")
            for r in exploit_results:
                mitre = r.get("mitre", {})
                if not mitre:
                    continue
                ln(f"\n  {r.get('host','')}:{r.get('port','')}  exploit: {r.get('exploit','')}")
                ln(f"  Primary  : [{mitre.get('source','?')}] "
                   f"{mitre.get('technique_id','?')} — {mitre.get('technique_name','?')}")
                ln(f"  Tactic   : {mitre.get('tactic','?')}")
                ln(f"  Conf     : {mitre.get('confidence',0):.0%}")
                if len(r.get("layers", [])) > 1:
                    ln(f"  All layers:")
                    for lyr in r["layers"]:
                        ln(f"    [{lyr.get('source','?')}] "
                           f"{lyr.get('technique_id','?')} "
                           f"{lyr.get('technique_name','?')} "
                           f"({lyr.get('confidence',0):.0%})")

            # ── Attack Chain ──
            if attack_chain:
                sec("PHASE 7 — ATTACK CHAIN (KILL-CHAIN)")
                for phase_num, phase in attack_chain.items():
                    ln(f"\n  Phase {phase_num}: {phase['phase_name']}  "
                       f"[{phase['tactic']}]  conf={phase['confidence']:.0%}")
                    for t in phase["techniques"]:
                        ln(f"    {t['id']}  {t['name']}")

            # ── Recommendations ──
            sec("RECOMMENDATIONS")
            recs = [
                "Patch all outdated software versions immediately (vsftpd, Samba, Apache).",
                "Disable unnecessary services — close ports 21, 23, 6667 if not in use.",
                "Enforce strong password policies and account lockout thresholds.",
                "Segment the network — restrict lateral movement between hosts.",
                "Deploy endpoint detection: monitor for hashdump, getsystem, arp sweep.",
                "Enable IDS/IPS and correlate with MITRE ATT&CK navigator layer (attached).",
                "Conduct periodic red team exercises against this attack chain.",
            ]
            for i, r in enumerate(recs, 1):
                ln(f"  {i}. {r}")

            ln(); ln("=" * 60); ln("END OF REPORT"); ln("=" * 60)

    # ── JSON ──────────────────────────────────────────────────────────

    def _write_json(self, path, target, live_hosts, scan_results,
                    vuln_findings, exploit_results, post_data, attack_chain):

        def sanitize(obj):
            """Make objects JSON-serialisable."""
            if isinstance(obj, dict):
                return {k: sanitize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [sanitize(i) for i in obj]
            if isinstance(obj, (str, int, float, bool)) or obj is None:
                return obj
            return str(obj)

        report = {
            "meta": {
                "generated":   datetime.datetime.now().isoformat(),
                "target":      target,
                "live_hosts":  live_hosts,
                "framework":   "Hybrid AI Red Team v2",
            },
            "scan_summary": {
                host: {
                    "os":    data.get("os", "unknown"),
                    "ports": data["ports"],
                }
                for host, data in scan_results.items()
            },
            "vulnerabilities": [
                {
                    "host":     f["host"],
                    "port":     f["port"],
                    "service":  f["service"],
                    "cve":      f["cve"],
                    "severity": f["severity"],
                    "cvss":     f["cvss"],
                    "risk_score": f.get("risk_score", 0),
                    "exploit":  f["exploit"],
                    "title":    f.get("edb_title", ""),
                }
                for f in vuln_findings
            ],
            "exploit_results": [
                {
                    "host":    r["host"],
                    "port":    r["port"],
                    "exploit": r["exploit"],
                    "success": r.get("success", False),
                    "mitre":   r.get("mitre", {}),
                    "layers":  r.get("layers", []),
                }
                for r in exploit_results
                if not r.get("_is_post")
            ],
            "post_exploitation": sanitize(post_data),
            "attack_chain": attack_chain or {},
            "mitre_summary": self._mitre_summary(exploit_results),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(sanitize(report), f, indent=2, ensure_ascii=False)

    @staticmethod
    def _mitre_summary(exploit_results: list) -> dict:
        """Aggregate techniques by tactic."""
        by_tactic: dict[str, list] = {}
        for r in exploit_results:
            for lyr in r.get("layers", []):
                tactic = lyr.get("tactic", "unknown")
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                entry = {
                    "id":         lyr.get("technique_id", ""),
                    "name":       lyr.get("technique_name", ""),
                    "confidence": lyr.get("confidence", 0),
                    "source":     lyr.get("source", ""),
                }
                ids = [e["id"] for e in by_tactic[tactic]]
                if entry["id"] not in ids:
                    by_tactic[tactic].append(entry)
        return by_tactic
