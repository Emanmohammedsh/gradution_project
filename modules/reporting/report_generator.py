"""
reporting/report_generator.py
-------------------------------
Orchestrates all report sections into a single unified report.
"""

import json
import os
from datetime import datetime
from modules.reporting.executive_report import ExecutiveReport
from modules.reporting.mitre_report     import MitreReport
from modules.reporting.threat_report    import ThreatReport
from modules.reporting.json_reporter    import JsonReporter
from modules.reporting.pdf_reporter     import PdfReporter
from config.settings import REPORT_DATE_FORMAT


class ReportGenerator:

    def __init__(self):
        self._exec    = ExecutiveReport()
        self._mitre   = MitreReport()
        self._threat  = ThreatReport()
        self._json    = JsonReporter()
        self._pdf     = PdfReporter()

    def generate(self, scan_results: dict, findings: list[dict],
                 mapped_results: list[dict], attack_chain: dict,
                 risk_summary: dict, coverage: dict,
                 formats: list[str] | None = None) -> dict:

        formats = formats or ["json"]
        ts      = datetime.now().strftime(REPORT_DATE_FORMAT)

        report = {
            "report_id":        f"REPORT_{ts}",
            "generated_at":     datetime.now().isoformat(),
            "executive_summary": self._exec.build(scan_results, findings, attack_chain, risk_summary),
            "threat_intelligence": self._threat.build(findings),
            "mitre_analysis":   self._mitre.build(mapped_results, attack_chain, coverage),
            "attack_chain":     attack_chain,
            "vulnerabilities":  findings,
            "risk_summary":     risk_summary,
        }

        saved = {}
        if "json" in formats:
            saved["json"] = self._json.save(report, f"attack_report_{ts}.json")
        if "pdf" in formats:
            saved["pdf"]  = self._pdf.save(report, f"attack_report_{ts}.pdf")

        report["saved_files"] = saved
        print(f"\n  [Report] Generated: {list(saved.values())}")
        return report
