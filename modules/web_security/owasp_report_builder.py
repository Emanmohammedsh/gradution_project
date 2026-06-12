"""
web_security/owasp_report_builder.py
--------------------------------------
Builds the structured OWASP report from a list of WebFinding objects.
Groups findings by OWASP category, computes statistics, and
produces a dict ready for JSON serialisation or frontend consumption.
"""

import json
from collections import defaultdict
from datetime import datetime
from typing import List

from .web_findings import WebFinding, load_metadata

# Canonical OWASP Top 10 2021 IDs (for coverage calculation)
_TOP10_IDS = [
    "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
    "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
]


class OWASPReportBuilder:

    def __init__(self):
        # Build reverse map: owasp_id → owasp_name from metadata JSON
        meta = load_metadata()
        self._owasp_names: dict = {}
        for entry in meta.values():
            oid  = entry.get("owasp", "")
            name = entry.get("owasp_name", "")
            if oid and name:
                self._owasp_names[oid] = name

    def build(self, findings: List[WebFinding], target: str = "unknown") -> dict:
        """
        Parameters
        ----------
        findings : list of WebFinding from OWASPEngine
        target   : IP or hostname string

        Returns
        -------
        Full OWASP report dict
        """
        by_category  = defaultdict(list)
        by_risk      = defaultdict(int)
        by_technique = defaultdict(int)

        for f in findings:
            by_category[f.owasp_id].append(f.to_dict())
            by_risk[f.risk_level]  += 1
            if f.mitre_technique:
                by_technique[f.mitre_technique] += 1

        covered = sorted(by_category.keys())
        missing = [oid for oid in _TOP10_IDS if oid not in by_category]

        max_cvss = max((f.cvss_base for f in findings), default=0.0)

        report = {
            "meta": {
                "target":         target,
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "framework":      "OWASP Top 10 2021",
                "total_findings": len(findings),
                "max_cvss":       max_cvss,
            },
            "risk_summary": {
                "CRITICAL": by_risk.get("CRITICAL", 0),
                "HIGH":     by_risk.get("HIGH",     0),
                "MEDIUM":   by_risk.get("MEDIUM",   0),
                "LOW":      by_risk.get("LOW",      0),
            },
            "owasp_coverage": {
                "covered_categories": covered,
                "missing_categories": missing,
                "coverage_pct":       round(len(covered) / 10 * 100, 1),
            },
            "mitre_techniques": dict(by_technique),
            "findings_by_category": {
                oid: {
                    "name":     self._owasp_names.get(oid, oid),
                    "count":    len(items),
                    "findings": items,
                }
                for oid, items in sorted(by_category.items())
            },
            "all_findings": [f.to_dict() for f in findings],
        }
        return report

    def to_json(self, report: dict, indent: int = 2) -> str:
        return json.dumps(report, indent=indent)

    def save(self, report: dict, path: str) -> None:
        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)
