"""
threat_intelligence/cvss_engine.py
------------------------------------
CVSS v3.1 score lookup and band classification.
Uses a local known-CVE table; falls back to NVD API if configured.
"""

import os
import json
import urllib.request
from config.settings import VULN_NVD_API_URL, VULN_NVD_API_KEY

KNOWN_CVSS = {
    "CVE-2011-2523": 10.0,
    "CVE-2007-2447": 9.3,
    "CVE-2017-0144": 9.3,   # EternalBlue
    "CVE-2021-44228": 10.0, # Log4Shell
    "CVE-2019-0708": 9.8,   # BlueKeep
    "CVE-2014-6271": 9.8,   # Shellshock
}


class CvssEngine:

    def score(self, cve: str) -> float:
        if cve in KNOWN_CVSS:
            return KNOWN_CVSS[cve]
        if VULN_NVD_API_KEY:
            return self._nvd_lookup(cve)
        return 3.0  # default low

    def band(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score >= 0.1: return "LOW"
        return "NONE"

    def _nvd_lookup(self, cve: str) -> float:
        try:
            url = f"{VULN_NVD_API_URL}?cveId={cve}"
            req = urllib.request.Request(url, headers={"apiKey": VULN_NVD_API_KEY})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0]["cve"].get("metrics", {})
                cvss3 = metrics.get("cvssMetricV31", [{}])[0]
                return cvss3.get("cvssData", {}).get("baseScore", 3.0)
        except Exception:
            pass
        return 3.0
