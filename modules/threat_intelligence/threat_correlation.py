"""
threat_intelligence/threat_correlation.py
------------------------------------------
Correlates vulnerability findings with threat intelligence signals
(CVSS, EPSS, KEV, vendor intel) to produce an enriched finding.
"""

from modules.threat_intelligence.cvss_engine        import CvssEngine
from modules.threat_intelligence.epss_engine        import EpssEngine
from modules.threat_intelligence.kev_engine         import KevEngine
from modules.threat_intelligence.vendor_intelligence import VendorIntelligence
from modules.threat_intelligence.product_intelligence import ProductIntelligence


class ThreatCorrelation:

    def __init__(self):
        self._cvss    = CvssEngine()
        self._epss    = EpssEngine()
        self._kev     = KevEngine()
        self._vendor  = VendorIntelligence()
        self._product = ProductIntelligence()

    def enrich(self, finding: dict) -> dict:
        cve     = finding.get("cve", "")
        product = finding.get("product", "")
        version = finding.get("version", "")

        cvss  = self._cvss.score(cve)
        epss  = self._epss.score(cve)
        is_kev = self._kev.is_kev(cve)

        finding["cvss_live"]    = cvss
        finding["epss"]         = round(epss, 4)
        finding["epss_label"]   = self._epss.risk_label(epss)
        finding["in_kev"]       = is_kev
        finding["eol_risk"]     = self._product.eol_risk(product, version)
        self._vendor.enrich_finding(finding)

        if is_kev:
            finding["severity"] = "critical"
        return finding

    def enrich_all(self, findings: list[dict]) -> list[dict]:
        return [self.enrich(f) for f in findings]
