"""
modules/threat_intelligence/__init__.py
-----------------------------------------
Preserves original RiskEngine interface; now backed by full TI pipeline.
"""

from modules.threat_intelligence.cvss_engine        import CvssEngine
from modules.threat_intelligence.epss_engine        import EpssEngine
from modules.threat_intelligence.kev_engine         import KevEngine
from modules.threat_intelligence.vendor_intelligence import VendorIntelligence
from modules.threat_intelligence.product_intelligence import ProductIntelligence
from modules.threat_intelligence.threat_correlation  import ThreatCorrelation
from modules.threat_intelligence.threat_score        import ThreatScore

# Alias so main.py import still works
from modules.risk_engine import RiskEngine  # noqa: F401  (kept for backward compat)

__all__ = [
    "CvssEngine", "EpssEngine", "KevEngine",
    "VendorIntelligence", "ProductIntelligence",
    "ThreatCorrelation", "ThreatScore", "RiskEngine",
]
