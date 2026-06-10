"""
OWASP Web Security Testing Module
Auto-generated from OWASP Top 10 2025 GitHub repository
Official Reference: https://github.com/OWASP/Top10
"""

from .owasp_engine import OWASPEngine
from .technology_detector import TechnologyDetector
from .web_asset_discovery import WebAssetDiscovery
from .injection_checker import InjectionChecker
from .broken_access_control_checker import BrokenAccessControlChecker
from .auth_failure_checker import AuthFailureChecker
from .security_misconfiguration_checker import SecurityMisconfigurationChecker
from .vulnerable_components_checker import VulnerableComponentsChecker
from .cryptographic_failure_checker import CryptographicFailureChecker
from .ssrf_checker import SSRFChecker
from .zap_connector import ZAPConnector
from .nuclei_connector import NucleiConnector
from .nikto_connector import NiktoConnector
from .owasp_report_builder import OWASPReportBuilder
from .models import WebFinding, OWASPReport

__version__ = "2.0.0"
__all__ = [
    'OWASPEngine',
    'TechnologyDetector',
    'WebAssetDiscovery',
    'InjectionChecker',
    'BrokenAccessControlChecker',
    'AuthFailureChecker',
    'SecurityMisconfigurationChecker',
    'VulnerableComponentsChecker',
    'CryptographicFailureChecker',
    'SSRFChecker',
    'ZAPConnector',
    'NucleiConnector',
    'NiktoConnector',
    'OWASPReportBuilder',
    'WebFinding',
    'OWASPReport'
]
