"""
Pydantic models for web security findings
"""

from typing import List, Optional
from datetime import datetime

class WebFinding:
    def __init__(self, check_name: str, owasp_id: str, title: str, description: str,
                 risk_level: str, confidence: float, affected_component: Optional[str] = None,
                 evidence: Optional[List[str]] = None, mitre_technique: Optional[str] = None,
                 cvss_base: float = 0.0, remediation: str = ""):
        self.check_name = check_name
        self.owasp_id = owasp_id
        self.title = title
        self.description = description
        self.risk_level = risk_level
        self.confidence = confidence
        self.affected_component = affected_component
        self.evidence = evidence or []
        self.mitre_technique = mitre_technique
        self.cvss_base = cvss_base
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self):
        return {
            'check_name': self.check_name,
            'owasp_id': self.owasp_id,
            'title': self.title,
            'description': self.description,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'affected_component': self.affected_component,
            'evidence': self.evidence,
            'mitre_technique': self.mitre_technique,
            'cvss_base': self.cvss_base,
            'remediation': self.remediation,
            'timestamp': self.timestamp
        }

class OWASPReport:
    def __init__(self, target: str, scan_time: str, findings: List[WebFinding]):
        self.target = target
        self.scan_time = scan_time
        self.findings = findings
    
    def to_dict(self):
        return {
            'target': self.target,
            'scan_time': self.scan_time,
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f.risk_level == 'CRITICAL']),
                'high': len([f for f in self.findings if f.risk_level == 'HIGH']),
                'medium': len([f for f in self.findings if f.risk_level == 'MEDIUM'])
            }
        }
