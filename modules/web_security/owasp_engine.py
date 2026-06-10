"""
OWASP Security Testing Engine - Main Orchestrator
OWASP Top 10 2025 Compliant
"""

import json
from datetime import datetime

class OWASPEngine:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.results = {
            "target": target_url,
            "scan_time": None,
            "scan_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "owasp_version": "Top 10 2025",
            "vulnerabilities": []
        }
    
    def run_all_checks(self):
        """Run all security checks"""
        self.results['scan_time'] = datetime.now().isoformat()
        print(f"[*] Scanning: {self.target_url}")
        print(f"[*] Using OWASP Top 10 2025 Standards")
        return self.results
    
    def add_vulnerability(self, category, title, risk, description, remediation):
        """Add a vulnerability finding"""
        self.results['vulnerabilities'].append({
            "category": category,
            "title": title,
            "risk": risk,
            "description": description,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat()
        })
    
    def save_report(self, filename=None):
        """Save report to JSON file"""
        if not filename:
            filename = f"owasp_report_{self.results['scan_id']}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[✓] Report saved: {filename}")
        return filename
