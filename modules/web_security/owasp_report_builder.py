"""
OWASP Report Builder
"""

import json
from datetime import datetime

class OWASPReportBuilder:
    def __init__(self):
        self.owasp_version = "Top 10 2025"
    
    def build_report(self, scan_results, format="html"):
        if format == "html":
            return self._build_html(scan_results)
        return json.dumps(scan_results, indent=2)
    
    def _build_html(self, results):
        filename = f"owasp_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html = f"<html><body><h1>OWASP Report</h1><pre>{json.dumps(results, indent=2)}</pre></body></html>"
        with open(filename, 'w') as f:
            f.write(html)
        return filename
