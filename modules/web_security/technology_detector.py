"""
Technology Detector - Detects web technologies and frameworks
"""

SIGNATURES = {
    "Joomla": ["Joomla", "/components/com_"],
    "Apache": ["Server: Apache"],
    "Nginx": ["Server: nginx"],
    "WordPress": ["wp-content", "wp-includes"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
}

class TechnologyDetector:
    def __init__(self, timeout=5):
        self.timeout = timeout
    
    def detect(self, url):
        detected = []
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            content = str(resp.headers) + resp.read(4096).decode("utf-8", errors="ignore")
            content = content.lower()
            for tech, patterns in SIGNATURES.items():
                if any(p.lower() in content for p in patterns):
                    detected.append(tech)
        except Exception as e:
            print(f"Error: {e}")
        return detected
