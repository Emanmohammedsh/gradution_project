"""
Technology Detector - Detects web technologies and frameworks
Based on OWASP Top 10 2025 - A06 Vulnerable Components
"""

SIGNATURES = {
    "Joomla": ["Joomla", "/components/com_"],
    "Apache": ["Server: Apache"],
    "Nginx": ["Server: nginx"],
    "IIS": ["Server: Microsoft-IIS"],
    "WordPress": ["wp-content", "wp-includes", "WordPress"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Django": ["csrfmiddlewaretoken", "Django"],
    "Laravel": ["laravel_session", "Laravel"],
    "React": ["react", "ReactDOM"],
    "Vue.js": ["vue.js", "vue.min.js"],
    "Angular": ["ng-app", "angular.js"],
}

class TechnologyDetector:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
    
    def detect(self, url: str) -> list:
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
