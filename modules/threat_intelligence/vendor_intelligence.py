"""
threat_intelligence/vendor_intelligence.py
-------------------------------------------
Maps product vendors to known threat actor targeting preferences.
"""

VENDOR_THREAT_MAP = {
    "microsoft": ["APT29", "APT28", "Lazarus", "FIN7"],
    "apache":    ["APT41", "FIN7"],
    "cisco":     ["Volt Typhoon", "APT31"],
    "samba":     ["APT28", "Lazarus"],
    "vsftpd":    ["APT28"],
    "openssl":   ["APT29", "Equation Group"],
}


class VendorIntelligence:

    def threat_actors(self, vendor: str) -> list[str]:
        return VENDOR_THREAT_MAP.get(vendor.lower(), [])

    def enrich_finding(self, finding: dict) -> dict:
        product = finding.get("product", "").lower().split()[0]
        actors  = self.threat_actors(product)
        finding["threat_actors"] = actors
        return finding
