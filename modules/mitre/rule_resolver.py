"""
rule_resolver.py — Layer 1 of the Hybrid MITRE Engine
------------------------------------------------------
Deterministic, rule-based technique resolution.
Checks: exact exploit match → port/service match → CVE prefix match.
Confidence: 0.85 – 0.95 (highest in the hybrid stack).
"""

import json
from pathlib import Path


# Port → (TechniqueID, Tactic, Description)
PORT_RULES = {
    21:   ("T1190",      "initial-access",      "FTP exploit"),
    22:   ("T1110",      "credential-access",   "SSH brute force"),
    23:   ("T1078",      "initial-access",      "Telnet valid accounts"),
    25:   ("T1566",      "initial-access",      "SMTP phishing relay"),
    80:   ("T1190",      "initial-access",      "Web application exploit"),
    110:  ("T1110",      "credential-access",   "POP3 brute force"),
    139:  ("T1210",      "lateral-movement",    "NetBIOS exploitation"),
    443:  ("T1190",      "initial-access",      "HTTPS web exploit"),
    445:  ("T1210",      "lateral-movement",    "SMB exploitation"),
    1099: ("T1210",      "lateral-movement",    "Java RMI exploitation"),
    3306: ("T1190",      "initial-access",      "MySQL exploit"),
    3389: ("T1021.001",  "lateral-movement",    "RDP remote desktop"),
    5432: ("T1190",      "initial-access",      "PostgreSQL exploit"),
    6667: ("T1190",      "initial-access",      "IRC backdoor"),
    8080: ("T1190",      "initial-access",      "Web proxy exploit"),
    8443: ("T1190",      "initial-access",      "HTTPS alternate port"),
}

# CVE prefix → technique hint
CVE_PREFIX_RULES = {
    "CVE-2011": ("T1190", "initial-access"),
    "CVE-2007": ("T1210", "lateral-movement"),
    "CVE-2017": ("T1210", "lateral-movement"),   # EternalBlue era
    "CVE-2019": ("T1210", "lateral-movement"),   # BlueKeep era
    "CVE-2021": ("T1190", "initial-access"),
}


class RuleResolver:

    def __init__(self):
        rules_path = Path("data/mitre_rules.json")
        if rules_path.exists():
            with open(rules_path) as f:
                self.rules = json.load(f)
        else:
            self.rules = {}
            print("  [RuleResolver] mitre_rules.json not found — using built-in rules only.")

    def resolve(self, context: dict) -> dict | None:
        exploit = context.get("exploit", "")
        port    = context.get("port")
        service = context.get("service", "").lower()
        cve     = context.get("cve", "")

        # Priority 1: exact exploit name match
        if exploit and exploit in self.rules:
            result = dict(self.rules[exploit])
            result["confidence"] = 0.95
            result["source"]     = "rule_exact"
            return result

        # Priority 2: service name as key (e.g. "ssh", "ftp", "web")
        for key in [service, service.split("/")[0]]:
            if key and key in self.rules:
                result = dict(self.rules[key])
                result["confidence"] = 0.90
                result["source"]     = "rule_service"
                return result

        # Priority 3: port number
        if port and int(port) in PORT_RULES:
            tid, tactic, desc = PORT_RULES[int(port)]
            return {
                "techniques": [{"id": tid, "name": desc}],
                "tactic":     tactic,
                "confidence": 0.85,
                "source":     "rule_port"
            }

        # Priority 4: CVE year prefix
        if cve:
            for prefix, (tid, tactic) in CVE_PREFIX_RULES.items():
                if cve.startswith(prefix):
                    return {
                        "techniques": [{"id": tid, "name": "CVE-based technique"}],
                        "tactic":     tactic,
                        "confidence": 0.80,
                        "source":     "rule_cve"
                    }

        return None
