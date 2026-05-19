class RiskEngine:

    def __init__(self):
        self.cvss_scores = {
            "CVE-2011-2523": 10.0,
            "CVE-2007-2447": 9.3,
            "BRUTE-FORCE": 5.0,
            "WEB-SCAN": 4.0
        }

        # Server priority weights — higher = more attractive attack target
        self.service_priority_weights = {
            "ftp":    10,   # Often misconfigured, direct file access
            "smb":    10,   # Lateral movement / ransomware vector
            "samba":  10,   # Same as SMB
            "telnet":  9,   # Plaintext credentials
            "ssh":     8,   # Remote shell access
            "http":    7,   # Web application attack surface
            "https":   7,
            "mysql":   8,   # Database — sensitive data
            "mssql":   8,
            "rdp":     9,   # Remote Desktop — direct GUI access
            "smtp":    6,   # Social engineering relay
            "pop3":    5,
            "imap":    5,
            "vnc":     9,   # Unencrypted remote desktop
            "snmp":    6,   # Information disclosure
        }

    def get_service_priority_bonus(self, finding):
        """Return bonus points based on the service type."""
        service = finding.get("service", "").lower()
        product = finding.get("matched_key", "").lower()

        for svc, weight in self.service_priority_weights.items():
            if svc in service or svc in product:
                return weight * 2   # Scale to match point system (max ~20)
        return 0

    def calculate_risk(self, finding):
        score = 0

        # CVSS Score (max 40 points)
        cve = finding.get("cve", "")
        cvss = self.cvss_scores.get(cve, 3.0)
        score += cvss * 4

        # Exploit Available (20 points)
        if finding.get("type") == "metasploit":
            score += 20

        # Exposure - well known ports (20 points)
        exposed_ports = [21, 22, 23, 80, 139, 445, 3306]
        if finding.get("port") in exposed_ports:
            score += 20

        # Credentials possible (20 points)
        if finding.get("type") == "hydra":
            score += 20

        # Server Priority Bonus (max 20 points)
        priority_bonus = self.get_service_priority_bonus(finding)
        score += priority_bonus
        finding["priority_bonus"] = priority_bonus

        finding["risk_score"] = round(score)
        finding["cvss"] = cvss

        print(f"  [Risk] {finding['host']}:{finding['port']} | "
              f"CVE: {cve} | CVSS: {cvss} | "
              f"Priority Bonus: +{priority_bonus} | Risk Score: {round(score)}")

        return finding

    def filter_by_risk(self, findings, threshold=30):
        print(f"\n[Risk Engine] Calculating Risk Scores...")
        print(f"[Risk Engine] Threshold: {threshold}")

        scored = []
        deferred = []

        for finding in findings:
            finding = self.calculate_risk(finding)
            if finding["risk_score"] >= threshold:
                scored.append(finding)
            else:
                deferred.append(finding)
                print(f"  [Low Risk] Deferring: {finding['host']}:{finding['port']}")

        print(f"\n  [+] High Risk Targets: {len(scored)}")
        print(f"  [-] Deferred Targets : {len(deferred)}")

        # Sort by: risk_score DESC, then CVSS DESC, then priority_bonus DESC
        scored.sort(
            key=lambda x: (x["risk_score"], x.get("cvss", 0), x.get("priority_bonus", 0)),
            reverse=True
        )

        print(f"\n  [Server Priority Order]")
        for i, f in enumerate(scored, 1):
            print(f"    #{i} {f['host']}:{f['port']} | "
                  f"Score: {f['risk_score']} | CVSS: {f.get('cvss', 'N/A')} | "
                  f"Service: {f.get('service', '?')}")

        return scored
