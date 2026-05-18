class RiskEngine:

    def __init__(self):
        self.cvss_scores = {
            "CVE-2011-2523": 10.0,
            "CVE-2007-2447": 9.3,
            "BRUTE-FORCE": 5.0,
            "WEB-SCAN": 4.0
        }

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

        finding["risk_score"] = round(score)

        print(f"  [Risk] {finding['host']}:{finding['port']} | "
              f"CVE: {cve} | Risk Score: {round(score)}")

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

        scored.sort(key=lambda x: x["risk_score"], reverse=True)
        return scored
