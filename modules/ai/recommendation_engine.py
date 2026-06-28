"""
ai/recommendation_engine.py
-----------------------------
Generates targeted remediation recommendations based on actual findings.
"""
RECS = {
    "initial-access":       "Patch public-facing services; enforce WAF and input validation.",
    "credential-access":    "Enable MFA; enforce password policy; monitor for brute-force activity.",
    "privilege-escalation": "Audit SUID binaries; restrict sudo; apply kernel patches.",
    "lateral-movement":     "Segment network; restrict SMB/RDP; deploy honeypots.",
    "persistence":          "Audit scheduled tasks and registry run keys; deploy FIM.",
    "discovery":            "Deploy deception assets; alert on enumeration patterns.",
    "exfiltration":         "Monitor outbound traffic; DLP controls; encrypt sensitive data.",
    "impact":               "Backup and DR plan; ransomware-resilient architecture.",
    "execution":            "Application whitelisting; restrict script interpreters.",
    "defense-evasion":      "Enable logging; deploy EDR; monitor process injection.",
    "collection":           "Encrypt sensitive data at rest; restrict file access.",
    "command-and-control":  "Block unauthorized outbound; deploy network monitoring.",
}

SERVICE_RECS = {
    "ftp":        "Disable FTP or upgrade to SFTP/FTPS. vsftpd 2.3.4 has a known backdoor (CVE-2011-2523) -- patch immediately.",
    "ssh":        "Disable password auth; use key-based auth only; update OpenSSH.",
    "telnet":     "Disable Telnet immediately -- unencrypted protocol. Use SSH instead.",
    "smtp":       "Update Postfix; disable open relay; enable SPF/DKIM/DMARC.",
    "mysql":      "Restrict MySQL to localhost; enforce strong root password; disable remote root login.",
    "vnc":        "Disable VNC or restrict to VPN only; enforce strong password.",
    "irc":        "Disable UnrealIRCd -- has known backdoor. Remove service if unused.",
    "http":       "Update Apache; disable directory listing; deploy WAF.",
    "netbios-ssn": "Update Samba; restrict SMB to trusted networks; disable SMBv1.",
}

CVE_RECS = {
    "CVE-2011-2523": "CRITICAL: vsftpd 2.3.4 backdoor -- upgrade to vsftpd 3.x immediately.",
    "CVE-2010-2075": "CRITICAL: UnrealIRCd 3.2.8.1 backdoor -- remove or upgrade immediately.",
}

class RecommendationEngine:
    def recommend(self, covered_tactics: list[str], findings: list[dict] = None) -> list[dict]:
        out = []
        seen = set()

        # CVE-specific recommendations
        if findings:
            for f in findings:
                cve = f.get("cve", "")
                if cve in CVE_RECS and cve not in seen:
                    out.append({"tactic": "CRITICAL", "recommendation": CVE_RECS[cve]})
                    seen.add(cve)
                service = f.get("service", "").lower()
                if service in SERVICE_RECS and service not in seen:
                    out.append({"tactic": service, "recommendation": SERVICE_RECS[service]})
                    seen.add(service)

        # Tactic-based recommendations
        for tactic in covered_tactics:
            rec = RECS.get(tactic)
            if rec and tactic not in seen:
                out.append({"tactic": tactic, "recommendation": rec})
                seen.add(tactic)

        return out
