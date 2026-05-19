import subprocess
import json
import shutil


class VulnMapperModule:

    def __init__(self):
        # Severity classification based on ExploitDB exploit type + keywords
        self.severity_rules = {
            "critical": ["remote code execution", "rce", "backdoor", "unauthenticated", "root"],
            "high":     ["privilege escalation", "command injection", "sql injection", "buffer overflow"],
            "medium":   ["information disclosure", "directory traversal", "brute force", "bypass"],
            "low":      ["denial of service", "dos", "xss", "cross-site"],
        }

        # Fallback attack type when searchsploit has no match
        self.service_fallback = {
            "ssh":    {"exploit": "ssh",    "type": "hydra",  "severity": "medium"},
            "ftp":    {"exploit": "ftp",    "type": "hydra",  "severity": "medium"},
            "telnet": {"exploit": "telnet", "type": "hydra",  "severity": "high"},
            "mysql":  {"exploit": "mysql",  "type": "hydra",  "severity": "medium"},
            "http":   {"exploit": "web",    "type": "web",    "severity": "low"},
            "https":  {"exploit": "web",    "type": "web",    "severity": "low"},
        }

        self.searchsploit_available = shutil.which("searchsploit") is not None

        if self.searchsploit_available:
            print("  [VulnMapper] searchsploit found — running on live ExploitDB.")
        else:
            print("  [VulnMapper] searchsploit NOT found — service fallback only.")
            print("  [VulnMapper] Run: sudo apt install exploitdb")

    # ------------------------------------------------------------------
    # Severity detection from exploit title
    # ------------------------------------------------------------------

    def _classify_severity(self, title: str) -> str:
        title_lower = title.lower()
        for level, keywords in self.severity_rules.items():
            for kw in keywords:
                if kw in title_lower:
                    return level
        return "low"

    def _severity_to_cvss(self, severity: str) -> float:
        return {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0}.get(severity, 3.0)

    def _severity_to_priority(self, severity: str) -> int:
        return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 5)

    # ------------------------------------------------------------------
    # ExploitDB lookup via searchsploit
    # ------------------------------------------------------------------

    def _searchsploit_lookup(self, query: str) -> list:
        """
        Query searchsploit --json and return list of parsed findings.
        Each finding has: cve, exploit path, type, severity, cvss, title.
        """
        if not self.searchsploit_available or not query.strip():
            return []

        try:
            result = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True, text=True, timeout=20
            )

            if result.returncode != 0 or not result.stdout.strip():
                return []

            data     = json.loads(result.stdout)
            exploits = data.get("RESULTS_EXPLOIT", [])

            findings = []
            for entry in exploits[:5]:   # Top 5 results max
                title = entry.get("Title", "")
                path  = entry.get("Path", "")
                etype = entry.get("Type", "")

                # Extract CVE if present in title
                cve = "N/A"
                for word in title.split():
                    if word.upper().startswith("CVE-"):
                        cve = word.upper().rstrip(".,)")
                        break

                severity = self._classify_severity(title)

                # Map exploit type
                if "remote" in etype.lower():
                    attack_type = "metasploit"
                elif "webapps" in etype.lower():
                    attack_type = "web"
                else:
                    attack_type = "manual"

                findings.append({
                    "cve":      cve,
                    "exploit":  path,
                    "type":     attack_type,
                    "severity": severity,
                    "cvss":     self._severity_to_cvss(severity),
                    "priority": self._severity_to_priority(severity),
                    "title":    title,
                    "source":   "exploitdb"
                })

            # Sort by severity (critical first)
            findings.sort(key=lambda x: x["priority"])
            return findings

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"    [!] searchsploit error: {e}")
            return []

    # ------------------------------------------------------------------
    # Service fallback (when searchsploit finds nothing)
    # ------------------------------------------------------------------

    def _fallback_lookup(self, service: str) -> dict | None:
        fb = self.service_fallback.get(service.lower())
        if not fb:
            return None
        return {
            "cve":      "BRUTE-FORCE" if fb["type"] == "hydra" else "WEB-SCAN",
            "exploit":  fb["exploit"],
            "type":     fb["type"],
            "severity": fb["severity"],
            "cvss":     self._severity_to_cvss(fb["severity"]),
            "priority": self._severity_to_priority(fb["severity"]),
            "title":    f"{service.upper()} service — fallback attack",
            "source":   "fallback"
        }

    # ------------------------------------------------------------------
    # Core mapping
    # ------------------------------------------------------------------

    def map_vulnerabilities(self, scan_results: dict) -> list:
        print(f"\n[R6] Starting Vulnerability Mapping...")
        print(f"     Mode: {'Live ExploitDB via searchsploit' if self.searchsploit_available else 'Fallback only'}")

        all_findings = []
        seen = set()

        for host, data in scan_results.items():
            for port_info in data["ports"]:
                service = port_info.get("service", "")
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                port    = port_info.get("port")
                uid     = f"{host}:{port}"

                if uid in seen:
                    continue
                seen.add(uid)

                # Build search query from what nmap gave us
                query = f"{product} {version}".strip() or service
                print(f"\n  [?] Querying: '{query}' ({host}:{port})")

                # 1. Try ExploitDB
                edb_results = self._searchsploit_lookup(query)

                if edb_results:
                    # Use the best (most critical) result as the primary finding
                    best = edb_results[0]
                    finding = {
                        "host":        host,
                        "port":        port,
                        "service":     service,
                        "product":     product,
                        "version":     version,
                        "matched_key": query,
                        "cve":         best["cve"],
                        "exploit":     best["exploit"],
                        "type":        best["type"],
                        "severity":    best["severity"],
                        "cvss":        best["cvss"],
                        "priority":    best["priority"],
                        "source":      "exploitdb",
                        "edb_title":   best["title"],
                        "all_matches": edb_results   # Keep all results for the report
                    }
                    all_findings.append(finding)
                    print(f"  [!] [ExploitDB] {host}:{port} | Severity: {best['severity'].upper()} "
                          f"| CVSS: {best['cvss']} | CVE: {best['cve']}")
                    print(f"      Title   : {best['title']}")
                    if len(edb_results) > 1:
                        print(f"      + {len(edb_results)-1} more exploit(s) found")

                else:
                    # 2. Fallback to service-based detection
                    fb = self._fallback_lookup(service)
                    if fb:
                        finding = {
                            "host":        host,
                            "port":        port,
                            "service":     service,
                            "product":     product,
                            "version":     version,
                            "matched_key": service,
                            "cve":         fb["cve"],
                            "exploit":     fb["exploit"],
                            "type":        fb["type"],
                            "severity":    fb["severity"],
                            "cvss":        fb["cvss"],
                            "priority":    fb["priority"],
                            "source":      "fallback",
                            "edb_title":   fb["title"],
                            "all_matches": []
                        }
                        all_findings.append(finding)
                        print(f"  [-] [Fallback] {host}:{port} | {service} | Severity: {fb['severity'].upper()}")
                    else:
                        print(f"  [~] No match found for {host}:{port} ({service})")

        # Summary
        if not all_findings:
            print("\n  [-] No vulnerabilities found.")
        else:
            critical = sum(1 for f in all_findings if f["severity"] == "critical")
            high     = sum(1 for f in all_findings if f["severity"] == "high")
            medium   = sum(1 for f in all_findings if f["severity"] == "medium")
            low      = sum(1 for f in all_findings if f["severity"] == "low")
            print(f"\n  [+] Total: {len(all_findings)} findings — "
                  f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium} LOW:{low}")

        all_findings.sort(key=lambda x: x["priority"])
        return all_findings
