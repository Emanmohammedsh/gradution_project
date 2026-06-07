# database/repository.py
"""
Dummy repository for pipeline compatibility.
Replace with real database implementation later.
"""

def save_session(session_id, target, lhost, live_hosts):
    print(f"[DB Dummy] save_session({session_id}, {target}, {lhost}, {live_hosts})")
    return 1  # fake db id

def save_vulnerabilities(db_id, vuln_findings):
    print(f"[DB Dummy] save_vulnerabilities({db_id}, {len(vuln_findings)} findings)")

def save_exploit_results(db_id, exploit_results):
    print(f"[DB Dummy] save_exploit_results({db_id}, {len(exploit_results)} results)")

def save_mitre_findings(db_id, mapped_results):
    print(f"[DB Dummy] save_mitre_findings({db_id}, {len(mapped_results)} mappings)")

def save_report(db_id, report_file, format_type):
    print(f"[DB Dummy] save_report({db_id}, {report_file}, {format_type})")
