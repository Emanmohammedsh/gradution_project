"""
main.py — Rule-Based Adaptive Red Teaming Orchestrator
========================================================
نقطة الدخول الرئيسية. يستدعي الـ modules بالترتيب
ويطبّق الـ Rule Table على نتيجة كل مرحلة.

Usage:
    python main.py --target 192.168.1.0/24
    python main.py --target 192.168.1.100
    python main.py --target 192.168.1.0/24 --dry-run
"""

import argparse
import sys
import os

# أضف root للـ path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.context import ScanContext

# ─── استيراد الـ Modules ─────────────────────
from modules import reconnaissance
from modules import scanning
from modules import vulnerability_mapping
from modules import exploitation
from modules import post_exploitation
from modules import reporting


# ─────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────

def run_pipeline(target: str, dry_run: bool = False) -> ScanContext:
    """
    ينفّذ كامل الـ pipeline بالترتيب.
    كل مرحلة ترجع True/False — الـ Orchestrator يقرر المتابعة أو الوقف.
    """
    print("\n" + "█"*55)
    print("  Rule-Based Adaptive Red Teaming Orchestrator")
    print("  UCAS University — Cyber Security Engineering 2026")
    print("█"*55)

    # إنشاء Context
    ctx = ScanContext(target_scope=target)
    print(f"\n  Session ID : {ctx.session_id}")
    print(f"  Target     : {target}")
    print(f"  Dry Run    : {dry_run}")

    if dry_run:
        print("\n  [DRY RUN] Pipeline simulation — no tools will be executed\n")
        return _dry_run_simulation(ctx)

    # ═══════════════════════════════════════
    # MODULE 1: Reconnaissance  (R0, R1)
    # ═══════════════════════════════════════
    if not reconnaissance.run(ctx):
        print("\n  [HALT] No live hosts. Stopping pipeline.")
        return _finalize(ctx, "HALTED")

    # ═══════════════════════════════════════
    # MODULE 2: Scanning & Enumeration  (R2–R5)
    # ═══════════════════════════════════════
    if not scanning.run(ctx):
        print("\n  [HALT] No open services found. Stopping pipeline.")
        return _finalize(ctx, "HALTED")

    # ═══════════════════════════════════════
    # MODULE 3: Vulnerability Mapping  (R6 + AI Risk Scoring)
    # ═══════════════════════════════════════
    if not vulnerability_mapping.run(ctx):
        print("\n  [HALT] No CVE matches found. Stopping pipeline.")
        reporting.run(ctx)         # ولّد تقرير حتى لو لا يوجد ثغرات
        return _finalize(ctx, "DONE")

    # ═══════════════════════════════════════
    # MODULE 4: Exploitation  (R7, R8, Risk Threshold)
    # ═══════════════════════════════════════
    exploitation.run(ctx)          # لا نوقف عند فشل — نكمل للتقرير

    # ═══════════════════════════════════════
    # MODULE 5: Post-Exploitation  (R9 + MITRE)
    # ═══════════════════════════════════════
    post_exploitation.run(ctx)

    # ═══════════════════════════════════════
    # MODULE 6: Reporting  (R10)
    # ═══════════════════════════════════════
    reporting.run(ctx)

    return _finalize(ctx, "DONE")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _finalize(ctx: ScanContext, status: str) -> ScanContext:
    ctx.status = status
    return ctx


def _dry_run_simulation(ctx: ScanContext) -> ScanContext:
    """
    محاكاة بدون تشغيل أدوات حقيقية — للاختبار والعرض.
    يملأ الـ context ببيانات وهمية ويولّد تقريراً.
    """
    from utils.context import Host

    # إضافة host وهمي
    host = ctx.add_host("192.168.1.100")
    host.hostname = "metasploitable"
    host.os_type = "LINUX"

    host.services = [
        {"service_id": "192.168.1.100:21", "port_number": 21,
         "protocol": "tcp", "service_name": "ftp",
         "product": "vsftpd", "version_string": "vsftpd 2.3.4"},
        {"service_id": "192.168.1.100:22", "port_number": 22,
         "protocol": "tcp", "service_name": "ssh",
         "product": "OpenSSH", "version_string": "openssh 4.7"},
        {"service_id": "192.168.1.100:445", "port_number": 445,
         "protocol": "tcp", "service_name": "microsoft-ds",
         "product": "Samba", "version_string": "samba 3.0"},
    ]

    host.vulnerabilities = [
        {"cve_id": "CVE-2011-2523", "cvss_score": 10.0, "risk_score": 0.95,
         "description": "vsftpd 2.3.4 backdoor RCE", "attack_type": "remote",
         "msf_module": "exploit/unix/ftp/vsftpd_234_backdoor",
         "requires_auth": False, "service_name": "ftp", "port_number": 21},
        {"cve_id": "CVE-2007-2447", "cvss_score": 9.3, "risk_score": 0.88,
         "description": "Samba usermap_script RCE", "attack_type": "remote",
         "msf_module": "exploit/multi/samba/usermap_script",
         "requires_auth": False, "service_name": "smb", "port_number": 445},
    ]

    host.exploit_attempts = [
        {"attempt_id": "sim_001", "cve_id": "CVE-2011-2523",
         "tool_used": "metasploit", "result": "SUCCESS",
         "port_number": 21, "timestamp": "2026-05-17T12:00:00"},
    ]

    host.post_exploitation = {
        "privilege_level": "ROOT",
        "password_hashes": ["root:$6$xyz...", "user:$6$abc..."],
        "persistence": "SSH key backdoor (T1547)",
        "high_value_assets": ["/etc/shadow", "/home/user/.ssh/id_rsa"],
        "pivot_candidates": ["192.168.1.101"],
    }

    host.mitre_mappings = [
        {"id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "detail": "CVE-2011-2523",
         "mapped_at": "2026-05-17T12:00:01"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation",
         "tactic": "Privilege Escalation", "detail": "getsystem",
         "mapped_at": "2026-05-17T12:00:10"},
        {"id": "T1003", "name": "OS Credential Dumping",
         "tactic": "Credential Access", "detail": "hashdump",
         "mapped_at": "2026-05-17T12:00:20"},
        {"id": "T1547", "name": "Boot/Logon Autostart Execution",
         "tactic": "Persistence", "detail": "SSH key",
         "mapped_at": "2026-05-17T12:00:30"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel",
         "tactic": "Exfiltration", "detail": "",
         "mapped_at": "2026-05-17T12:00:40"},
    ]

    # تسجيل الـ rules
    ctx.log_rule("R0", "target is 192.168.1.100", "run Nmap host discovery")
    ctx.log_rule("R1", "1 live host found", "proceed to scanning")
    ctx.log_rule("R3", "3 open ports found", "run service fingerprinting")
    ctx.log_rule("R4", "OS: LINUX", "run linux-specific scripts")
    ctx.log_rule("R6", "vsftpd 2.3.4 detected", "CVE-2011-2523 → MSF module")
    ctx.log_rule("R7", "exploit available | risk=0.95", "trigger exploitation")
    ctx.log_rule("R9", "shell established", "proceed to post-exploitation")
    ctx.log_rule("R10", "all phases complete", "generate report")

    reporting.run(ctx)
    return _finalize(ctx, "DONE")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Rule-Based Adaptive Red Teaming Orchestrator"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP or CIDR subnet (e.g. 192.168.1.0/24 or 192.168.1.100)"
    )
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Simulate the pipeline without running real tools"
    )

    args = parser.parse_args()
    run_pipeline(target=args.target, dry_run=args.dry_run)


if __name__ == "__main__":
    main()