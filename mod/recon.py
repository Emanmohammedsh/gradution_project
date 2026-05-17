"""
reconnaissance.py — Module 1
------------------------------
المسؤول عن اكتشاف الـ Hosts الحية في الـ target scope.
الأدوات: Nmap (ICMP echo, TCP SYN, ARP)
Rules: R0 (subnet → discover), R1 (hosts found → proceed)
"""

import subprocess
import xml.etree.ElementTree as ET
from utils.context import ScanContext, Host


def run(ctx: ScanContext) -> bool:
    """
    يشغّل مرحلة Reconnaissance ويعدّل الـ ctx مباشرة.
    Returns True إذا وُجد hosts، False إذا لم يُوجد.
    """
    print("\n" + "="*55)
    print("[MODULE 1] Reconnaissance — Host Discovery")
    print("="*55)

    target = ctx.target_scope

    # R0: إذا الـ target subnet أو network → شغّل discovery
    ctx.log_rule(
        "R0",
        f"target is {target}",
        "run Nmap host discovery"
    )

    hosts = _nmap_discover(target, ctx)

    if not hosts:
        # R0 fallback: لا يوجد hosts → halt
        ctx.log_rule("R0-HALT", "no live hosts found", "halt + log")
        ctx.log_error("reconnaissance", f"No live hosts found in {target}")
        ctx.status = "HALTED"
        return False

    # R1: وُجد hosts → تابع للمرحلة التالية
    ctx.log_rule(
        "R1",
        f"{len(hosts)} live hosts found",
        "proceed to scanning & enumeration"
    )
    print(f"\n  ✓ Found {len(hosts)} live host(s): {hosts}")
    return True


# ─────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────

def _nmap_discover(target: str, ctx: ScanContext) -> list:
    """
    يشغّل Nmap host discovery ويرجع قائمة IPs الحية.
    يكتب النتائج في ctx.hosts.
    """
    output_file = f"/tmp/recon_{ctx.session_id}.xml"

    cmd = [
        "nmap",
        "-sn",                  # ping scan فقط (no port scan)
        "-PE",                  # ICMP echo
        "-PS22,80,443,445",     # TCP SYN ping على ports شائعة
        "-PA80,443",            # TCP ACK ping
        "--min-rate", "300",
        "-oX", output_file,
        target
    ]

    print(f"  [*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            ctx.log_error("reconnaissance", f"Nmap error: {result.stderr[:200]}")
            return []

        return _parse_nmap_xml(output_file, ctx)

    except subprocess.TimeoutExpired:
        ctx.log_error("reconnaissance", "Nmap discovery timed out after 120s")
        return []
    except FileNotFoundError:
        ctx.log_error("reconnaissance", "Nmap not found — is it installed?")
        return []


def _parse_nmap_xml(xml_file: str, ctx: ScanContext) -> list:
    """
    يقرأ XML output من Nmap ويملأ ctx.hosts.
    """
    live_ips = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host_elem in root.findall("host"):
            # تحقق أن الـ host up
            status = host_elem.find("status")
            if status is None or status.get("state") != "up":
                continue

            # استخرج الـ IP
            addr_elem = host_elem.find("address[@addrtype='ipv4']")
            if addr_elem is None:
                continue
            ip = addr_elem.get("addr", "")
            if not ip:
                continue

            # استخرج الـ hostname لو موجود
            hostname = ""
            hostnames = host_elem.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            # أضف لـ context
            host_obj = ctx.add_host(ip)
            host_obj.hostname = hostname
            live_ips.append(ip)

            print(f"  [+] Host UP: {ip}" + (f" ({hostname})" if hostname else ""))

    except ET.ParseError as e:
        ctx.log_error("reconnaissance", f"XML parse error: {e}")
    except FileNotFoundError:
        ctx.log_error("reconnaissance", f"Nmap output file not found: {xml_file}")

    return live_ips