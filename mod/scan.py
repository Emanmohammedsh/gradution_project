"""
scanning.py — Module 2
-----------------------
Port scanning + service fingerprinting + OS detection.
الأدوات: Nmap (-sV -O -sC), enum4linux-ng (SMB), rpcclient
Rules: R2 (IDS detected → adjust), R3 (ports open → fingerprint),
       R4 (OS detected → branch), R5 (web ports → web discovery)
"""

import subprocess
import xml.etree.ElementTree as ET
from utils.context import ScanContext, Host


# خدمات SMB التي تستدعي enum4linux
SMB_SERVICES = {"microsoft-ds", "netbios-ssn", "smb"}

# منافذ الويب
WEB_PORTS = {80, 443, 8080, 8443, 8000}


def run(ctx: ScanContext) -> bool:
    """
    يفحص كل host مكتشف ويملأ services في كل Host object.
    Returns True إذا وُجدت خدمات على الأقل في host واحد.
    """
    print("\n" + "="*55)
    print("[MODULE 2] Scanning & Enumeration")
    print("="*55)

    any_services = False

    for host in ctx.hosts:
        print(f"\n  [*] Scanning host: {host.ip_address}")
        services = _deep_scan(host, ctx)

        if not services:
            # لا توجد خدمات → تخطَّ هذا الـ host
            ctx.log_rule(
                "R3-SKIP",
                f"no open ports on {host.ip_address}",
                "skip host + log"
            )
            print(f"  [-] No open ports on {host.ip_address} — skipping")
            continue

        host.services = services
        any_services = True

        # R3: يوجد ports مفتوحة → fingerprint
        ctx.log_rule(
            "R3",
            f"{len(services)} open ports on {host.ip_address}",
            "run service & OS fingerprinting"
        )

        # R4: تفريع حسب OS
        _apply_r4(host, ctx)

        # R5: هل يوجد web ports؟
        _apply_r5(host, ctx)

        # SMB enumeration إذا لزم
        _smb_enumerate(host, ctx)

        _print_services(host)

    if not any_services:
        ctx.log_error("scanning", "No open services found on any host")
        return False

    return True


# ─────────────────────────────────────────────
# Deep scan helpers
# ─────────────────────────────────────────────

def _deep_scan(host: Host, ctx: ScanContext) -> list:
    """
    Nmap full scan: version detection + OS + default scripts.
    """
    output_file = f"/tmp/scan_{ctx.session_id}_{host.ip_address.replace('.','_')}.xml"

    cmd = [
        "nmap",
        "-sV",              # version detection
        "-O",               # OS detection
        "-sC",              # default scripts
        "--open",           # فقط الـ ports المفتوحة
        "-T4",              # timing (قابل للتعديل بـ R2)
        "--min-rate", "500",
        "-oX", output_file,
        host.ip_address
    ]

    # R2: إذا كان IDS مشتبهاً → عدّل التوقيت
    if _ids_suspected(ctx):
        ctx.log_rule(
            "R2",
            "IDS/firewall suspected",
            "adjust scan timing + use decoys"
        )
        cmd = [c for c in cmd if c not in ["-T4", "500"]]
        cmd.insert(cmd.index("-oX"), "-T2")
        cmd.insert(cmd.index("-oX"), "--min-rate")
        cmd.insert(cmd.index("-oX"), "100")

    print(f"  [*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and not result.stdout:
            ctx.log_error("scanning", f"Nmap scan error: {result.stderr[:200]}")
            return []
        return _parse_scan_xml(output_file, host, ctx)
    except subprocess.TimeoutExpired:
        ctx.log_error("scanning", f"Scan timed out for {host.ip_address}")
        return []
    except FileNotFoundError:
        ctx.log_error("scanning", "Nmap not found")
        return []


def _parse_scan_xml(xml_file: str, host: Host, ctx: ScanContext) -> list:
    """
    يقرأ نتائج الـ scan ويبني قائمة services.
    """
    services = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        host_elem = root.find("host")
        if host_elem is None:
            return services

        # OS detection
        os_elem = host_elem.find(".//osmatch")
        if os_elem is not None:
            os_name = os_elem.get("name", "").lower()
            if "windows" in os_name:
                host.os_type = "WINDOWS"
            elif any(x in os_name for x in ["linux", "unix", "ubuntu", "debian"]):
                host.os_type = "LINUX"

        # Services
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            return services

        for port_elem in ports_elem.findall("port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_num = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = ""
            version_string = ""
            product = ""

            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extra = service_elem.get("extrainfo", "")
                version_string = " ".join(filter(None, [product, version, extra])).strip()

            svc = {
                "service_id": f"{host.ip_address}:{port_num}",
                "port_number": port_num,
                "protocol": protocol,
                "service_name": service_name,
                "product": product,
                "version_string": version_string,
            }
            services.append(svc)

    except (ET.ParseError, FileNotFoundError) as e:
        ctx.log_error("scanning", f"Parse error: {e}")

    return services


def _apply_r4(host: Host, ctx: ScanContext):
    """R4: تفريع حسب OS."""
    ctx.log_rule(
        "R4",
        f"OS detected: {host.os_type} on {host.ip_address}",
        f"run {host.os_type.lower()}-specific enumeration scripts"
    )


def _apply_r5(host: Host, ctx: ScanContext):
    """R5: إذا يوجد web ports → web directory discovery."""
    open_ports = {s["port_number"] for s in host.services}
    web_found = open_ports & WEB_PORTS
    if web_found:
        ctx.log_rule(
            "R5",
            f"web ports found: {web_found} on {host.ip_address}",
            "run web directory discovery (gobuster/dirb)"
        )
        # يمكن تفعيل web_scanner module هنا لاحقاً
        print(f"  [R5] Web ports detected: {web_found} — web discovery queued")


def _smb_enumerate(host: Host, ctx: ScanContext):
    """يشغّل enum4linux-ng إذا كانت SMB خدمة موجودة."""
    smb_ports = [
        s for s in host.services
        if s["service_name"].lower() in SMB_SERVICES or s["port_number"] in {139, 445}
    ]
    if not smb_ports:
        return

    print(f"  [*] SMB detected on {host.ip_address} — running enum4linux-ng")

    cmd = ["enum4linux-ng", "-A", host.ip_address, "-oY",
           f"/tmp/enum4linux_{host.ip_address.replace('.','_')}.yaml"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        # تخزين raw output في context
        host.services.append({
            "service_id": f"{host.ip_address}:smb-enum",
            "port_number": 445,
            "protocol": "tcp",
            "service_name": "smb-enumeration",
            "product": "enum4linux-ng",
            "version_string": result.stdout[:500] if result.stdout else "no output"
        })
        print(f"  [+] enum4linux-ng completed for {host.ip_address}")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        ctx.log_error("scanning", f"enum4linux-ng failed: {e}")


def _ids_suspected(ctx: ScanContext) -> bool:
    """
    يكتشف إذا كان هناك IDS/Firewall نشط
    (بناءً على errors في جلسات سابقة أو نمط معين).
    """
    ids_keywords = ["filtered", "admin-prohibited", "host-unreach"]
    for err in ctx.errors:
        if any(kw in err.get("message", "").lower() for kw in ids_keywords):
            return True
    return False


def _print_services(host: Host):
    print(f"\n  [+] Services on {host.ip_address} (OS: {host.os_type}):")
    for svc in host.services:
        print(f"      {svc['port_number']}/{svc['protocol']}"
              f"  {svc['service_name']:<20} {svc['version_string']}") 