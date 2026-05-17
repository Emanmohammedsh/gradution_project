"""
reporting.py — Module 6
-------------------------
يولّد تقرير PDF/JSON شامل عند انتهاء كل المراحل.
Rule R10: process finished → generate detailed report
"""

import json
import os
import time
from datetime import datetime
from utils.context import ScanContext


def run(ctx: ScanContext) -> bool:
    """
    R10: ينشئ تقرير نصي + JSON كامل.
    يعيد True دائماً (Reporting لا تفشل).
    """
    print("\n" + "="*55)
    print("[MODULE 6] Reporting (R10)")
    print("="*55)

    ctx.log_rule(
        "R10",
        "all phases complete",
        "generate detailed report — PDF + JSON"
    )

    ctx.end_time = datetime.now().isoformat()
    ctx.status = "DONE"

    # مسارات الملفات
    ts = time.strftime("%Y%m%d_%H%M%S")
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)

    json_path = os.path.join(report_dir, f"report_{ctx.session_id}_{ts}.json")
    txt_path  = os.path.join(report_dir, f"report_{ctx.session_id}_{ts}.txt")

    # توليد JSON
    _write_json_report(ctx, json_path)

    # توليد Text report
    _write_text_report(ctx, txt_path)

    ctx.report_path = txt_path

    print(f"\n  ✓ JSON report : {json_path}")
    print(f"  ✓ Text report : {txt_path}")

    # محاولة توليد PDF (يحتاج reportlab)
    try:
        pdf_path = txt_path.replace(".txt", ".pdf")
        _write_pdf_report(ctx, pdf_path)
        print(f"  ✓ PDF report  : {pdf_path}")
    except ImportError:
        print("  [!] PDF skipped — install reportlab: pip install reportlab --break-system-packages")

    _print_console_summary(ctx)
    return True


# ─────────────────────────────────────────────
# JSON Report
# ─────────────────────────────────────────────

def _write_json_report(ctx: ScanContext, path: str):
    data = {
        "session_id": ctx.session_id,
        "target_scope": ctx.target_scope,
        "start_time": ctx.start_time,
        "end_time": ctx.end_time,
        "status": ctx.status,
        "summary": ctx.summary(),
        "hosts": [],
        "rule_log": ctx.rule_log,
        "errors": ctx.errors,
    }

    for host in ctx.hosts:
        host_data = {
            "host_id": host.host_id,
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "os_type": host.os_type,
            "services": host.services,
            "vulnerabilities": host.vulnerabilities,
            "exploit_attempts": host.exploit_attempts,
            "mitre_mappings": host.mitre_mappings,
            "post_exploitation": host.post_exploitation,
        }
        data["hosts"].append(host_data)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────
# Text Report
# ─────────────────────────────────────────────

def _write_text_report(ctx: ScanContext, path: str):
    lines = []
    W = 60

    def h1(t): lines.append("=" * W + "\n" + t.center(W) + "\n" + "=" * W)
    def h2(t): lines.append("\n" + "─" * W + "\n" + f"  {t}\n" + "─" * W)
    def row(k, v): lines.append(f"  {k:<28} {v}")
    def blank(): lines.append("")

    h1("PENETRATION TEST REPORT")
    blank()
    row("Session ID",   ctx.session_id)
    row("Target",       ctx.target_scope)
    row("Start Time",   ctx.start_time)
    row("End Time",     ctx.end_time or "N/A")
    row("Status",       ctx.status)
    blank()

    # Executive Summary
    h2("EXECUTIVE SUMMARY")
    s = ctx.summary()
    row("Hosts Discovered",     str(s["hosts_found"]))
    row("Vulnerabilities Found", str(s["total_vulnerabilities"]))
    row("Exploit Attempts",     str(s["exploit_attempts"]))
    row("Successful Exploits",  str(s["successful_exploits"]))
    row("Rules Fired",          str(s["rules_fired"]))

    # Per-Host Details
    for host in ctx.hosts:
        h2(f"HOST: {host.ip_address}  [{host.os_type}]")
        if host.hostname:
            row("Hostname", host.hostname)

        # Services
        blank()
        lines.append("  OPEN SERVICES:")
        for svc in host.services:
            lines.append(
                f"    {svc['port_number']}/{svc['protocol']:<4} "
                f"{svc['service_name']:<20} {svc['version_string']}"
            )

        # Vulnerabilities
        blank()
        lines.append("  VULNERABILITIES (sorted by risk):")
        for vuln in host.vulnerabilities:
            lines.append(
                f"    [{vuln['cve_id']}]  CVSS:{vuln['cvss_score']}  "
                f"Risk:{vuln['risk_score']:.2f}"
            )
            lines.append(f"      {vuln.get('description','')}")
            lines.append(f"      MSF: {vuln.get('msf_module','N/A')}")

        # Exploit Attempts
        blank()
        lines.append("  EXPLOIT ATTEMPTS:")
        for att in host.exploit_attempts:
            status_icon = "✓" if att["result"] == "SUCCESS" else "✗"
            lines.append(
                f"    {status_icon} {att['cve_id']}  via {att['tool_used']}  → {att['result']}"
            )

        # MITRE ATT&CK
        blank()
        lines.append("  MITRE ATT&CK TECHNIQUES:")
        seen = set()
        for m in host.mitre_mappings:
            if m["id"] not in seen:
                lines.append(f"    {m['id']}  {m['name']}")
                lines.append(f"           Tactic: {m['tactic']}")
                seen.add(m["id"])

        # Post-Exploitation
        blank()
        lines.append("  POST-EXPLOITATION:")
        pe = host.post_exploitation
        row("  Privilege Level", pe.get("privilege_level", "N/A"))
        row("  Credentials", "Found" if pe.get("password_hashes") else "Not Found")
        row("  Persistence",  pe.get("persistence", "Not established"))
        pivots = pe.get("pivot_candidates", [])
        if pivots:
            row("  Pivot Candidates", ", ".join(pivots))
        assets = pe.get("high_value_assets", [])
        if assets:
            lines.append(f"  High-Value Assets ({len(assets)}):")
            for a in assets[:10]:
                lines.append(f"      {a}")

    # Rule Trace (Explainability)
    h2("RULE EXECUTION TRACE (Explainability Log)")
    for entry in ctx.rule_log:
        lines.append(
            f"  [{entry['rule']:<12}] {entry['condition'][:38]:<38}"
            f" → {entry['action'][:35]}"
        )

    # Recommendations
    h2("RECOMMENDATIONS")
    _add_recommendations(ctx, lines)

    # Errors
    if ctx.errors:
        h2("ERRORS / WARNINGS")
        for err in ctx.errors:
            lines.append(f"  [{err['module']}] {err['message']}")

    blank()
    lines.append("=" * W)
    lines.append("  End of Report".center(W))
    lines.append("=" * W)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _add_recommendations(ctx: ScanContext, lines: list):
    """يولّد توصيات بناءً على الثغرات المكتشفة."""
    seen_cves = set()
    for host in ctx.hosts:
        for vuln in host.vulnerabilities:
            cve = vuln["cve_id"]
            if cve in seen_cves:
                continue
            seen_cves.add(cve)
            lines.append(f"\n  [{cve}] — CVSS {vuln['cvss_score']}")
            lines.append(f"    Issue : {vuln.get('description','')}")
            lines.append(f"    Action: Update {vuln.get('service_name','')} to latest version")
            lines.append(f"            Apply vendor security patches immediately")
            if vuln.get("attack_type") == "brute-force":
                lines.append(f"            Enable fail2ban + enforce strong password policy")
            if not vuln.get("requires_auth"):
                lines.append(f"            Restrict network access via firewall rules")

    if not seen_cves:
        lines.append("  No critical vulnerabilities found — maintain regular scanning schedule")


# ─────────────────────────────────────────────
# PDF Report (optional — needs reportlab)
# ─────────────────────────────────────────────

def _write_pdf_report(ctx: ScanContext, path: str):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import mm

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=18)
    h2_style    = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13,
                                 textColor=colors.HexColor("#1a237e"))
    body_style  = styles["Normal"]

    story.append(Paragraph("Penetration Test Report", title_style))
    story.append(Spacer(1, 6*mm))

    s = ctx.summary()
    meta = [
        ["Target", ctx.target_scope],
        ["Session", ctx.session_id],
        ["Status", ctx.status],
        ["Hosts", str(s["hosts_found"])],
        ["Vulnerabilities", str(s["total_vulnerabilities"])],
        ["Successful Exploits", str(s["successful_exploits"])],
    ]
    t = Table(meta, colWidths=[50*mm, 120*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#e8eaf6")),
        ("FONTNAME", (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))

    for host in ctx.hosts:
        story.append(Paragraph(f"Host: {host.ip_address} [{host.os_type}]", h2_style))
        for vuln in host.vulnerabilities:
            story.append(Paragraph(
                f"• {vuln['cve_id']} | CVSS: {vuln['cvss_score']} | "
                f"Risk: {vuln['risk_score']:.2f} — {vuln.get('description','')}",
                body_style
            ))
        story.append(Spacer(1, 4*mm))

    doc.build(story)


# ─────────────────────────────────────────────
# Console Summary
# ─────────────────────────────────────────────

def _print_console_summary(ctx: ScanContext):
    s = ctx.summary()
    print("\n" + "="*55)
    print("  SCAN COMPLETE — SUMMARY")
    print("="*55)
    print(f"  Hosts Found       : {s['hosts_found']}")
    print(f"  Vulnerabilities   : {s['total_vulnerabilities']}")
    print(f"  Exploit Attempts  : {s['exploit_attempts']}")
    print(f"  Successful        : {s['successful_exploits']}")
    print(f"  Rules Fired       : {s['rules_fired']}")
    print(f"  Session ID        : {s['session_id']}")
    print("="*55)