"""
reporting/pdf_reporter.py
"""
import os
from datetime import datetime
from config.settings import REPORT_PDF_DIR, FRAMEWORK_NAME, FRAMEWORK_VERSION, REPORT_DATE_FORMAT
try:
    from fpdf import FPDF
    _FPDF = True
except ImportError:
    _FPDF = False

class PdfReporter:
    def save(self, report_data: dict, filename=None) -> str:
        os.makedirs(REPORT_PDF_DIR, exist_ok=True)
        ts = datetime.now().strftime(REPORT_DATE_FORMAT)
        filename = filename or f"report_{ts}.pdf"
        path = os.path.join(REPORT_PDF_DIR, filename)
        if _FPDF:
            try:
                self._build_pdf(report_data, path)
                print(f"  [PDF] Report saved -> {path}")
            except Exception as e:
                print(f"  [PDF] Error: {e}")
                return ""
        return path

    def _c(self, text, limit=100):
        return str(text)[:limit].encode("latin-1", errors="replace").decode("latin-1")

    def _build_pdf(self, data, path):
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_left_margin(15)
        pdf.set_right_margin(15)

        # Title
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(180, 10, f"{FRAMEWORK_NAME} - Attack Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", size=9)
        pdf.cell(180, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | UCAS Cybersecurity 2026", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)

        # Executive Summary
        exec_s = data.get("executive_summary", {})
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(30, 30, 30)
        pdf.cell(180, 8, "EXECUTIVE SUMMARY", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        risk = exec_s.get("overall_risk", "N/A")
        hosts = exec_s.get("total_hosts", "N/A")
        ports = exec_s.get("total_ports", "N/A")
        pdf.cell(180, 6, f"Overall Risk: {risk}  |  Hosts: {hosts}  |  Open Ports: {ports}", new_x="LMARGIN", new_y="NEXT")
        sev = exec_s.get("severity_counts", {})
        pdf.cell(180, 6, f"Critical: {sev.get('critical',0)}  High: {sev.get('high',0)}  Medium: {sev.get('medium',0)}  Low: {sev.get('low',0)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # MITRE Analysis
        mitre = data.get("mitre_analysis", {})
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(180, 8, "MITRE ATT&CK ANALYSIS", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        pdf.cell(180, 6, f"Techniques: {mitre.get('total_techniques','N/A')}  |  Tactics: {mitre.get('total_tactics','N/A')}  |  Coverage: {mitre.get('coverage_pct','N/A')}%", new_x="LMARGIN", new_y="NEXT")
        techs = mitre.get("techniques", [])
        for t in techs[:15]:
            if isinstance(t, dict):
                line = f"  {t.get('technique_id','?')} - {t.get('technique_name','?')} ({t.get('tactic','?')})"
                pdf.cell(180, 5, self._c(line, 90), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Vulnerabilities
        vulns = data.get("vulnerabilities", [])
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(180, 8, f"VULNERABILITIES ({len(vulns)} FOUND)", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=8)
        for v in vulns[:20]:
            if isinstance(v, dict):
                line = f"  [{v.get('severity','?').upper()}] {v.get('host','?')}:{v.get('port','?')} - {v.get('title','?')} (CVSS:{v.get('cvss','?')})"
                pdf.cell(180, 5, self._c(line, 100), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Risk Summary
        risk_s = data.get("risk_summary", {})
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(180, 8, "RISK SUMMARY", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        pdf.cell(180, 6, f"Total Findings: {risk_s.get('total_findings', risk_s.get('total','N/A'))}  |  High Risk: {risk_s.get('high_risk','N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Threat Intelligence
        ti = data.get("threat_intelligence", {})
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(180, 8, "THREAT INTELLIGENCE", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        pdf.cell(180, 6, f"KEV CVEs: {ti.get('kev_count', 0)}  |  Avg CVSS: {ti.get('avg_cvss', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        pdf.output(path)

    @staticmethod
    def _write_text(f, data):
        for section, content in data.items():
            f.write(f"\n{section}\n{str(content)}\n")
