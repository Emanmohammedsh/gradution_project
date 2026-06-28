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
                print(f"  [PDF] Error: {e} -- skipping PDF")
                return ""
        return path

    def _clean(self, text, limit=80):
        t = str(text)[:limit]
        return t.encode("latin-1", errors="replace").decode("latin-1")

    def _build_pdf(self, data, path):
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_left_margin(20)
        pdf.set_right_margin(20)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(170, 10, f"{FRAMEWORK_NAME} - Attack Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", size=9)
        pdf.cell(170, 7, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)
        for section, content in data.items():
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(170, 7, self._clean(str(section).upper(), 60), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=8)
            if isinstance(content, list):
                for item in content[:10]:
                    pdf.multi_cell(170, 4, self._clean(str(item), 90))
            elif isinstance(content, dict):
                for k, v in list(content.items())[:10]:
                    pdf.multi_cell(170, 4, self._clean(f"{k}: {v}", 90))
            else:
                pdf.multi_cell(170, 4, self._clean(str(content), 200))
            pdf.ln(2)
        pdf.output(path)

    @staticmethod
    def _write_text(f, data):
        for section, content in data.items():
            f.write(f"\n{section}\n{str(content)}\n")
