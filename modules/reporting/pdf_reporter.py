"""
reporting/pdf_reporter.py
---------------------------
Generates PDF reports using fpdf2. Falls back to plain text if unavailable.
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

    def save(self, report_data: dict, filename: str | None = None) -> str:
        os.makedirs(REPORT_PDF_DIR, exist_ok=True)
        ts       = datetime.now().strftime(REPORT_DATE_FORMAT)
        filename = filename or f"report_{ts}.pdf"
        path     = os.path.join(REPORT_PDF_DIR, filename)

        if _FPDF:
            self._build_pdf(report_data, path)
        else:
            # Fallback: save as text
            txt_path = path.replace(".pdf", ".txt")
            with open(txt_path, "w", encoding="utf-8") as f:
                self._write_text(f, report_data)
            print(f"  [PDF] fpdf2 not installed — saved as text → {txt_path}")
            return txt_path

        print(f"  [PDF] Report saved → {path}")
        return path

    def _build_pdf(self, data: dict, path: str):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"{FRAMEWORK_NAME} — Attack Report", ln=True, align="C")
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 8, f"Version {FRAMEWORK_VERSION}  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True, align="C")
        pdf.ln(6)

        for section, content in data.items():
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, str(section).upper(), ln=True)
            pdf.set_font("Helvetica", size=9)
            if isinstance(content, list):
                for item in content[:20]:
                    pdf.multi_cell(0, 5, str(item)[:120])
            elif isinstance(content, dict):
                for k, v in list(content.items())[:20]:
                    pdf.multi_cell(0, 5, f"  {k}: {str(v)[:100]}")
            else:
                pdf.multi_cell(0, 5, str(content)[:300])
            pdf.ln(3)

        pdf.output(path)

    @staticmethod
    def _write_text(f, data: dict):
        for section, content in data.items():
            f.write(f"\n{'='*60}\n{section}\n{'='*60}\n")
            f.write(str(content) + "\n")
