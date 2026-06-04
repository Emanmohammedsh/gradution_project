"""
reporting/json_reporter.py
----------------------------
Saves any data structure as a formatted JSON report file.
"""

import json
import os
from datetime import datetime
from config.settings import REPORT_JSON_DIR, REPORT_DATE_FORMAT


class JsonReporter:

    def save(self, data: dict, filename: str | None = None) -> str:
        os.makedirs(REPORT_JSON_DIR, exist_ok=True)
        if not filename:
            ts       = datetime.now().strftime(REPORT_DATE_FORMAT)
            filename = f"report_{ts}.json"
        path = os.path.join(REPORT_JSON_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"  [JSON] Report saved → {path}")
        return path
