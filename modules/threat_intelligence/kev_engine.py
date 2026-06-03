"""
threat_intelligence/kev_engine.py
-----------------------------------
CISA Known Exploited Vulnerabilities (KEV) catalog check.
Downloads the catalog once and caches it locally.
"""

import json
import os
import urllib.request
from datetime import datetime

KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = "data/kev_catalog.json"


class KevEngine:

    def __init__(self):
        self._catalog: set[str] = set()
        self._load()

    def is_kev(self, cve: str) -> bool:
        return cve.upper() in self._catalog

    def _load(self):
        if os.path.exists(KEV_CACHE):
            try:
                with open(KEV_CACHE, encoding="utf-8") as f:
                    data = json.load(f)
                self._catalog = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
                print(f"  [KEV] {len(self._catalog)} known exploited CVEs loaded.")
                return
            except Exception:
                pass

        self._download()

    def _download(self):
        try:
            os.makedirs("data", exist_ok=True)
            urllib.request.urlretrieve(KEV_URL, KEV_CACHE)
            self._load()
        except Exception as e:
            print(f"  [KEV] Could not load catalog: {e}")
