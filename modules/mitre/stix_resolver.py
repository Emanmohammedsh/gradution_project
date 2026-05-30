"""
stix_resolver.py — Layer 2 of the Hybrid MITRE Engine
------------------------------------------------------
Dynamic lookup against the MITRE ATT&CK STIX dataset (local JSON cache).

On first run: downloads enterprise-attack.json from MITRE's GitHub.
After that:   reads from data/enterprise-attack.json (offline).

Confidence: 0.60 – 0.75
"""

import json
import re
import os
from pathlib import Path
from functools import lru_cache

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

STIX_PATH = Path("data/enterprise-attack.json")


class StixResolver:

    def __init__(self):
        self.ready = False
        self.techniques = []
        self.index: dict[str, list[str]] = {}  # word → [technique_id, ...]
        self._load()

    # -----------------------------------------------------------------------
    # Load / download
    # -----------------------------------------------------------------------

    def _load(self):
        if not STIX_PATH.exists():
            print("  [StixResolver] enterprise-attack.json not found.")
            print(f"  [StixResolver] Downloading from MITRE CTI...")
            self._download()

        if STIX_PATH.exists():
            try:
                data = json.loads(STIX_PATH.read_text(encoding="utf-8"))
                self.techniques = [
                    obj for obj in data.get("objects", [])
                    if obj.get("type") == "attack-pattern"
                    and not obj.get("revoked", False)
                    and not obj.get("x_mitre_deprecated", False)
                ]
                self._build_index()
                self.ready = True
                print(f"  [StixResolver] Loaded {len(self.techniques)} techniques.")
            except Exception as e:
                print(f"  [StixResolver] Failed to parse STIX data: {e}")
        else:
            print("  [StixResolver] Offline mode — STIX lookup disabled.")

    def _download(self):
        try:
            import urllib.request
            os.makedirs("data", exist_ok=True)
            urllib.request.urlretrieve(STIX_URL, STIX_PATH)
            print("  [StixResolver] Download complete.")
        except Exception as e:
            print(f"  [StixResolver] Download failed: {e}")
            print("  [StixResolver] Manual download:")
            print(f"    wget {STIX_URL} -O {STIX_PATH}")

    # -----------------------------------------------------------------------
    # Index build
    # -----------------------------------------------------------------------

    def _build_index(self):
        """Build a word → [technique_id] inverted index for fast lookup."""
        for tech in self.techniques:
            ext_refs = tech.get("external_references", [])
            if not ext_refs:
                continue
            tid  = ext_refs[0].get("external_id", "")
            name = tech.get("name", "").lower()
            desc = tech.get("description", "").lower()[:500]
            text = name + " " + desc
            # Index meaningful words (≥4 chars)
            for word in set(re.findall(r'\b[a-z]{4,}\b', text)):
                self.index.setdefault(word, []).append(tid)

    # -----------------------------------------------------------------------
    # Resolve
    # -----------------------------------------------------------------------

    @lru_cache(maxsize=512)
    def _cached_resolve(self, query: str) -> list:
        """Returns list of (technique_id, hit_count) sorted by relevance."""
        words  = set(re.findall(r'\b[a-z]{4,}\b', query.lower()))
        scores = {}
        for word in words:
            for tid in self.index.get(word, []):
                scores[tid] = scores.get(tid, 0) + 1
        return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:5]

    def resolve(self, context: dict) -> dict | None:
        if not self.ready:
            return None

        # Build a query string from all available context
        parts = [
            context.get("exploit", ""),
            context.get("service", ""),
            context.get("cve", ""),
            context.get("payload_type", ""),
            context.get("edb_title", ""),
        ]
        query = " ".join(p for p in parts if p).strip()
        if not query:
            return None

        top_matches = self._cached_resolve(query)
        if not top_matches:
            return None

        techniques = []
        for tid, hit_count in top_matches[:3]:
            tech = next(
                (t for t in self.techniques
                 if t.get("external_references", [{}])[0].get("external_id") == tid),
                None
            )
            if not tech:
                continue
            phases = tech.get("kill_chain_phases", [])
            tactic = phases[0].get("phase_name", "unknown") if phases else "unknown"
            techniques.append({
                "id":     tid,
                "name":   tech.get("name", tid),
                "tactic": tactic,
                "hits":   hit_count
            })

        if not techniques:
            return None

        # Confidence based on hit strength (capped at 0.75)
        top_hits    = top_matches[0][1]
        confidence  = min(0.75, 0.45 + top_hits * 0.05)

        return {
            "techniques": techniques,
            "tactic":     techniques[0]["tactic"],
            "confidence": round(confidence, 2),
            "source":     "stix"
        }
