"""
mitre_engine.py — Hybrid MITRE ATT&CK Classification Engine
-------------------------------------------------------------
Orchestrates three resolution layers in priority order:

  Layer 1 — Rule-Based Resolver   (confidence 0.85–0.95)
  Layer 2 — STIX Dynamic Lookup   (confidence 0.60–0.75)
  Layer 3 — ML Tactic Classifier  (confidence 0.50–0.70)

Post-exploitation output is merged as a fourth enrichment source.
"""

from modules.mitre.rule_resolver       import RuleResolver
from modules.mitre.stix_resolver       import StixResolver
from modules.mitre.ml_classifier       import MitreMLClassifier
from modules.mitre.post_exploit_mapper import PostExploitMapper


# Kill chain phase inference
TACTIC_PHASES = {
    "reconnaissance":        1,
    "resource-development":  1,
    "initial-access":        2,
    "execution":             3,
    "persistence":           4,
    "privilege-escalation":  4,
    "defense-evasion":       5,
    "credential-access":     5,
    "discovery":             6,
    "lateral-movement":      7,
    "collection":            8,
    "command-and-control":   9,
    "exfiltration":         10,
    "impact":               11,
}


class MitreEngine:

    def __init__(self):
        print("\n[MitreEngine] Initializing hybrid classification engine...")
        self.rule_resolver  = RuleResolver()
        self.stix_resolver  = StixResolver()
        self.ml_classifier  = MitreMLClassifier()
        self.post_mapper    = PostExploitMapper()
        print("[MitreEngine] Ready.\n")

    # -----------------------------------------------------------------------
    # Main classify entry point
    # -----------------------------------------------------------------------

    def classify(self, context: dict) -> dict:
        """
        Classify a single exploitation finding.

        context keys expected:
          exploit, port, service, cve, payload_type,
          edb_title, post_output (dict from PostExploitModule),
          host

        Returns a result dict with:
          techniques, tactic, confidence, source,
          extra_techniques, attack_phase, context
        """
        result = None

        # --- Layer 1: Rules (fastest, most reliable) ---
        rule_result = self.rule_resolver.resolve(context)
        if rule_result and rule_result["confidence"] >= 0.85:
            result = rule_result

        # --- Layer 2: STIX (if rules gave low confidence or no match) ---
        if not result or result["confidence"] < 0.85:
            stix_result = self.stix_resolver.resolve(context)
            if stix_result:
                if not result or stix_result["confidence"] > result["confidence"]:
                    result = stix_result

        # --- Layer 3: ML (enrichment / fallback) ---
        ml_result = self.ml_classifier.predict(context)
        if ml_result:
            if not result:
                result = ml_result
            elif ml_result["confidence"] > result["confidence"] + 0.10:
                # ML wins only if notably more confident
                result = ml_result

        # --- Fallback: unknown ---
        if not result:
            result = {
                "techniques": [{"id": "T1000", "name": "Unknown Technique"}],
                "tactic":     "unknown",
                "confidence": 0.0,
                "source":     "none"
            }

        # --- Post-exploitation enrichment ---
        post_output      = context.get("post_output", {})
        extra_techniques = self.post_mapper.map(post_output)

        # --- Finalize ---
        tactic       = result.get("tactic", "unknown").lower().replace(" ", "-")
        attack_phase = TACTIC_PHASES.get(tactic, 0)

        result["extra_techniques"] = extra_techniques
        result["attack_phase"]     = attack_phase
        result["context"]          = context

        self._print_result(context, result)
        return result

    # -----------------------------------------------------------------------
    # Batch classify (replaces old MitreMapper.map_techniques)
    # -----------------------------------------------------------------------

    def map_techniques(self, exploit_results: list) -> list:
        """
        Drop-in replacement for the old MitreMapper.map_techniques().
        Accepts the exploit_results list from ExploiterModule and returns
        the same list with a 'mitre' key added to each entry.
        """
        print("\n[MitreEngine] Starting ATT&CK classification...")
        mapped = []
        for result in exploit_results:
            context = {
                "exploit":       result.get("exploit", ""),
                "port":          result.get("port"),
                "service":       result.get("service", ""),
                "cve":           result.get("cve", ""),
                "payload_type":  "meterpreter" if result.get("success") else "",
                "edb_title":     result.get("edb_title", ""),
                "post_output":   result.get("post_data", {}),
                "host":          result.get("host", "")
            }
            classified    = self.classify(context)
            result["mitre"] = classified
            mapped.append(result)
        return mapped

    # -----------------------------------------------------------------------

    def _print_result(self, context: dict, result: dict):
        host   = context.get("host", "?")
        port   = context.get("port", "?")
        source = result.get("source", "?")
        conf   = result.get("confidence", 0)
        tactic = result.get("tactic", "unknown")

        print(f"  [+] {host}:{port}")
        print(f"      Tactic     : {tactic}")
        print(f"      Source     : {source} (confidence={conf})")
        for tech in result.get("techniques", []):
            print(f"      Technique  : {tech['id']} — {tech.get('name', '')}")
        for tech in result.get("extra_techniques", []):
            print(f"      Post-Expl  : {tech['id']} — {tech.get('name', '')}")
