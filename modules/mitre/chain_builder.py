"""
chain_builder.py
----------------
Builds an ordered ATT&CK Kill Chain from all classified findings.
Groups techniques by attack phase (1–11) and tactic.
"""


# ATT&CK tactic → kill chain phase number
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

PHASE_NAMES = {
    1:  "Reconnaissance / Resource Development",
    2:  "Initial Access",
    3:  "Execution",
    4:  "Persistence / Privilege Escalation",
    5:  "Defense Evasion / Credential Access",
    6:  "Discovery",
    7:  "Lateral Movement",
    8:  "Collection",
    9:  "Command & Control",
    10: "Exfiltration",
    11: "Impact",
}


class AttackChainBuilder:

    def build(self, mitre_results: list) -> dict:
        """
        mitre_results: list of dicts from MitreEngine.classify()
        Returns: ordered dict  { phase_number → { tactic, phase_name, techniques, hosts } }
        """
        chain = {}

        for result in mitre_results:
            tactic  = result.get("tactic", "unknown").lower().replace(" ", "-")
            phase   = TACTIC_PHASES.get(tactic, 0)
            host    = result.get("context", {}).get("host", "unknown")

            all_techniques = (
                result.get("techniques", []) +
                result.get("extra_techniques", [])
            )

            if phase not in chain:
                chain[phase] = {
                    "phase_name": PHASE_NAMES.get(phase, f"Phase {phase}"),
                    "tactic":     tactic,
                    "techniques": [],
                    "hosts":      [],
                    "confidence": result.get("confidence", 0.0),
                    "source":     result.get("source", "unknown")
                }

            # Add techniques (deduplicate by ID)
            existing_ids = {t["id"] for t in chain[phase]["techniques"]}
            for tech in all_techniques:
                if tech.get("id") and tech["id"] not in existing_ids:
                    chain[phase]["techniques"].append(tech)
                    existing_ids.add(tech["id"])

            if host not in chain[phase]["hosts"]:
                chain[phase]["hosts"].append(host)

            # Keep highest confidence per phase
            if result.get("confidence", 0) > chain[phase]["confidence"]:
                chain[phase]["confidence"] = result["confidence"]
                chain[phase]["source"]     = result.get("source", "unknown")

        return dict(sorted(chain.items()))

    def print_chain(self, chain: dict):
        print("\n" + "=" * 60)
        print("  ATT&CK Kill Chain Summary")
        print("=" * 60)
        for phase, data in chain.items():
            print(f"\n  Phase {phase}: {data['phase_name']}")
            print(f"    Tactic     : {data['tactic']}")
            print(f"    Confidence : {data['confidence']} [{data['source']}]")
            print(f"    Hosts      : {', '.join(data['hosts'])}")
            for tech in data["techniques"]:
                print(f"    [{tech['id']}] {tech.get('name', '')}")
