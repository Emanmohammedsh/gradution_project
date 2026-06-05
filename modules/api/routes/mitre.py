"""
api/routes/mitre.py — MITRE ATT&CK API
"""
from fastapi import APIRouter, HTTPException
from modules.api.schemas import MitreResponse, TechniqueOut, TacticDistOut, HeatmapResponse, HeatmapTechniqueOut

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])

DEMO_TECHNIQUES = [
    {"technique_id":"T1190","technique_name":"Exploit Public-Facing Application","tactic":"initial-access",      "confidence":0.95,"source":"rule_exact","host":"192.168.1.100"},
    {"technique_id":"T1210","technique_name":"Exploitation of Remote Services",  "tactic":"lateral-movement",   "confidence":0.88,"source":"stix",      "host":"192.168.1.100"},
    {"technique_id":"T1059.004","technique_name":"Unix Shell",                   "tactic":"execution",          "confidence":0.90,"source":"rule_exact","host":"192.168.1.100"},
    {"technique_id":"T1068","technique_name":"Exploitation for Privilege Escalation","tactic":"privilege-escalation","confidence":0.93,"source":"post_exploit","host":"192.168.1.100"},
    {"technique_id":"T1003","technique_name":"OS Credential Dumping",            "tactic":"credential-access",  "confidence":0.95,"source":"post_exploit","host":"192.168.1.100"},
    {"technique_id":"T1110","technique_name":"Brute Force",                      "tactic":"credential-access",  "confidence":0.87,"source":"rule_service","host":"192.168.1.100"},
    {"technique_id":"T1082","technique_name":"System Information Discovery",     "tactic":"discovery",          "confidence":0.95,"source":"post_exploit","host":"192.168.1.100"},
    {"technique_id":"T1016","technique_name":"System Network Config Discovery",  "tactic":"discovery",          "confidence":0.93,"source":"post_exploit","host":"192.168.1.100"},
    {"technique_id":"T1057","technique_name":"Process Discovery",                "tactic":"discovery",          "confidence":0.93,"source":"post_exploit","host":"192.168.1.100"},
    {"technique_id":"T1547","technique_name":"Boot/Logon Autostart Execution",   "tactic":"persistence",        "confidence":0.65,"source":"ml",         "host":"192.168.1.100"},
    {"technique_id":"T1041","technique_name":"Exfiltration Over C2 Channel",     "tactic":"exfiltration",       "confidence":0.60,"source":"ml",         "host":"192.168.1.100"},
]

COLOR_MAP = {"rule_exact":"#e03d3d","rule_service":"#e07d00","post_exploit":"#34d399","stix":"#c0882a","ml":"#3b82f6"}
SCORE_MAP = {"rule_exact":100,"rule_service":80,"post_exploit":95,"stix":65,"ml":55}


@router.get("/techniques", response_model=MitreResponse)
async def list_techniques():
    techs = [TechniqueOut(**t) for t in DEMO_TECHNIQUES]

    # Tactic distribution
    by_tactic: dict[str,list] = {}
    for t in DEMO_TECHNIQUES:
        tac = t["tactic"]
        by_tactic.setdefault(tac, [])
        by_tactic[tac].append(t["technique_id"])

    dist = [TacticDistOut(tactic=tac, count=len(ids), techniques=ids)
            for tac, ids in by_tactic.items()]

    return MitreResponse(
        total_techniques = len(techs),
        tactics_covered  = len(by_tactic),
        techniques       = techs,
        tactic_distribution = dist,
    )


@router.get("/tactics")
async def list_tactics():
    by_tactic: dict[str,int] = {}
    for t in DEMO_TECHNIQUES:
        by_tactic[t["tactic"]] = by_tactic.get(t["tactic"], 0) + 1
    return {"tactic_distribution": by_tactic, "total_tactics": len(by_tactic)}


@router.get("/heatmap", response_model=HeatmapResponse)
async def get_heatmap():
    heatmap_techs = [
        HeatmapTechniqueOut(
            techniqueID = t["technique_id"],
            score       = SCORE_MAP.get(t["source"], 50),
            color       = COLOR_MAP.get(t["source"], "#6b7280"),
            comment     = f"Source: {t['source']} | Confidence: {int(t['confidence']*100)}%",
        )
        for t in DEMO_TECHNIQUES
    ]
    return HeatmapResponse(
        name       = "Red Team AI — ATT&CK Layer",
        domain     = "enterprise-attack",
        techniques = heatmap_techs,
        legend     = [
            {"label": "Rule-based (0.85–0.95)", "color": "#e03d3d"},
            {"label": "STIX semantic (0.60–0.75)", "color": "#c0882a"},
            {"label": "ML classifier (0.50–0.70)", "color": "#3b82f6"},
            {"label": "Post-exploitation", "color": "#34d399"},
        ],
    )


@router.get("/chain")
async def get_chain():
    from modules.mitre.chain_builder import ChainBuilder
    builder = ChainBuilder()
    # Wrap techniques as mapped results for chain builder
    fake_mapped = [{"host": t["host"], "layers": [t], "mitre": t} for t in DEMO_TECHNIQUES]
    chain = builder.build(fake_mapped)
    return {"phase_count": len(chain), "attack_chain": chain}
