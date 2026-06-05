"""
api/routes/analytics.py — Dashboard Analytics API
"""
from fastapi import APIRouter
from modules.api.schemas import DashboardResponse, RiskDistOut

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard():
    """Returns all key metrics for the main dashboard."""
    return DashboardResponse(
        session_id      = "SIM-A3F9",
        target          = "192.168.1.100",
        host_count      = 1,
        vuln_count      = 6,
        exploit_count   = 3,
        technique_count = 11,
        kev_count       = 4,
        risk_dist       = RiskDistOut(critical=4, high=2, medium=0, low=0),
        top_techniques  = [
            {"id":"T1190","name":"Exploit Public-Facing Application","confidence":0.95,"count":3},
            {"id":"T1003","name":"OS Credential Dumping",           "confidence":0.95,"count":2},
            {"id":"T1082","name":"System Information Discovery",    "confidence":0.95,"count":2},
            {"id":"T1068","name":"Exploitation for Priv. Escalation","confidence":0.93,"count":1},
            {"id":"T1210","name":"Exploitation of Remote Services", "confidence":0.88,"count":2},
        ],
        pipeline_status = {
            "recon":           True,
            "scan":            True,
            "vuln_mapping":    True,
            "risk_scoring":    True,
            "exploitation":    True,
            "post_exploit":    True,
            "mitre_mapping":   True,
            "report":          True,
        },
    )


@router.get("/risk")
async def risk_analytics():
    return {
        "risk_distribution":   {"critical": 4, "high": 2, "medium": 0, "low": 0},
        "avg_cvss":            9.33,
        "avg_epss":            0.831,
        "avg_risk_score":      76.5,
        "kev_percentage":      66.7,
        "top_risk_services":   [
            {"service": "ftp",   "port": 21,   "risk": 95, "cve": "CVE-2011-2523"},
            {"service": "smb",   "port": 445,  "risk": 88, "cve": "CVE-2007-2447"},
            {"service": "http",  "port": 80,   "risk": 84, "cve": "CVE-2017-7679"},
        ],
    }


@router.get("/coverage")
async def coverage_analytics():
    """Detection coverage metrics."""
    techniques = ["T1190","T1210","T1059.004","T1068","T1003","T1110","T1082","T1016","T1057","T1547","T1041"]
    covered    = ["T1190","T1003","T1082","T1016","T1057","T1068","T1059.004","T1110"]
    return {
        "total_techniques":    len(techniques),
        "covered_by_sigma":    len(covered),
        "coverage_pct":        round(len(covered)/len(techniques)*100, 1),
        "covered_techniques":  covered,
        "not_covered":         [t for t in techniques if t not in covered],
        "log_sources_needed":  ["Windows Security Log","Sysmon","auditd","Apache access log","netflow"],
    }


@router.get("/mitre")
async def mitre_analytics():
    return {
        "tactics_covered":      7,
        "total_tactics":        14,
        "coverage_pct":         50.0,
        "tactic_distribution":  {
            "initial-access":       2, "execution":      2,
            "privilege-escalation": 1, "credential-access": 2,
            "discovery":            4, "lateral-movement": 2,
            "exfiltration":         1,
        },
        "confidence_distribution": {
            "high (≥0.85)":   7,
            "medium (0.65-0.85)": 2,
            "low (<0.65)":    2,
        },
        "source_distribution": {
            "rule_exact":   4,
            "post_exploit": 5,
            "stix":         1,
            "ml":           1,
        },
    }


@router.get("/ml")
async def ml_analytics():
    return {
        "model_type":    "RandomForest",
        "backend":       "scikit-learn",
        "training_rows": 37,
        "accuracy":      0.625,
        "f1_weighted":   0.617,
        "cv_f1_mean":    0.311,
        "tactics_classes": 10,
        "model_status":  "fallback_keyword",
        "note":          "Train model: python train_mitre_model.py",
        "predictions":   [
            {"exploit":"vsftpd_234_backdoor", "tactic":"initial-access",    "conf":0.95, "source":"rule"},
            {"exploit":"samba/usermap_script","tactic":"lateral-movement",   "conf":0.88, "source":"stix"},
            {"exploit":"mysql brute force",   "tactic":"credential-access",  "conf":0.74, "source":"ml"},
        ],
    }
