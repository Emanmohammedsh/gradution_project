"""
config/settings.py
------------------
Central runtime configuration for the Hybrid AI Red Team Framework.
All tuneable parameters live here; modules import from this file
instead of hard-coding values.
"""

import os
from pathlib import Path

# ─────────────────────────────────────────────
# Base Paths
# ─────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR  = BASE_DIR / "models"

# ─────────────────────────────────────────────
# Framework Identity
# ─────────────────────────────────────────────
FRAMEWORK_NAME    = "Hybrid AI Red Team Simulation Framework"
FRAMEWORK_VERSION = "2.0.0"
UNIVERSITY        = "UCAS Cyber Security Engineering 2026"

# ─────────────────────────────────────────────
# Reconnaissance Settings
# ─────────────────────────────────────────────
RECON_TIMEOUT_SEC      = 30        # host-discovery timeout per host
RECON_NMAP_ARGS_PING   = "-sn"     # ping-sweep arguments
RECON_MAX_HOSTS        = 256       # max hosts in a /24 sweep

# ─────────────────────────────────────────────
# Scanner Settings
# ─────────────────────────────────────────────
SCAN_NMAP_ARGS         = "-sV -sC -O --open -T4"
SCAN_TOP_PORTS         = 1000
SCAN_TIMEOUT_SEC       = 120

# ─────────────────────────────────────────────
# Vulnerability / Risk Settings
# ─────────────────────────────────────────────
VULN_NVD_API_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULN_NVD_API_KEY       = os.getenv("NVD_API_KEY", "")
RISK_THRESHOLD_DEFAULT = 30        # minimum risk score to proceed with exploitation
CVSS_CRITICAL_MIN      = 9.0
CVSS_HIGH_MIN          = 7.0
CVSS_MEDIUM_MIN        = 4.0

# ─────────────────────────────────────────────
# Exploitation Settings
# ─────────────────────────────────────────────
EXPLOIT_LHOST_DEFAULT  = "127.0.0.1"
EXPLOIT_LPORT_DEFAULT  = 4444
EXPLOIT_TIMEOUT_SEC    = 60

# ─────────────────────────────────────────────
# MITRE ATT&CK Settings
# ─────────────────────────────────────────────
MITRE_STIX_FILE        = str(DATA_DIR / "enterprise-attack.json")
MITRE_RULES_FILE       = str(DATA_DIR / "mitre_rules.json")
MITRE_HEATMAP_DIR      = str(REPORTS_DIR / "heatmaps")
MITRE_CHAIN_DIR        = str(REPORTS_DIR)
MITRE_NAVIGATOR_LAYER_VERSION = "4.5"

# ─────────────────────────────────────────────
# AI / ML Settings
# ─────────────────────────────────────────────
ML_MODEL_DIR              = str(MODELS_DIR)
ML_MITRE_CLASSIFIER_FILE  = str(MODELS_DIR / "mitre_classifier.pkl")
ML_RISK_MODEL_FILE        = str(MODELS_DIR / "risk_model.pkl")
ML_VECTORIZER_FILE        = str(MODELS_DIR / "vectorizer.pkl")
ML_LABEL_ENCODER_FILE     = str(MODELS_DIR / "label_encoder.pkl")
ML_TRAINING_DATASET_FILE  = str(DATA_DIR / "training_dataset.csv")
ML_CONFIDENCE_THRESHOLD   = 0.55   # minimum confidence to accept ML prediction

# ─────────────────────────────────────────────
# Reporting Settings
# ─────────────────────────────────────────────
REPORT_OUTPUT_DIR   = str(REPORTS_DIR)
REPORT_JSON_DIR     = str(REPORTS_DIR / "json")
REPORT_PDF_DIR      = str(REPORTS_DIR / "pdf")
REPORT_DATE_FORMAT  = "%Y%m%d_%H%M%S"

# ─────────────────────────────────────────────
# API / Server Settings (future FastAPI backend)
# ─────────────────────────────────────────────
API_HOST            = os.getenv("API_HOST", "0.0.0.0")
API_PORT            = int(os.getenv("API_PORT", 8000))
API_DEBUG           = os.getenv("API_DEBUG", "false").lower() == "true"
API_SECRET_KEY      = os.getenv("API_SECRET_KEY", "change-me-in-production")

# ─────────────────────────────────────────────
# Database (see database.py for connection logic)
# ─────────────────────────────────────────────
DB_URL              = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'database' / 'redteam.db'}")
