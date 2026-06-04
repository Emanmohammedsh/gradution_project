"""
api/routes/threat_intelligence.py
-----------------------------------
FastAPI routes for threat intelligence data.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/threat-intelligence", tags=["Threat Intelligence"])


@router.get("/")
async def get_ti():
    return {"message": "Returns threat intelligence enrichment for all findings."}


@router.get("/kev")
async def kev():
    return {"message": "Returns findings present in CISA KEV catalog."}


@router.get("/epss/top")
async def top_epss():
    return {"message": "Returns top 10 findings by EPSS score."}
