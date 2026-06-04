"""
api/routes/mitre.py
--------------------
FastAPI routes for MITRE ATT&CK data.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/mitre", tags=["MITRE"])


@router.get("/techniques")
async def list_techniques():
    return {"message": "Returns all mapped ATT&CK techniques."}


@router.get("/tactics")
async def list_tactics():
    return {"message": "Returns tactic distribution for the last scan."}


@router.get("/heatmap")
async def get_heatmap():
    return {"message": "Returns ATT&CK Navigator layer JSON."}


@router.get("/chain")
async def get_chain():
    return {"message": "Returns the full attack chain for the last scan."}
