"""
api/routes/vulnerabilities.py
-------------------------------
FastAPI routes for vulnerability data.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("/")
async def list_vulnerabilities():
    return {"message": "Returns all vulnerability findings from the last scan."}


@router.get("/critical")
async def critical_vulnerabilities():
    return {"message": "Returns CRITICAL severity findings only."}


@router.get("/{cve_id}")
async def get_by_cve(cve_id: str):
    return {"cve": cve_id, "message": "Returns findings matching this CVE."}
