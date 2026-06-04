"""
api/routes/scan.py
-------------------
FastAPI routes for scan operations.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/scan", tags=["Scan"])


class ScanRequest(BaseModel):
    target: str
    lhost:  str = "127.0.0.1"


@router.post("/run")
async def run_scan(req: ScanRequest):
    """Trigger a full scan pipeline on the given target."""
    try:
        from modules.recon   import ReconModule
        from modules.scanner import ScannerModule

        recon   = ReconModule(req.target)
        hosts   = recon.discover_hosts()
        scanner = ScannerModule(req.target)
        results = scanner.scan_target()
        return {"status": "ok", "hosts": hosts, "scan_results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{host}")
async def get_results(host: str):
    """Return cached scan results for a host."""
    return {"host": host, "message": "Query the database for persisted results."}
