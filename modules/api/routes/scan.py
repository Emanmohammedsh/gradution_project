"""
api/routes/scan.py — Scan Pipeline API
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from modules.api.schemas import ScanRequest, ScanResponse, ScanHostOut, ServiceOut
from datetime import datetime
import uuid

router = APIRouter(prefix="/api/scan", tags=["Scan"])

# In-memory session store (replace with DB in production)
_sessions: dict[str, dict] = {}


@router.post("/run", response_model=ScanResponse)
async def run_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """
    Trigger a full scan pipeline on a target.
    In dry_run mode (default) only simulates — no real tools executed.
    """
    session_id = f"SIM-{uuid.uuid4().hex[:6].upper()}"
    ts = datetime.now().isoformat()

    if req.dry_run:
        # Return simulated result immediately
        result = ScanResponse(
            status     = "completed",
            session_id = session_id,
            target     = req.target,
            live_hosts = [req.target],
            host_detail= [ScanHostOut(
                ip="192.168.1.100", hostname="target", os="linux",
                services=[
                    ServiceOut(port=21,  service="ftp",  product="vsftpd", version="2.3.4"),
                    ServiceOut(port=22,  service="ssh",  product="OpenSSH",version="4.7p1"),
                    ServiceOut(port=445, service="smb",  product="Samba",  version="3.0.20"),
                    ServiceOut(port=80,  service="http", product="Apache", version="2.2.8"),
                ]
            )],
            port_count = 10,
            timestamp  = ts,
        )
        _sessions[session_id] = result.model_dump()
        return result

    # Real scan (only on Kali/Linux with nmap + msf installed)
    try:
        from modules.recon   import ReconModule
        from modules.scanner import ScannerModule

        recon   = ReconModule(req.target)
        hosts   = recon.discover_hosts()
        if not hosts:
            raise HTTPException(status_code=404, detail="No live hosts found.")

        scanner = ScannerModule(hosts[0])
        results = scanner.scan_target()

        host_detail = []
        port_count  = 0
        for host, data in results.items():
            services = [
                ServiceOut(port=p["port"], service=p.get("service",""),
                           product=p.get("product",""), version=p.get("version",""))
                for p in data.get("ports", [])
            ]
            port_count += len(services)
            host_detail.append(ScanHostOut(ip=host, os=data.get("os","unknown"), services=services))

        resp = ScanResponse(
            status=      "completed",
            session_id=  session_id,
            target=      req.target,
            live_hosts=  hosts,
            host_detail= host_detail,
            port_count=  port_count,
            timestamp=   ts,
        )
        _sessions[session_id] = resp.model_dump()
        return resp

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sessions")
async def list_sessions():
    """List all scan sessions."""
    return {"sessions": list(_sessions.keys()), "count": len(_sessions)}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    """Get a specific session result."""
    if session_id not in _sessions:
        raise HTTPException(status_code=404, detail="Session not found.")
    return _sessions[session_id]
