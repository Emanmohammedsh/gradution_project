"""
api/routes/scan.py — Scan Pipeline API
يحفظ كل جلسة في DB ويقرأ منه — بدل in-memory dict.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks

from modules.api.schemas import ScanRequest, ScanResponse, ScanHostOut, ServiceOut
from database.repository import (
    save_session,
    update_session_status,
    get_all_sessions,
    get_session_by_id,
)

router = APIRouter(prefix="/api/scan", tags=["Scan"])


@router.post("/run", response_model=ScanResponse)
async def run_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    session_id = f"SIM-{uuid.uuid4().hex[:6].upper()}"
    ts         = datetime.now().isoformat()

    if req.dry_run:
        result = ScanResponse(
            status      = "completed",
            session_id  = session_id,
            target      = req.target,
            live_hosts  = [req.target],
            host_detail = [ScanHostOut(
                ip       = "192.168.1.100",
                hostname = "target",
                os       = "linux",
                services = [
                    ServiceOut(port=21,  service="ftp",  product="vsftpd",  version="2.3.4"),
                    ServiceOut(port=22,  service="ssh",  product="OpenSSH", version="4.7p1"),
                    ServiceOut(port=445, service="smb",  product="Samba",   version="3.0.20"),
                    ServiceOut(port=80,  service="http", product="Apache",  version="2.2.8"),
                ],
            )],
            port_count = 4,
            timestamp  = ts,
        )
        db_id = save_session(session_id, req.target, "", [req.target])
        update_session_status(session_id, "completed", 0.0)
        return result

    try:
        from modules.recon   import ReconModule
        from modules.scanner import ScannerModule

        recon = ReconModule(req.target)
        hosts = recon.discover_hosts()
        if not hosts:
            raise HTTPException(status_code=404, detail="No live hosts found.")

        scanner = ScannerModule(hosts[0])
        results = scanner.scan_target()

        host_detail = []
        port_count  = 0
        for host, data in results.items():
            services = [
                ServiceOut(
                    port    = p["port"],
                    service = p.get("service", ""),
                    product = p.get("product", ""),
                    version = p.get("version", ""),
                )
                for p in data.get("ports", [])
            ]
            port_count += len(services)
            host_detail.append(
                ScanHostOut(ip=host, os=data.get("os", "unknown"), services=services)
            )

        resp = ScanResponse(
            status      = "completed",
            session_id  = session_id,
            target      = req.target,
            live_hosts  = hosts,
            host_detail = host_detail,
            port_count  = port_count,
            timestamp   = ts,
        )
        db_id = save_session(session_id, req.target, "", hosts)
        update_session_status(session_id, "completed", 0.0)
        return resp

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/sessions")
async def list_sessions():
    sessions = get_all_sessions()
    return {"sessions": sessions, "count": len(sessions)}


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    session = get_session_by_id(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    return session
