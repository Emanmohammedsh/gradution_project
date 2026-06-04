"""
api/routes/analytics.py
------------------------
FastAPI routes for dashboard analytics.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("/dashboard")
async def dashboard():
    return {"message": "Returns all dashboard metrics."}


@router.get("/risk")
async def risk():
    return {"message": "Returns risk analytics."}


@router.get("/coverage")
async def coverage():
    return {"message": "Returns detection coverage analytics."}
