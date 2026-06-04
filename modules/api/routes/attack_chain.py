"""
api/routes/attack_chain.py
---------------------------
FastAPI routes for attack chain data.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/attack-chain", tags=["Attack Chain"])


@router.get("/")
async def get_attack_chain():
    return {"message": "Returns the reconstructed attack chain."}


@router.get("/phases")
async def get_phases():
    return {"message": "Returns individual attack phases."}
