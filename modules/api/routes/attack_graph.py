"""
api/routes/attack_graph.py
---------------------------
FastAPI routes for attack graph data.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/attack-graph", tags=["Attack Graph"])


@router.get("/")
async def get_graph():
    return {"message": "Returns nodes and edges of the attack graph."}


@router.get("/critical-nodes")
async def critical_nodes():
    return {"message": "Returns the most critical pivot nodes."}
