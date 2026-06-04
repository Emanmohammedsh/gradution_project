"""
api/dependencies/db.py
------------------------
FastAPI dependency injection for database sessions.
"""

from config.database import get_db  # re-export for route use

__all__ = ["get_db"]
