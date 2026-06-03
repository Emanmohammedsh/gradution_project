"""
config/database.py
------------------
Database connection and session management.
Supports SQLite (default / dev) and PostgreSQL (production).
Uses SQLAlchemy so the rest of the code stays DB-agnostic.
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config.settings import DB_URL

# ─────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────
_connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}

engine = create_engine(
    DB_URL,
    connect_args=_connect_args,
    echo=False,          # set True to log every SQL statement
    pool_pre_ping=True,  # auto-reconnect on stale connections
)

# ─────────────────────────────────────────────
# Session factory
# ─────────────────────────────────────────────
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

# ─────────────────────────────────────────────
# Declarative base (all ORM models inherit this)
# ─────────────────────────────────────────────
Base = declarative_base()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def get_db():
    """
    FastAPI / dependency-injection style session generator.

    Usage:
        from config.database import get_db
        from sqlalchemy.orm import Session
        from fastapi import Depends

        @router.get("/items")
        def read_items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Create all tables defined via ORM models.
    Call once at application startup (e.g. from main.py or an Alembic migration).
    """
    # Import models here so they register with Base before create_all
    # from database.models import scan, vulnerability, report   # uncomment when models exist
    Base.metadata.create_all(bind=engine)
    print("[DB] Tables initialised.")


def ping():
    """
    Return True if the database is reachable, False otherwise.
    Useful for health-check endpoints.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"[DB] Ping failed: {exc}")
        return False
