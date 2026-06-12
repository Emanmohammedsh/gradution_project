from sqlalchemy import Column, String, Integer, DateTime, JSON
from sqlalchemy.sql import func
from config.database import Base

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True)
    target     = Column(String)
    status     = Column(String, default="running")
    result     = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
