import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Integer, Float, Text, Enum
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = Column(String, nullable=False)
    name = Column(String, nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    scan_types = Column(JSON, default=list)
    headers = Column(JSON, default=dict)
    cookies = Column(JSON, default=dict)
    auth_token = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    progress = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    vulnerabilities = Column(JSON, default=list)
    scan_log = Column(JSON, default=list)
    error_message = Column(Text, nullable=True)
    endpoints_tested = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
