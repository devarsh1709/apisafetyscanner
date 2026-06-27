import asyncio
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.services import scan_service
from app.scanners.base import Severity

router = APIRouter()


class ScanCreate(BaseModel):
    target_url: str
    name: Optional[str] = None
    scan_types: Optional[list[str]] = None
    headers: Optional[dict] = {}
    cookies: Optional[dict] = {}
    auth_token: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    target_url: str
    name: Optional[str]
    status: str
    scan_types: list
    progress: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: float
    created_at: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    endpoints_tested: int
    requests_made: int
    error_message: Optional[str]

    class Config:
        from_attributes = True


def _scan_to_response(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "name": scan.name,
        "status": scan.status,
        "scan_types": scan.scan_types or [],
        "progress": scan.progress,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "endpoints_tested": scan.endpoints_tested,
        "requests_made": scan.requests_made,
        "error_message": scan.error_message,
    }


@router.get("/")
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    total = db.query(Scan).count()
    return {
        "scans": [_scan_to_response(s) for s in scans],
        "total": total,
    }


@router.post("/", status_code=201)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan = Scan(
        id=str(uuid.uuid4()),
        target_url=payload.target_url,
        name=payload.name or f"Scan — {payload.target_url[:40]}",
        scan_types=payload.scan_types or list(scan_service.SCANNER_MAP.keys()),
        headers=payload.headers or {},
        cookies=payload.cookies or {},
        auth_token=payload.auth_token,
        status=ScanStatus.PENDING,
        progress=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan_bg, scan.id)
    return _scan_to_response(scan)


async def _run_scan_bg(scan_id: str):
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        await scan_service.run_scan(scan_id, db)
    finally:
        db.close()


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_response(scan)


@router.get("/{scan_id}/vulnerabilities")
async def get_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = scan.vulnerabilities or []
    if severity:
        vulns = [v for v in vulns if v.get("severity") == severity.lower()]
    if category:
        vulns = [v for v in vulns if v.get("category", "").lower() == category.lower()]

    return {"vulnerabilities": vulns, "total": len(vulns)}


@router.get("/{scan_id}/log")
async def get_scan_log(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"log": scan.scan_log or [], "progress": scan.progress, "status": scan.status}


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


@router.get("/stats/overview")
async def get_stats(db: Session = Depends(get_db)):
    scans = db.query(Scan).all()
    completed = [s for s in scans if s.status == ScanStatus.COMPLETED]
    return {
        "total_scans": len(scans),
        "completed_scans": len(completed),
        "running_scans": len([s for s in scans if s.status == ScanStatus.RUNNING]),
        "total_vulnerabilities": sum(s.total_vulnerabilities for s in completed),
        "critical_total": sum(s.critical_count for s in completed),
        "high_total": sum(s.high_count for s in completed),
        "medium_total": sum(s.medium_count for s in completed),
        "avg_risk_score": round(
            sum(s.risk_score for s in completed) / len(completed) if completed else 0, 2
        ),
        "recent_scans": [_scan_to_response(s) for s in sorted(scans, key=lambda x: x.created_at, reverse=True)[:5]],
    }
