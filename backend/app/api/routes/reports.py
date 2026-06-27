from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.services.report_service import generate_json_report, generate_markdown_report

router = APIRouter()


@router.get("/{scan_id}/json")
async def get_json_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not yet completed")
    return generate_json_report(scan)


@router.get("/{scan_id}/markdown", response_class=PlainTextResponse)
async def get_markdown_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not yet completed")
    return PlainTextResponse(
        generate_markdown_report(scan),
        headers={"Content-Disposition": f'attachment; filename="report-{scan_id[:8]}.md"'},
    )
