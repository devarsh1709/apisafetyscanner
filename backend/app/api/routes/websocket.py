import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus

router = APIRouter()


@router.websocket("/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        while True:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                await websocket.send_json({"error": "Scan not found"})
                break

            payload = {
                "scan_id": scan_id,
                "status": scan.status,
                "progress": scan.progress,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "log": scan.scan_log[-5:] if scan.scan_log else [],
            }
            await websocket.send_json(payload)
            db.expire_all()

            if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                break

            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        db.close()
