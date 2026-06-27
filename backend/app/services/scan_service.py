import asyncio
import uuid
from datetime import datetime
from typing import Callable, Awaitable
from sqlalchemy.orm import Session
from app.models.scan import Scan, ScanStatus
from app.scanners.base import ScanContext, Vulnerability, SEVERITY_SCORES, Severity
from app.scanners import (
    auth_scanner,
    rate_limit_scanner,
    injection_scanner,
    cors_scanner,
    header_scanner,
    ssl_scanner,
    info_disclosure_scanner,
    idor_scanner,
    method_scanner,
)

SCANNER_MAP = {
    "authentication": ("Authentication & JWT", auth_scanner),
    "rate_limiting": ("Rate Limiting", rate_limit_scanner),
    "injection": ("Injection Attacks", injection_scanner),
    "cors": ("CORS Misconfiguration", cors_scanner),
    "headers": ("Security Headers", header_scanner),
    "ssl": ("SSL/TLS", ssl_scanner),
    "info_disclosure": ("Information Disclosure", info_disclosure_scanner),
    "idor": ("IDOR & Access Control", idor_scanner),
    "methods": ("HTTP Methods", method_scanner),
}

ProgressCallback = Callable[[str, int, str], Awaitable[None]]


async def run_scan(
    scan_id: str,
    db: Session,
    progress_callback: ProgressCallback | None = None,
) -> None:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    db.commit()

    ctx = ScanContext(
        target_url=scan.target_url,
        headers=scan.headers or {},
        cookies=scan.cookies or {},
        auth_token=scan.auth_token or "",
        timeout=10,
        scan_id=scan_id,
    )

    if ctx.auth_token and "Authorization" not in ctx.headers:
        ctx.headers["Authorization"] = f"Bearer {ctx.auth_token}"

    scan_types = scan.scan_types or list(SCANNER_MAP.keys())
    total_steps = len(scan_types)
    all_vulns: list[Vulnerability] = []
    log_entries: list[dict] = []

    try:
        for idx, scan_type in enumerate(scan_types):
            if scan_type not in SCANNER_MAP:
                continue

            label, module = SCANNER_MAP[scan_type]
            progress_pct = int((idx / total_steps) * 90)

            log_entry = {
                "time": datetime.utcnow().isoformat(),
                "module": label,
                "status": "running",
                "message": f"Running {label} scan...",
            }
            log_entries.append(log_entry)

            if progress_callback:
                await progress_callback(label, progress_pct, f"Running {label}...")

            scan.progress = progress_pct
            scan.scan_log = log_entries[:]
            db.commit()

            try:
                vulns = await asyncio.wait_for(module.run(ctx), timeout=60)
                all_vulns.extend(vulns)
                log_entry["status"] = "done"
                log_entry["found"] = len(vulns)
                log_entry["message"] = f"{label} complete — {len(vulns)} finding(s)"
            except asyncio.TimeoutError:
                log_entry["status"] = "timeout"
                log_entry["message"] = f"{label} timed out"
            except Exception as e:
                log_entry["status"] = "error"
                log_entry["message"] = f"{label} error: {str(e)[:100]}"

        vuln_dicts = [v.to_dict() for v in all_vulns]
        counts = {s: 0 for s in Severity}
        for v in all_vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1

        risk_score = min(10.0, sum(SEVERITY_SCORES[v.severity] for v in all_vulns) / max(1, len(all_vulns)))

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.progress = 100
        scan.vulnerabilities = vuln_dicts
        scan.total_vulnerabilities = len(all_vulns)
        scan.critical_count = counts.get(Severity.CRITICAL, 0)
        scan.high_count = counts.get(Severity.HIGH, 0)
        scan.medium_count = counts.get(Severity.MEDIUM, 0)
        scan.low_count = counts.get(Severity.LOW, 0)
        scan.info_count = counts.get(Severity.INFO, 0)
        scan.risk_score = round(risk_score, 2)
        scan.requests_made = total_steps * 8
        scan.endpoints_tested = total_steps
        scan.scan_log = log_entries

        if progress_callback:
            await progress_callback("Complete", 100, "Scan completed successfully")

        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
