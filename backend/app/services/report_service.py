import json
from datetime import datetime
from app.models.scan import Scan


def generate_json_report(scan: Scan) -> dict:
    duration = None
    if scan.started_at and scan.completed_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()

    return {
        "report_generated_at": datetime.utcnow().isoformat(),
        "scan": {
            "id": scan.id,
            "name": scan.name or f"Scan of {scan.target_url}",
            "target_url": scan.target_url,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": duration,
            "scan_types": scan.scan_types or [],
        },
        "summary": {
            "risk_score": scan.risk_score,
            "risk_level": _risk_level(scan.risk_score),
            "total_vulnerabilities": scan.total_vulnerabilities,
            "by_severity": {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count,
            },
            "endpoints_tested": scan.endpoints_tested,
            "requests_made": scan.requests_made,
        },
        "vulnerabilities": scan.vulnerabilities or [],
        "recommendations": _build_recommendations(scan.vulnerabilities or []),
    }


def generate_markdown_report(scan: Scan) -> str:
    data = generate_json_report(scan)
    s = data["summary"]
    vulns = data["vulnerabilities"]

    lines = [
        f"# API Security Scan Report",
        f"",
        f"**Target:** `{scan.target_url}`  ",
        f"**Generated:** {data['report_generated_at']}  ",
        f"**Risk Score:** {s['risk_score']}/10 ({s['risk_level'].upper()})  ",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {s['by_severity']['critical']} |",
        f"| 🟠 High | {s['by_severity']['high']} |",
        f"| 🟡 Medium | {s['by_severity']['medium']} |",
        f"| 🟢 Low | {s['by_severity']['low']} |",
        f"| ℹ️ Info | {s['by_severity']['info']} |",
        f"| **Total** | **{s['total_vulnerabilities']}** |",
        f"",
        f"**Endpoints Tested:** {s['endpoints_tested']}  ",
        f"**Requests Made:** {s['requests_made']}  ",
        f"",
        f"## Vulnerabilities",
        f"",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.get("severity", "info"), 99))

    for vuln in sorted_vulns:
        sev = vuln.get("severity", "info").upper()
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}.get(sev, "⚪")
        lines += [
            f"### {emoji} [{sev}] {vuln.get('title', 'Unknown')}",
            f"",
            f"**Category:** {vuln.get('category', '')}  ",
            f"**CWE:** {vuln.get('cwe', 'N/A')}  ",
            f"**CVSS Score:** {vuln.get('cvss_score', 'N/A')}  ",
            f"**Endpoint:** `{vuln.get('endpoint', 'N/A')}`  ",
            f"**Method:** `{vuln.get('method', 'N/A')}`  ",
            f"",
            f"**Description:**  ",
            f"{vuln.get('description', '')}",
            f"",
            f"**Evidence:**  ",
            f"```",
            f"{vuln.get('evidence', 'N/A')}",
            f"```",
            f"",
            f"**Remediation:**  ",
            f"{vuln.get('remediation', '')}",
            f"",
            f"---",
            f"",
        ]

    if data["recommendations"]:
        lines += ["## Top Recommendations", ""]
        for i, rec in enumerate(data["recommendations"][:5], 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    return "\n".join(lines)


def _risk_level(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "informational"


def _build_recommendations(vulns: list[dict]) -> list[str]:
    recs = set()
    categories = {v.get("category") for v in vulns}
    severity_map = {v.get("category"): v.get("severity") for v in vulns}

    if "Authentication" in categories:
        recs.add("Implement strong authentication on all API endpoints (JWT with RS256, OAuth 2.0, or mTLS).")
    if "Rate Limiting" in categories:
        recs.add("Deploy API gateway-level rate limiting with per-user and per-IP controls.")
    if "Injection" in categories:
        recs.add("Use parameterized queries and input validation to prevent injection attacks.")
    if "CORS" in categories:
        recs.add("Configure CORS with explicit origin allowlists — remove wildcard (*) from authenticated APIs.")
    if "Security Headers" in categories:
        recs.add("Add CSP, HSTS, X-Frame-Options, and X-Content-Type-Options to all API responses.")
    if "SSL/TLS" in categories:
        recs.add("Enforce TLS 1.2+ and configure automated certificate renewal.")
    if "Broken Access Control" in categories:
        recs.add("Implement object-level authorization checks on every endpoint accessing user data.")
    if "Information Disclosure" in categories:
        recs.add("Audit API responses for sensitive data leakage and configure error handling to suppress stack traces.")

    return list(recs)
