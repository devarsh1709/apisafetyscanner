import asyncio
import uuid
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext

REQUIRED_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "check": lambda v: v and "max-age" in v and int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000,
        "title": "Missing or Weak HTTP Strict Transport Security (HSTS)",
        "severity": Severity.HIGH,
        "cvss": 7.4,
        "cwe": "CWE-319",
        "description": "HSTS forces browsers to use HTTPS. Without it, users are vulnerable to SSL stripping and downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    {
        "name": "Content-Security-Policy",
        "check": lambda v: v is not None,
        "title": "Missing Content-Security-Policy Header",
        "severity": Severity.HIGH,
        "cvss": 6.1,
        "cwe": "CWE-1021",
        "description": "Without CSP, browsers allow inline scripts and resources from any origin, enabling XSS attacks.",
        "remediation": "Add a restrictive CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    {
        "name": "X-Frame-Options",
        "check": lambda v: v and v.upper() in ("DENY", "SAMEORIGIN"),
        "title": "Missing X-Frame-Options Header",
        "severity": Severity.MEDIUM,
        "cvss": 4.7,
        "cwe": "CWE-1021",
        "description": "Without X-Frame-Options, the page can be embedded in iframes on attacker sites, enabling clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN. Alternatively use CSP frame-ancestors directive.",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    {
        "name": "X-Content-Type-Options",
        "check": lambda v: v and v.lower() == "nosniff",
        "title": "Missing X-Content-Type-Options Header",
        "severity": Severity.LOW,
        "cvss": 3.7,
        "cwe": "CWE-430",
        "description": "Without nosniff, browsers may MIME-sniff responses, potentially executing uploaded files as scripts.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    {
        "name": "Referrer-Policy",
        "check": lambda v: v and v.lower() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"
        ),
        "title": "Missing or Permissive Referrer-Policy",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "cwe": "CWE-200",
        "description": "A missing or permissive Referrer-Policy leaks the full URL in the Referer header to third parties, potentially exposing tokens or private paths.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    {
        "name": "Permissions-Policy",
        "check": lambda v: v is not None,
        "title": "Missing Permissions-Policy Header",
        "severity": Severity.LOW,
        "cvss": 2.5,
        "cwe": "CWE-693",
        "description": "Without Permissions-Policy, the browser may grant access to powerful features (camera, geolocation, microphone) to scripts.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "refs": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
]

DANGEROUS_HEADERS = [
    {
        "name": "Server",
        "check": lambda v: v and len(v) > 5 and any(
            tech in v.lower() for tech in ["apache", "nginx", "iis", "lighttpd", "express", "tomcat"]
        ),
        "extract": lambda v: v,
        "title": "Server Version Disclosure",
        "severity": Severity.LOW,
        "cvss": 4.0,
        "cwe": "CWE-200",
        "description": "The Server header reveals the web server software and version, helping attackers identify known vulnerabilities.",
        "remediation": "Configure your web server to suppress or anonymize the Server header.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    {
        "name": "X-Powered-By",
        "check": lambda v: v is not None,
        "extract": lambda v: v,
        "title": "Technology Stack Disclosed via X-Powered-By",
        "severity": Severity.LOW,
        "cvss": 3.5,
        "cwe": "CWE-200",
        "description": "The X-Powered-By header reveals the backend framework (e.g., Express, PHP, ASP.NET), aiding attackers in targeting known vulnerabilities.",
        "remediation": "Remove the X-Powered-By header. In Express: app.disable('x-powered-by').",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
    {
        "name": "X-AspNet-Version",
        "check": lambda v: v is not None,
        "extract": lambda v: v,
        "title": "ASP.NET Version Disclosed",
        "severity": Severity.LOW,
        "cvss": 3.5,
        "cwe": "CWE-200",
        "description": "The X-AspNet-Version header discloses the exact ASP.NET version, allowing targeted version-specific attacks.",
        "remediation": "Remove via httpRuntime enableVersionHeader='false' in web.config.",
        "refs": ["https://owasp.org/www-project-secure-headers/"],
    },
]


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        try:
            resp = await client.get(ctx.target_url, headers=ctx.headers)
            tasks = [
                _check_required_headers(resp, ctx),
                _check_dangerous_headers(resp, ctx),
                _check_cache_control(resp, ctx),
                _check_cookie_security(resp, ctx),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    vulns.extend(r)
        except Exception:
            pass

    return vulns


async def _check_required_headers(resp: httpx.Response, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    for hdr in REQUIRED_HEADERS:
        value = resp.headers.get(hdr["name"])
        if not hdr["check"](value):
            evidence = f"Header '{hdr['name']}' value: {repr(value)}"
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=hdr["title"],
                severity=hdr["severity"],
                category="Security Headers",
                description=hdr["description"],
                evidence=evidence,
                remediation=hdr["remediation"],
                cwe=hdr["cwe"],
                cvss_score=hdr["cvss"],
                endpoint=ctx.target_url,
                method="GET",
                response_details={"header": hdr["name"], "value": value},
                references=hdr["refs"],
            ))
    return vulns


async def _check_dangerous_headers(resp: httpx.Response, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    for hdr in DANGEROUS_HEADERS:
        value = resp.headers.get(hdr["name"])
        if hdr["check"](value):
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=hdr["title"],
                severity=hdr["severity"],
                category="Security Headers",
                description=hdr["description"],
                evidence=f"Header '{hdr['name']}': {value}",
                remediation=hdr["remediation"],
                cwe=hdr["cwe"],
                cvss_score=hdr["cvss"],
                endpoint=ctx.target_url,
                method="GET",
                references=hdr["refs"],
            ))
    return vulns


async def _check_cache_control(resp: httpx.Response, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    cache_control = resp.headers.get("cache-control", "")
    pragma = resp.headers.get("pragma", "")
    content_type = resp.headers.get("content-type", "")

    is_sensitive = any(k in ctx.target_url.lower() for k in [
        "api", "auth", "user", "account", "profile", "token", "login", "admin"
    ])

    if is_sensitive and not any(d in cache_control.lower() for d in ["no-store", "no-cache", "private"]):
        vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            title="Sensitive API Endpoint Missing Cache Control",
            severity=Severity.MEDIUM,
            category="Security Headers",
            description="API endpoints containing sensitive data should prevent caching. Without proper Cache-Control headers, responses may be stored in browser caches, CDNs, or proxy caches.",
            evidence=f"Cache-Control: {cache_control or '(not set)'}\nPragma: {pragma or '(not set)'}",
            remediation="Add: Cache-Control: no-store, no-cache, must-revalidate\nPragma: no-cache",
            cwe="CWE-524",
            cvss_score=4.3,
            endpoint=ctx.target_url,
            method="GET",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"],
        ))
    return vulns


async def _check_cookie_security(resp: httpx.Response, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, 'get_list') else []
    if not set_cookie_headers:
        raw = resp.headers.get("set-cookie")
        if raw:
            set_cookie_headers = [raw]

    for cookie_header in set_cookie_headers:
        cookie_lower = cookie_header.lower()
        issues = []
        if "httponly" not in cookie_lower:
            issues.append("Missing HttpOnly flag (JavaScript can access this cookie)")
        if "secure" not in cookie_lower:
            issues.append("Missing Secure flag (cookie transmitted over HTTP)")
        if "samesite" not in cookie_lower:
            issues.append("Missing SameSite attribute (vulnerable to CSRF)")

        if issues:
            cookie_name = cookie_header.split("=")[0].strip()
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=f"Insecure Cookie Flags on '{cookie_name}'",
                severity=Severity.MEDIUM,
                category="Security Headers",
                description=f"The cookie '{cookie_name}' is missing security flags: {'; '.join(issues)}",
                evidence=f"Set-Cookie: {cookie_header[:120]}",
                remediation="Set cookies with: HttpOnly; Secure; SameSite=Strict (or Lax for normal use).",
                cwe="CWE-1004",
                cvss_score=5.0,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            ))
    return vulns
