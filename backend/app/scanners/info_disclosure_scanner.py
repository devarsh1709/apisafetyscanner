import asyncio
import uuid
import re
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/config.json", "/config.yml", "/config.yaml", "/settings.json",
    "/api/debug", "/api/test", "/debug", "/test", "/health/details",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/metrics", "/actuator/mappings", "/actuator/beans",
    "/__debug__", "/wp-config.php", "/phpinfo.php",
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
    "/.git/config", "/.git/HEAD", "/Dockerfile", "/docker-compose.yml",
    "/package.json", "/composer.json", "/requirements.txt",
    "/api/v1/users", "/api/users", "/users",
    "/admin", "/api/admin", "/internal",
    "/metrics", "/stats",
]

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [\w\.$]+\([\w\.]+\.java:\d+\)", "Java stack trace"),
    (r"at [\w\.$]+\([\w\.]+\.cs:\d+\)", ".NET stack trace"),
    (r"Fatal error:.*on line \d+", "PHP error"),
    (r"Error: Cannot find module", "Node.js module error"),
    (r"System\.Exception|System\.NullReferenceException", ".NET exception"),
    (r"mysql_connect\(\)|pg_connect\(\)", "DB connection leak"),
    (r"SQLSTATE\[", "PDO SQL error"),
    (r"<b>Warning</b>:.*PHP Warning", "PHP warning"),
]

PII_PATTERNS = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email Address"),
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "Phone Number"),
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa Card Number"),
    (r"\b5[1-5][0-9]{14}\b", "Mastercard Number"),
    (r"\b(?:\d[ -]*?){13,16}\b", "Possible Credit Card"),
    (r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b", "SSN-like Pattern"),
]

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    (r"(?i)password\s*[=:]\s*[\"']?([^\s\"']{8,})[\"']?", "Password"),
    (r"(?i)private[_-]?key\s*[=:]\s*[\"']?([^\s\"']{10,})[\"']?", "Private Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key"),
    (r"(?i)api[_-]?key\s*[=:]\s*[\"']?([A-Za-z0-9\-_]{16,})[\"']?", "API Key"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key Block"),
]


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    from urllib.parse import urlparse
    parsed = urlparse(ctx.target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_sensitive_paths(client, ctx, base_url),
            _test_error_pages(client, ctx),
            _test_verbose_responses(client, ctx),
            _test_debug_headers(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_sensitive_paths(client: httpx.AsyncClient, ctx: ScanContext, base_url: str) -> list[Vulnerability]:
    vulns = []
    tasks = []
    for path in SENSITIVE_PATHS:
        url = base_url + path
        tasks.append(_check_path(client, ctx, url, path))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Vulnerability):
            vulns.append(r)
    return vulns


async def _check_path(client: httpx.AsyncClient, ctx: ScanContext, url: str, path: str) -> Vulnerability | None:
    try:
        resp = await client.get(url, headers=ctx.headers)
        if resp.status_code in (200, 201) and len(resp.content) > 10:
            body_preview = resp.text[:500]
            category = _classify_sensitive_path(path, resp.text)
            if category:
                return Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"Sensitive File/Path Exposed: {path}",
                    severity=Severity.HIGH if "env" in path or "config" in path or "git" in path else Severity.MEDIUM,
                    category="Information Disclosure",
                    description=f"The path '{path}' is publicly accessible and returns content ({category}). This may expose configuration, credentials, or internal application details.",
                    evidence=f"GET {url} → HTTP {resp.status_code}\nContent preview: {body_preview[:200]}",
                    remediation=f"Block access to '{path}' via web server configuration. Remove development files from production.",
                    cwe="CWE-538",
                    cvss_score=7.5,
                    endpoint=url,
                    method="GET",
                    response_details={"status": resp.status_code, "size": len(resp.content), "content_type": resp.headers.get("content-type", "")},
                    references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
                )
    except Exception:
        pass
    return None


def _classify_sensitive_path(path: str, body: str) -> str | None:
    if "env" in path or "config" in path:
        return "Environment/Configuration file"
    if "git" in path:
        return "Git repository file"
    if "swagger" in path or "openapi" in path or "api-docs" in path:
        return "API documentation"
    if "actuator" in path or "debug" in path or "metrics" in path:
        return "Application monitoring endpoint"
    if "package" in path or "composer" in path or "requirements" in path:
        return "Dependency manifest"
    if "admin" in path:
        return "Admin interface"
    if len(body) > 10:
        return "Accessible endpoint"
    return None


async def _test_error_pages(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    error_triggers = [
        (ctx.target_url + "/nonexistent-path-xyz-123", "GET"),
        (ctx.target_url, "INVALID_METHOD"),
    ]
    try:
        for url, method in error_triggers:
            try:
                if method == "GET":
                    resp = await client.get(url, headers=ctx.headers)
                else:
                    resp = await client.request(method, url, headers=ctx.headers)

                body = resp.text
                for pattern, label in STACK_TRACE_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title=f"Stack Trace / Internal Error Exposed ({label})",
                            severity=Severity.MEDIUM,
                            category="Information Disclosure",
                            description=f"The API leaks internal stack traces in error responses ({label}). This gives attackers details about the technology stack, file paths, and code structure.",
                            evidence=f"Pattern '{label}' detected in {resp.status_code} response to {method} {url[:80]}",
                            remediation="Implement generic error handlers that return sanitized error messages. Never expose stack traces in production.",
                            cwe="CWE-209",
                            cvss_score=5.3,
                            endpoint=url,
                            method=method,
                            false_positive_likelihood="low",
                            references=["https://owasp.org/www-community/Improper_Error_Handling"],
                        ))
                        break
            except Exception:
                continue
    except Exception:
        pass
    return vulns


async def _test_verbose_responses(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.get(ctx.target_url, headers=ctx.headers)
        body = resp.text

        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, body):
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"Potential Secret/Credential Exposed in Response ({label})",
                    severity=Severity.CRITICAL,
                    category="Information Disclosure",
                    description=f"The API response appears to contain a {label}. Exposed credentials allow immediate unauthorized access.",
                    evidence=f"Pattern '{label}' matched in response body.",
                    remediation="Audit all API response fields. Remove sensitive data before serializing responses. Use field-level encryption for truly sensitive values.",
                    cwe="CWE-312",
                    cvss_score=9.1,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                ))

        for pattern, label in PII_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"PII Data Exposed in API Response ({label})",
                    severity=Severity.HIGH,
                    category="Information Disclosure",
                    description=f"The response contains what appears to be {label} data. Exposing PII may violate GDPR, CCPA, and other privacy regulations.",
                    evidence=f"{len(matches)} instance(s) of {label} pattern detected in response.",
                    remediation="Apply data minimization principles. Mask or redact PII in API responses. Implement field-level access control.",
                    cwe="CWE-200",
                    cvss_score=7.5,
                    endpoint=ctx.target_url,
                    method="GET",
                    false_positive_likelihood="medium",
                    references=["https://gdpr.eu/what-is-gdpr/"],
                ))
    except Exception:
        pass
    return vulns


async def _test_debug_headers(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.get(ctx.target_url, headers=ctx.headers)
        debug_headers = {
            "X-Debug-Info", "X-Debug", "X-Request-Id", "X-Trace-Id",
            "X-Correlation-Id", "X-Runtime", "X-Response-Time",
        }
        found_debug = [h for h in debug_headers if resp.headers.get(h)]
        if len(found_debug) >= 2:
            values = {h: resp.headers.get(h) for h in found_debug}
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="Verbose Debug Headers Exposed",
                severity=Severity.LOW,
                category="Information Disclosure",
                description=f"The response includes multiple internal debug/tracing headers: {', '.join(found_debug)}. These reveal internal infrastructure details to external clients.",
                evidence=f"Headers found: {values}",
                remediation="Remove debug and tracing headers from production responses, or restrict them to authenticated internal clients only.",
                cwe="CWE-200",
                cvss_score=3.5,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://owasp.org/www-project-secure-headers/"],
            ))
    except Exception:
        pass
    return vulns
