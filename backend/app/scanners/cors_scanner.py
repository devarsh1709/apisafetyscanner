import asyncio
import uuid
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_wildcard_cors(client, ctx),
            _test_arbitrary_origin(client, ctx),
            _test_null_origin(client, ctx),
            _test_subdomain_cors(client, ctx),
            _test_credentials_with_wildcard(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_wildcard_cors(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.options(
            ctx.target_url,
            headers={**ctx.headers, "Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            if acac.lower() == "true":
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="CORS: Wildcard Origin with Credentials",
                    severity=Severity.CRITICAL,
                    category="CORS",
                    description="The API returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. This combination allows any site to make credentialed cross-origin requests.",
                    evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    remediation="Never combine wildcard ACAO with Allow-Credentials: true. Specify explicit allowed origins instead.",
                    cwe="CWE-346",
                    cvss_score=9.0,
                    endpoint=ctx.target_url,
                    method="OPTIONS",
                    references=["https://portswigger.net/web-security/cors"],
                ))
            else:
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="CORS: Wildcard Origin Allowed",
                    severity=Severity.MEDIUM,
                    category="CORS",
                    description="The API allows all origins (*). Any website can read the API response. This is acceptable for fully public APIs but dangerous for authenticated APIs.",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation="If the API requires authentication, restrict ACAO to specific trusted origins instead of a wildcard.",
                    cwe="CWE-346",
                    cvss_score=5.3,
                    endpoint=ctx.target_url,
                    method="OPTIONS",
                    false_positive_likelihood="high",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                ))
    except Exception:
        pass
    return vulns


async def _test_arbitrary_origin(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    test_origins = [
        "https://evil.com",
        "https://attacker.io",
        "null",
    ]
    try:
        for origin in test_origins:
            resp = await client.get(
                ctx.target_url,
                headers={**ctx.headers, "Origin": origin},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == origin or (acao and acao != "*" and origin in acao):
                severity = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="CORS: Arbitrary Origin Reflected",
                    severity=severity,
                    category="CORS",
                    description=f"The server reflects the requesting origin '{origin}' in Access-Control-Allow-Origin without validation. Any attacker-controlled site can make cross-origin requests.",
                    evidence=f"Request Origin: {origin}\nResponse ACAO: {acao}\nAllow-Credentials: {acac}",
                    remediation="Validate the Origin header against an explicit allowlist. Do not dynamically reflect arbitrary origins.",
                    cwe="CWE-346",
                    cvss_score=9.0 if acac.lower() == "true" else 7.5,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://portswigger.net/web-security/cors/lab-reflect-arbitrary-origins"],
                ))
                return vulns
    except Exception:
        pass
    return vulns


async def _test_null_origin(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.get(
            ctx.target_url,
            headers={**ctx.headers, "Origin": "null"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if acao == "null":
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="CORS: Null Origin Trusted",
                severity=Severity.HIGH,
                category="CORS",
                description="The server trusts the 'null' origin. Sandboxed iframes and local files send a null origin, which can be abused by attackers to bypass CORS restrictions.",
                evidence=f"Origin: null → Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                remediation="Remove 'null' from trusted origins. Sandboxed contexts should not be granted API access.",
                cwe="CWE-346",
                cvss_score=7.5,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack"],
            ))
    except Exception:
        pass
    return vulns


async def _test_subdomain_cors(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        from urllib.parse import urlparse
        parsed = urlparse(ctx.target_url)
        domain = parsed.netloc
        evil_subdomain = f"https://evil.{domain}"
        resp = await client.get(
            ctx.target_url,
            headers={**ctx.headers, "Origin": evil_subdomain},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == evil_subdomain:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="CORS: Subdomain Origin Trusted Without Validation",
                severity=Severity.HIGH,
                category="CORS",
                description=f"The server accepts any subdomain of its own domain (e.g., evil.{domain}). If an attacker can control a subdomain (via XSS or subdomain takeover), they can make CORS requests.",
                evidence=f"Origin: {evil_subdomain} → ACAO: {acao}",
                remediation="Validate the full origin string, not just a suffix match. Ensure CORS validation uses an explicit allowlist.",
                cwe="CWE-346",
                cvss_score=7.1,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://portswigger.net/web-security/cors/lab-breaking-https-attack"],
            ))
    except Exception:
        pass
    return vulns


async def _test_credentials_with_wildcard(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.options(
            ctx.target_url,
            headers={
                **ctx.headers,
                "Origin": "https://trusted.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
        allow_headers = resp.headers.get("access-control-allow-headers", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if "*" in allow_headers and acac.lower() == "true":
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="CORS: Wildcard Allowed Headers with Credentials",
                severity=Severity.HIGH,
                category="CORS",
                description="The preflight response allows all headers (*) combined with credentials. This means any custom header (including Authorization) can be sent cross-origin.",
                evidence=f"Access-Control-Allow-Headers: {allow_headers}\nAccess-Control-Allow-Credentials: {acac}",
                remediation="Specify explicit allowed headers instead of wildcard when credentials are enabled.",
                cwe="CWE-346",
                cvss_score=7.5,
                endpoint=ctx.target_url,
                method="OPTIONS",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflight_requests_and_credentials"],
            ))
    except Exception:
        pass
    return vulns
