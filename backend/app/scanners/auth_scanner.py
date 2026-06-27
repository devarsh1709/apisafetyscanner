import asyncio
import base64
import json
import uuid
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    client_args = {
        "timeout": ctx.timeout,
        "follow_redirects": True,
        "verify": False,
    }

    async with httpx.AsyncClient(**client_args) as client:
        tasks = [
            _test_no_auth(client, ctx),
            _test_broken_jwt(client, ctx),
            _test_jwt_none_alg(client, ctx),
            _test_api_key_in_url(client, ctx),
            _test_default_credentials(client, ctx),
            _test_auth_bypass_headers(client, ctx),
            _test_token_in_response(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_no_auth(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        no_auth_headers = {k: v for k, v in ctx.headers.items()
                           if k.lower() not in ("authorization", "x-api-key", "x-auth-token")}
        resp = await client.get(ctx.target_url, headers=no_auth_headers)

        if resp.status_code in (200, 201):
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="Missing Authentication on Endpoint",
                severity=Severity.HIGH,
                category="Authentication",
                description="The endpoint returns a successful response without any authentication credentials, suggesting it may be publicly accessible when it should be protected.",
                evidence=f"GET {ctx.target_url} → HTTP {resp.status_code} (no Authorization header)",
                remediation="Implement authentication middleware (JWT, OAuth 2.0, or API key) and return 401 for unauthenticated requests.",
                cwe="CWE-306",
                cvss_score=7.5,
                endpoint=ctx.target_url,
                method="GET",
                response_details={"status_code": resp.status_code, "content_length": len(resp.content)},
                references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            ))
    except Exception:
        pass
    return vulns


async def _test_broken_jwt(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    weak_secrets = ["secret", "password", "123456", "admin", "test", "key", "jwt", ""]
    if not ctx.auth_token:
        return vulns
    try:
        parts = ctx.auth_token.split(".")
        if len(parts) != 3:
            return vulns
        header_decoded = base64.urlsafe_b64decode(parts[0] + "==").decode()
        header_obj = json.loads(header_decoded)

        for secret in weak_secrets:
            import hmac
            import hashlib
            payload = parts[0] + "." + parts[1]
            sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
            test_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            if test_sig == parts[2]:
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="JWT Signed with Weak Secret",
                    severity=Severity.CRITICAL,
                    category="Authentication",
                    description=f"The JWT token is signed using a weak, guessable secret: '{secret}'. An attacker can forge tokens and impersonate any user.",
                    evidence=f"JWT secret '{secret}' successfully verified the token signature.",
                    remediation="Use a cryptographically random secret of at least 256 bits. Consider switching to RS256 (asymmetric) signing.",
                    cwe="CWE-798",
                    cvss_score=9.8,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://portswigger.net/web-security/jwt"],
                ))
                break
    except Exception:
        pass
    return vulns


async def _test_jwt_none_alg(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    if not ctx.auth_token:
        return vulns
    try:
        parts = ctx.auth_token.split(".")
        if len(parts) != 3:
            return vulns

        for none_val in ["none", "None", "NONE", "nOnE"]:
            fake_header = base64.urlsafe_b64encode(
                json.dumps({"alg": none_val, "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            forged_token = f"{fake_header}.{parts[1]}."
            test_headers = {**ctx.headers, "Authorization": f"Bearer {forged_token}"}
            resp = await client.get(ctx.target_url, headers=test_headers)
            if resp.status_code in (200, 201):
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="JWT Algorithm Confusion (None Algorithm)",
                    severity=Severity.CRITICAL,
                    category="Authentication",
                    description="The server accepts JWT tokens with the 'none' algorithm, meaning tokens with no signature are accepted. An attacker can forge arbitrary tokens.",
                    evidence=f"Forged JWT with alg='{none_val}' accepted → HTTP {resp.status_code}",
                    remediation="Explicitly whitelist allowed JWT algorithms on the server side. Reject tokens with 'none' algorithm.",
                    cwe="CWE-347",
                    cvss_score=9.8,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                ))
                break
    except Exception:
        pass
    return vulns


async def _test_api_key_in_url(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    import re
    patterns = [
        r"[?&](api[_-]?key|apikey|key|token|access[_-]?token|auth)=([^&\s]{8,})",
        r"[?&](secret|client[_-]?secret|app[_-]?key)=([^&\s]{8,})",
    ]
    for pattern in patterns:
        if re.search(pattern, ctx.target_url, re.IGNORECASE):
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="API Key Exposed in URL",
                severity=Severity.HIGH,
                category="Authentication",
                description="Sensitive credentials (API key or token) are embedded in the URL query string. These are logged by web servers, proxies, and browser history.",
                evidence=f"Credential pattern detected in URL: {ctx.target_url[:100]}...",
                remediation="Move credentials to HTTP headers (Authorization, X-API-Key) or request body. Never include secrets in URLs.",
                cwe="CWE-598",
                cvss_score=7.4,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"],
            ))
    return vulns


async def _test_default_credentials(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("test", "test"), ("api", "api"), ("root", "root"),
    ]
    try:
        for username, password in default_creds:
            creds = base64.b64encode(f"{username}:{password}".encode()).decode()
            test_headers = {**ctx.headers, "Authorization": f"Basic {creds}"}
            resp = await client.get(ctx.target_url, headers=test_headers)
            if resp.status_code in (200, 201):
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"Default Credentials Accepted ({username}/{password})",
                    severity=Severity.CRITICAL,
                    category="Authentication",
                    description=f"The API accepts the default credential pair '{username}:{password}'. Attackers routinely test default credentials.",
                    evidence=f"Basic auth with {username}:{password} → HTTP {resp.status_code}",
                    remediation="Remove or change all default credentials. Enforce strong password policies.",
                    cwe="CWE-1391",
                    cvss_score=9.8,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                ))
                break
    except Exception:
        pass
    return vulns


async def _test_auth_bypass_headers(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    bypass_headers_sets = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ]
    try:
        base_resp = await client.get(ctx.target_url, headers=ctx.headers)
        if base_resp.status_code in (401, 403):
            for bypass in bypass_headers_sets:
                test_headers = {**ctx.headers, **bypass}
                resp = await client.get(ctx.target_url, headers=test_headers)
                if resp.status_code in (200, 201):
                    header_name = list(bypass.keys())[0]
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title=f"Authentication Bypass via {header_name} Header",
                        severity=Severity.CRITICAL,
                        category="Authentication",
                        description=f"Adding the '{header_name}' header bypasses authentication controls. The server trusts untrusted proxy headers.",
                        evidence=f"Without header: HTTP {base_resp.status_code} → With {header_name}: HTTP {resp.status_code}",
                        remediation="Never trust X-Forwarded-For or similar headers for authentication decisions unless behind a verified trusted proxy.",
                        cwe="CWE-290",
                        cvss_score=9.1,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://portswigger.net/web-security/access-control/idor"],
                    ))
    except Exception:
        pass
    return vulns


async def _test_token_in_response(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    import re
    try:
        resp = await client.get(ctx.target_url, headers=ctx.headers)
        body = resp.text
        patterns = [
            (r'"(api_key|apiKey|api-key)"\s*:\s*"([^"]{10,})"', "API Key"),
            (r'"(secret|client_secret|clientSecret)"\s*:\s*"([^"]{10,})"', "Secret"),
            (r'"(password|passwd|pwd)"\s*:\s*"([^"]{4,})"', "Password"),
            (r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', "JWT Token"),
        ]
        for pattern, label in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"Sensitive Data ({label}) Exposed in Response",
                    severity=Severity.HIGH,
                    category="Information Disclosure",
                    description=f"The API response contains what appears to be a {label}. Sensitive credentials should never be returned in API responses.",
                    evidence=f"Pattern '{label}' detected in response body (first 200 chars): {body[:200]}",
                    remediation="Remove sensitive fields from API responses. Apply field-level filtering before serializing responses.",
                    cwe="CWE-312",
                    cvss_score=7.5,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                ))
    except Exception:
        pass
    return vulns
