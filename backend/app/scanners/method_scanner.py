import asyncio
import uuid
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_dangerous_methods(client, ctx),
            _test_method_override(client, ctx),
            _test_http_trace(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_dangerous_methods(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    methods_to_test = {
        "DELETE": (Severity.HIGH, 8.1, "CWE-749", "DELETE method could allow unauthorized deletion of resources."),
        "PUT": (Severity.HIGH, 7.5, "CWE-749", "PUT method could allow unauthorized modification or creation of resources."),
        "PATCH": (Severity.MEDIUM, 6.5, "CWE-749", "PATCH method could allow partial modification of resources without proper authorization."),
        "CONNECT": (Severity.HIGH, 7.5, "CWE-918", "CONNECT method can be used to create TCP tunnels through the server (SSRF)."),
    }

    try:
        get_resp = await client.get(ctx.target_url, headers=ctx.headers)
        allowed_methods_header = get_resp.headers.get("allow", "").upper()

        for method, (severity, cvss, cwe, desc) in methods_to_test.items():
            try:
                resp = await client.request(method, ctx.target_url, headers=ctx.headers)
                if resp.status_code not in (405, 501, 400, 403):
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title=f"HTTP Method {method} Enabled on Endpoint",
                        severity=severity,
                        category="HTTP Methods",
                        description=f"{desc} The server returned HTTP {resp.status_code} instead of 405 Method Not Allowed.",
                        evidence=f"{method} {ctx.target_url} → HTTP {resp.status_code}",
                        remediation=f"Explicitly disable the {method} method on this endpoint unless it is intentionally required. Return 405 Method Not Allowed with an Allow header listing permitted methods.",
                        cwe=cwe,
                        cvss_score=cvss,
                        endpoint=ctx.target_url,
                        method=method,
                        response_details={"status_code": resp.status_code},
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return vulns


async def _test_method_override(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    override_headers = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]
    try:
        delete_direct = await client.request("DELETE", ctx.target_url, headers=ctx.headers)

        if delete_direct.status_code in (405, 403, 401):
            for override_header in override_headers:
                try:
                    resp = await client.get(
                        ctx.target_url,
                        headers={**ctx.headers, override_header: "DELETE"},
                    )
                    if resp.status_code not in (405, 403, 400, 401, 404):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title=f"HTTP Method Override via {override_header}",
                            severity=Severity.HIGH,
                            category="HTTP Methods",
                            description=f"The {override_header} header bypasses HTTP method restrictions. DELETE was blocked directly (HTTP {delete_direct.status_code}) but succeeded via method override (HTTP {resp.status_code}).",
                            evidence=f"DELETE direct: {delete_direct.status_code}\nGET + {override_header}: DELETE → {resp.status_code}",
                            remediation="Disable HTTP method override support in production. Validate and restrict HTTP methods at the routing layer, not just by the method verb.",
                            cwe="CWE-650",
                            cvss_score=7.5,
                            endpoint=ctx.target_url,
                            method=f"GET (+{override_header}:DELETE)",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        ))
                        break
                except Exception:
                    continue
    except Exception:
        pass
    return vulns


async def _test_http_trace(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        resp = await client.request(
            "TRACE",
            ctx.target_url,
            headers={**ctx.headers, "X-Trace-Test-Header": "security-scanner-probe"},
        )
        if resp.status_code == 200 and "X-Trace-Test-Header" in resp.text:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="HTTP TRACE Method Enabled (Cross-Site Tracing Risk)",
                severity=Severity.MEDIUM,
                category="HTTP Methods",
                description="The HTTP TRACE method is enabled and echoes the request back. Combined with XSS, this enables Cross-Site Tracing (XST) attacks that can read HttpOnly cookies.",
                evidence=f"TRACE {ctx.target_url} → HTTP {resp.status_code}, request headers reflected in response.",
                remediation="Disable the HTTP TRACE method in your web server configuration.",
                cwe="CWE-693",
                cvss_score=5.8,
                endpoint=ctx.target_url,
                method="TRACE",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            ))
        elif resp.status_code == 200:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="HTTP TRACE Method Enabled",
                severity=Severity.LOW,
                category="HTTP Methods",
                description="The HTTP TRACE method returns HTTP 200. While not directly exploitable alone, it is a security best practice to disable it.",
                evidence=f"TRACE {ctx.target_url} → HTTP {resp.status_code}",
                remediation="Disable the HTTP TRACE method in your web server configuration (TraceEnable Off in Apache, methods off in Nginx).",
                cwe="CWE-693",
                cvss_score=3.5,
                endpoint=ctx.target_url,
                method="TRACE",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            ))
    except Exception:
        pass
    return vulns
