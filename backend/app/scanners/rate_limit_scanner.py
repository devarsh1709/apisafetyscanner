import asyncio
import time
import uuid
import httpx
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_missing_rate_limit(client, ctx),
            _test_rate_limit_bypass_headers(client, ctx),
            _test_rate_limit_bypass_paths(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_missing_rate_limit(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    burst_count = 15
    try:
        tasks = [client.get(ctx.target_url, headers=ctx.headers) for _ in range(burst_count)]
        start = time.monotonic()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start

        valid = [r for r in responses if isinstance(r, httpx.Response)]
        rate_limited = [r for r in valid if r.status_code == 429]
        success = [r for r in valid if r.status_code < 400]

        has_limit_headers = any(
            any(k.lower().startswith(("x-ratelimit", "ratelimit", "retry-after", "x-rate-limit"))
                for k in r.headers)
            for r in valid if isinstance(r, httpx.Response)
        )

        if not rate_limited and len(success) >= burst_count * 0.8:
            severity = Severity.MEDIUM if has_limit_headers else Severity.HIGH
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="No Rate Limiting Detected",
                severity=severity,
                category="Rate Limiting",
                description=f"Sent {burst_count} requests in {elapsed:.2f}s and received {len(success)} successful responses with no HTTP 429. "
                            f"Without rate limiting, the API is vulnerable to brute-force, credential stuffing, and enumeration attacks.",
                evidence=f"{burst_count} rapid requests → {len(success)} succeeded, 0 rate-limited. Rate-limit headers present: {has_limit_headers}",
                remediation="Implement rate limiting per IP and per user. Return 429 Too Many Requests with Retry-After header. Consider token bucket or sliding window algorithms.",
                cwe="CWE-770",
                cvss_score=6.5,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
            ))
        elif rate_limited and not has_limit_headers:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="Rate Limiting Without Informative Headers",
                severity=Severity.LOW,
                category="Rate Limiting",
                description="Rate limiting is enforced (HTTP 429 returned) but no standard rate limit headers are included. Clients cannot implement proper backoff.",
                evidence=f"{len(rate_limited)}/{burst_count} requests rate-limited. No X-RateLimit-* headers found.",
                remediation="Add X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, and Retry-After headers to rate limit responses.",
                cwe="CWE-799",
                cvss_score=3.1,
                endpoint=ctx.target_url,
                method="GET",
                references=["https://tools.ietf.org/html/rfc6585"],
            ))
    except Exception:
        pass
    return vulns


async def _test_rate_limit_bypass_headers(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    bypass_headers_list = [
        {"X-Forwarded-For": "192.168.1.1"},
        {"X-Real-IP": "10.0.0.1"},
        {"X-Originating-IP": "172.16.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"Client-IP": "8.8.8.8"},
    ]
    try:
        base_resp = await client.get(ctx.target_url, headers=ctx.headers)
        if base_resp.status_code != 429:
            return vulns

        for bypass in bypass_headers_list:
            tasks = [
                client.get(ctx.target_url, headers={**ctx.headers, **bypass})
                for _ in range(5)
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            successes = [r for r in responses if isinstance(r, httpx.Response) and r.status_code != 429]
            if len(successes) >= 3:
                header = list(bypass.keys())[0]
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title=f"Rate Limit Bypass via {header} Header",
                    severity=Severity.HIGH,
                    category="Rate Limiting",
                    description=f"Rate limiting can be bypassed by spoofing the '{header}' header with different IP addresses. Attackers can rotate IPs to bypass limits.",
                    evidence=f"Original IP: 429 rate-limited. With spoofed {header}: {len(successes)}/5 requests succeeded.",
                    remediation="Do not rely on client-supplied headers for rate limiting. Use the actual TCP connection IP from the socket layer.",
                    cwe="CWE-290",
                    cvss_score=7.5,
                    endpoint=ctx.target_url,
                    method="GET",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                ))
                break
    except Exception:
        pass
    return vulns


async def _test_rate_limit_bypass_paths(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    path_variants = [
        ctx.target_url + "/",
        ctx.target_url + "//",
        ctx.target_url + "?",
        ctx.target_url + "#",
        ctx.target_url.replace("https://", "https://") + "%20",
    ]
    try:
        base_resp = await client.get(ctx.target_url, headers=ctx.headers)
        if base_resp.status_code != 429:
            return vulns

        for variant in path_variants:
            try:
                resp = await client.get(variant, headers=ctx.headers)
                if resp.status_code not in (429, 404, 400):
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title="Rate Limit Bypass via URL Variation",
                        severity=Severity.MEDIUM,
                        category="Rate Limiting",
                        description="Rate limiting can be bypassed using URL variations (trailing slashes, encoded characters). The rate limiter does not normalize URLs before applying limits.",
                        evidence=f"Original: 429 → Variant '{variant[-30:]}': HTTP {resp.status_code}",
                        remediation="Normalize URL paths before applying rate limiting rules.",
                        cwe="CWE-183",
                        cvss_score=5.3,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
                    ))
                    break
            except Exception:
                continue
    except Exception:
        pass
    return vulns
