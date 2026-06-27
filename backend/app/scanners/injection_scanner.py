import asyncio
import uuid
import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.scanners.base import Vulnerability, Severity, ScanContext

SQL_PAYLOADS = [
    ("' OR '1'='1", "SQL Injection"),
    ("' OR '1'='1'--", "SQL Injection"),
    ("1' OR '1'='1", "SQL Injection"),
    ("'; DROP TABLE users;--", "SQL Injection"),
    ("1 UNION SELECT NULL,NULL,NULL--", "SQL Injection"),
    ("' AND SLEEP(3)--", "Time-based SQL Injection"),
    ("1; WAITFOR DELAY '0:0:3'--", "Time-based SQL Injection (MSSQL)"),
]

NOSQL_PAYLOADS = [
    ('{"$gt": ""}', "NoSQL Injection"),
    ('{"$ne": null}', "NoSQL Injection"),
    ('{"$where": "1==1"}', "NoSQL Injection"),
    ("[\"$gt\"]", "NoSQL Injection"),
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "SSTI - Jinja2/Twig"),
    ("${7*7}", "49", "SSTI - Freemarker"),
    ("<%= 7*7 %>", "49", "SSTI - ERB"),
    ("#{7*7}", "49", "SSTI - Ruby"),
    ("*{7*7}", "49", "SSTI - Spring"),
]

CMD_PAYLOADS = [
    ("; id", r"uid=\d+", "Command Injection (Unix)"),
    ("| id", r"uid=\d+", "Command Injection (Unix)"),
    ("` id`", r"uid=\d+", "Command Injection (backtick)"),
    ("; whoami", r"(root|admin|www-data|nobody)", "Command Injection"),
    ("& dir", r"(Directory of|Volume)", "Command Injection (Windows)"),
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    parsed = urlparse(ctx.target_url)
    params = parse_qs(parsed.query)

    async with httpx.AsyncClient(timeout=ctx.timeout + 5, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_sql_injection(client, ctx, parsed, params),
            _test_nosql_injection(client, ctx),
            _test_ssti(client, ctx, parsed, params),
            _test_command_injection(client, ctx, parsed, params),
            _test_xss(client, ctx, parsed, params),
            _test_xxe(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


def _inject_param(parsed, params: dict, param_key: str, payload: str) -> str:
    new_params = dict(params)
    new_params[param_key] = [payload]
    new_query = urlencode(new_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _test_sql_injection(client: httpx.AsyncClient, ctx: ScanContext, parsed, params: dict) -> list[Vulnerability]:
    vulns = []
    error_patterns = [
        r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"PG::SyntaxError",
        r"SQLite3::Exception", r"Unclosed quotation", r"syntax error.*SQL",
        r"Microsoft OLE DB Provider", r"JDBC.*error", r"postgresql.*error",
        r"Warning.*mysql_", r"valid MySQL result",
    ]

    test_params = list(params.keys()) if params else ["id", "search", "query", "q", "user", "name"]

    for param in test_params[:3]:
        for payload, label in SQL_PAYLOADS[:4]:
            try:
                if params:
                    url = _inject_param(parsed, params, param, payload)
                else:
                    url = f"{ctx.target_url}?{param}={payload}"

                resp = await client.get(url, headers=ctx.headers)
                body = resp.text.lower()

                for pattern in error_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title=f"{label} Vulnerability Detected",
                            severity=Severity.CRITICAL,
                            category="Injection",
                            description=f"The parameter '{param}' is vulnerable to SQL injection. The database error message was leaked in the response, confirming unsanitized input reaches the SQL query.",
                            evidence=f"Payload: {payload}\nResponse contained DB error pattern: '{pattern}'\nURL: {url}",
                            remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Apply input validation and principle of least privilege for DB accounts.",
                            cwe="CWE-89",
                            cvss_score=9.8,
                            endpoint=ctx.target_url,
                            method="GET",
                            request_details={"url": url, "payload": payload, "param": param},
                            response_details={"status": resp.status_code, "error_pattern": pattern},
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://portswigger.net/web-security/sql-injection",
                            ],
                        ))
                        return vulns

                if resp.status_code == 500:
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title=f"Potential {label} (Server Error Triggered)",
                        severity=Severity.HIGH,
                        category="Injection",
                        description=f"Injecting SQL payload into '{param}' triggered a 500 Internal Server Error, which may indicate unsanitized input reaching database queries.",
                        evidence=f"Payload: {payload} → HTTP 500\nURL: {url}",
                        remediation="Use parameterized queries. Implement proper error handling that does not expose server errors to clients.",
                        cwe="CWE-89",
                        cvss_score=7.5,
                        endpoint=ctx.target_url,
                        method="GET",
                        false_positive_likelihood="medium",
                        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    ))
            except Exception:
                continue
    return vulns


async def _test_nosql_injection(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        for payload, label in NOSQL_PAYLOADS[:3]:
            for content_type in ["application/json"]:
                try:
                    resp = await client.post(
                        ctx.target_url,
                        headers={**ctx.headers, "Content-Type": content_type},
                        content=f'{{"query": {payload}}}',
                    )
                    if resp.status_code in (200, 201):
                        body = resp.text
                        if len(body) > 50 and any(c in body for c in ["{", "["]):
                            vulns.append(Vulnerability(
                                id=str(uuid.uuid4()),
                                title="Potential NoSQL Injection",
                                severity=Severity.HIGH,
                                category="Injection",
                                description=f"Injecting a NoSQL operator payload returned a non-empty successful response, suggesting the query operator was executed by the database.",
                                evidence=f"Payload: {payload}\nResponse: HTTP {resp.status_code}, body length {len(body)}",
                                remediation="Validate and sanitize all query parameters. Use ODM libraries with built-in injection protection. Reject unexpected object types in query inputs.",
                                cwe="CWE-943",
                                cvss_score=8.1,
                                endpoint=ctx.target_url,
                                method="POST",
                                false_positive_likelihood="medium",
                                references=["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                            ))
                            return vulns
                except Exception:
                    continue
    except Exception:
        pass
    return vulns


async def _test_ssti(client: httpx.AsyncClient, ctx: ScanContext, parsed, params: dict) -> list[Vulnerability]:
    vulns = []
    test_params = list(params.keys()) if params else ["name", "template", "msg", "message", "subject"]
    for param in test_params[:2]:
        for payload, expected, label in SSTI_PAYLOADS:
            try:
                if params:
                    url = _inject_param(parsed, params, param, payload)
                else:
                    url = f"{ctx.target_url}?{param}={payload}"
                resp = await client.get(url, headers=ctx.headers)
                if expected in resp.text:
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title=f"Server-Side Template Injection ({label})",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        description=f"Template expression '{payload}' was evaluated server-side and returned '{expected}'. This allows remote code execution.",
                        evidence=f"Payload: {payload}\nExpected output '{expected}' found in response.\nURL: {url}",
                        remediation="Never pass user input directly to template engines. Use sandboxed environments or render templates with a separate untrusted template engine.",
                        cwe="CWE-94",
                        cvss_score=9.8,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                    ))
                    return vulns
            except Exception:
                continue
    return vulns


async def _test_command_injection(client: httpx.AsyncClient, ctx: ScanContext, parsed, params: dict) -> list[Vulnerability]:
    vulns = []
    test_params = list(params.keys()) if params else ["cmd", "exec", "command", "run", "ping", "host", "ip"]
    for param in test_params[:3]:
        for payload, pattern, label in CMD_PAYLOADS[:3]:
            try:
                if params:
                    url = _inject_param(parsed, params, param, payload)
                else:
                    url = f"{ctx.target_url}?{param}={payload}"
                resp = await client.get(url, headers=ctx.headers)
                if re.search(pattern, resp.text, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title=f"{label} Detected",
                        severity=Severity.CRITICAL,
                        category="Injection",
                        description=f"OS command output was detected in the response after injecting '{payload}' into parameter '{param}'. This allows full server compromise.",
                        evidence=f"Payload: {payload}\nOS command output pattern '{pattern}' detected in response.",
                        remediation="Never pass user input to OS commands. Use language-native libraries instead. If unavoidable, use strict allow-lists and never string concatenation.",
                        cwe="CWE-78",
                        cvss_score=10.0,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    ))
                    return vulns
            except Exception:
                continue
    return vulns


async def _test_xss(client: httpx.AsyncClient, ctx: ScanContext, parsed, params: dict) -> list[Vulnerability]:
    vulns = []
    test_params = list(params.keys()) if params else ["q", "search", "name", "message", "comment"]
    for param in test_params[:2]:
        for payload in XSS_PAYLOADS[:3]:
            try:
                if params:
                    url = _inject_param(parsed, params, param, payload)
                else:
                    url = f"{ctx.target_url}?{param}={payload}"
                resp = await client.get(url, headers=ctx.headers)
                ct = resp.headers.get("content-type", "")
                if "html" in ct and payload in resp.text:
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title="Reflected Cross-Site Scripting (XSS)",
                        severity=Severity.HIGH,
                        category="Injection",
                        description=f"The XSS payload '{payload[:40]}' was reflected unescaped in the HTML response. This allows attackers to execute scripts in victims' browsers.",
                        evidence=f"Payload injected into '{param}' was found verbatim in HTML response.",
                        remediation="Apply context-aware output encoding. Use a Content Security Policy. Validate and sanitize all user inputs.",
                        cwe="CWE-79",
                        cvss_score=6.1,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://portswigger.net/web-security/cross-site-scripting"],
                    ))
                    return vulns
            except Exception:
                continue
    return vulns


async def _test_xxe(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
    try:
        resp = await client.post(
            ctx.target_url,
            headers={**ctx.headers, "Content-Type": "application/xml"},
            content=xxe_payload,
        )
        if resp.status_code not in (400, 415, 405) and any(
            p in resp.text for p in ["root:", "nobody:", "daemon:", "bin:"]
        ):
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="XML External Entity (XXE) Injection",
                severity=Severity.CRITICAL,
                category="Injection",
                description="The API processes XML with external entity resolution enabled. The XXE payload retrieved /etc/passwd content, confirming file system read access.",
                evidence=f"XXE payload returned file contents in response body.",
                remediation="Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Apply XML schema validation.",
                cwe="CWE-611",
                cvss_score=9.1,
                endpoint=ctx.target_url,
                method="POST",
                references=["https://portswigger.net/web-security/xxe"],
            ))
    except Exception:
        pass
    return vulns
