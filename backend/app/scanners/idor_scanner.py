import asyncio
import uuid
import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []

    async with httpx.AsyncClient(timeout=ctx.timeout, follow_redirects=True, verify=False) as client:
        tasks = [
            _test_numeric_id_manipulation(client, ctx),
            _test_path_traversal(client, ctx),
            _test_mass_assignment(client, ctx),
            _test_object_level_auth(client, ctx),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                vulns.extend(r)

    return vulns


async def _test_numeric_id_manipulation(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    parsed = urlparse(ctx.target_url)
    path = parsed.path

    id_in_path = re.search(r"/(\d+)(?:/|$)", path)
    params = parse_qs(parsed.query)
    id_params = [k for k in params if k.lower() in ("id", "user_id", "userId", "account_id", "record_id", "item_id")]

    try:
        original_resp = await client.get(ctx.target_url, headers=ctx.headers)
        original_size = len(original_resp.content)
        original_status = original_resp.status_code

        if original_status not in (200, 201):
            return vulns

        test_ids = []
        if id_in_path:
            current_id = int(id_in_path.group(1))
            test_ids_path = [str(current_id - 1), str(current_id + 1), str(current_id + 100), "1", "0"]
            for test_id in test_ids_path:
                new_path = path.replace(f"/{id_in_path.group(1)}", f"/{test_id}", 1)
                test_url = urlunparse(parsed._replace(path=new_path))
                test_ids.append(("path", test_url, test_id))

        for param in id_params:
            current_val = params[param][0]
            try:
                current_int = int(current_val)
                for delta in [-1, 1, 100]:
                    new_params = dict(params)
                    new_params[param] = [str(current_int + delta)]
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                    test_ids.append(("param", test_url, str(current_int + delta)))
            except ValueError:
                pass

        for id_type, test_url, test_id in test_ids[:8]:
            try:
                resp = await client.get(test_url, headers=ctx.headers)
                if resp.status_code in (200, 201) and len(resp.content) > 50:
                    if abs(len(resp.content) - original_size) < original_size * 0.5:
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title="Potential Insecure Direct Object Reference (IDOR)",
                            severity=Severity.HIGH,
                            category="Broken Access Control",
                            description=f"Manipulating the {id_type} identifier to '{test_id}' returned a successful response of similar size to the original. This suggests object-level authorization is not enforced.",
                            evidence=f"Original: GET {ctx.target_url} → {original_status} ({original_size} bytes)\nManipulated: GET {test_url} → {resp.status_code} ({len(resp.content)} bytes)",
                            remediation="Implement object-level authorization on every endpoint. Verify the authenticated user owns the requested resource before returning data.",
                            cwe="CWE-639",
                            cvss_score=8.1,
                            endpoint=test_url,
                            method="GET",
                            false_positive_likelihood="medium",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                "https://portswigger.net/web-security/access-control/idor",
                            ],
                        ))
                        return vulns
            except Exception:
                continue
    except Exception:
        pass
    return vulns


async def _test_path_traversal(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    payloads = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "..%252Fetc%252Fpasswd",
        "....//etc/passwd",
    ]
    parsed = urlparse(ctx.target_url)
    params = parse_qs(parsed.query)
    file_params = [k for k in params if k.lower() in ("file", "path", "page", "include", "dir", "folder", "doc", "document")]

    try:
        for param in (file_params or ["file", "path"]):
            for payload in payloads[:4]:
                try:
                    if params and param in params:
                        new_params = dict(params)
                        new_params[param] = [payload]
                        test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
                    else:
                        test_url = f"{ctx.target_url}?{param}={payload}"

                    resp = await client.get(test_url, headers=ctx.headers)
                    if resp.status_code == 200 and re.search(r"root:.*:/bin/(bash|sh)", resp.text):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title="Path Traversal Vulnerability Detected",
                            severity=Severity.CRITICAL,
                            category="Broken Access Control",
                            description=f"The parameter '{param}' is vulnerable to path traversal. The server returned the contents of /etc/passwd.",
                            evidence=f"Payload: {payload} in param '{param}'\nResponse contained /etc/passwd content.",
                            remediation="Validate and canonicalize file paths. Reject paths containing '../'. Use an allowlist of permitted file locations.",
                            cwe="CWE-22",
                            cvss_score=9.1,
                            endpoint=ctx.target_url,
                            method="GET",
                            references=["https://portswigger.net/web-security/file-path-traversal"],
                        ))
                        return vulns
                except Exception:
                    continue
    except Exception:
        pass
    return vulns


async def _test_mass_assignment(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    privilege_payloads = [
        {"role": "admin", "is_admin": True, "admin": True},
        {"role": "superuser", "permissions": ["admin", "write", "delete"]},
        {"is_verified": True, "email_verified": True, "account_status": "active"},
        {"credits": 99999, "balance": 99999},
    ]
    try:
        for payload in privilege_payloads:
            resp = await client.post(
                ctx.target_url,
                headers={**ctx.headers, "Content-Type": "application/json"},
                json=payload,
            )
            if resp.status_code in (200, 201):
                body = resp.text
                for key in payload:
                    val = payload[key]
                    if str(val).lower() in body.lower() or (isinstance(val, bool) and str(val).lower() in body.lower()):
                        vulns.append(Vulnerability(
                            id=str(uuid.uuid4()),
                            title="Potential Mass Assignment Vulnerability",
                            severity=Severity.HIGH,
                            category="Broken Access Control",
                            description=f"The API accepted and reflected privileged fields ('{key}') in the response. Mass assignment allows attackers to modify fields they should not have access to.",
                            evidence=f"Sent: {payload}\nPrivileged field '{key}' reflected in {resp.status_code} response.",
                            remediation="Use allowlists (not blocklists) when binding request data to model objects. Explicitly specify which fields are user-editable.",
                            cwe="CWE-915",
                            cvss_score=8.8,
                            endpoint=ctx.target_url,
                            method="POST",
                            false_positive_likelihood="medium",
                            references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
                        ))
                        return vulns
    except Exception:
        pass
    return vulns


async def _test_object_level_auth(client: httpx.AsyncClient, ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    try:
        auth_headers_to_test = [
            {},
            {"Authorization": "Bearer invalid_token_xyz"},
            {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI5OTk5OSIsInJvbGUiOiJ1c2VyIn0."},
        ]
        original_resp = await client.get(ctx.target_url, headers=ctx.headers)
        if original_resp.status_code not in (200, 201):
            return vulns

        for bad_headers in auth_headers_to_test:
            try:
                merged = {**ctx.headers, **bad_headers}
                resp = await client.get(ctx.target_url, headers=merged)
                if resp.status_code in (200, 201) and len(resp.content) > 20:
                    token_label = bad_headers.get("Authorization", "no auth")[:40]
                    vulns.append(Vulnerability(
                        id=str(uuid.uuid4()),
                        title="Broken Object-Level Authorization",
                        severity=Severity.CRITICAL,
                        category="Broken Access Control",
                        description=f"The endpoint returned data with invalid or no authentication credentials ({token_label}). Object-level authorization is not enforced.",
                        evidence=f"Credentials: '{token_label}' → HTTP {resp.status_code} ({len(resp.content)} bytes)",
                        remediation="Every API endpoint must validate that the authenticated user is authorized to access the specific object. Return 401/403 for invalid credentials.",
                        cwe="CWE-284",
                        cvss_score=9.1,
                        endpoint=ctx.target_url,
                        method="GET",
                        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                    ))
                    return vulns
            except Exception:
                continue
    except Exception:
        pass
    return vulns
