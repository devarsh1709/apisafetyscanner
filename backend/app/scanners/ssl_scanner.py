import asyncio
import uuid
import ssl
import socket
import datetime
import httpx
from urllib.parse import urlparse
from app.scanners.base import Vulnerability, Severity, ScanContext


async def run(ctx: ScanContext) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    parsed = urlparse(ctx.target_url)

    if parsed.scheme != "https":
        vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            title="API Not Using HTTPS",
            severity=Severity.CRITICAL,
            category="SSL/TLS",
            description="The target URL uses HTTP instead of HTTPS. All data transmitted is unencrypted and visible to network observers, including credentials, tokens, and sensitive data.",
            evidence=f"URL scheme: {parsed.scheme}://",
            remediation="Enable TLS on the server and redirect all HTTP traffic to HTTPS. Obtain a certificate from Let's Encrypt or a commercial CA.",
            cwe="CWE-319",
            cvss_score=9.1,
            endpoint=ctx.target_url,
            method="GET",
            references=["https://owasp.org/www-community/vulnerabilities/Insecure_Transport"],
        ))
        return vulns

    loop = asyncio.get_event_loop()
    results = await asyncio.gather(
        loop.run_in_executor(None, _check_certificate, parsed.hostname, parsed.port or 443),
        _test_http_redirect(ctx),
        _test_weak_cipher_acceptance(parsed.hostname, parsed.port or 443, loop),
        return_exceptions=True,
    )
    for r in results:
        if isinstance(r, list):
            vulns.extend(r)

    return vulns


def _check_certificate(hostname: str, port: int) -> list[Vulnerability]:
    vulns = []
    try:
        ctx_ssl = ssl.create_default_context()
        conn = ctx_ssl.wrap_socket(
            socket.create_connection((hostname, port), timeout=10),
            server_hostname=hostname,
        )
        cert = conn.getpeercert()
        conn.close()

        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days

        if days_left < 0:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="SSL Certificate Has Expired",
                severity=Severity.CRITICAL,
                category="SSL/TLS",
                description=f"The SSL certificate expired {abs(days_left)} days ago. Browsers will show security warnings and refuse connections.",
                evidence=f"Certificate expiry: {cert['notAfter']} ({abs(days_left)} days ago)",
                remediation="Renew the certificate immediately. Use Let's Encrypt with auto-renewal.",
                cwe="CWE-298",
                cvss_score=9.0,
                endpoint=f"https://{hostname}",
                method="",
                references=["https://letsencrypt.org/docs/"],
            ))
        elif days_left < 14:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=f"SSL Certificate Expires in {days_left} Days",
                severity=Severity.HIGH,
                category="SSL/TLS",
                description=f"The SSL certificate will expire in {days_left} days. Without renewal, services will become inaccessible and users will see security warnings.",
                evidence=f"Certificate expiry: {cert['notAfter']}",
                remediation="Renew the certificate now. Set up automated renewal with certbot.",
                cwe="CWE-298",
                cvss_score=7.5,
                endpoint=f"https://{hostname}",
                method="",
                references=["https://letsencrypt.org/docs/"],
            ))
        elif days_left < 30:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title=f"SSL Certificate Expiring Soon ({days_left} Days)",
                severity=Severity.MEDIUM,
                category="SSL/TLS",
                description=f"The SSL certificate expires in {days_left} days. Plan renewal to avoid service disruption.",
                evidence=f"Certificate expiry: {cert['notAfter']}",
                remediation="Schedule certificate renewal. Automate with Let's Encrypt certbot.",
                cwe="CWE-298",
                cvss_score=4.0,
                endpoint=f"https://{hostname}",
                method="",
                references=["https://letsencrypt.org/docs/"],
            ))

        san = cert.get("subjectAltName", ())
        alt_names = [n for t, n in san if t == "DNS"]
        subject_cn = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")

        if not any(
            n == hostname or (n.startswith("*.") and hostname.endswith(n[1:]))
            for n in (alt_names or [subject_cn])
        ):
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="SSL Certificate Domain Mismatch",
                severity=Severity.HIGH,
                category="SSL/TLS",
                description=f"The certificate is not valid for '{hostname}'. Browsers will display a security warning.",
                evidence=f"Certificate CN: {subject_cn}, SANs: {alt_names}, Requested: {hostname}",
                remediation="Obtain a certificate that includes the correct domain in its Subject Alternative Names.",
                cwe="CWE-297",
                cvss_score=7.4,
                endpoint=f"https://{hostname}",
                method="",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Certificate_Transparency"],
            ))

    except ssl.SSLCertVerificationError as e:
        vulns.append(Vulnerability(
            id=str(uuid.uuid4()),
            title="Invalid SSL Certificate",
            severity=Severity.CRITICAL,
            category="SSL/TLS",
            description=f"The SSL certificate failed verification: {str(e)[:200]}. This may indicate a self-signed certificate or misconfigured chain.",
            evidence=str(e)[:300],
            remediation="Install a valid certificate from a trusted CA. Ensure the full certificate chain is configured correctly.",
            cwe="CWE-295",
            cvss_score=8.1,
            endpoint=f"https://{hostname}",
            method="",
            references=["https://letsencrypt.org/docs/"],
        ))
    except Exception:
        pass
    return vulns


async def _test_http_redirect(ctx: ScanContext) -> list[Vulnerability]:
    vulns = []
    parsed = urlparse(ctx.target_url)
    http_url = f"http://{parsed.netloc}{parsed.path}"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            resp = await client.get(http_url, headers=ctx.headers)
            if resp.status_code not in (301, 302, 307, 308) or not resp.headers.get("location", "").startswith("https"):
                vulns.append(Vulnerability(
                    id=str(uuid.uuid4()),
                    title="HTTP Not Redirected to HTTPS",
                    severity=Severity.HIGH,
                    category="SSL/TLS",
                    description="The HTTP version of the endpoint does not redirect to HTTPS. Users who visit via HTTP will communicate unencrypted.",
                    evidence=f"GET {http_url} → HTTP {resp.status_code} (expected 3xx redirect to https://)",
                    remediation="Configure a permanent 301 redirect from all HTTP URLs to HTTPS equivalents.",
                    cwe="CWE-319",
                    cvss_score=7.4,
                    endpoint=http_url,
                    method="GET",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                ))
    except Exception:
        pass
    return vulns


async def _test_weak_cipher_acceptance(hostname: str, port: int, loop) -> list[Vulnerability]:
    vulns = []
    try:
        weak_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_ctx.check_hostname = False
        weak_ctx.verify_mode = ssl.CERT_NONE
        weak_ctx.set_ciphers("DES-CBC3-SHA:RC4-SHA:RC4-MD5:NULL-SHA")
        conn = weak_ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=5),
            server_hostname=hostname,
        )
        cipher = conn.cipher()
        conn.close()
        if cipher:
            vulns.append(Vulnerability(
                id=str(uuid.uuid4()),
                title="Weak SSL Cipher Suite Accepted",
                severity=Severity.HIGH,
                category="SSL/TLS",
                description=f"The server accepted a connection using the weak cipher '{cipher[0]}'. Weak ciphers are vulnerable to decryption attacks.",
                evidence=f"Server accepted cipher: {cipher[0]} ({cipher[1]})",
                remediation="Configure the server to only allow strong cipher suites (AES-128-GCM, AES-256-GCM, CHACHA20). Disable RC4, DES, 3DES, and NULL ciphers.",
                cwe="CWE-326",
                cvss_score=7.4,
                endpoint=f"https://{hostname}",
                method="",
                references=["https://ciphersuite.info/", "https://testssl.sh/"],
            ))
    except Exception:
        pass
    return vulns
