"""Security-misconfiguration + transport checks (black-box, read-only).

Covers Shannon's ✅ CONF (security headers, HTTP methods) and CRYP-01/03 (weak TLS,
sensitive data over an unencrypted channel). Everything here is non-destructive:
GET + OPTIONS + TLS handshakes only. Scope-gated like every tool.
"""
import socket
import ssl
from urllib.parse import urlparse

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

# header -> why it matters when absent
_SEC_HEADERS = {
    "content-security-policy": "no CSP (XSS/clickjacking mitigation missing)",
    "strict-transport-security": "no HSTS (downgrade/SSL-strip)",
    "x-frame-options": "no X-Frame-Options / frame-ancestors (clickjacking)",
    "x-content-type-options": "no nosniff (MIME sniffing)",
    "referrer-policy": "no Referrer-Policy (referrer leakage)",
}
_RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def _cookie_flags(resp: httpx.Response) -> list[dict]:
    out = []
    for raw in resp.headers.get_list("set-cookie"):
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = [f for f, tok in (("HttpOnly", "httponly"), ("Secure", "secure"),
                                    ("SameSite", "samesite")) if tok not in low]
        if missing:
            out.append({"cookie": name, "missing_flags": missing})
    return out


def _http_methods(target: str) -> dict:
    try:
        stealth.jitter()
        r = safehttp.request("OPTIONS", target, timeout=HTTP_TIMEOUT,
                          follow_redirects=False, headers=stealth.headers())
        allow = r.headers.get("allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        return {"allow": allow, "risky": sorted(set(methods) & _RISKY_METHODS)}
    except httpx.HTTPError:
        return {"allow": "", "risky": []}


def check_config(target: str) -> dict:
    """Audit response headers, CORS, cookie flags, HTTP methods, version disclosure."""
    check(target)
    stealth.jitter()
    r = safehttp.get(target, timeout=HTTP_TIMEOUT, follow_redirects=False, headers=stealth.headers())
    h = {k.lower(): v for k, v in r.headers.items()}
    is_https = target.lower().startswith("https")
    issues = []

    for hdr, note in _SEC_HEADERS.items():
        if hdr == "strict-transport-security" and not is_https:
            continue
        if hdr not in h:
            issues.append({"type": "missing-header", "header": hdr, "note": note})
    if h.get("x-content-type-options", "").lower() not in ("", "nosniff") :
        issues.append({"type": "weak-header", "header": "x-content-type-options", "value": h["x-content-type-options"]})

    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if hdr in h and any(c.isdigit() for c in h[hdr]):
            issues.append({"type": "version-disclosure", "header": hdr, "value": h[hdr]})

    aco = h.get("access-control-allow-origin", "")
    if aco == "*":
        issues.append({"type": "cors", "note": "Access-Control-Allow-Origin: * (open CORS)",
                       "with_credentials": h.get("access-control-allow-credentials", "").lower() == "true"})

    if not is_https:
        issues.append({"type": "transport", "note": "served over HTTP — credentials/sensitive data in cleartext (CRYP-03)"})

    return {
        "target": target, "status": r.status_code,
        "issues": issues,
        "cookie_issues": _cookie_flags(r),
        "http_methods": _http_methods(target),
        "verdict": "misconfig" if (issues or _cookie_flags(r)) else "clean",
    }


def _probe_protocol(host: str, port: int, maximum) -> str | None:
    """Return the negotiated protocol if a handshake capped at `maximum` succeeds, else None."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = maximum
    except (ValueError, OSError):
        return None
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version()
    except (ssl.SSLError, OSError):
        return None


def tls(target: str) -> dict:
    """Inspect the target's TLS: negotiated version + cipher, and whether the server
    still accepts the obsolete TLS 1.0 / 1.1. Handshakes only — nothing is sent."""
    check(target)
    u = urlparse(target if "://" in target else f"https://{target}")
    scheme = (u.scheme or "https").lower()
    host = u.hostname
    port = u.port or (443 if scheme == "https" else 80)
    if scheme != "https":
        return {"target": target, "tls": False,
                "note": "target is not HTTPS — no TLS; credentials/sensitive data would be cleartext (CRYP-01/03)",
                "verdict": "weak"}

    best = _probe_protocol(host, port, ssl.TLSVersion.MAXIMUM_SUPPORTED)
    if best is None:
        return {"target": target, "tls": False, "error": "TLS handshake failed"}
    cipher = None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cipher = ss.cipher()
    except (ssl.SSLError, OSError):
        pass

    weak_versions = []
    for ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        got = _probe_protocol(host, port, ver)
        if got in ("TLSv1", "TLSv1.1"):
            weak_versions.append(got)

    issues = []
    if best in ("TLSv1", "TLSv1.1", "SSLv3"):
        issues.append(f"negotiates obsolete {best}")
    if weak_versions:
        issues.append(f"still accepts {sorted(set(weak_versions))}")
    return {
        "target": target, "tls": True, "negotiated": best,
        "cipher": cipher[0] if cipher else None,
        "accepts_legacy": sorted(set(weak_versions)),
        "issues": issues,
        "verdict": "weak" if issues else "ok",
    }
