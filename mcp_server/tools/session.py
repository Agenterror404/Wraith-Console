"""CSRF + session-management testing. Covers Shannon ✅ SESS-02/03/05/07/10.
csrf inspects forms for anti-CSRF tokens; session audits cookie attributes
and decodes any JWTs (header/payload, unverified) to flag alg:none / missing exp / HS256.
"""
import base64
import json
import re

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

_FORM_RE = re.compile(r"(<form\b[^>]*>)(.*?)</form>", re.I | re.S)
_METHOD_RE = re.compile(r'method\s*=\s*["\']?\s*(post|put|delete|patch)', re.I)
_TOKEN_RE = re.compile(r'name\s*=\s*["\']?[^"\'>\s]*(?:csrf|token|nonce|authenticity|xsrf)', re.I)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*$")


def _b64url(seg: str) -> dict | None:
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        return json.loads(raw)
    except Exception:
        return None


def csrf(target: str, cookies: dict | None = None) -> dict:
    """Find state-changing forms with no anti-CSRF token, and report session-cookie SameSite."""
    check(target)
    stealth.jitter()
    r = safehttp.get(target, timeout=HTTP_TIMEOUT, follow_redirects=False,
                  headers=stealth.headers(), cookies=cookies or {})
    findings = []
    for i, (tag, body) in enumerate(_FORM_RE.findall(r.text)):
        state_changing = bool(_METHOD_RE.search(tag))
        has_token = bool(_TOKEN_RE.search(body))
        if state_changing and not has_token:
            findings.append({"form_index": i, "issue": "state-changing form has no anti-CSRF token field"})
    samesite = []
    for raw in r.headers.get_list("set-cookie"):
        if "samesite" not in raw.lower():
            samesite.append({"cookie": raw.split("=", 1)[0].strip(), "issue": "no SameSite attribute"})
    return {"target": target, "forms_without_token": findings, "cookies_without_samesite": samesite,
            "verdict": "VULNERABLE" if findings else ("review" if samesite else "ok")}


def session(target: str, cookies: dict | None = None) -> dict:
    """Audit Set-Cookie flags; decode JWTs found in cookies and flag weak settings."""
    check(target)
    stealth.jitter()
    r = safehttp.get(target, timeout=HTTP_TIMEOUT, follow_redirects=False,
                  headers=stealth.headers(), cookies=cookies or {})
    cookie_issues, jwts = [], []
    for raw in r.headers.get_list("set-cookie"):
        low = raw.lower()
        name, _, rest = raw.partition("=")
        name = name.strip()
        missing = [f for f, tok in (("HttpOnly", "httponly"), ("Secure", "secure"),
                                    ("SameSite", "samesite")) if tok not in low]
        if missing:
            cookie_issues.append({"cookie": name, "missing_flags": missing})
        value = rest.split(";", 1)[0].strip()
        if _JWT_RE.match(value):
            parts = value.split(".")
            header, payload = _b64url(parts[0]), _b64url(parts[1])
            flags = []
            if header and str(header.get("alg", "")).lower() == "none":
                flags.append("alg:none (signature not verified)")
            if header and str(header.get("alg", "")).upper().startswith("HS"):
                flags.append(f"{header.get('alg')} (HMAC — brute-forceable if weak secret)")
            if payload and "exp" not in payload:
                flags.append("no exp claim (token never expires)")
            jwts.append({"cookie": name, "alg": (header or {}).get("alg"),
                         "claims": list((payload or {}).keys()), "flags": flags})
    return {"target": target, "cookie_issues": cookie_issues, "jwts": jwts,
            "verdict": "review" if (cookie_issues or any(j["flags"] for j in jwts)) else "ok"}
