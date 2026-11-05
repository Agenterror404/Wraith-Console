"""API testing: surface recon + GraphQL introspection. Covers Shannon ✅ APIT-01/02/99.
(Object-level authz / BOLA is driven by authz with two sessions + object IDs.)
"""
import json
from urllib.parse import urlparse

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import OutOfScope, check

_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/v1", "/v2", "/rest", "/graphql", "/graphiql",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs", "/api/docs",
    "/.well-known/openid-configuration", "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/health", "/status",
]
_INTROSPECT = {"query": "query{__schema{queryType{name} types{name kind}}}"}


def _base(target: str) -> str:
    u = urlparse(target if "://" in target else f"http://{target}")
    return f"{u.scheme or 'http'}://{u.netloc}"


def api(target: str, cookies: dict | None = None) -> dict:
    """Probe common API/doc endpoints and test GraphQL introspection."""
    check(target)
    base = _base(target)
    found = []
    with safehttp.client(target, timeout=HTTP_TIMEOUT, follow_redirects=False, headers=stealth.headers()) as c:
        for p in _API_PATHS:
            url = base + p
            try:
                check(url)
            except OutOfScope:
                continue
            try:
                stealth.jitter()
                r = c.get(url, cookies=cookies or {})
                if r.status_code < 400 or r.status_code in (401, 403):
                    found.append({"path": p, "status": r.status_code,
                                  "ctype": r.headers.get("content-type", "")[:40]})
            except httpx.HTTPError:
                continue

    gql = None
    for gpath in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
        gurl = base + gpath
        try:
            check(gurl)
        except OutOfScope:
            continue
        try:
            stealth.jitter()
            r = safehttp.post(gurl, json=_INTROSPECT, timeout=HTTP_TIMEOUT,
                              headers=stealth.headers(), cookies=cookies or {})
            if r.status_code < 400 and "__schema" in r.text:
                try:
                    ntypes = len(json.loads(r.text)["data"]["__schema"]["types"])
                except Exception:
                    ntypes = None
                gql = {"endpoint": gpath, "introspection_enabled": True, "types": ntypes,
                       "note": "introspection should be disabled in production"}
                break
        except httpx.HTTPError:
            continue

    return {"target": target, "base": base, "api_surface": found, "graphql": gql,
            "verdict": "review" if (found or gql) else "none-found"}
