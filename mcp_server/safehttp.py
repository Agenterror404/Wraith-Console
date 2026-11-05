"""Pinned, browser-impersonating HTTP for the in-process tools (H-2 + stealth).

The in-process methodology tools run from wraith-ui, which has real outbound
egress. This module does two jobs:

  1. Anti-rebind (H-2): scope-check the host, resolve + validate the IP ONCE
     (scope_guard.resolve_pin, which rejects blocked ranges incl. IPv4-mapped IPv6),
     and pin the connection to that IP via CURLOPT_RESOLVE. SNI + Host + cert
     verification stay the real hostname, so a sub-second DNS rebind cannot redirect
     the connect to loopback / cloud-metadata / internal.

  2. TLS/JA4 + HTTP/2 stealth: traffic goes out via curl_cffi with impersonate="chrome",
     so recon_http / enum_paths and the other in-process probes present a real Chrome
     ClientHello, HTTP/2 profile and header set — not an httpx fingerprint (httpx
     advertises 36 ciphers vs Chrome's 15, JA4 t13d3614h1_...) that a WAF flags as a
     tool. A VPN hides the source IP; this hides the client fingerprint.

Drop-in for the subset of httpx the tools use: get / post / request + client (multi-
request flows). Responses are curl_cffi Response objects — status_code / headers
(httpx-style, incl. .get_list) / text / content / json — duck-compatible with what the
callers read. Transport errors are re-raised as httpx exceptions (httpx.ReadTimeout for
timeouts, else httpx.HTTPError) so every existing `except httpx.HTTPError` /
`except httpx.ReadTimeout` around a safehttp call keeps working with no change.
"""
import os
from urllib.parse import urlparse

import httpx  # kept ONLY to re-raise the httpx-typed errors the callers already catch
from curl_cffi import CurlOpt
from curl_cffi import requests as _cc
from curl_cffi.requests import exceptions as _cce

from .scope_guard import resolve_pin

# curl_cffi browser profile. "chrome" tracks the newest Chrome the installed curl_cffi
# knows about; pin a specific one (e.g. "chrome131") via env for reproducibility.
IMPERSONATE = os.environ.get("PENTEST_IMPERSONATE", "chrome")

# Header names that ARE the browser fingerprint. impersonate supplies a matching,
# self-consistent set, so a caller's copy must not override them (that would desync
# UA / client-hints from the JA4). Non-fingerprint headers (cookies, auth, referer,
# requested-with, content-type, …) still pass through.
_FP_HEADERS = {
    "user-agent", "accept", "accept-language", "accept-encoding",
    "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-ch-ua-platform", "connection",
}


def _host_port(url: str):
    p = urlparse(url if "://" in url else f"http://{url}")
    return (p.hostname or ""), (p.port or (443 if p.scheme == "https" else 80))


def _pin_opts(host: str, ip: str) -> dict:
    # pin this host on both default ports to the vetted IP (covers http + https)
    return {CurlOpt.RESOLVE: [f"{host}:443:{ip}", f"{host}:80:{ip}"]}


def _clean_headers(h):
    if not h:
        return None
    keep = {k: v for k, v in h.items() if k.lower() not in _FP_HEADERS}
    return keep or None


def _map(kw: dict) -> dict:
    """Translate the httpx-style kwargs the callers pass into curl_cffi ones."""
    out = {}
    if "timeout" in kw:
        out["timeout"] = kw["timeout"]
    if "follow_redirects" in kw:
        out["allow_redirects"] = bool(kw["follow_redirects"])
    elif "allow_redirects" in kw:
        out["allow_redirects"] = bool(kw["allow_redirects"])
    for k in ("params", "data", "json", "cookies", "verify"):
        if k in kw:
            out[k] = kw[k]
    h = _clean_headers(kw.get("headers"))
    if h:
        out["headers"] = h
    return out


def _session(url: str) -> "_cc.Session":
    host, _ = _host_port(url)
    ip = resolve_pin(host)  # validates (raises scope_guard.OutOfScope on blocked/rebind) + returns a vetted IP
    return _cc.Session(impersonate=IMPERSONATE, curl_options=_pin_opts(host, ip))


def _reraise(e: Exception):
    if isinstance(e, _cce.Timeout):
        raise httpx.ReadTimeout(str(e) or "timeout") from e
    raise httpx.HTTPError(str(e) or e.__class__.__name__) from e


class _ClientCtx:
    """`with safehttp.client(url) as c: c.get(path)` — every request pinned to the URL's
    validated host IP and impersonating Chrome. Mirrors the httpx.Client subset used."""

    def __init__(self, url: str, **kw):
        self._s = _session(url)
        self._defaults = _map(kw)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        try:
            self._s.close()
        except Exception:
            pass

    def request(self, method: str, url: str, **kw):
        m = dict(self._defaults)
        m.update(_map(kw))
        try:
            return self._s.request(method, url, **m)
        except _cce.RequestException as e:
            _reraise(e)

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw):
        return self.request("POST", url, **kw)


def client(url: str, **kw) -> _ClientCtx:
    """A pinned, Chrome-impersonating client for the URL's host — for flows that make
    several requests to the same target. The host is resolved + pinned once (anti-rebind)."""
    return _ClientCtx(url, **kw)


def request(method: str, url: str, **kw):
    s = _session(url)
    try:
        return s.request(method, url, **_map(kw))
    except _cce.RequestException as e:
        _reraise(e)
    finally:
        try:
            s.close()
        except Exception:
            pass


def get(url: str, **kw):
    return request("GET", url, **kw)


def post(url: str, **kw):
    return request("POST", url, **kw)


if __name__ == "__main__":
    # ponytail: self-check — CURLOPT_RESOLVE pins to the vetted IP while Host/SNI stay the
    # real host, the client impersonates Chrome, and resolve_pin blocks metadata/loopback.
    import http.server
    import threading

    from .scope_guard import OutOfScope

    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen["host"] = self.headers.get("Host")
            seen["ua"] = self.headers.get("User-Agent")
            b = b"ok"
            self.send_response(200)
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.socket.getsockname()[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # pin target.local:<port> → 127.0.0.1; connect goes to loopback, Host stays target.local
    with _cc.Session(impersonate=IMPERSONATE,
                     curl_options={CurlOpt.RESOLVE: [f"target.local:{port}:127.0.0.1"]}) as s:
        r = s.get(f"http://target.local:{port}/x", timeout=5, allow_redirects=False)
    assert r.status_code == 200, r.status_code
    assert (seen["host"] or "").startswith("target.local"), seen
    assert "Chrome" in (seen["ua"] or ""), seen["ua"]  # impersonation is in effect
    srv.shutdown()
    # resolve_pin must refuse a host that resolves only to a blocked range → _session won't build
    for bad in ("http://169.254.169.254/", "http://127.0.0.1:1/"):
        try:
            _session(bad)
            raise SystemExit(f"FAIL: {bad} should be blocked")
        except OutOfScope:
            pass
    print("safehttp self-check OK")
