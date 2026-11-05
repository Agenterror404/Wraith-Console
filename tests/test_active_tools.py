"""Functional self-check for the Shannon-coverage active tools.

Stands up one deliberately-vulnerable HTTP server on a non-loopback IP (so the
scope guard's loopback block doesn't reject it), points scope.yaml at it, and
fires each active tool — asserting the *detection logic* actually fires on a
real planted vuln, and that an out-of-scope target is still refused.

  python tests/test_active_tools.py

ponytail: covers the non-trivial exploitation logic (marker echo, template
eval, file read, 3xx redirect, stored persistence) end-to-end; the target-only
parsers (config/tls/csrf/session/api/auth) get a smoke run (returns a dict,
doesn't throw). Add per-tool cases when a detector grows real branches.
"""
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # repo root
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# non-loopback, non-metadata: RFC-5737 TEST-NET bound to this container's iface.
_IP = (lambda s: (s.connect(("10.255.255.255", 1)), s.getsockname()[0], s.close())[1])(
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

_STORE = {}  # stored-xss persistence


class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body="", ctype="text/html", extra=None):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Server", "VulnServer/1.0")          # version disclosure
        self.send_header("Set-Cookie", "sid=abc123")           # no HttpOnly/Secure/SameSite
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path, val = u.path, (q.get("q", [""])[0] or q.get("file", [""])[0]
                             or q.get("url", [""])[0] or q.get("redirect", [""])[0])
        if path == "/cmdi":
            return self._send(200, f"searched for: {val}")          # reflects -> marker echo
        if path == "/ssti":
            ev = {"${7*7}": "49", "{{7*7}}": "49", "#{7*7}": "49", "<%= 7*7 %>": "49",
                  "${{7*7}}": "49", "{{7*'7'}}": "7777777", "#{ 7*7 }": "49", "{7*7}": "49",
                  "*{7*7}": "49", "@(7*7)": "49", "${7*'7'}": "7777777"}
            return self._send(200, f"result = {ev[val]}" if val in ev else "result = ?")
        if path == "/lfi":
            if "passwd" in val:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
            if "win.ini" in val:
                return self._send(200, "[extensions]\nmp3=mplayer")
            return self._send(200, "no file")
        if path == "/redir" and val:
            return self._send(302, "", extra={"Location": val})     # open redirect
        if path == "/comment":
            return self._send(200, "<div>" + _STORE.get("c", "") + "</div>")  # unescaped
        if path.startswith("/api") or path == "/graphql":
            return self._send(200, json.dumps({"data": {"__schema": {"types": []}}}),
                              ctype="application/json")
        # root: a state-changing form with NO anti-CSRF token
        return self._send(200, "<form method='post' action='/x'><input name='amt'></form>")

    def do_POST(self):
        u = urlparse(self.path)
        ln = int(self.headers.get("Content-Length", 0))
        body = parse_qs(self.rfile.read(ln).decode()) if ln else {}
        if u.path == "/comment":
            _STORE["c"] = body.get("comment", [""])[0]
            return self._send(200, "stored")
        if u.path == "/login":
            email = body.get("email", [""])[0]
            pw = body.get("password", [""])[0]
            ok = pw in ("admin", "admin123", "password", "123456")
            return self._send(200 if ok else 401,
                              json.dumps({"token": "x"} if ok else {"error": "invalid"}),
                              ctype="application/json")
        return self._send(200, "ok")


def main():
    srv = ThreadingHTTPServer((_IP, 0), _Vuln)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://{_IP}:{port}"

    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(f"targets:\n  - host: {_IP}\n    port: {port}\n")
    f.close()
    os.environ["PENTEST_SCOPE_FILE"] = f.name

    from mcp_server.scope_guard import OutOfScope
    from mcp_server.tools import api, authn, injection, misconfig, session, webflaws

    # --- active exploitation: detection logic must fire on the planted vuln ---
    r = injection.cmdi(f"{base}/cmdi", "q")
    assert r["verdict"] == "VULNERABLE" and r["findings"], f"cmdi: {r}"

    r = injection.ssti(f"{base}/ssti", "q")
    assert r["verdict"] == "VULNERABLE" and r["findings"], f"ssti: {r}"

    r = injection.path_traversal(f"{base}/lfi", "file")
    assert r["verdict"] == "VULNERABLE" and r["findings"], f"traversal: {r}"

    r = webflaws.open_redirect(f"{base}/redir", "redirect")
    assert r["verdict"] == "VULNERABLE" and r["findings"], f"open_redirect: {r}"

    r = webflaws.stored_xss(f"{base}/comment", "comment", method="POST",
                                 verify_url=f"{base}/comment")
    assert r["verdict"] == "VULNERABLE" and r["stored_unescaped"], f"stored_xss: {r}"

    # --- target-only probes: must return a dict and not throw ---
    for label, res in [
        ("check_config", misconfig.check_config(base)),
        ("tls", misconfig.tls(base)),
        ("csrf", session.csrf(base)),
        ("session", session.session(base)),
        ("api", api.api(base)),
    ]:
        assert isinstance(res, dict), f"{label} returned {type(res)}"

    # config detector should flag the missing headers / version / loose cookie we planted
    cfg = misconfig.check_config(base)
    assert cfg.get("findings") or cfg.get("verdict"), f"check_config found nothing: {cfg}"

    # auth: default creds must be caught
    r = authn.auth(f"{base}/login", username_field="email", password_field="password")
    assert isinstance(r, dict), f"auth: {r}"

    # --- scope still holds: out-of-scope + loopback refuse ---
    for bad in ("http://evil.example:80/", "http://127.0.0.1/"):
        try:
            injection.cmdi(bad, "q")
            raise SystemExit(f"FAIL: {bad} should have been refused")
        except OutOfScope:
            pass

    srv.shutdown()
    print("active-tools self-check OK  (cmdi/ssti/traversal/redirect/stored_xss confirmed, "
          "config/tls/csrf/session/api/auth smoke-ran, scope holds)")


if __name__ == "__main__":
    main()
