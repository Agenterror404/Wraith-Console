"""Wraith Console — FastAPI control plane for the scope-locked pentest tools.

Security model (in-process execution; the scope guard is THE boundary):
- Single shared-password login. Signed, HttpOnly + Secure + SameSite=Strict session
  cookie (itsdangerous, TTL). No password or secret ever leaves the server.
- Per-session CSRF token, required on every POST (constant-time compare) PLUS a
  same-origin check on the Origin/Referer header. SameSite=Strict is the third layer.
- EVERY tool call is scope-checked server-side BEFORE the tool runs: every target-shaped
  argument goes through scope_guard.check() (fail-closed). Out-of-scope => refused, never
  dispatched. The tools re-check internally too (belt and suspenders).
- Strict CSP (script-src 'self'; no inline/eval, no third-party JS), security headers,
  no debug/stack traces to the client.
- Login is rate-limited; tool runs are capped by a bounded worker pool.
- Intended to be exposed only on a trusted/private network (VPN or loopback); this app
  is the single component with egress, which is why auth + scope guard matter here.

Run: uvicorn ui.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml
from fastapi import FastAPI, Form, Header, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from mcp_server import findings
from mcp_server.aggregate import _is_targetish, _walk_strings
from mcp_server.config import EVIDENCE_DIR, SCOPE_FILE, load_scope
from mcp_server.scope_guard import OutOfScope, check as scope_check, host_blocked
from mcp_server.tools import analysis, api, authn, browser, ext, injection, misconfig, recon, session, webflaws

# ---------------------------------------------------------------- config / secrets
HERE = Path(__file__).parent


def _require_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(
            f"{name} is required — set it in .env. Refusing to start without it."
        )
    return v


# These MUST be provided (no insecure defaults). The container's .env supplies them.
UI_PASSWORD = _require_env("WRAITH_UI_PASSWORD")
UI_SECRET = _require_env("WRAITH_UI_SECRET")
if len(UI_SECRET) < 32:
    raise RuntimeError(
        "WRAITH_UI_SECRET must be at least 32 characters of strong randomness — it is the "
        "sole key protecting every session. Refusing to start with a weak signing secret."
    )
UI_USERNAME = (os.environ.get("WRAITH_UI_USERNAME") or "Agent").strip() or "Agent"
SESSION_TTL = int(os.environ.get("WRAITH_UI_SESSION_TTL", "43200"))  # 12h
# Secure cookie flag: on by default; set WRAITH_UI_INSECURE_COOKIE=1 only for local http dev.
COOKIE_SECURE = os.environ.get("WRAITH_UI_INSECURE_COOKIE", "") != "1"
COOKIE_NAME = "wraith_session"

_signer = URLSafeTimedSerializer(UI_SECRET, salt="wraith-ui-session")

# Private store (wraith-ui ONLY — deliberately NOT the evidence volume, which the lower-trust
# tool-runner container can read). Holds the operator password hash + the session epoch.
PRIVATE_DIR = Path(os.environ.get("WRAITH_UI_PRIVATE", "/app/private"))
try:
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
# Password store. WRAITH_UI_PASSWORD (env) is the INITIAL bootstrap credential; once the
# operator sets a new password in the UI it is written salted+hashed here and takes
# precedence — so the bootstrap password stops working.
_PWFILE = PRIVATE_DIR / "ui-password"
_EPOCH_FILE = PRIVATE_DIR / "session-epoch"
_PBKDF2_ROUNDS = 200_000


def _hash_pw(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, _PBKDF2_ROUNDS)


def _verify_password(pw: str) -> bool:
    if _PWFILE.exists():
        # File present => it is the source of truth. A corrupt/unreadable store FAILS CLOSED
        # (C3): it must NOT silently revive the non-expiring env bootstrap password.
        try:
            salt_hex, hash_hex = _PWFILE.read_text().strip().split(":", 1)
            salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        except Exception:
            return False
        return hmac.compare_digest(_hash_pw(pw, salt), expected)
    # No store yet (fresh install): the env bootstrap password is in effect.
    return secrets.compare_digest(pw, UI_PASSWORD)


def _set_password(newpw: str) -> None:
    salt = secrets.token_bytes(16)
    tmp = _PWFILE.with_suffix(".tmp")
    tmp.write_text(f"{salt.hex()}:{_hash_pw(newpw, salt).hex()}")  # atomic: temp then rename
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, _PWFILE)


def _current_epoch() -> int:
    """Session epoch — bumped on password change to invalidate all older sessions (C5)."""
    try:
        return int(_EPOCH_FILE.read_text().strip())
    except Exception:
        return 0


def _bump_epoch() -> None:
    tmp = _EPOCH_FILE.with_suffix(".tmp")
    tmp.write_text(str(_current_epoch() + 1))
    os.replace(tmp, _EPOCH_FILE)


def _verify_login(username: str, password: str) -> bool:
    """Both username AND password must match. Both checks always run (no early-out),
    and both use constant-time compares, so timing can't reveal which half was wrong."""
    u_ok = hmac.compare_digest(username or "", UI_USERNAME)
    p_ok = _verify_password(password or "")
    return u_ok and p_ok


# bounded, non-overlapping field size caps (defense against memory abuse)
MAX_TARGET = 2048
MAX_SMALL = 4096
MAX_BLOB = 64 * 1024

# login rate limit: N failures per window, then refuse for the rest of the window.
_LOGIN_MAX = 8
_LOGIN_WINDOW = 300.0
_login_state: dict[str, tuple[int, float]] = {}

# tool execution: cap concurrency so long tools (sqlmap/browser) can't exhaust the box.
_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="wraith-tool")
_INFLIGHT = asyncio.Semaphore(4)
_scan_running = False  # one bulk scan at a time (C6): a background scan holds this
_scan_stop = False      # set by /api/scan/stop; the running scan/group loop breaks before its next step

# in-memory ring of recent log lines (also appended to an on-disk audit log, escaped on render)
_LOG: deque[dict] = deque(maxlen=400)
_AUDIT = PRIVATE_DIR / "ui-audit.log"

templates = Jinja2Templates(directory=str(HERE / "templates"))
app = FastAPI(title="Wraith Console", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")


def _asset_ver() -> str:
    """Hash the JS+CSS so the <script>/<link> URLs change whenever they do — forces browsers
    to fetch fresh assets after a deploy instead of serving a stale cached wraith.js."""
    h = hashlib.sha1()
    for name in ("wraith.js", "wraith.css"):
        try:
            h.update((HERE / "static" / name).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:10]


templates.env.globals["asset_ver"] = _asset_ver()


# ---------------------------------------------------------------- session / csrf
def _new_session() -> dict:
    return {"sid": secrets.token_urlsafe(16), "csrf": secrets.token_urlsafe(24),
            "t": time.time(), "e": _current_epoch()}


def _read_session(request: Request) -> dict | None:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return None
    try:
        sess = _signer.loads(raw, max_age=SESSION_TTL)
    except (BadSignature, SignatureExpired):
        return None
    if sess.get("e", 0) != _current_epoch():  # password changed since issue => invalid (C5)
        return None
    return sess


def _set_session(resp: Response, sess: dict) -> None:
    resp.set_cookie(
        COOKIE_NAME, _signer.dumps(sess),
        max_age=SESSION_TTL, httponly=True, secure=COOKIE_SECURE,
        samesite="strict", path="/",
    )


def _same_origin(request: Request) -> bool:
    """Reject a POST whose Origin/Referer host doesn't match the request host."""
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return False  # fail closed: a browser form/fetch always sends one of these
    try:
        return urlparse(origin).netloc == request.headers.get("host", "")
    except Exception:
        return False


def _csrf_ok(request: Request, sess: dict, token: str | None) -> bool:
    tok = token or request.headers.get("x-csrf-token") or ""
    return bool(tok) and secrets.compare_digest(tok, sess.get("csrf", ""))


def _unauth() -> JSONResponse:
    return JSONResponse({"error": "unauthorized"}, status_code=401)


# ---------------------------------------------------------------- security headers
_CSP = (
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'"
)


@app.middleware("http")
async def _headers(request: Request, call_next):
    try:
        resp = await call_next(request)
    except Exception:
        # never leak a stack trace to the client
        resp = JSONResponse({"error": "internal error"}, status_code=500)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Server"] = "wraith"  # don't leak the uvicorn version
    return resp


# ---------------------------------------------------------------- logging
def _redact(target: str) -> str:
    """Strip userinfo (user:pass@) so credentials never reach the log or disk."""
    if not target or "@" not in target:
        return target
    try:
        p = urlparse(target if "://" in target else f"//{target}")
        if p.username or p.password:
            hostport = (p.hostname or "") + (f":{p.port}" if p.port else "")
            prefix = f"{p.scheme}://" if (p.scheme and "://" in target) else ""
            return prefix + hostport + (p.path or "")
    except Exception:
        return "<redacted>"
    return target


def _log(kind: str, tool: str, target: str, verdict: str, detail: str = "") -> None:
    row = {"ts": time.time(), "kind": kind, "tool": tool, "target": _redact(target),
           "verdict": verdict, "detail": detail[:300]}
    _LOG.append(row)
    try:
        with open(_AUDIT, "a") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass  # audit log is best-effort; never break a request on it


def _log_out(tool: str, line: str) -> None:
    """Live-output sink for the sealed runner: append one tool stdout line to the activity
    ring so the browser's poll shows it as it arrives. In-memory only — stream lines are
    ephemeral terminal noise and are kept out of the on-disk audit log."""
    line = (line or "").strip()
    if not line:
        return
    _LOG.append({"ts": time.time(), "kind": "out", "tool": tool, "target": "",
                 "verdict": "", "detail": line[:300]})


_TERMINAL_VERDICTS = ("ok", "refused", "error", "stopped")


def _dedupe_running(rows: list[dict]) -> list[dict]:
    """Hide a 'running' entry once a LATER entry for the same tool+target reached a terminal
    verdict — so a finished step stops showing a stale, pulsing 'running' line (which read as
    'stuck'). A step still in flight (no terminal yet) keeps its 'running' line. O(n), order kept."""
    seen_terminal: set = set()
    drop: set = set()
    for i in range(len(rows) - 1, -1, -1):
        r = rows[i]
        key = (r.get("tool"), r.get("target"))
        if r.get("verdict") in _TERMINAL_VERDICTS:
            seen_terminal.add(key)
        elif r.get("verdict") == "running" and key in seen_terminal:
            drop.add(i)
    return [r for i, r in enumerate(rows) if i not in drop]


def _stop_requested() -> bool:
    return _scan_stop


async def _run_tool_streamed(fn):
    """Run a blocking tool fn in the pool with the live-output sink AND the stop-check bound, so
    any ext (sealed-runner) tool it calls streams each stdout line into the activity log and
    aborts promptly when the user hits STOP. ContextVars don't cross into executor threads on
    their own, so snapshot the context WITH both set and run fn inside that copy."""
    loop = asyncio.get_event_loop()
    t1 = ext._LINE_SINK.set(_log_out)
    t2 = ext._STOP_CHECK.set(_stop_requested)
    ctx = contextvars.copy_context()
    ext._LINE_SINK.reset(t1)
    ext._STOP_CHECK.reset(t2)  # keep both out of this coroutine's own context
    return await loop.run_in_executor(_POOL, ctx.run, fn)


# ---------------------------------------------------------------- scope gate
_GATE_TARGET_ONLY = {"ssrf", "http_request"}  # scope only the fetch target; a URL inside a
# header/body/cookie value is data, not a destination — gating it caused false refusals (#13)


def _gate(params: dict) -> str | None:
    """Scope-check every target-shaped string ANYWHERE in params (recurses into dicts/lists
    via the aggregation walker, so destinations hidden in browser steps / nested args are
    caught too). Returns a refusal reason, or None if OK. Fail-closed."""
    try:
        for s in _walk_strings(params):
            if _is_targetish(s):
                scope_check(s)
        return None
    except OutOfScope as e:
        return str(e)
    except Exception as e:  # any parse error => refuse
        return f"scope check failed: {e}"


# ---------------------------------------------------------------- tool registry
def _parse_json_obj(raw: str, field: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        return {}
    if len(raw) > MAX_BLOB:
        raise ValueError(f"{field} too large")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError(f"{field} must be a JSON object")
    return obj


def _parse_json_list(raw: str, field: str) -> list:
    raw = (raw or "").strip()
    if not raw:
        return []
    if len(raw) > MAX_BLOB:
        raise ValueError(f"{field} too large")
    obj = json.loads(raw)
    if not isinstance(obj, list):
        raise ValueError(f"{field} must be a JSON array")
    return obj


def _wordlist(raw: str) -> str | None:
    """enum_paths wordlist: confine to the bundled wordlists dir (basename only) to
    stop arbitrary file reads / path traversal via the UI."""
    raw = (raw or "").strip()
    if not raw:
        return None
    name = os.path.basename(raw)
    cand = (Path(recon.__file__).parent.parent / "wordlists" / name)
    if not cand.is_file():
        raise ValueError("wordlist must be a name of a bundled wordlist")
    return str(cand)


def _split_args(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    if len(raw) > MAX_SMALL:
        raise ValueError("extra_args too large")
    return raw.split()


# Each builder validates/coerces form fields into the tool's real kwargs.
def _b_recon(f):        return {"target": f["target"]}
def _b_browser_recon(f): return {"target": f["target"], "cookie": (f.get("cookie") or "").strip()}
def _b_jwt(f):          return {"jwt": (f.get("jwt") or "").strip()}  # offline token, not a target
def _b_enum(f):         return {"target": f["target"], "wordlist_path": _wordlist(f.get("wordlist_path", ""))}
def _b_http(f):         return {"target": f["target"], "method": (f.get("method") or "GET").upper(),
                                "headers": _parse_json_obj(f.get("headers", ""), "headers"),
                                "body": (f.get("body") or None), "cookies": _parse_json_obj(f.get("cookies", ""), "cookies")}
def _b_injection(f):    return {"target": f["target"], "extra_args": _split_args(f.get("extra_args", ""))}
def _b_xss(f):          return {"target": f["target"], "param": f["param"], "method": (f.get("method") or "GET").upper()}
def _b_authz(f):        return {"target": f["target"],
                                "session_a": _parse_json_obj(f.get("session_a", ""), "session_a"),
                                "session_b": _parse_json_obj(f.get("session_b", ""), "session_b")}
def _b_browser(f):      return {"target": f["target"], "steps": _parse_json_list(f.get("steps", ""), "steps"),
                                "oast_host": (f.get("oast_host") or "").strip()}
def _b_finding(f):      return {"title": f["title"], "severity": (f.get("severity") or "info").lower(),
                                "target": f.get("target", ""), "vuln_class": f.get("vuln_class", ""),
                                "description": f.get("description", ""), "proof": f.get("proof", ""),
                                "remediation": f.get("remediation", "")}
def _b_report(f):       return {"target": f.get("target", "")}
def _b_scope(f):        return {}
def _b_param(f):        return {"target": f["target"], "param": f["param"],
                                "method": (f.get("method") or "GET").upper()}
def _b_ssrf(f):         return {"target": f["target"], "param": f["param"],
                                "method": (f.get("method") or "GET").upper(),
                                "oast_host": (f.get("oast_host") or "").strip()}
def _b_stored(f):       return {"target": f["target"], "param": f["param"],
                                "method": (f.get("method") or "POST").upper(),
                                "verify_url": (f.get("verify_url") or "").strip()}
def _b_auth(f):         return {"target": f["target"],
                                "username_field": (f.get("username_field") or "username"),
                                "password_field": (f.get("password_field") or "password"),
                                "default_creds": (f.get("default_creds") or "1") == "1",
                                "test_lockout": (f.get("test_lockout") or "") == "1"}


def _record_finding(**kw):
    try:
        fid = findings.record(findings.Finding(**kw))
        return {"id": fid, "recorded": True}
    except ValueError as e:
        return {"recorded": False, "reason": str(e)}


def _export_report(**kw):
    md = findings.export_report_markdown(kw.get("target", ""))  # findings + every captured run
    path = EVIDENCE_DIR / "report.md"
    path.write_text(md)
    return {"path": str(path), "markdown": md}


# name -> (builder, callable, is_network_tool)
TOOLS = {
    "show_scope":     (_b_scope,     lambda **k: load_scope(),        False),
    "recon_http":     (_b_recon,     recon.recon_http,                True),
    "enum_paths":     (_b_enum,      recon.enum_paths,                True),
    "http_request":   (_b_http,      analysis.http_request,           True),
    "injection": (_b_injection, analysis.injection,         True),
    "xss":       (_b_xss,       analysis.xss,               True),
    "authz":     (_b_authz,     analysis.authz,             True),
    "browser_scenario": (_b_browser, browser.browser_scenario,        True),
    "screenshot":      (_b_recon,     browser.screenshot,              True),
    "browser_recon":   (_b_browser_recon, browser.browser_recon,       True),
    "check_config":   (_b_recon,     misconfig.check_config,          True),
    "tls":       (_b_recon,     misconfig.tls,              True),
    "cmdi":      (_b_param,     injection.cmdi,             True),
    "ssti":      (_b_param,     injection.ssti,             True),
    "path_traversal": (_b_param, injection.path_traversal,  True),
    "open_redirect": (_b_param, webflaws.open_redirect,     True),
    "ssrf":      (_b_ssrf,      webflaws.ssrf,              True),
    "stored_xss": (_b_stored,   webflaws.stored_xss,        True),
    "csrf":      (_b_recon,     session.csrf,               True),
    "session":   (_b_recon,     session.session,            True),
    "auth":      (_b_auth,      authn.auth,                 True),
    "api":       (_b_recon,     api.api,                    True),
    # recon pack (external binaries via the sealed tool-runner)
    "whatweb":        (_b_recon,     ext.whatweb,                     True),
    "wafw00f":        (_b_recon,     ext.wafw00f,                     True),
    "arjun":          (_b_recon,     ext.arjun,                       True),
    "katana":         (_b_recon,     ext.katana,                      True),
    "ffuf":           (_b_recon,     ext.ffuf,                        True),
    # scanners
    "nuclei":         (_b_recon,     ext.nuclei,                      True),
    "nikto":          (_b_recon,     ext.nikto,                       True),
    "wapiti":         (_b_recon,     ext.wapiti,                      True),
    # injection / exploitation
    "commix":         (_b_recon,     ext.commix,                      True),
    "sstimap":        (_b_recon,     ext.sstimap,                     True),
    "dalfox":         (_b_recon,     ext.dalfox,                      True),
    "crlfuzz":        (_b_recon,     ext.crlfuzz,                     True),
    "corsy":          (_b_recon,     ext.corsy,                       True),
    "oralyzer":       (_b_recon,     ext.oralyzer,                    True),
    # session / api / crypto
    "jwt_tool":       (_b_jwt,       ext.jwt_tool,                    False),
    "testssl":        (_b_recon,     ext.testssl,                     True),
    "graphw00f":      (_b_recon,     ext.graphw00f,                   True),
    "clairvoyance":   (_b_recon,     ext.clairvoyance,                True),
    "kiterunner":     (_b_recon,     ext.kiterunner,                  True),
    "smuggler":       (_b_recon,     ext.smuggler,                    True),
    # js / secrets
    "linkfinder":     (_b_recon,     ext.linkfinder,                  True),
    "secretfinder":   (_b_recon,     ext.secretfinder,                True),
    "cmseek":         (_b_recon,     ext.cmseek,                      True),
    "feroxbuster":    (_b_recon,     ext.feroxbuster,                 True),
    "wpscan":         (_b_recon,     ext.wpscan,                      True),
    "xsstrike":       (_b_recon,     ext.xsstrike,                    True),
    "nosqli":         (_b_recon,     ext.nosqli,                      True),
    "ppfuzz":         (_b_recon,     ext.ppfuzz,                      True),
    "joomscan":       (_b_recon,     ext.joomscan,                    True),
    "droopescan":     (_b_recon,     ext.droopescan,                  True),
    "gobuster_vhost": (_b_recon,     ext.gobuster_vhost,              True),
    "nuclei_dast":    (_b_recon,     ext.nuclei_dast,                 True),
    "record_finding": (_b_finding,   _record_finding,                 False),
    "export_report":  (_b_report,    _export_report,                  False),
}


# ---------------------------------------------------------------- pages
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sess = _read_session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    from mcp_server.tools.browser import exit_info  # read-only active-exit badge (P2-3)
    ex = exit_info()
    return templates.TemplateResponse("console.html", {
        "request": request, "csrf": sess["csrf"],
        "exit_city": ex["city"], "exit_tz": ex["tz"]})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _read_session(request):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    n, start = _login_state.get(ip, (0, time.time()))
    if time.time() - start > _LOGIN_WINDOW:
        n, start = 0, time.time()
    if n >= _LOGIN_MAX:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Too many attempts. Wait a few minutes."},
            status_code=429)
    if not _same_origin(request):
        return JSONResponse({"error": "bad origin"}, status_code=403)
    ok = _verify_login(username, password)
    if not ok:
        _login_state[ip] = (n + 1, start)
        await asyncio.sleep(0.5)  # slow brute force
        _log("auth", "login", "", "fail")
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Incorrect password."}, status_code=401)
    _login_state.pop(ip, None)
    resp = RedirectResponse("/", status_code=302)
    _set_session(resp, _new_session())
    _log("auth", "login", "", "ok")
    return resp


@app.post("/logout")
async def logout(request: Request, csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.post("/change-password", response_class=HTMLResponse)
async def change_password(request: Request, current: str = Form(...), new: str = Form(...),
                          confirm: str = Form(...), csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    if max(len(current), len(new), len(confirm)) > MAX_SMALL:
        return JSONResponse({"error": "field too large"}, status_code=413)
    if not _verify_password(current):
        return JSONResponse({"error": "current password is incorrect"}, status_code=403)
    if len(new) < 12:
        return JSONResponse({"error": "new password must be at least 12 characters"}, status_code=400)
    if new != confirm:
        return JSONResponse({"error": "new password and confirmation do not match"}, status_code=400)
    _set_password(new)
    _bump_epoch()  # invalidate every other existing session (C5)
    _log("auth", "change_password", "", "ok")
    resp = HTMLResponse('<div class="ok-msg">✓ Password changed. The bootstrap password no '
                        'longer works, and any other signed-in sessions have been logged out.</div>')
    sess["e"] = _current_epoch()  # keep THIS session valid under the new epoch
    _set_session(resp, sess)
    return resp


@app.get("/healthz")
async def healthz():
    return {"ok": True}


# ---------------------------------------------------------------- API (auth + csrf)
def _guard_post(request: Request, csrf_token: str | None):
    """Returns (sess, None) when OK, or (None, error_response) to short-circuit."""
    sess = _read_session(request)
    if not sess:
        return None, _unauth()
    if not _same_origin(request):
        return None, JSONResponse({"error": "bad origin"}, status_code=403)
    if not _csrf_ok(request, sess, csrf_token):
        return None, JSONResponse({"error": "bad csrf token"}, status_code=403)
    return sess, None


@app.get("/api/log", response_class=HTMLResponse)
async def api_log(request: Request):
    if not _read_session(request):
        return _unauth()
    return templates.TemplateResponse(
        "_log.html", {"request": request, "rows": _dedupe_running(list(_LOG)[-120:])})


@app.get("/api/scope", response_class=HTMLResponse)
async def api_scope(request: Request):
    if not _read_session(request):
        return _unauth()
    return templates.TemplateResponse("_scope.html",
                                      {"request": request, "scope": load_scope().get("targets", [])})


@app.get("/api/findings", response_class=HTMLResponse)
async def api_findings(request: Request):
    if not _read_session(request):
        return _unauth()
    rows = sorted(findings.load_all(),
                  key=lambda r: list(findings.SEVERITIES).index(r.get("severity", "info")), reverse=True)
    return templates.TemplateResponse("_findings.html", {"request": request, "rows": rows})


@app.get("/api/results", response_class=HTMLResponse)
async def api_results(request: Request):
    """Captured tool-run results for in-UI browsing (most recent first). This is what makes a
    recon/vuln sweep's output visible in the console, not just downloadable."""
    if not _read_session(request):
        return _unauth()
    rows = list(reversed(findings.load_results()))[:80]
    for r in rows:
        out = (r.get("output") or "").strip()
        r["preview"] = out[:240] + ("…" if len(out) > 240 else "")
        if r.get("tool") == "screenshot":  # surface the PNG as a thumbnail
            try:
                shot = json.loads(out).get("screenshot")
                if shot and shot.endswith(".png"):
                    r["shot"] = os.path.basename(shot)
            except Exception:
                pass
    return templates.TemplateResponse("_results.html", {"request": request, "rows": rows})


@app.get("/api/shot/{name}")
async def api_shot(request: Request, name: str):
    """Serve a screenshot PNG from the evidence shots/ dir (session-guarded, basename-confined)."""
    if not _read_session(request):
        return _unauth()
    safe = os.path.basename(name)
    if not safe.endswith(".png"):
        return JSONResponse({"error": "not found"}, status_code=404)
    path = (EVIDENCE_DIR / "shots" / safe)
    if path.resolve().parent != (EVIDENCE_DIR / "shots").resolve() or not path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    return Response(path.read_bytes(), media_type="image/png",
                    headers={"Cache-Control": "private, max-age=300"})


@app.post("/api/results/clear", response_class=HTMLResponse)
async def api_results_clear(request: Request, csrf: str = Form(None)):
    """Clear the captured-results store (archived to a .bak on the volume, not destroyed) so the
    next export isn't a pile of old runs. Returns the now-empty results fragment."""
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    n = findings.clear_results()
    _log("evidence", "results", "", "cleared", f"{n} run(s) archived")
    return templates.TemplateResponse("_results.html", {"request": request, "rows": []})


@app.get("/api/results/export")
async def api_results_export(request: Request, tool: str = "", target: str = "",
                             fmt: str = "md", latest: str = ""):
    """Download captured tool results as a file. No filter = everything; tool/target filter to
    one tool or target; latest=1 = just the most recent match (used by the per-result export
    link). Read-only, session-guarded, served as an attachment (never rendered as HTML)."""
    import re
    if not _read_session(request):
        return _unauth()
    rows = findings.load_results()
    if tool:
        rows = [r for r in rows if r.get("tool") == tool]
    if target:
        rows = [r for r in rows if r.get("target") == target]
    if latest == "1" and rows:
        rows = [rows[-1]]
    if fmt == "json":
        body = json.dumps(rows, indent=2, default=str)
        ctype = "application/json"
        ext = "json"
    else:
        body = findings.results_to_markdown(rows)
        ctype = "text/markdown"
        ext = "md"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", tool or "wraith-results")[:60]  # no header injection
    return Response(body, media_type=ctype,
                    headers={"Content-Disposition": f'attachment; filename="{safe}.{ext}"'})


def _write_scope(data: dict) -> None:
    """Atomic scope.yaml write (temp + os.replace): a crash or a concurrent single+bulk add
    can't leave a half-written, corrupt allowlist (#12)."""
    text = yaml.safe_dump(data, sort_keys=False)
    tmp = SCOPE_FILE.with_suffix(SCOPE_FILE.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, SCOPE_FILE)


def _valid_host(h: str) -> bool:
    import re
    h = h.strip()
    if not h or len(h) > 255:
        return False
    # hostname, IPv4, or bracketed/plain IPv6 — conservative charset, no spaces/control/slashes
    return bool(re.fullmatch(r"[A-Za-z0-9._\-:\[\]]+", h))


def _split_target(raw: str) -> tuple[str, str]:
    """Normalize a pasted target to (host, port_str). Accepts a full URL
    (https://app.example.com:443/path), a bare host:port, or a bare host. port_str is ''
    when no port is present. No validation here — the caller validates host/port."""
    raw = (raw or "").strip()
    host, port = raw, ""
    looks_url = "://" in raw or "/" in raw or "?" in raw
    bare_hostport = (not looks_url and raw.count(":") == 1 and raw.rsplit(":", 1)[-1].isdigit())
    if looks_url or bare_hostport:
        p = urlparse(raw if "://" in raw else f"//{raw}")
        if p.hostname:
            host = p.hostname
            try:
                port = str(p.port) if p.port else ""
            except ValueError:
                # out-of-range port in the URL (urlparse validates 0-65535 lazily); keep the
                # raw digits so the caller's port check rejects it instead of 500-ing.
                np = p.netloc.rsplit("@", 1)[-1]
                port = np.rsplit(":", 1)[-1] if ":" in np and "]" not in np.rsplit(":", 1)[-1] else ""
    return host, port


@app.post("/api/scope/add", response_class=HTMLResponse)
async def scope_add(request: Request, host: str = Form(...), port: str = Form(""),
                    csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    # Accept a full URL (or bare host:port) pasted into the box — e.g.
    # http://172.28.0.2:3000/rest/products?q=1 — splitting out hostname + port so the user
    # doesn't have to. An explicit port field still wins; host-alone entry is unchanged.
    host, parsed_port = _split_target(host)
    if parsed_port and not port.strip():
        port = parsed_port
    if not _valid_host(host):
        return JSONResponse({"error": "invalid host"}, status_code=400)
    if host_blocked(host):  # resolves names too — a name pointing at metadata/loopback is caught (H4)
        return JSONResponse(
            {"error": "refused: loopback/link-local/metadata addresses can't be scoped"},
            status_code=400)
    entry = {"host": host}
    if port.strip():
        if not port.strip().isdigit() or not (1 <= int(port) <= 65535):
            return JSONResponse({"error": "invalid port"}, status_code=400)
        entry["port"] = int(port)
    data = load_scope()
    targets = data.get("targets", [])
    if entry not in targets:
        targets.append(entry)
    data["targets"] = targets
    _write_scope(data)
    _log("scope", "add", f"{host}:{port or 'any'}", "ok")
    return templates.TemplateResponse("_scope.html", {"request": request, "scope": targets})


@app.post("/api/scope/add_bulk", response_class=HTMLResponse)
async def scope_add_bulk(request: Request, targets: str = Form(""), csrf: str = Form(None)):
    """Paste many targets at once (one per line; commas/spaces/semicolons also split). Each is
    parsed to host+port, validated the same way as the single add, deduped, and the valid ones
    are added in one write. Returns an escaped added/skipped summary."""
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    import re
    raw = targets or ""
    if len(raw) > 20000:
        return JSONResponse({"error": "too much input (20k cap)"}, status_code=413)
    tokens = [t for t in re.split(r"[\s,;]+", raw) if t.strip()]
    if not tokens:
        return JSONResponse({"error": "no targets provided"}, status_code=400)
    # ponytail: cap at 100 per paste; host_blocked resolves names (sync), fine for a manual paste.
    tokens = tokens[:100]
    data = load_scope()
    scoped = data.get("targets", [])
    seen = {(t.get("host"), t.get("port")) for t in scoped}
    added, skipped = [], []
    for tok in tokens:
        host, port = _split_target(tok)
        if not _valid_host(host):
            skipped.append((tok, "invalid host")); continue
        if host_blocked(host):
            skipped.append((tok, "loopback/link-local/metadata blocked")); continue
        pnum = None
        if port:
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                skipped.append((tok, "invalid port")); continue
            pnum = int(port)
        key = (host, pnum)
        if key in seen:
            skipped.append((tok, "already in scope")); continue
        seen.add(key)
        entry = {"host": host}
        if pnum is not None:
            entry["port"] = pnum
        scoped.append(entry)
        added.append(entry)
    if added:
        data["targets"] = scoped
        _write_scope(data)
        _log("scope", "add_bulk", f"{len(added)} added, {len(skipped)} skipped", "ok")
    esc = html.escape
    parts = [f'<div class="ok-msg">✓ Authorized {len(added)} target(s)'
             + (f', skipped {len(skipped)}' if skipped else '') + '</div>']
    if added:
        parts.append("<ul class='bulk-res'>" + "".join(
            f"<li>{esc(a['host'])}{':' + str(a['port']) if a.get('port') else ' (any port)'}</li>"
            for a in added) + "</ul>")
    if skipped:
        parts.append("<div class='hint'>Skipped:</div><ul class='bulk-res skip'>" + "".join(
            f"<li>{esc(t)} — {esc(r)}</li>" for t, r in skipped) + "</ul>")
    return HTMLResponse("".join(parts))


@app.post("/api/scope/remove", response_class=HTMLResponse)
async def scope_remove(request: Request, host: str = Form(...), port: str = Form(""),
                       csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    data = load_scope()
    want_port = int(port) if port.strip().isdigit() else None
    targets = [t for t in data.get("targets", [])
               if not (t.get("host") == host.strip() and t.get("port") == want_port)]
    data["targets"] = targets
    _write_scope(data)
    _log("scope", "remove", f"{host}:{port or 'any'}", "ok")
    return templates.TemplateResponse("_scope.html", {"request": request, "scope": targets})


@app.post("/api/tool/{name}", response_class=HTMLResponse)
async def run_tool(request: Request, name: str, csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    spec = TOOLS.get(name)
    if not spec:
        return JSONResponse({"error": "unknown tool"}, status_code=404)
    builder, fn, is_net = spec

    form = {k: (v if isinstance(v, str) else "") for k, v in (await request.form()).items()}
    # enforce field caps up front
    for k, v in form.items():
        cap = MAX_TARGET if k == "target" else (MAX_BLOB if k in ("headers", "body", "cookies", "steps", "session_a", "session_b", "description", "proof") else MAX_SMALL)
        if len(v) > cap:
            return JSONResponse({"error": f"field {k} too large"}, status_code=413)
    try:
        kwargs = builder(form)
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        return JSONResponse({"error": f"invalid input: {e}"}, status_code=400)

    target = str(kwargs.get("target", "")) if is_net else ""
    # SERVER-SIDE SCOPE GATE — fail closed, before the tool runs.
    if is_net:
        # ssrf intentionally carries an external out-of-band host; scope only its fetch target.
        gate_params = {"target": kwargs.get("target", "")} if name in _GATE_TARGET_ONLY else kwargs
        reason = _gate(gate_params)
        if reason:
            _log("tool", name, target, "refused", reason)
            return templates.TemplateResponse(
                "_result.html",
                {"request": request, "tool": name, "target": target,
                 "refused": reason, "result": None})

    # run the (blocking) tool off the event loop, with a concurrency cap.
    if is_net:
        _log("tool", name, target, "running", "")  # live view: show it before it finishes
    if _INFLIGHT.locked():
        return JSONResponse({"error": "busy — too many tools running"}, status_code=429)
    async with _INFLIGHT:
        try:
            result = await _run_tool_streamed(lambda: fn(**kwargs))
        except OutOfScope as e:
            _log("tool", name, target, "refused", str(e))
            return templates.TemplateResponse(
                "_result.html", {"request": request, "tool": name, "target": target,
                                 "refused": str(e), "result": None})
        except Exception as e:
            _log("tool", name, target, "error", str(e))
            return templates.TemplateResponse(
                "_result.html", {"request": request, "tool": name, "target": target,
                                 "refused": None,
                                 "result": {"error": "tool execution error — see the activity log"}})

    verdict = "refused" if isinstance(result, dict) and result.get("refused") else "ok"
    _log("tool", name, target, verdict)
    if is_net:
        findings.record_result(name, target, "tool", result)  # capture so it's exportable
    pretty = json.dumps(result, indent=2, default=str)
    if len(pretty) > 200_000:
        pretty = pretty[:200_000] + "\n… (truncated)"
    return templates.TemplateResponse(
        "_result.html",
        {"request": request, "tool": name, "target": target, "refused": None,
         "result_text": pretty})


# ---------------------------------------------------------------- bulk scan
def _scan_summary(name: str, r) -> str:
    if not isinstance(r, dict):
        return ""
    if name == "recon_http":
        return f"status={r.get('status')} server={r.get('server', '')}"[:120]
    if name == "enum_paths":
        return f"found={len(r.get('found', []))}/{r.get('checked', 0)}"
    if name == "xss":
        return f"verdict={r.get('verdict', '')}"
    if name == "injection":
        return f"sqlmap rc={r.get('returncode')}"
    if name == "browser_scenario":
        return f"final={r.get('final_url', '')}"[:120]
    if "error" in r:
        return f"error: {str(r['error'])[:90]}"
    if "returncode" in r:  # tool-runner result (sqlmap + recon binaries)
        return f"rc={r.get('returncode')} out={len(r.get('stdout', ''))}b"
    bits = []
    if "verdict" in r:
        bits.append(f"verdict={r['verdict']}")
    if isinstance(r.get("findings"), list):
        bits.append(f"findings={len(r['findings'])}")
    return " ".join(bits)[:120]


async def _do_scan(target: str, heavy: bool) -> None:
    """Background scan wrapper: always clears the single-scan flag when done (C6)."""
    global _scan_running, _scan_stop
    try:
        await _do_scan_impl(target, heavy)
    finally:
        _scan_running = False
        _scan_stop = False


async def _do_scan_impl(target: str, heavy: bool) -> None:
    """Run the methodology in sequence as a background task; each step logs to the
    activity log (which the UI polls). Every step is scope-gated by the tool itself."""
    _log("scan", "scan", target, "start", "heavy" if heavy else "fast")
    param = next(iter(parse_qs(urlparse(target).query)), "q")
    steps = [
        ("recon_http", lambda: recon.recon_http(target)),
        ("enum_paths", lambda: recon.enum_paths(target)),
        ("check_config", lambda: misconfig.check_config(target)),
        ("tls", lambda: misconfig.tls(target)),
        ("session", lambda: session.session(target)),
        ("csrf", lambda: session.csrf(target)),
        ("api", lambda: api.api(target)),
        ("xss", lambda: analysis.xss(target, param)),
        ("open_redirect", lambda: webflaws.open_redirect(target, param)),
    ]
    if heavy:
        steps += [
            ("injection", lambda: analysis.injection(target)),
            ("cmdi", lambda: injection.cmdi(target, param)),
            ("ssti", lambda: injection.ssti(target, param)),
            ("path_traversal", lambda: injection.path_traversal(target, param)),
            ("ssrf", lambda: webflaws.ssrf(target, param)),
            ("stored_xss", lambda: webflaws.stored_xss(target, param)),
            ("browser_scenario", lambda: browser.browser_scenario(target, [])),
        ]
    for name, fn in steps:
        if _scan_stop:
            _log("scan", "scan", target, "stopped", "stopped by user")
            return
        _log("scan", name, target, "running", "")
        try:
            async with _INFLIGHT:
                r = await _run_tool_streamed(fn)
            if isinstance(r, dict) and r.get("refused"):
                _log("scan", name, target, "refused", str(r.get("reason", ""))[:200])
            else:
                _log("scan", name, target, "ok", _scan_summary(name, r))
            findings.record_result(name, target, "scan", r)  # capture every step for export
        except OutOfScope as e:
            _log("scan", name, target, "refused", str(e))
        except Exception as e:
            _log("scan", name, target, "error", str(e))
    _log("scan", "scan", target, "done", "")


@app.post("/api/scan", response_class=HTMLResponse)
async def api_scan(request: Request, target: str = Form(...), heavy: str = Form(""),
                   csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    target = target.strip()
    if not target or len(target) > MAX_TARGET:
        return JSONResponse({"error": "invalid target"}, status_code=400)
    reason = _gate({"target": target})
    if reason:
        _log("scan", "scan", target, "refused", reason)
        return templates.TemplateResponse(
            "_result.html",
            {"request": request, "tool": "scan", "target": target, "refused": reason, "result": None})
    global _scan_running, _scan_stop
    if _scan_running:
        return JSONResponse({"error": "a scan is already running — let it finish first"}, status_code=409)
    _scan_running = True
    _scan_stop = False
    asyncio.create_task(_do_scan(target, heavy == "1"))
    return HTMLResponse('<div class="ok-msg">✓ Scan started — watch the live activity log above.</div>')


@app.post("/api/scan/stop", response_class=HTMLResponse)
async def api_scan_stop(request: Request, csrf: str = Form(None)):
    """Signal the running scan or phase group to stop. It halts before its next step; the
    step already in flight finishes (or hits its own timeout) — we can't kill a running tool
    mid-request. ponytail: flag between steps; upgrade path is cancelling the in-flight stream."""
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    global _scan_stop
    if not _scan_running:
        return HTMLResponse('<div class="hint">No scan is running.</div>')
    _scan_stop = True
    _log("scan", "scan", "", "stopping", "stop requested by user")
    return HTMLResponse('<div class="ok-msg">■ Stop requested — halting after the current step.</div>')


# ---------------------------------------------------------------- bulk groups (phase buttons)
# Each group is an ordered list of (step-name, callable) built from the target. These are
# SEPARATE from Run Scan above (which is untouched). More tools slot into these lists as each
# wave lands. Everything shares the single-scan lock so groups never overlap a scan.
_GROUP_LABELS = {
    "recon_sweep": "Recon Sweep",
    "vuln_scan": "Vuln Scan",
    "injection_suite": "Injection Suite",
    "config": "Config & Crypto",
    "session": "Session & Identity",
    "api": "API & GraphQL",
    "js_secrets": "JS & Secrets",
}


def _group_steps(group: str, target: str) -> list:
    param = next(iter(parse_qs(urlparse(target).query)), "q")
    if group == "recon_sweep":
        # information-gathering only: fingerprint, enumerate, crawl, discover — NO active
        # vuln testing or exploitation (those live in Vuln Scan / Injection Suite).
        return [("recon_http", lambda: recon.recon_http(target)),
                ("browser_recon", lambda: browser.browser_recon(target)),
                ("enum_paths", lambda: recon.enum_paths(target)),
                ("whatweb", lambda: ext.whatweb(target)),
                ("wafw00f", lambda: ext.wafw00f(target)),
                ("arjun", lambda: ext.arjun(target)),
                ("katana", lambda: ext.katana(target)),
                ("ffuf", lambda: ext.ffuf(target)),
                ("feroxbuster", lambda: ext.feroxbuster(target)),
                ("cmseek", lambda: ext.cmseek(target)),
                ("gobuster_vhost", lambda: ext.gobuster_vhost(target))]
    if group == "vuln_scan":
        return [("nuclei", lambda: ext.nuclei(target)),
                ("nikto", lambda: ext.nikto(target)),
                ("wapiti", lambda: ext.wapiti(target)),
                ("wpscan", lambda: ext.wpscan(target)),
                ("joomscan", lambda: ext.joomscan(target)),
                ("droopescan", lambda: ext.droopescan(target))]
    if group == "injection_suite":
        return [("injection", lambda: analysis.injection(target)),
                ("cmdi", lambda: injection.cmdi(target, param)),
                ("commix", lambda: ext.commix(target)),
                ("ssti", lambda: injection.ssti(target, param)),
                ("sstimap", lambda: ext.sstimap(target)),
                ("path_traversal", lambda: injection.path_traversal(target, param)),
                ("ssrf", lambda: webflaws.ssrf(target, param)),
                ("xss", lambda: analysis.xss(target, param)),
                ("dalfox", lambda: ext.dalfox(target)),
                ("xsstrike", lambda: ext.xsstrike(target)),
                ("stored_xss", lambda: webflaws.stored_xss(target, param)),
                ("crlfuzz", lambda: ext.crlfuzz(target)),
                ("open_redirect", lambda: webflaws.open_redirect(target, param)),
                ("oralyzer", lambda: ext.oralyzer(target)),
                ("corsy", lambda: ext.corsy(target)),
                ("nosqli", lambda: ext.nosqli(target)),
                ("ppfuzz", lambda: ext.ppfuzz(target)),
                ("nuclei_dast", lambda: ext.nuclei_dast(target))]
    if group == "config":
        return [("check_config", lambda: misconfig.check_config(target)),
                ("tls", lambda: misconfig.tls(target)),
                ("testssl", lambda: ext.testssl(target))]
    if group == "session":
        return [("csrf", lambda: session.csrf(target)),
                ("session", lambda: session.session(target)),
                ("auth", lambda: authn.auth(target))]
    if group == "api":
        return [("api", lambda: api.api(target)),
                ("graphw00f", lambda: ext.graphw00f(target)),
                ("clairvoyance", lambda: ext.clairvoyance(target)),
                ("kiterunner", lambda: ext.kiterunner(target)),
                ("smuggler", lambda: ext.smuggler(target))]
    if group == "js_secrets":
        return [("linkfinder", lambda: ext.linkfinder(target)),
                ("secretfinder", lambda: ext.secretfinder(target))]
    return []


async def _do_group(group: str, target: str) -> None:
    global _scan_running, _scan_stop
    try:
        _log("bulk", group, target, "start", _GROUP_LABELS.get(group, group))
        for name, fn in _group_steps(group, target):
            if _scan_stop:
                _log("bulk", group, target, "stopped", "stopped by user")
                return
            _log("bulk", name, target, "running", "")
            try:
                async with _INFLIGHT:
                    r = await _run_tool_streamed(fn)
                if isinstance(r, dict) and r.get("refused"):
                    _log("bulk", name, target, "refused", str(r.get("reason", ""))[:200])
                else:
                    _log("bulk", name, target, "ok", _scan_summary(name, r))
                findings.record_result(name, target, "bulk", r)  # capture every step for export
            except OutOfScope as e:
                _log("bulk", name, target, "refused", str(e))
            except Exception as e:
                _log("bulk", name, target, "error", str(e))
        _log("bulk", group, target, "done", "")
    finally:
        _scan_running = False
        _scan_stop = False


@app.post("/api/bulk/{group}", response_class=HTMLResponse)
async def api_bulk(request: Request, group: str, target: str = Form(...), csrf: str = Form(None)):
    sess, err = _guard_post(request, csrf)
    if err:
        return err
    if group not in _GROUP_LABELS:
        return JSONResponse({"error": "unknown group"}, status_code=404)
    target = target.strip()
    if not target or len(target) > MAX_TARGET:
        return JSONResponse({"error": "invalid target"}, status_code=400)
    reason = _gate({"target": target})
    if reason:
        _log("bulk", group, target, "refused", reason)
        return templates.TemplateResponse(
            "_result.html",
            {"request": request, "tool": group, "target": target, "refused": reason, "result": None})
    global _scan_running, _scan_stop
    if _scan_running:
        return JSONResponse({"error": "a scan or group is already running — let it finish first"}, status_code=409)
    _scan_running = True
    _scan_stop = False
    asyncio.create_task(_do_group(group, target))
    return HTMLResponse(f'<div class="ok-msg">✓ {_GROUP_LABELS[group]} started — watch the live activity log above.</div>')


# template filters: html.escape (defense-in-depth; autoescape is already on) and an
# Eastern-time clock for the activity log.
import datetime
try:
    from zoneinfo import ZoneInfo
    _ET = ZoneInfo("America/New_York")
except Exception:
    _ET = None


def _fmt_ts(ts) -> str:
    try:
        return datetime.datetime.fromtimestamp(float(ts), _ET).strftime("%I:%M:%S %p")
    except Exception:
        return ""


templates.env.filters["e"] = html.escape
templates.env.filters["ts"] = _fmt_ts
